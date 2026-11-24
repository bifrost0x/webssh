(function(root){
 'use strict';
 const entries=[];
 // Identical to MAINTENANCE_COMMAND in app/host_platform.py; a run of exactly this step
 // updates the overview's restart and update facts for each host (tests keep both equal).
 const MAINTENANCE_COMMAND=String.raw`LC_ALL=C
PATH=/usr/sbin:/usr/bin:/sbin:/bin
export LC_ALL PATH
if [ -e /var/run/reboot-required ] || [ -e /run/reboot-required ]; then printf 'reboot=yes\n';
elif [ -d /var/lib/dpkg ]; then printf 'reboot=no\n'; fi
command -v timeout >/dev/null 2>&1 || exit 0
command -v apt-get >/dev/null 2>&1 || exit 0
# Without downloaded package lists every count would read 0, so report none.
set -- /var/lib/apt/lists/*_Packages*
[ -e "$1" ] || exit 0
if simulated=$(timeout 6 apt-get -s -o Debug::NoLocking=1 -o Dir::Log::Planner=/dev/null -o Dir::Cache::pkgcache= -o Dir::Cache::srcpkgcache= upgrade 2>/dev/null); then
  printf 'apt=%s\n' "$(printf '%s\n' "$simulated" | grep -c '^Inst ')"
  printf 'aptsecurity=%s\n' "$(printf '%s\n' "$simulated" | grep '^Inst ' | grep -ci 'securi')"
fi
:
`;
 const tools={maintenance:'grep',inventory:'uname uptime df',disk:'df lsblk',memory:'free cat vmstat',cpu:'lscpu uptime ps head',processes:'ps head wc',boot:'uname systemd-analyze journalctl systemctl',time:'date timedatectl systemctl',network:'ip',listeners:'ss',dns:'resolvectl systemctl',links:'ip',services:'systemctl',timers:'systemctl',journal:'journalctl',docker:'docker','docker-stats':'docker',compose:'docker',podman:'podman','apt-list':'dpkg-query apt-mark','apt-upgrade':'apt-get dpkg','dnf-upgrade':'dnf',macos:'sw_vers uname uptime df vm_stat'};
 function prerequisites(entry){
  const checks=[];
  if(!['docker','docker-stats','compose','podman'].includes(entry.id)){
   const platform=entry.id==='macos'?'Darwin':'Linux';
   checks.push(`if [ "$(uname -s)" != "${platform}" ]; then printf '%s\\n' 'This template requires ${platform}.' >&2; exit 1; fi`);
  }
  checks.push(`for tool in ${tools[entry.id]}; do command -v "$tool" >/dev/null 2>&1 || { printf 'Required command is missing: %s\\n' "$tool" >&2; exit 127; }; done`);
  if(['boot','time','dns','services','timers'].includes(entry.id))checks.push("systemctl show --property=Version --value >/dev/null || { printf '%s\\n' 'This template requires a running systemd manager.' >&2; exit 1; }");
  if(entry.id==='compose')checks.push("docker compose version >/dev/null || { printf '%s\\n' 'This template requires Docker Compose v2.' >&2; exit 1; }");
  if(['docker','docker-stats','compose'].includes(entry.id))checks.push("docker info >/dev/null || { printf '%s\\n' 'Docker daemon access is required for this SSH user.' >&2; exit 1; }");
  if(entry.id==='apt-upgrade')checks.push(". /etc/os-release; case \"$ID\" in debian|ubuntu) ;; *) printf '%s\\n' 'This upgrade template supports Debian and Ubuntu.' >&2; exit 1;; esac");
  checks.push("printf '%s\\n' 'Prerequisites available.'");
  return {name:'Check prerequisites',command:checks.join('\n'),timeout:30,sudo:false};
 }
 // Titles and requirements are translated as automation.template.<id>.title and .requires.
 const add=(id,group,commands,{writes=false,sudo=false,timeout=30}={})=>entries.push({id,group,writes,steps:commands.map(([name,command])=>({name,command,timeout,sudo}))});
 add('inventory','system',[['System and uptime','uname -a && uptime'],['Disk capacity','df -hP']]);
 add('disk','system',[['Filesystems','df -hP'],['Inodes','df -iP'],['Block devices','lsblk -o NAME,SIZE,FSTYPE,MOUNTPOINT']]);
 add('memory','system',[['Memory','free -h'],['Swap','cat /proc/swaps'],['Virtual memory activity','vmstat 1 5']]);
 add('cpu','system',[['CPU','lscpu'],['Load','uptime'],['Top CPU processes',`processes=$(ps -eo pid,comm,pcpu,pmem --sort=-pcpu) && printf '%s\n' "$processes" | head -n 16`]]);
 add('processes','system',[['Memory consumers',`processes=$(ps -eo pid,comm,pmem,pcpu --sort=-pmem) && printf '%s\n' "$processes" | head -n 21`],['Process count',`processes=$(ps -e --no-headers) && printf '%s\n' "$processes" | wc -l`]]);
 add('boot','system',[['Kernel','uname -r'],['Boot timing','systemd-analyze time'],['Previous boots','journalctl --list-boots --no-pager']]);
 add('time','system',[['System clock','date -Is'],['Time synchronization','timedatectl status']]);
 add('network','network',[['Addresses','ip -brief address'],['Routes','ip route show'],['IPv6 routes','ip -6 route show']]);
 add('listeners','network',[['TCP and UDP listeners','ss -lntu'],['Socket statistics','ss -s']]);
 add('dns','network',[['Resolver status','resolvectl status'],['Resolver statistics','resolvectl statistics']]);
 add('links','network',[['Link counters','ip -s link'],['Neighbor table','ip neigh show']]);
 add('services','services',[['Failed services','systemctl --failed --no-pager'],['Running services','systemctl list-units --type=service --state=running --no-pager']]);
 add('timers','services',[['Timers','systemctl list-timers --all --no-pager'],['Failed units','systemctl --failed --no-pager']]);
 add('journal','services',[['Recent errors','journalctl -p err -n 80 --no-pager'],['Journal disk usage','journalctl --disk-usage']]);
 add('docker','containers',[['Containers','docker ps -a'],['Images','docker image ls'],['Disk usage','docker system df']]);
 add('docker-stats','containers',[['Resource snapshot','docker stats --no-stream'],['Container status','docker ps -a --format "table {{.Names}}\t{{.Status}}\t{{.Image}}"']]);
 add('compose','containers',[['Compose projects','docker compose ls --all'],['Container inventory','docker ps -a']]);
 add('podman','containers',[['Containers','podman ps -a'],['Images','podman images'],['Disk usage','podman system df']]);
 add('maintenance','packages',[['Updates and restart status',MAINTENANCE_COMMAND]]);
 add('apt-list','packages',[['Installed packages',"dpkg-query -W -f='${binary:Package}\t${Version}\n'"],['Held packages','apt-mark showhold']],{timeout:60});
 add('apt-upgrade','packages',[['Refresh package metadata','apt-get update'],['Upgrade installed packages','DEBIAN_FRONTEND=noninteractive apt-get -y -o Dpkg::Options::=--force-confold upgrade']],{writes:true,sudo:true,timeout:300});
 add('dnf-upgrade','packages',[['Upgrade packages','dnf -y upgrade --refresh']],{writes:true,sudo:true,timeout:300});
 add('macos','system',[['System version','sw_vers && uname -a'],['Uptime and capacity','uptime && df -h'],['Memory','vm_stat']]);
 const api={MAINTENANCE_COMMAND,list:()=>entries.map(({steps,...entry})=>({...entry,stepCount:steps.length+1})),create:id=>{const entry=entries.find(item=>item.id===id);return entry?{...entry,steps:[prerequisites(entry),...entry.steps.map(step=>({...step}))]}:null;}};
 root.AutomationTemplates=api;
 if(typeof module!=='undefined'&&module.exports)module.exports=api;
})(typeof window==='undefined'?globalThis:window);
