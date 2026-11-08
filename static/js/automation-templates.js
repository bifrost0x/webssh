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
 const add=(id,group,en,de,requires,requiresDe,commands,{writes=false,sudo=false,timeout=30}={})=>entries.push({id,group,title:{en,de},requires:{en:requires,de:requiresDe},writes,steps:commands.map(([name,command])=>({name,command,timeout,sudo}))});
 add('inventory','system','System inventory','Systeminventar','Linux; uname, uptime, df','Linux; uname, uptime, df',[['System and uptime','uname -a && uptime'],['Disk capacity','df -hP']]);
 add('disk','system','Disk and inode capacity','Speicherplatz und Inodes','Linux; df, lsblk','Linux; df, lsblk',[['Filesystems','df -hP'],['Inodes','df -iP'],['Block devices','lsblk -o NAME,SIZE,FSTYPE,MOUNTPOINT']]);
 add('memory','system','Memory and swap','Arbeitsspeicher und Swap','Linux; procps','Linux; procps',[['Memory','free -h'],['Swap','cat /proc/swaps'],['Virtual memory activity','vmstat 1 5']]);
 add('cpu','system','CPU and system load','CPU und Systemlast','Linux; lscpu, procps','Linux; lscpu, procps',[['CPU','lscpu'],['Load','uptime'],['Top CPU processes',`processes=$(ps -eo pid,comm,pcpu,pmem --sort=-pcpu) && printf '%s\n' "$processes" | head -n 16`]]);
 add('processes','system','Process overview','Prozessübersicht','Linux; procps','Linux; procps',[['Memory consumers',`processes=$(ps -eo pid,comm,pmem,pcpu --sort=-pmem) && printf '%s\n' "$processes" | head -n 21`],['Process count',`processes=$(ps -e --no-headers) && printf '%s\n' "$processes" | wc -l`]]);
 add('boot','system','Boot and kernel information','Boot- und Kernelinformationen','Linux; systemd','Linux; systemd',[['Kernel','uname -r'],['Boot timing','systemd-analyze time'],['Previous boots','journalctl --list-boots --no-pager']]);
 add('time','system','Clock and time synchronization','Uhrzeit und Zeitsynchronisierung','Linux; systemd','Linux; systemd',[['System clock','date -Is'],['Time synchronization','timedatectl status']]);
 add('network','network','Network interfaces and routes','Netzwerkschnittstellen und Routen','Linux; iproute2','Linux; iproute2',[['Addresses','ip -brief address'],['Routes','ip route show'],['IPv6 routes','ip -6 route show']]);
 add('listeners','network','Listening ports','Offene Serverports','Linux; iproute2. Process details may require elevated privileges.','Linux; iproute2. Prozessdetails können erhöhte Rechte erfordern.',[['TCP and UDP listeners','ss -lntu'],['Socket statistics','ss -s']]);
 add('dns','network','DNS configuration','DNS-Konfiguration','Linux; systemd-resolved','Linux; systemd-resolved',[['Resolver status','resolvectl status'],['Resolver statistics','resolvectl statistics']]);
 add('links','network','Network link counters','Netzwerkzähler','Linux; iproute2','Linux; iproute2',[['Link counters','ip -s link'],['Neighbor table','ip neigh show']]);
 add('services','services','Service health','Dienstzustand','Linux; systemd','Linux; systemd',[['Failed services','systemctl --failed --no-pager'],['Running services','systemctl list-units --type=service --state=running --no-pager']]);
 add('timers','services','Scheduled system timers','Geplante System-Timer','Linux; systemd','Linux; systemd',[['Timers','systemctl list-timers --all --no-pager'],['Failed units','systemctl --failed --no-pager']]);
 add('journal','services','Recent system errors','Letzte Systemfehler','Linux; systemd journal access. Output may contain sensitive log data.','Linux; Zugriff auf das systemd-Journal. Ausgaben können sensible Protokolldaten enthalten.',[['Recent errors','journalctl -p err -n 80 --no-pager'],['Journal disk usage','journalctl --disk-usage']]);
 add('docker','containers','Docker inventory','Docker-Inventar','Docker CLI and access to the Docker daemon','Docker-CLI und Zugriff auf den Docker-Daemon',[['Containers','docker ps -a'],['Images','docker image ls'],['Disk usage','docker system df']]);
 add('docker-stats','containers','Docker resource usage','Docker-Ressourcenverbrauch','Docker CLI and access to the Docker daemon','Docker-CLI und Zugriff auf den Docker-Daemon',[['Resource snapshot','docker stats --no-stream'],['Container status','docker ps -a --format "table {{.Names}}\t{{.Status}}\t{{.Image}}"']]);
 add('compose','containers','Compose projects','Compose-Projekte','Docker Compose v2 plugin; Docker daemon access','Docker-Compose-v2-Plugin; Zugriff auf den Docker-Daemon',[['Compose projects','docker compose ls --all'],['Container inventory','docker ps -a']]);
 add('podman','containers','Podman inventory','Podman-Inventar','Podman; shows containers belonging to the SSH user','Podman; zeigt die Container des SSH-Benutzers',[['Containers','podman ps -a'],['Images','podman images'],['Disk usage','podman system df']]);
 add('maintenance','packages','Updates and restart status','Updates und Neustart-Status','Debian or Ubuntu for update counts, any Linux for the restart marker. Reads the local package lists without sudo, refreshing them or writing files. Fedora and others report only the restart marker. A scheduled run keeps the overview current.','Debian oder Ubuntu für Update-Zahlen, jedes Linux für die Neustart-Markierung. Liest die lokalen Paketlisten ohne sudo, ohne sie zu aktualisieren und ohne Dateien zu schreiben. Fedora und andere melden nur die Neustart-Markierung. Ein Zeitplan hält die Übersicht aktuell.',[['Updates and restart status',MAINTENANCE_COMMAND]]);
 add('apt-list','packages','Debian / Ubuntu package inventory','Debian-/Ubuntu-Paketinventar','Debian or Ubuntu; reads existing package metadata without refreshing it','Debian oder Ubuntu; liest vorhandene Paketdaten ohne Aktualisierung',[['Installed packages',"dpkg-query -W -f='${binary:Package}\t${Version}\n'"],['Held packages','apt-mark showhold']],{timeout:60});
 add('apt-upgrade','packages','Debian / Ubuntu package upgrade','Debian-/Ubuntu-Paketupgrade','Changes the host: refreshes package metadata and upgrades installed packages. Services may restart. Keeps existing configuration files. Requires passwordless sudo; each step has a 300-second limit.','Ändert den Host: aktualisiert Paketdaten und installierte Pakete. Dienste können neu starten. Bestehende Konfigurationsdateien bleiben erhalten. Erfordert kennwortloses sudo; Zeitlimit je Schritt: 300 Sekunden.',[['Refresh package metadata','apt-get update'],['Upgrade installed packages','DEBIAN_FRONTEND=noninteractive apt-get -y -o Dpkg::Options::=--force-confold upgrade']],{writes:true,sudo:true,timeout:300});
 add('dnf-upgrade','packages','Fedora / RHEL package upgrade','Fedora-/RHEL-Paketupgrade','Changes the host: refreshes metadata and upgrades installed packages. Services may restart. Requires DNF and passwordless sudo; 300-second limit.','Ändert den Host: aktualisiert Paketdaten und installierte Pakete. Dienste können neu starten. Erfordert DNF und kennwortloses sudo; Zeitlimit: 300 Sekunden.',[['Upgrade packages','dnf -y upgrade --refresh']],{writes:true,sudo:true,timeout:300});
 add('macos','system','macOS inventory','macOS-Inventar','macOS; read-only system and storage information','macOS; liest System- und Speicherinformationen',[['System version','sw_vers && uname -a'],['Uptime and capacity','uptime && df -h'],['Memory','vm_stat']]);
 const api={MAINTENANCE_COMMAND,list:()=>entries.map(({steps,...entry})=>({...entry,stepCount:steps.length+1})),create:id=>{const entry=entries.find(item=>item.id===id);return entry?{...entry,steps:[prerequisites(entry),...entry.steps.map(step=>({...step}))]}:null;}};
 root.AutomationTemplates=api;
 if(typeof module!=='undefined'&&module.exports)module.exports=api;
})(typeof window==='undefined'?globalThis:window);
