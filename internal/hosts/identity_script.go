package hosts

// The shell text of the read-only probes of app/host_platform.py, byte for
// byte (the differential test compares the assembled scripts).

// identityTemplate is _IDENTITY_TEMPLATE: os-release, kernel, board model,
// platform markers, virtualization, systemd target and services, guest
// count, then the catalog paths, snaps and container engines.
const identityTemplate = `LC_ALL=C
PATH=/usr/sbin:/usr/bin:/sbin:/bin:/usr/local/bin:/snap/bin
export LC_ALL PATH
found() { printf 'service=%s\n' "$1"; }
if [ -r /etc/os-release ]; then
  head -c 2048 /etc/os-release 2>/dev/null | awk -F= '$1 ~ /^(ID|ID_LIKE|VERSION_ID|VARIANT_ID)$/ && seen[$1]++ == 0 { print substr($0, 1, 200) }'
fi
printf 'kernel=%s\n' "$(uname -s 2>/dev/null)"
if [ -r /proc/device-tree/model ]; then
  printf 'model='; head -c 160 /proc/device-tree/model 2>/dev/null | tr -d '\000-\037'; printf '\n'
fi
if [ -r /etc/pve/.version ] || [ -d /usr/share/pve-manager ]; then printf 'marker=proxmox\n';
elif [ -r /conf/config.xml ] && [ -d /usr/local/opnsense ]; then printf 'marker=opnsense\n';
elif [ -r /etc/version ]; then
  head -c 256 /etc/version 2>/dev/null | awk '/^TrueNAS-/ { print "marker=truenas"; exit }'
fi
if [ -d /usr/share/proxmox-backup ] || [ -d /etc/proxmox-backup ]; then printf 'marker=proxmoxbackup\n'; fi
pf=/etc/platform
if head -c 256 "$pf" 2>/dev/null | grep -q pfSense; then printf 'marker=pfsense\n'; fi
if [ -e /etc/unraid-version ]; then printf 'marker=unraid\n'; fi
if [ -r /etc.defaults/VERSION ] && head -c 2048 /etc.defaults/VERSION 2>/dev/null | grep -qi synology; then printf 'marker=synology\n'; fi
if [ -e /etc/config/uLinux.conf ]; then printf 'marker=qnap\n'; fi
if [ -e /etc/openwrt_release ]; then printf 'marker=openwrt\n'; fi
if { [ -d /opt/vyatta ] && [ ! -e /usr/libexec/vyos ] && ! head -c 256 /opt/vyatta/etc/version 2>/dev/null | grep -qi vyos; } || { [ -r /usr/lib/version ] && head -c 256 /usr/lib/version 2>/dev/null | grep -q UniFi; }; then printf 'marker=ubiquiti\n'; fi
virt=$(systemd-detect-virt 2>/dev/null | head -n 1 | cut -c1-32)
if [ -z "$virt" ] || [ "$virt" = none ]; then
  if [ -e /.dockerenv ]; then virt=docker
  elif [ -e /run/.containerenv ]; then virt=podman
  elif head -c 4096 /proc/1/cgroup 2>/dev/null | grep -q -e docker -e kubepods -e containerd; then virt=docker
  elif head -c 4096 /proc/1/cgroup 2>/dev/null | grep -q lxc; then virt=lxc
  fi
fi
if [ -n "$virt" ]; then printf 'virt=%s\n' "$virt"; fi
if command -v systemctl >/dev/null 2>&1; then
  target=$(systemctl get-default 2>/dev/null | head -n 1 | cut -c1-40)
  if [ -n "$target" ]; then printf 'target=%s\n' "$target"; fi
  systemctl list-units --type=service --state=active --no-legend --plain 2>/dev/null | head -n 2000 | {
    wireguard=
    while read -r name rest; do
      name=${name%.service}
      case "$name" in
        wg-quick@*) wireguard=1 ;;
@UNITCASE@
@TEMPLATECASE@
      esac
    done
    if [ -n "$wireguard" ]; then found wireguard; fi
  } | sort -u
fi
if [ -r /etc/pve/qemu-server ] && [ -x /etc/pve/qemu-server ] && [ -r /etc/pve/lxc ] && [ -x /etc/pve/lxc ]; then
  printf 'guests=%s\n' "$(ls /etc/pve/qemu-server/*.conf /etc/pve/lxc/*.conf 2>/dev/null | wc -l | tr -d ' ')"
fi
@PATHS@
@SNAPS@
images=
@ENGINES@
printf '%s\n' "$images" | sed '/^$/d' | sort -u | head -n 100 | cut -c1-120 | awk '{ used += length($0) + 7; if (used > 3000) exit; print "image=" $0 }'
:
`

// dockerBlock is _DOCKER_BLOCK: Docker is asked only through a local
// daemon socket named with -H (never a context or DOCKER_HOST), not when
// an inactive docker.service would be socket-activated, and a socket that
// links to Podman is left to podmanBlock.
const dockerBlock = `dsock=
dstart() {
  { [ -d /run/systemd/system ] && command -v systemctl >/dev/null 2>&1; } || return 1
  systemctl -q "$@" is-active docker.service && return 1
  systemctl -q "$@" is-active docker.socket; [ $? -le 1 ]
}
du=
if [ -S /var/run/docker.sock ]; then dsock=/var/run/docker.sock
elif [ -n "$XDG_RUNTIME_DIR" ] && [ -S "$XDG_RUNTIME_DIR/docker.sock" ]; then dsock=$XDG_RUNTIME_DIR/docker.sock; du=--user
fi
psock=
if [ -n "$dsock" ] && [ -h "$dsock" ] && command -v readlink >/dev/null 2>&1; then
  case $(readlink "$dsock" 2>/dev/null | head -c 256) in
    *podman*) psock=$dsock; dsock= ;;
  esac
fi
if [ -n "$dsock" ]; then
  found docker
  if command -v docker >/dev/null 2>&1 && command -v timeout >/dev/null 2>&1 && ! dstart $du; then
    if out=$(timeout 1 docker -H "unix://$dsock" ps --format '{{.Image}}' 2>/dev/null); then
      printf 'engine=docker:ok\n'
      images=$(printf '%s\n%s' "$images" "$out")
    else
      printf 'engine=docker:denied\n'
    fi
  fi
fi`

// podmanBlock is _PODMAN_BLOCK: Podman is asked only through an existing
// API socket (--remote), so no rootless runtime is started.
const podmanBlock = `if [ -n "$psock" ] || command -v podman >/dev/null 2>&1; then
  sock=$psock
  if [ -z "$sock" ] && [ -S /run/podman/podman.sock ]; then sock=/run/podman/podman.sock
  elif [ -z "$sock" ] && [ -n "$XDG_RUNTIME_DIR" ] && [ -S "$XDG_RUNTIME_DIR/podman/podman.sock" ]; then sock=$XDG_RUNTIME_DIR/podman/podman.sock
  fi
  found podman
  if [ -n "$sock" ] && command -v podman >/dev/null 2>&1 && command -v timeout >/dev/null 2>&1; then
    if out=$(timeout 1 podman --remote --url "unix://$sock" ps --format '{{.Image}}' 2>/dev/null); then
      printf 'engine=podman:ok\n'
      images=$(printf '%s\n%s' "$images" "$out")
    else
      printf 'engine=podman:denied\n'
    fi
  fi
fi`

// maintenanceScript is MAINTENANCE_COMMAND: pending package updates and a
// required restart, read without refreshing package metadata, taking a
// lock, sudo or writing a file. WebSSH never runs it on its own; only a
// workflow the user starts or schedules does (internal/automation).
const maintenanceScript = `LC_ALL=C
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
`

// rebootHintScript is REBOOT_HINT_COMMAND: the restart marker test alone.
const rebootHintScript = `LC_ALL=C
PATH=/usr/sbin:/usr/bin:/sbin:/bin
export LC_ALL PATH
if [ -e /var/run/reboot-required ] || [ -e /run/reboot-required ]; then printf 'reboot=yes\n';
else printf 'reboot=no\n'; fi
:
`
