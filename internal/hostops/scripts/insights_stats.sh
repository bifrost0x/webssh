LC_ALL=C
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/snap/bin
export LC_ALL PATH
if [ -r /proc/stat ] && command -v awk >/dev/null 2>&1; then
  awk 'NR == 1 { $1=""; sub(/^ /, ""); print "cpu=" $0; exit }' /proc/stat 2>/dev/null
fi
if [ -r /proc/meminfo ] && command -v awk >/dev/null 2>&1; then
  awk '
    /^MemTotal:/ { print "mem_total_kib=" $2 }
    /^MemAvailable:/ { print "mem_available_kib=" $2 }
  ' /proc/meminfo 2>/dev/null
fi
if command -v df >/dev/null 2>&1 && command -v awk >/dev/null 2>&1; then
  df -Pk / 2>/dev/null | awk 'NR == 2 {
    percent=$5; sub(/%$/, "", percent)
    print "disk_total_kib=" $2
    print "disk_used_kib=" $3
    print "disk_available_kib=" $4
    print "disk_percent=" percent
  }'
fi
if [ -r /proc/uptime ] && command -v awk >/dev/null 2>&1; then
  awk '{ print "uptime_seconds=" $1; exit }' /proc/uptime 2>/dev/null
fi
if [ -r /etc/os-release ] && command -v awk >/dev/null 2>&1; then
  os_name=$(awk -F= '/^PRETTY_NAME=/ { sub(/^PRETTY_NAME=/, ""); print; exit }' /etc/os-release 2>/dev/null)
  os_name=${os_name#\"}; os_name=${os_name%\"}
  os_name=${os_name#\'}; os_name=${os_name%\'}
elif command -v uname >/dev/null 2>&1; then
  os_name=$(uname -srm 2>/dev/null)
else
  os_name=
fi
[ -n "$os_name" ] && printf 'os_name=%s\n' "$os_name"
:
