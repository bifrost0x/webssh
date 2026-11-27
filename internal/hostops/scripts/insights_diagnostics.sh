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

if [ -r /proc/meminfo ] && command -v awk >/dev/null 2>&1; then
  awk '
    /^SwapTotal:/ { print "swap_total_kib=" $2 }
    /^SwapFree:/ { print "swap_free_kib=" $2 }
  ' /proc/meminfo 2>/dev/null
fi
if [ -r /proc/loadavg ] && command -v awk >/dev/null 2>&1; then
  awk '{
    print "load_1=" $1
    print "load_5=" $2
    print "load_15=" $3
  }' /proc/loadavg 2>/dev/null
fi
if [ -r /proc/stat ] && command -v awk >/dev/null 2>&1; then
  awk '/^cpu[0-9]+ / { count++ } END {
    if (count > 0) print "cpu_count=" count
  }' /proc/stat 2>/dev/null
fi
if [ -r /proc/net/dev ] && command -v awk >/dev/null 2>&1; then
  awk 'NR > 2 {
    separator = index($0, ":")
    if (separator == 0) next
    interface = substr($0, 1, separator - 1)
    gsub(/^[[:space:]]+|[[:space:]]+$/, "", interface)
    if (interface == "lo") next
    counters = substr($0, separator + 1)
    sub(/^[[:space:]]+/, "", counters)
    count = split(counters, fields, /[[:space:]]+/)
    if (count >= 16) {
      received += fields[1]
      transmitted += fields[9]
    }
  } END {
    print "network_received_bytes=" received + 0
    print "network_transmitted_bytes=" transmitted + 0
  }' /proc/net/dev 2>/dev/null
fi

process_probe=$(ps -p $$ -o pid= 2>&1)
process_status=$?
if [ "$process_status" -eq 0 ]; then
  ps -e -o stat= 2>/dev/null | awk '
    { total++ }
    substr($1, 1, 1) == "Z" { zombies++ }
    END {
      print "process_total=" total + 0
      print "process_zombies=" zombies + 0
    }'
  ps -e -o pid=,user=,comm=,pcpu=,pmem= --sort=-pcpu 2>/dev/null \
    | awk 'NR <= 5 {
        printf "process_cpu=%s|%s|%s|%s|%s\n", $1, $2, $3, $4, $5
      }'
  ps -e -o pid=,user=,comm=,pcpu=,pmem= --sort=-pmem 2>/dev/null \
    | awk 'NR <= 5 {
        printf "process_memory=%s|%s|%s|%s|%s\n", $1, $2, $3, $4, $5
      }'
elif printf '%s' "$process_probe" | grep -Eqi \
    'permission denied|access denied|not authorized|authorization denied'; then
  printf 'permission_denied=processes\n'
fi
:

