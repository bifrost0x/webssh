package hosts

// Catalogs of app/host_catalog.py for the identity probe. Everything a
// remote host reports is mapped onto these ids; nothing it prints is
// stored or shown directly. The differential test compares them with the
// Python catalog.

// services is SERVICES.
var services = set(
	"adguard", "apache", "audiobookshelf", "authelia", "authentik", "bazarr", "bind", "bookstack", "caddy",
	"calibreweb", "dashy", "deluge", "docker", "dozzle", "emby", "esphome", "filebrowser", "gitea", "gitlab",
	"grafana", "haproxy", "homarr", "homeassistant", "homebridge", "homepage", "immich", "influxdb", "jellyfin",
	"jellyseerr", "jenkins", "joplin", "k3s", "kavita", "keycloak", "lidarr", "loki", "mariadb", "mealie",
	"mongodb", "mosquitto", "navidrome", "netdata", "nextcloud", "nginx", "nginxproxymanager", "nodered",
	"ollama", "opensearch", "openvpn", "openwebui", "overseerr", "owncloud", "paperless", "photoprism",
	"pihole", "plex", "podman", "portainer", "postgresql", "prometheus", "prowlarr", "qbittorrent", "radarr",
	"readarr", "redis", "sabnzbd", "samba", "seafile", "sonarr", "stirlingpdf", "syncthing", "tailscale",
	"traefik", "transmission", "unbound", "uptimekuma", "vaultwarden", "watchtower", "wikijs", "wireguard",
	"woodpecker", "zabbix", "zerotier", "zigbee2mqtt",
)

// priorityServices and infrastructureServices order a list longer than
// maxServices: priority first, infrastructure last.
var (
	priorityServices = set(
		"gitea", "grafana", "homeassistant", "immich", "jellyfin", "nextcloud", "openvpn", "paperless", "pihole",
		"tailscale", "vaultwarden", "wireguard", "zerotier",
	)
	infrastructureServices = set(
		"apache", "caddy", "docker", "dozzle", "haproxy", "k3s", "mariadb", "mongodb", "nginx", "podman",
		"portainer", "postgresql", "redis", "traefik", "watchtower",
	)
)

// maxServices is MAX_SERVICES.
const maxServices = 24

// nonPOSIXPlatforms are recognised from a greeting only; no probe runs on
// them (NON_POSIX_PLATFORMS).
var nonPOSIXPlatforms = set("cisco", "mikrotik", "windows")

// osIDPlatforms is OS_ID_PLATFORMS (os-release ID).
var osIDPlatforms = map[string]string{
	"ubuntu": "ubuntu", "debian": "debian", "fedora": "fedora", "rocky": "rockylinux", "almalinux": "almalinux",
	"rhel": "redhat", "centos": "centos", "opensuse": "opensuse", "opensuse-leap": "opensuse",
	"opensuse-tumbleweed": "opensuse", "sles": "opensuse", "sled": "opensuse", "nixos": "nixos",
	"manjaro": "manjaro", "endeavouros": "endeavouros", "linuxmint": "linuxmint", "pop": "popos",
	"kali": "kalilinux", "gentoo": "gentoo", "void": "voidlinux", "arch": "archlinux", "alpine": "alpinelinux",
	"haos": "homeassistant", "truenas": "truenas", "openwrt": "openwrt", "raspbian": "raspberrypi",
	"freebsd": "freebsd",
}

// familyOf is FAMILIES (os-release ID_LIKE token).
var familyOf = map[string]string{
	"debian": "debian", "ubuntu": "ubuntu", "rhel": "redhat", "fedora": "fedora", "centos": "redhat",
	"suse": "opensuse", "opensuse": "opensuse", "arch": "archlinux", "alpine": "alpinelinux",
	"gentoo": "gentoo",
}

// markerPlatforms is MARKER_PLATFORMS in its order: the first marker
// present wins.
var markerPlatforms = [][2]string{
	{"proxmox", "proxmox"}, {"proxmoxbackup", "proxmoxbackup"}, {"truenas", "truenas"},
	{"opnsense", "opnsense"}, {"pfsense", "pfsense"}, {"unraid", "unraid"}, {"synology", "synology"},
	{"qnap", "qnap"}, {"openwrt", "openwrt"}, {"ubiquiti", "ubiquiti"},
}

// kernelPlatforms is KERNEL_PLATFORMS (uname -s).
var kernelPlatforms = map[string]string{"Linux": "linux", "Darwin": "apple", "FreeBSD": "freebsd"}

// virtMap is VIRT_MAP (systemd-detect-virt and the probe's own names).
var virtMap = map[string]string{
	"none": "bare-metal", "kvm": "vm", "qemu": "vm", "vmware": "vm", "microsoft": "vm", "oracle": "vm",
	"xen": "vm", "bochs": "vm", "parallels": "vm", "bhyve": "vm", "amazon": "vm", "google": "vm",
	"vm-other": "vm", "apple": "vm", "powervm": "vm", "zvm": "vm", "acrn": "vm", "qnx": "vm", "sre": "vm",
	"lxc": "lxc", "lxc-libvirt": "lxc", "openvz": "lxc", "systemd-nspawn": "lxc", "docker": "container",
	"podman": "container", "rkt": "container", "wsl": "wsl",
}

// serviceUnits is SERVICE_UNITS (systemd unit without .service). The
// probe matches the names in this order.
var serviceUnits = [][2]string{
	{"nginx", "nginx"}, {"apache2", "apache"}, {"httpd", "apache"}, {"caddy", "caddy"}, {"mariadb", "mariadb"},
	{"mysql", "mariadb"}, {"postgresql", "postgresql"}, {"smbd", "samba"}, {"k3s", "k3s"},
	{"jellyfin", "jellyfin"}, {"plexmediaserver", "plex"}, {"emby-server", "emby"}, {"sonarr", "sonarr"},
	{"radarr", "radarr"}, {"lidarr", "lidarr"}, {"readarr", "readarr"}, {"prowlarr", "prowlarr"},
	{"bazarr", "bazarr"}, {"overseerr", "overseerr"}, {"jellyseerr", "jellyseerr"},
	{"qbittorrent-nox", "qbittorrent"}, {"transmission-daemon", "transmission"}, {"deluged", "deluge"},
	{"sabnzbdplus", "sabnzbd"}, {"navidrome", "navidrome"}, {"audiobookshelf", "audiobookshelf"},
	{"kavita", "kavita"}, {"calibre-web", "calibreweb"}, {"photoprism", "photoprism"}, {"seafile", "seafile"},
	{"syncthing", "syncthing"}, {"filebrowser", "filebrowser"}, {"bookstack", "bookstack"},
	{"wikijs", "wikijs"}, {"mealie", "mealie"}, {"authentik", "authentik"}, {"authelia", "authelia"},
	{"keycloak", "keycloak"}, {"gitea", "gitea"}, {"forgejo", "gitea"}, {"gitlab-runsvdir", "gitlab"},
	{"jenkins", "jenkins"}, {"woodpecker-server", "woodpecker"}, {"mosquitto", "mosquitto"},
	{"zigbee2mqtt", "zigbee2mqtt"}, {"nodered", "nodered"}, {"esphome", "esphome"},
	{"homebridge", "homebridge"}, {"vaultwarden", "vaultwarden"}, {"grafana-server", "grafana"},
	{"prometheus", "prometheus"}, {"influxdb", "influxdb"}, {"loki", "loki"}, {"zabbix-server", "zabbix"},
	{"netdata", "netdata"}, {"redis-server", "redis"}, {"redis", "redis"}, {"mongod", "mongodb"},
	{"opensearch", "opensearch"}, {"tailscaled", "tailscale"}, {"zerotier-one", "zerotier"},
	{"unbound", "unbound"}, {"named", "bind"}, {"bind9", "bind"}, {"haproxy", "haproxy"},
	{"traefik", "traefik"}, {"pihole-FTL", "pihole"}, {"AdGuardHome", "adguard"}, {"uptime-kuma", "uptimekuma"},
	{"ollama", "ollama"}, {"open-webui", "openwebui"}, {"paperless-webserver", "paperless"},
	{"immich-server", "immich"}, {"homeassistant", "homeassistant"}, {"home-assistant", "homeassistant"},
}

// serviceUnitTemplates is SERVICE_UNIT_TEMPLATES (name before '@').
var serviceUnitTemplates = [][2]string{
	{"syncthing", "syncthing"}, {"openvpn", "openvpn"}, {"openvpn-server", "openvpn"},
	{"openvpn-client", "openvpn"},
}

// servicePaths is SERVICE_PATHS: fixed paths whose existence alone
// identifies the service.
var servicePaths = [][2]string{
	{"/var/www/nextcloud/occ", "nextcloud"}, {"/var/www/html/nextcloud/occ", "nextcloud"},
	{"/var/www/owncloud/occ", "owncloud"}, {"/etc/pihole", "pihole"}, {"/var/lib/sonarr", "sonarr"},
	{"/var/lib/radarr", "radarr"}, {"/var/lib/lidarr", "lidarr"}, {"/var/lib/readarr", "readarr"},
	{"/var/lib/prowlarr", "prowlarr"}, {"/var/lib/jellyfin", "jellyfin"}, {"/var/lib/plexmediaserver", "plex"},
	{"/var/lib/emby", "emby"}, {"/opt/gitlab", "gitlab"}, {"/etc/gitlab", "gitlab"},
	{"/var/lib/jenkins", "jenkins"}, {"/opt/zigbee2mqtt", "zigbee2mqtt"}, {"/var/lib/homebridge", "homebridge"},
	{"/var/lib/influxdb", "influxdb"}, {"/etc/netdata", "netdata"}, {"/var/lib/mongodb", "mongodb"},
	{"/etc/haproxy", "haproxy"}, {"/etc/authelia", "authelia"}, {"/opt/AdGuardHome", "adguard"},
}

// serviceSnaps is SERVICE_SNAPS (snap name).
var serviceSnaps = [][2]string{
	{"nextcloud", "nextcloud"}, {"jellyfin", "jellyfin"}, {"plexmediaserver", "plex"}, {"docker", "docker"},
	{"homeassistant", "homeassistant"}, {"adguard-home", "adguard"}, {"syncthing", "syncthing"},
	{"mosquitto", "mosquitto"}, {"node-red", "nodered"}, {"prometheus", "prometheus"}, {"grafana", "grafana"},
	{"influxdb", "influxdb"}, {"redis", "redis"}, {"mongodb", "mongodb"}, {"ollama", "ollama"},
	{"tailscale", "tailscale"}, {"zerotier", "zerotier"}, {"bind9", "bind"}, {"haproxy", "haproxy"},
	{"gitea", "gitea"}, {"gitlab", "gitlab"}, {"netdata", "netdata"},
}
