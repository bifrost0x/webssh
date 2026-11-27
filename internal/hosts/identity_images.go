package hosts

import (
	"regexp"
	"strings"
)

// imageRule is one entry of SERVICE_IMAGES. Python anchors each pattern
// at the start of an image name segment through a lookahead, which RE2
// does not have; matchImage tries every segment start instead and the
// rule matches from there.
type imageRule struct {
	service string
	re      *regexp.Regexp
}

// image is _image: the names as alternatives, followed by the edition
// suffixes of official images unless strict, then a tag, a digest or the
// end. Exporters and bundles ("postgres-exporter") do not match.
func image(service string, strict bool, names ...string) imageRule {
	tail := `(?:-server|-ce|-ee|-nox|-oss)?`
	if strict {
		tail = ""
	}
	return imageRule{service, regexp.MustCompile(`^(?:` + strings.Join(names, "|") + `)` + tail + `(?::|@|$)`)}
}

func imagePattern(service, body string) imageRule {
	return imageRule{service, regexp.MustCompile(`^` + body + `(?::|@|$)`)}
}

// serviceImages is SERVICE_IMAGES, matched against lower-cased image
// references; the first match wins, so specific names come first.
var serviceImages = []imageRule{
	image("nginxproxymanager", false, "nginx-proxy-manager"),
	image("nextcloud", false, "nextcloud", "aio-nextcloud", "nextcloud/all-in-one", "nextcloud-releases/all-in-one"),
	imagePattern("homeassistant", `(?:home-?assistant/[a-z0-9-]+-)?home-?assistant`),
	image("jellyfin", false, "jellyfin"),
	image("plex", false, "plex", "pms-docker"),
	image("portainer", false, "portainer", "portainer/agent"),
	image("traefik", false, "traefik"),
	image("vaultwarden", true, "vaultwarden", "vaultwarden/server", "bitwardenrs/server"),
	image("immich", false, "immich", "immich-machine-learning"),
	image("gitea", false, "gitea", "forgejo"),
	image("paperless", false, "paperless", "paperless-ngx", "paperless-ng"),
	imagePattern("grafana", `grafana(?:-oss|-enterprise)?`),
	image("pihole", false, "pihole", "pi-hole"),
	image("adguard", false, "adguardhome", "adguard-home"),
	image("uptimekuma", false, "uptime-kuma"),
	image("jellyseerr", false, "jellyseerr"),
	image("overseerr", false, "overseerr"),
	image("emby", false, "embyserver", "emby"),
	image("sonarr", false, "sonarr"),
	image("radarr", false, "radarr"),
	image("lidarr", false, "lidarr"),
	image("readarr", false, "readarr"),
	image("prowlarr", false, "prowlarr"),
	image("bazarr", false, "bazarr"),
	image("qbittorrent", false, "qbittorrent"),
	image("transmission", false, "transmission"),
	image("deluge", false, "deluge"),
	image("sabnzbd", false, "sabnzbd"),
	image("navidrome", false, "navidrome"),
	image("audiobookshelf", false, "audiobookshelf"),
	image("kavita", false, "kavita"),
	image("calibreweb", false, "calibre-web"),
	image("photoprism", false, "photoprism"),
	image("owncloud", false, "owncloud"),
	image("owncloud", true, "owncloud/server"),
	image("seafile", false, "seafile", "seafile-mc"),
	image("syncthing", false, "syncthing"),
	image("filebrowser", false, "filebrowser"),
	image("stirlingpdf", false, "stirling-pdf"),
	image("bookstack", false, "bookstack"),
	image("wikijs", false, "wikijs"),
	image("wikijs", true, "requarks/wiki"),
	image("joplin", false, "joplin-server", "joplin"),
	image("joplin", true, "joplin/server"),
	image("mealie", false, "mealie"),
	image("authentik", false, "authentik"),
	image("authentik", true, "goauthentik/server"),
	image("authelia", false, "authelia"),
	image("keycloak", false, "keycloak"),
	image("gitlab", false, "gitlab-ce", "gitlab-ee", "gitlab"),
	image("jenkins", false, "jenkins"),
	image("woodpecker", false, "woodpecker"),
	image("mosquitto", false, "eclipse-mosquitto", "mosquitto"),
	image("zigbee2mqtt", false, "zigbee2mqtt"),
	image("nodered", false, "node-red"),
	image("esphome", false, "esphome"),
	image("homebridge", false, "homebridge"),
	image("prometheus", false, "prometheus"),
	image("influxdb", false, "influxdb"),
	image("loki", false, "loki"),
	image("zabbix", false, "zabbix", "zabbix-server-(?:mysql|pgsql)"),
	image("netdata", false, "netdata"),
	image("opensearch", false, "opensearch"),
	image("tailscale", false, "tailscale"),
	image("zerotier", false, "zerotier"),
	image("openvpn", false, "openvpn"),
	image("wireguard", false, "wireguard", "wg-easy"),
	image("unbound", false, "unbound"),
	image("bind", false, "bind9"),
	image("haproxy", true, "haproxy", "haproxy-alpine", "haproxy-debian", "haproxy-ubuntu"),
	image("dozzle", false, "dozzle"),
	image("watchtower", false, "watchtower"),
	image("homepage", true, "gethomepage/homepage", "benphelps/homepage"),
	image("homarr", false, "homarr"),
	image("dashy", false, "dashy"),
	image("ollama", false, "ollama"),
	image("openwebui", false, "open-webui"),
	imagePattern("mariadb", `(?:mariadb|mysql)`),
	imagePattern("postgresql", `postgres(?:ql)?`),
	image("redis", true, "redis", "valkey"),
	image("mongodb", true, "mongo"),
	imagePattern("nginx", `nginx`),
	imagePattern("caddy", `caddy`),
	image("apache", true, "httpd"),
}

// segmentStarts are the offsets where _SEGMENT matches: after every '/',
// and at the start unless the first segment is a registry host (it holds
// ':' or '.' and more segments follow).
func segmentStarts(ref string) []int {
	var starts []int
	first, _, more := strings.Cut(ref, "/")
	if !more || !strings.ContainsAny(first, ".:") {
		starts = append(starts, 0)
	}
	for i := range len(ref) {
		if ref[i] == '/' {
			starts = append(starts, i+1)
		}
	}
	return starts
}

// matchImage returns the service of a lower-cased image reference, or "".
func matchImage(ref string) string {
	starts := segmentStarts(ref)
	for _, rule := range serviceImages {
		for _, at := range starts {
			if rule.re.MatchString(ref[at:]) {
				return rule.service
			}
		}
	}
	return ""
}
