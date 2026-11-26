#!/bin/sh
# Configure the LDAP timeout paths on toxiproxy. Idempotent.
set -eu
api="${TOXIPROXY_API:-http://toxiproxy.lab.test:8474}"
proxy() {
    curl -fsS -X POST "$api/proxies" -H 'Content-Type: application/json' \
        -d "{\"name\":\"$1\",\"listen\":\"0.0.0.0:$2\",\"upstream\":\"ldap1.lab.test:389\",\"enabled\":true}" >/dev/null \
        || curl -fsS "$api/proxies/$1" >/dev/null
}
toxic() {
    curl -fsS -X DELETE "$api/proxies/$1/toxics/$2" >/dev/null 2>&1 || true
    curl -fsS -X POST "$api/proxies/$1/toxics" -H 'Content-Type: application/json' -d "$3" >/dev/null
}
proxy ldap_slow 3891
proxy ldap_blackhole 3892
toxic ldap_slow slow '{"name":"slow","type":"latency","stream":"downstream","attributes":{"latency":3000,"jitter":0}}'
toxic ldap_blackhole hole '{"name":"hole","type":"timeout","stream":"downstream","attributes":{"timeout":0}}'
curl -fsS "$api/proxies" | jq -c 'to_entries[] | {name: .key, listen: .value.listen, toxics: [.value.toxics[].type]}'
