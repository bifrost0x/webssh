#!/usr/bin/env bash
set -euo pipefail

packages=(libldap2-dev libsasl2-dev)
missing=false
for package in "${packages[@]}"; do
    if [[ "$(dpkg-query -W -f='${Status}' "$package" 2>/dev/null)" != 'install ok installed' ]]; then
        missing=true
        break
    fi
done

if [[ "$missing" == false ]]; then
    echo 'CI test system dependencies are already installed.'
    exit 0
fi

# Hosted runners commonly have usable indexes already. Refresh only if needed.
# Bound stalled mirrors so apt can reach the next configured mirror promptly.
apt_options=(-o Acquire::http::Timeout=5 -o Acquire::https::Timeout=5 -o Acquire::Retries=0)
if ! sudo apt-get "${apt_options[@]}" install --yes --no-install-recommends "${packages[@]}"; then
    sudo apt-get "${apt_options[@]}" update
    sudo apt-get "${apt_options[@]}" install --yes --no-install-recommends "${packages[@]}"
fi
