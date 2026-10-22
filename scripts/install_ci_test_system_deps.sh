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
if ! sudo apt-get install --yes --no-install-recommends "${packages[@]}"; then
    sudo apt-get update
    sudo apt-get install --yes --no-install-recommends "${packages[@]}"
fi
