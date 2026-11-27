"""Record how app/host_platform.py reads probe answers.

Writes a corpus with the expected results so the Go tests replay it without
Python. Run from the repository root with the project virtual environment:

    WS=$PWD .venv/bin/python -I internal/hosts/testdata/platform_oracle.py \
        internal/hosts/testdata/platform_oracle.json \
        internal/hostops/testdata/banner_oracle.json

The corpus holds hand-written answers of real systems, hostile answers and
answers combined at random from probe lines (fixed seed).
"""
import json
import os
import random
import sys
import tempfile
from pathlib import Path

WS = Path(os.environ['WS'])
sys.path.insert(0, str(WS))
os.environ.setdefault('SECRET_KEY', '0' * 64)
os.environ['DATA_DIR'] = tempfile.mkdtemp(prefix='platform-oracle-')

import app.host_catalog as catalog  # noqa: E402
import app.host_platform as hp  # noqa: E402

REAL = [
    'ID=debian\nVERSION_ID="12"\nkernel=Linux\nvirt=kvm\ntarget=multi-user.target\nunit=nginx\nunit=postgresql\nservice=docker\nengine=docker:ok\nimage=nextcloud:28\nimage=postgres:16\n',
    'ID=ubuntu\nID_LIKE=debian\nVERSION_ID="24.04"\nkernel=Linux\nvirt=none\ntarget=graphical.target\nservice=wireguard\nsnap=tailscale\n',
    'ID=debian\nVERSION_ID="12"\nkernel=Linux\nmarker=proxmox\nvirt=none\ntarget=multi-user.target\nguests=7\n',
    'ID=debian\nVERSION_ID="12"\nkernel=Linux\nmarker=proxmox\nmarker=proxmoxbackup\nguests=0\n',
    'ID=raspbian\nID_LIKE=debian\nVERSION_ID="12"\nkernel=Linux\nmodel=Raspberry Pi 4 Model B Rev 1.4\n',
    'ID=debian\nVERSION_ID="12"\nkernel=Linux\nmodel=Raspberry Pi 5 Model B Rev 1.0\nservice=pihole\n',
    'ID=alpine\nVERSION_ID=3.20.3\nkernel=Linux\nvirt=docker\n',
    'ID=slackware\nVERSION_ID=15.0\nkernel=Linux\nmarker=unraid\nservice=docker\nengine=docker:denied\n',
    'kernel=Linux\nmarker=synology\n',
    'kernel=Linux\nmarker=qnap\n',
    'ID="openwrt"\nID_LIKE="lede openwrt"\nVERSION_ID="23.05.5"\nkernel=Linux\nmarker=openwrt\n',
    'kernel=Darwin\n',
    'ID=freebsd\nVERSION_ID="14.1"\nkernel=FreeBSD\nmarker=truenas\n',
    'ID=freebsd\nVERSION_ID="14.1"\nkernel=FreeBSD\nmarker=opnsense\n',
    'ID=freebsd\nVERSION_ID=14.1\nkernel=FreeBSD\nmarker=pfsense\n',
    'ID=fedora\nVERSION_ID=41\nVARIANT_ID=workstation\nkernel=Linux\ntarget=graphical.target\nservice=podman\nengine=podman:ok\nimage=docker.io/library/redis:7\n',
    'ID=rocky\nID_LIKE="rhel centos fedora"\nVERSION_ID="9.4"\nkernel=Linux\nvirt=vmware\n',
    'ID=arch\nkernel=Linux\nvirt=wsl\n',
    'ID=nixos\nVERSION_ID="24.11"\nkernel=Linux\n',
    'ID=linuxmint\nID_LIKE="ubuntu debian"\nVERSION_ID="22"\nkernel=Linux\n',
    'ID=haos\nVERSION_ID=13.2\nkernel=Linux\nvirt=kvm\n',
    'ID=customos\nID_LIKE=debian\nVERSION_ID=1.0\nkernel=Linux\n',
    'ID=customos\nVERSION_ID=1.0\nkernel=Linux\n',
    'kernel=Linux\nmarker=ubiquiti\nservice=wireguard\n',
    'ID=debian\nkernel=Linux\nunit=syncthing\nservice=syncthing\nunit=pihole-FTL\nunit=AdGuardHome\nunit=forgejo\n',
    'ID=debian\nkernel=Linux\nvirt=lxc\nimage=ghcr.io/home-assistant/home-assistant:stable\nimage=gitea/gitea:1.22\nimage=lscr.io/linuxserver/jellyfin:latest\nimage=prom/prometheus\nimage=quay.io/prometheus/node-exporter\nimage=postgres-exporter:1\nimage=registry.local:5000/nginx\nimage=gitea:3000/me/app\nimage=postgres.internal/x\n',
]
REAL.append('kernel=Linux\n' + ''.join(f'service={s}\n' for s in sorted(catalog.SERVICES)))
REAL.append('kernel=Linux\n' + ''.join(f'service={s}\n' for s in sorted(catalog.SERVICES)[::2]))
HOSTILE = [
    '', 'kernel', 'kernel=\n', 'Welcome to the menu\nChoose 1 or 2\n', 'kernel=Linux\x1b[31m\nID=ubuntu\n',
    'ID=ubuntu\nID=debian\nkernel=Linux\n', 'kernel=Linux\nkernel=Darwin\n', 'kernel=Linux\nID=UBUNTU\n',
    'kernel=Linux\nID=ubuntu ID=debian\n', 'kernel=Linux\r\nID=ubuntu\r\n', 'kernel=Linux\nID=' + 'a' * 33 + '\n',
    'kernel=Linux\nmodel=' + 'x' * 201 + '\n', 'kernel=Linux\nVERSION_ID=12\n', 'kernel=Linux\nID=debian\nVERSION_ID=v12\n',
    'kernel=Linux\nguests=12345\n', 'kernel=Linux\nguests=-1\n', 'kernel=Linux\nguests=0012\n', 'kernel=Linux\ntarget=\n',
    'kernel=Linux\nservice=evil\nunit=sshd\nengine=docker:maybe\n', 'kernel=Linux\nID="debian\n', "kernel=Linux\nID='alpine'\n",
    'kernel=Linux\nID= debian \n', 'kernel=Linux\nID= debian \n', 'kernel=Linux\x85\nID=debian\n', 'kernel=Linux\tx\n',
    'kernel=Linux\nimage=JELLYFIN\nimage=İmmich\n', 'kernel=Linux\nmarker=unraid\nmarker=proxmox\n',
    'kernel=Linux\nmodel=Raspberry Pi\n', 'kernel=Linux\nmodel=Raspberry Pi 4 é\n', 'x' * 8193, 'kernel=Linux\n' + 'service=docker\n' * 600,
    '=\nkernel=Linux\n=x\n', 'kernel==Linux\n', 'ID_LIKE=suse opensuse\nkernel=Linux\nID=sles\n',
]
FRAGMENTS = (
    [f'ID={x}' for x in ('debian', 'ubuntu', '"fedora"', 'arch', 'rocky', 'custom', 'raspbian', 'Debian', '')]
    + [f'ID_LIKE={x}' for x in ('debian', '"rhel fedora"', 'suse', 'arch', 'unknown', 'ubuntu debian')]
    + [f'VERSION_ID={x}' for x in ('12', '"24.04"', '3.20.3', 'rolling', '1', '')]
    + [f'kernel={x}' for x in ('Linux', 'Darwin', 'FreeBSD', 'SunOS', '')]
    + [f'marker={x}' for x in catalog.MARKER_PLATFORMS] + ['marker=bogus']
    + [f'virt={x}' for x in ('none', 'kvm', 'lxc', 'docker', 'wsl', 'zvm', 'weird')]
    + [f'target={x}' for x in ('graphical.target', 'multi-user.target')]
    + [f'guests={x}' for x in ('0', '3', '9999', '10000')]
    + [f'model={x}' for x in ('Raspberry Pi 3 Model B', 'Pine64')]
    + [f'service={x}' for x in sorted(catalog.SERVICES)[::3]]
    + [f'unit={x}' for x in list(catalog.SERVICE_UNITS)[::2]]
    + [f'snap={x}' for x in catalog.SERVICE_SNAPS]
    + [f'engine={x}' for x in ('docker:ok', 'docker:denied', 'podman:ok', 'podman:denied')]
    + [f'image={x}' for x in ('nextcloud:28', 'jellyfin/jellyfin', 'linuxserver/sonarr', 'mysql:8', 'valkey/valkey',
                                'traefik:v3', 'grafana/grafana-oss', 'grafana/agent', 'redis-stack', 'httpd:2.4',
                                'portainer/agent:2', 'zabbix/zabbix-server-pgsql', 'ollama/ollama@sha256:ab', 'mongo-express')]
    + ['junk line', 'key=value', '\x1b]0;title\x07', 'service']
)


def identity_json(result):
    return {k: result[k] for k in ('state', 'platform', 'family', 'os_id', 'os_version', 'virt', 'graphical',
                                   'guests', 'services', 'container_access')}


def parse_case(text):
    try:
        return {'ok': identity_json(hp.parse_identity(text))}
    except ValueError:
        return {'error': True}


def main():
    rng = random.Random(378)
    identity = list(REAL) + list(HOSTILE)
    for _ in range(800):
        lines = rng.sample(FRAGMENTS, rng.randint(1, 18))
        identity.append('\n'.join(lines) + rng.choice(['', '\n', '\r\n']))
    deadline = [b'', b'\x1b[0m', b'\x1b]0;x\x07\r\n  ', b'ID=debian\nkernel=Linux\n', b'ID=debian\nkern', b'kernel=Linux',
                b'Press 1 for menu', b'\xff\xfe\n', b'service=docker\n', b'garbage\nmore', b'\x1b[2J\x1b[H', b'\x00\x01',
                b'x' * 9000 + b'\n', 'Welcome é\n'.encode(), b'ID=debian\n\xff']
    maintenance = ['', 'reboot=yes\n', 'reboot=no\napt=12\naptsecurity=3\n', 'apt=3\naptsecurity=9\n', 'apt=100001\n',
                   'apt=1234567\n', 'apt=007\naptsecurity=\n', 'reboot=YES\n', 'reboot=yes\nreboot=no\n', 'apt=5\x00\n',
                   'apt= 5 \n', 'apt=5 aptsecurity=2\n', 'apt=5\x85aptsecurity=1', 'apt=5\r\naptsecurity=1\r\n',
                   'x' * 1025, 'aptsecurity=4\n', 'apt=٥\n', 'apt=5\x0baptsecurity=2\n', 'reboot=yes\tx\n', 'apt=2\naptsecurity=2']
    reboot = ['reboot=yes', 'reboot=no\n', ' reboot=yes \n', 'reboot=maybe', 'banner\nreboot=yes', '', 'x' * 65, 'reboot=no ']
    banners = [b'SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13.5', b'SSH-2.0-OpenSSH_9.2p1 Debian-2+deb12u3\r\n',
               b'SSH-2.0-OpenSSH_for_Windows_9.5', b'SSH-2.0-OpenSSH_for_WindowsX', b'SSH-2.0-ROSSSH',
               b'SSH-2.0-ROSSSH2', b'SSH-2.0-Cisco-1.25', b'SSH-2.0-CiscoX', b'SSH-2.0-dropbear_2022.83',
               b'SSH-2.0-dropbear', b'SSH-2.0-dropbearX', b'SSH-1.99-OpenSSH_8.0 FreeBSD-20200214',
               b'SSH-2.0-OpenSSH_8.7 rocky.fc38', b'SSH-2.0-OpenSSH_9.0 OpenWrt', b'SSH-2.0-OpenSSH_9.0 xopenwrtx',
               b'SSH-2.0-Raspbian-ssh', b'SSH-2.0-alpine', b'SSH-2.0-', b'SSH-2.0-x y z', b'HTTP/1.1 200 OK',
               b'SSH-2.0-OpenSSH_9.6\xc3\xa9', b'SSH-2.0-' + b'a' * 101, b'SSH-2.0-' + b'a' * 100 + b' ' + b'c' * 120,
               b'SSH-2.0-a ' + b'c' * 121, b'SSH-2.0-OpenSSH_9.6\r\r\r', b'SSH-2.0-OpenSSH_9.6\nSSH-2.0-other', b'',
               b'SSH-x.0-a', b'SSH-2.0-OpenSSH_for Windows', b'SSH-2.0-openssh_FOR_windows_1', b'SSH-2.0-a\tb',
               b'SSH-2.0-UBUNTU_x debian']
    for _ in range(300):
        banners.append(b'SSH-2.0-' + bytes(rng.choice(b'abcdefgh_-. 0123456789UBDFROWSs') for _ in range(rng.randint(1, 40))))

    def banner(raw):
        from app.discovery_routes import describe_banner
        return describe_banner(raw)

    corpus = {
        'identity_script': hp.IDENTITY_SCRIPT,
        'maintenance_command': hp.MAINTENANCE_COMMAND,
        'reboot_hint_command': hp.REBOOT_HINT_COMMAND,
        'catalog': {
            'services': sorted(catalog.SERVICES), 'priority': sorted(catalog.PRIORITY_SERVICES),
            'infrastructure': sorted(catalog.INFRASTRUCTURE_SERVICES), 'max_services': catalog.MAX_SERVICES,
            'non_posix': sorted(catalog.NON_POSIX_PLATFORMS), 'os_id_platforms': catalog.OS_ID_PLATFORMS,
            'families': catalog.FAMILIES, 'markers': list(catalog.MARKER_PLATFORMS.items()),
            'kernels': catalog.KERNEL_PLATFORMS, 'virt': catalog.VIRT_MAP, 'units': list(catalog.SERVICE_UNITS.items()),
            'templates': list(catalog.SERVICE_UNIT_TEMPLATES.items()), 'paths': [list(p) for p in catalog.SERVICE_PATHS],
            'snaps': list(catalog.SERVICE_SNAPS.items()), 'platforms': sorted(catalog.PLATFORMS),
        },
        'identity': [dict(text=t, **parse_case(t)) for t in identity],
        'deadline': [{'output': list(o), 'answer': hp._identity_at_deadline(o)[1]} for o in deadline],
        'maintenance': [],
        'reboot': [],
    }
    banner_cases = []
    for text in maintenance:
        try:
            corpus['maintenance'].append({'text': text, 'ok': hp.parse_maintenance(text)})
        except ValueError:
            corpus['maintenance'].append({'text': text, 'error': True})
    for text in reboot:
        try:
            corpus['reboot'].append({'text': text, 'ok': hp.parse_reboot_hint(text)})
        except ValueError:
            corpus['reboot'].append({'text': text, 'error': True})
    for raw in banners:
        banner_cases.append({'raw': list(raw), 'result': banner(raw)})
    Path(sys.argv[1]).write_text(json.dumps(corpus, indent=0, ensure_ascii=True) + '\n')
    Path(sys.argv[2]).write_text(json.dumps(banner_cases, indent=0, ensure_ascii=True) + '\n')


main()
