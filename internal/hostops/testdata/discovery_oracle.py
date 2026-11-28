"""Record how app/discovery_routes.py reads the scan input.

Writes a corpus with the expected results so the Go tests replay it without
Python. Run from the repository root with the venv in $WEBSSH_PYTHON_ROOT:

    WS=$WEBSSH_PYTHON_ROOT $WEBSSH_PYTHON_ROOT/.venv/bin/python -I internal/hostops/testdata/discovery_oracle.py \
        internal/hostops/testdata/discovery_oracle.json
"""
import ipaddress
import json
import os
import random
import sys
import tempfile
from pathlib import Path

WS = Path(os.environ['WS'])
sys.path.insert(0, str(WS))
os.environ.setdefault('SECRET_KEY', '0' * 64)
os.environ['DATA_DIR'] = tempfile.mkdtemp(prefix='discovery-oracle-')

from app.discovery_routes import ScanRequestError, parse_network, parse_ports  # noqa: E402

NETWORKS = [
    '192.168.1.0/24', '192.168.1.77/24', ' 10.0.0.0/24 ', '10.0.0.1', '10.0.0.0/31', '10.0.0.0/30', '10.0.0.0/23',
    '10.0.0.0/255.255.255.0', '10.0.0.5/0.0.0.255', '10.0.0.0/255.255.0.255', '10.0.0.0/024', '10.0.0.0/33', '10.0.0.0/',
    '10.0.0.0/ 24', '10.0.0.0/24/1', '01.2.3.4', '1.2.3', '1.2.3.256', '256.1.1.1', '', '   ', 'host.local', '10.0.0.0/-1',
    '::1', '2001:db8::/120', '2001:db8::/119', '2001:db8::1/128', '2001:db8:0:0:1:0:0:1/127', '::ffff:10.0.0.1/120',
    '::ffff:10.0.0.1', 'fe80::1%eth0', 'fe80::1%eth0/120', '1:2:3:4:5:6:7::', '1::2::3', ':::', '2001:DB8::/124',
    '10.0.0.0/24　', ' 10.0.0.0/24', '\x1c10.0.0.0/24', '1' * 65, '10.0.0.0/' + '0' * 60 + '24', '0.0.0.0/24',
    '255.255.255.255', '255.255.255.0/24', '10.0.0.0/32', '10.0.0.0/0', '10.0.0.0/8', '::/120', '1.2.3.4/255.255.255.255',
    '1.2.3.4/0.0.0.0', '١.2.3.4', '1.2.3.4/٢٤', 'fe80::/64', '2001:db8::1:2:3:4:5:6', '::ffff:0:0/120',
]
PORTS = ['null', '[22]', '[22, 2222]', '[2222, 22, 22]', '[22, 23, 24]', '[22, 23, 24, 25]', '[]', '[0]', '[65536]',
         '[65535]', '[22.0]', '["22"]', '[true]', '[1e2]', '[-22]', '22', '"22"', '{}', '[22, null]', '[[22]]']


def main():
    rng = random.Random(29)
    for _ in range(200):
        a = '.'.join(str(rng.randint(0, 260)) for _ in range(4))
        NETWORKS.append(f'{a}/{rng.randint(20, 33)}')
    nets = []
    for value in NETWORKS:
        try:
            addresses = parse_network(value)
            network = str(ipaddress.ip_network(value.strip(), strict=False))
            nets.append({'value': value, 'network': network, 'addresses': addresses})
        except ScanRequestError as error:
            nets.append({'value': value, 'error': error.code})
    ports = []
    for raw in PORTS:
        try:
            ports.append({'raw': raw, 'ports': parse_ports(json.loads(raw))})
        except ScanRequestError as error:
            ports.append({'raw': raw, 'error': error.code})
    Path(sys.argv[1]).write_text(json.dumps({'networks': nets, 'ports': ports}, indent=0, ensure_ascii=True) + '\n')


main()
