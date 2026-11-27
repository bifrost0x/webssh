"""Record how the Python release builds and parses server operations,
session insights, the runtime inventory and Herdr snapshots.

Writes a corpus with the expected results so the Go tests replay it without
Python. Run from the repository root with the project virtual environment:

    WS=$PWD .venv/bin/python -I internal/hostops/testdata/oracle.py \
        internal/hostops/testdata/oracle.json

The functions run unchanged. Inputs cover the collector output of real
hosts, the bounds and hostile output (control characters, bidirectional
overrides, inconsistent counters, malformed JSON). The size limits are
tested in Go, without a large corpus.
"""
import json
import os
import sys
import tempfile
from pathlib import Path

WS = Path(os.environ['WS'])
sys.path.insert(0, str(WS))
os.environ.setdefault('SECRET_KEY', '0' * 64)
os.environ['DATA_DIR'] = tempfile.mkdtemp(prefix='hostops-oracle-')

import app.herdr as herdr  # noqa: E402
import app.runtime_inventory as inventory  # noqa: E402
import app.server_operations as ops  # noqa: E402
import app.session_insights as insights  # noqa: E402


def outcome(fn, *args, **kwargs):
    try:
        return {'ok': fn(*args, **kwargs)}
    except (ValueError, ops.OperationError) as error:
        return {'error': getattr(error, 'code', 'value_error')}


STATS = """cpu=4705 150 1406 136325 345 0 33 0 0 0
mem_total_kib=16314220
mem_available_kib=12011452
disk_total_kib=61202244
disk_used_kib=10283664
disk_available_kib=47774620
disk_percent=18
uptime_seconds=12345.67
os_name=Debian GNU/Linux 13 (trixie)
swap_total_kib=2097148
swap_free_kib=2097148
load_1=0.12
load_5=0.30
load_15=0.25
cpu_count=8
network_received_bytes=123456789
network_transmitted_bytes=987654321
process_total=212
process_zombies=1
process_cpu=1234|root|sshd|12.5|0.3
process_cpu=77|www-data|nginx|3.0|1.1
process_memory=900|postgres|postgres|0.1|12.0
"""

STATS_CASES = [
    STATS,
    STATS.replace('\n', '\r\n'),
    'cpu=1 2 3\nmem_total_kib=10\nmem_available_kib=11\n',
    'cpu=1 2 3 -4\nos_name=  spaced  \n',
    'os_name=bad\x1b[31mred\n',
    'os_name=' + 'x' * 201 + '\n',
    'os_name=‮evil\n',
    'disk_total_kib=10\ndisk_used_kib=11\ndisk_available_kib=1\ndisk_percent=5\n',
    'disk_total_kib=10\ndisk_used_kib=1\ndisk_available_kib=1\ndisk_percent=101\n',
    'load_1=1\nload_5=2\nload_15=3\ncpu_count=0\nuptime_seconds=nan\n',
    'load_1=1e3\nload_5=.5\nload_15=3.\ncpu_count=2\n',
    'load_1=1000001\nload_5=1\nload_15=1\ncpu_count=1\n',
    'swap_total_kib=5\nswap_free_kib=6\nnetwork_received_bytes=18446744073709551615\nnetwork_transmitted_bytes=0\n',
    'network_received_bytes=18446744073709551616\nnetwork_transmitted_bytes=0\n',
    'process_total=3\nprocess_zombies=4\nprocess_cpu=1|a|b|1|1\n',
    'process_total=3\nprocess_zombies=0\nprocess_cpu=0|a|b|1|1\nprocess_cpu=2|a|b|1|101\nprocess_cpu=3|a|b\n',
    'process_total=3\nprocess_zombies=0\n' + ''.join(f'process_cpu={i}|u|c|1|1\n' for i in range(1, 20)),
    'process_total=1\nprocess_zombies=0\nprocess_memory=5| |cmd|1|1\nprocess_memory=6|u|' + 'c' * 129 + '|1|1\n',
    'permission_denied=processes\npermission_denied=processes\npermission_denied=disk\n',
    'nothing here\n',
    '',
    'cpu\nmem_total_kib\n=5\n',
    'uptime_seconds=5\x0bos_name=vt\x0cload_1=1\x1cx=1\x85y=2 os_name=ls\n',
    'cpu=1 2 3 4\ncpu=5 6 7 8 9\n',
    'uptime_seconds= 42 \n',
    'mem_total_kib=+10\nmem_available_kib=-0\n',
]

INVENTORY = """systemd_state=running
systemd_total=3
systemd_active=2
systemd_failed=1
systemd_returned=3
systemd_service=ssh.service|loaded|active|running|OpenBSD Secure Shell server
systemd_service=cron.service|loaded|active|running|Regular background program processing daemon
systemd_service=backup.service|loaded|failed|failed|Nightly backup
docker_version=27.3.1
docker_total=2
docker_running=1
docker_returned=2
docker_container=web|Up 2 hours
docker_container=db|Exited (0) 3 days ago
"""

INVENTORY_CASES = [
    INVENTORY,
    INVENTORY.replace('systemd_returned=3', 'systemd_returned=2'),
    INVENTORY.replace('systemd_state=running', 'systemd_state=weird'),
    INVENTORY.replace('systemd_active=2', 'systemd_active=3'),
    INVENTORY.replace('ssh.service|loaded', 'ssh service|loaded'),
    INVENTORY.replace('|OpenBSD Secure Shell server', '|bad\x1bdesc'),
    INVENTORY.replace('|running|OpenBSD', '|   |OpenBSD'),
    INVENTORY.replace('Nightly backup', 'a|b|c'),
    INVENTORY.replace('docker_container=web|Up 2 hours', 'docker_container=-web|Up'),
    INVENTORY.replace('docker_container=web|Up 2 hours', 'docker_container=web'),
    INVENTORY.replace('docker_version=27.3.1', 'docker_version='),
    INVENTORY.replace('docker_running=1', 'docker_running=3'),
    INVENTORY.replace('|Up 2 hours', '|' + 'u' * 161),
    INVENTORY.replace('Nightly backup', '‮Nightly backup⁦'),
    'permission_denied=systemd\npermission_denied= docker \npermission_denied=systemd\npermission_denied=x\n',
    'systemd_state= degraded \nsystemd_total=0\nsystemd_active=0\nsystemd_failed=0\nsystemd_returned=0\n',
    'systemd_state=running\nsystemd_total=500\nsystemd_active=0\nsystemd_failed=0\nsystemd_returned=201\n'
    + 'systemd_service=a.service|loaded|active|running|d\n' * 201,
    '',
    'garbage\n=\n',
]

PS = """    1 root                              0.0  0.1 systemd
  245 root                              0.0  0.0 sshd
 1201 www-data                         12.5  3.2 nginx: worker
"""

PS_CASES = [
    PS, PS + '\n\n', '', '   \n',
    PS + '  245 root 0.0 0.0 dup\n',
    'abc root 0.0 0.0 x\n',
    '0 root 0.0 0.0 x\n',
    '4194305 root 0.0 0.0 x\n',
    '12345678 root 0.0 0.0 x\n',
    '1 root 1,5 0.0 x\n',
    '1 root 0.0 0.0\n',
    '1 root 0.0 0.0 cmd with   spaces  \n',
    '1\troot\t0.0\t0.0\tx\x85y\n',
    '١ root 0.0 0.0 x\n',
]

LOG_CASES = [
    ('2026-11-26T10:00:00.000000001Z a\n2026-11-26T10:00:02.000000000Z b\n  continued\n',
     '2026-11-26T10:00:01.000000000Z err\nplain err\n'),
    ('before\n2026-11-26T10:00:00.000000000Z x\n2026-11-26T10:00:00.000000000Z same\n', ''),
    ('2026-11-26T10:00:00.00000000Z short\n2026-11-26T10:00:00.000000000Zno-space\n', ''),
    ('٢026-11-26T10:00:00.000000000Z unicode digit\n', ''),
    ('', ''),
    ('2026-11-26T10:00:00.000000000Z\ttab\r\n2026-11-25T10:00:00.000000000Z　ideographic\n', 'x\n'),
]

DISPLAY_CASES = [
    b'plain\ttext\nline\r\n', b'\x1b[31mred\x1b[0m', b'\xff\xfe', b'\xe2\x82', b'\xe2\x82\xac',
    b'\xf0\x9f\x98', b'\xed\xa0\x80', b'\xc0\xaf', b'a\xf4\x90\x80\x80b', b'\xe0\x80\xaf',
    '‮  x​'.encode(), b'\x00\x7f\x85', '­﻿'.encode(),
]

TARGETS = [
    ('service.restart', {'unit': 'nginx.service'}, False),
    ('service.stop', {'unit': 'getty@tty1.service'}, True),
    ('service.start', {'unit': 'a:b.service'}, False),
    ('service.logs', {'unit': 'ssh.service'}, False),
    ('service.logs', {'unit': 'ssh.service'}, True),
    ('service.restart', {'unit': 'nginx'}, False),
    ('service.restart', {'unit': 'x;reboot.service'}, False),
    ('service.restart', {'unit': '-x.service'}, False),
    ('service.restart', {'unit': "a'b.service"}, False),
    ('service.restart', {'unit': 'a$(id).service'}, False),
    ('service.restart', {'unit': 'a' * 255 + '.service'}, False),
    ('service.restart', {'unit': 'a' * 256 + '.service'}, False),
    ('service.restart', {'unit': 5}, False),
    ('service.restart', {}, False),
    ('container.inspect', {'name': 'web'}, False),
    ('container.inspect', {'name': 'web'}, True),
    ('container.inspect', {'name': 'we b'}, False),
    ('container.inspect', {'name': '-rm'}, False),
    ('container.logs', {'container': 'a' * 64}, False),
    ('container.stop', {'container': 'b' * 64}, True),
    ('container.restart', {'container': 'c' * 64}, False),
    ('container.start', {'container': '0' * 64}, False),
    ('container.start', {'container': 'A' * 64}, False),
    ('container.start', {'container': 'a' * 63}, False),
    ('container.start', {'name': 'web'}, False),
    ('process.list', {}, False),
    ('process.list', {}, True),
    ('process.inspect', {'pid': 1234}, False),
    ('process.inspect', {'pid': 1}, False),
    ('process.inspect', {'pid': 4194305}, False),
    ('process.inspect', {'pid': '12'}, False),
    ('process.inspect', {'pid': True}, False),
    ('process.inspect', {'pid': 12.0}, False),
    ('process.terminate', {'pid': 99, 'start_time': '123456'}, False),
    ('process.terminate', {'pid': 99, 'start_time': '123456'}, True),
    ('process.terminate', {'pid': 99, 'start_time': '12 34'}, False),
    ('process.terminate', {'pid': 99, 'start_time': 123}, False),
    ('process.terminate', {'pid': 99, 'start_time': '1' * 21}, False),
    ('process.terminate', {'pid': 99}, False),
    ('system.reboot', {}, False),
    ('system.reboot', {}, True),
    ('system.inspect', {}, False),
    ('system.inspect', {}, True),
    ('system.shutdown', {}, False),
    ('service.restart', None, False),
    ('service.restart', {'unit': 'nginx.service'}, 'yes'),
]

HERDR_SNAPSHOT = {
    'id': 1, 'result': {'type': 'session_snapshot', 'snapshot': {
        'agents': [
            {'pane_id': 'p1', 'agent': 'claude', 'display_agent': 'Claude', 'name': 'refactor',
             'cwd': '/home/u/project', 'agent_status': 'working'},
            {'pane_id': 'p2', 'agent': 'codex', 'cwd': '/srv', 'agent_status': 'sleeping'},
            {'pane_id': 'p2', 'agent': 'dup'},
            {'pane_id': 'bad id', 'agent': 'x'},
            'not a dict',
            {'pane_id': 'p3', 'agent': 'a‮b\u0000c d', 'name': '  \t', 'cwd': 5,
             'agent_status': 'idle'},
            {'pane_id': 'p4', 'display_agent': '', 'agent': 'x' * 600, 'name': ' y ' * 100},
        ],
        'panes': [{'pane_id': 'p2', 'label': 'pane two'}, {'pane_id': 'p2', 'label': 'second'},
                  {'pane_id': 'p3', 'label': 'three'}, 'x'],
    }},
}

HERDR_CASES = [
    json.dumps(HERDR_SNAPSHOT).encode(),
    json.dumps({'result': {'type': 'session_snapshot', 'snapshot': {
        'agents': [{'pane_id': f'p{i}'} for i in range(70)]}}}).encode(),
    json.dumps({'result': {'type': 'other', 'snapshot': {'agents': []}}}).encode(),
    json.dumps({'result': {'type': 'session_snapshot', 'snapshot': {'agents': {}}}}).encode(),
    json.dumps({'result': {'type': 'session_snapshot'}}).encode(),
    json.dumps([1, 2]).encode(),
    b'{"result": {"type": "session_snapshot", "snapshot": {"agents": [], "agents": [{"pane_id": "z"}]}}}',
    b'not json', b'', b'\xff', b'{"result": 1}',
    json.dumps({'result': {'type': 'session_snapshot', 'snapshot': {'agents': [], 'panes': 'x'}}}).encode(),
]

FAILURE_CASES = [
    (127, b''), (2, b'{"error":{"code":"server_not_running"}}'), (1, b''),
    (1, b'noise\n{"error":{"code":"server_not_running"}}\n'),
    (1, b'{"error":{"code":"protocol_mismatch"}}\r\nnot json\n'),
    (1, b'{"error":{"code":"other"}}'), (1, b'{"error":{"code":5}}\n{"error":{"code":"protocol_mismatch"}}'),
    (1, b'\xff\n'), (0, b''),
]


def main(path):
    corpus = {
        'scripts': {
            'insights_stats': insights.LINUX_STATS_COMMAND,
            'insights_diagnostics': insights.LINUX_DIAGNOSTICS_COMMAND,
            'runtime_inventory': inventory.RUNTIME_INVENTORY_COMMAND,
            'herdr_probe': herdr.AVAILABLE_COMMAND,
            'herdr_snapshot': herdr.SNAPSHOT_COMMAND,
            'herdr_session': herdr.SESSION_COMMAND,
        },
        'actions': {'read': sorted(ops.READ_ACTIONS), 'write': sorted(ops.WRITE_ACTIONS)},
        'commands': [{'action': a, 'target': t, 'sudo': s, **outcome(ops.build_command, a, t, use_sudo=s)}
                     for a, t, s in TARGETS],
        'stats': [{'input': text, **outcome(insights.parse_linux_stats, text)} for text in STATS_CASES],
        'inventory': [{'input': text, **outcome(inventory.parse_runtime_inventory, text)} for text in INVENTORY_CASES],
        'processes': [{'input': text, **outcome(ops.parse_process_list, text)} for text in PS_CASES],
        'logs': [{'output': o, 'error_output': e, 'ok': list(ops.newest_container_logs(o, e))} for o, e in LOG_CASES],
        'display': [{'input': b.hex(), 'ok': ops._display(b.decode('utf-8', 'replace'))} for b in DISPLAY_CASES],
        'herdr': [{'input': b.hex(), **outcome(herdr.parse_snapshot, b)} for b in HERDR_CASES],
        'herdr_failure': [{'status': s, 'stderr': b.hex(), 'ok': herdr._failure_reason(s, b)} for s, b in FAILURE_CASES],
    }
    Path(path).write_text(json.dumps(corpus, indent=1, ensure_ascii=True, sort_keys=True) + '\n')


if __name__ == '__main__':
    main(sys.argv[1])
