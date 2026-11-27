"""Record how app/profile_manager.py stores detected host facts.

Writes a corpus with the expected results so the Go tests replay it without
Python. Run from the repository root with the project virtual environment:

    WS=$PWD .venv/bin/python -I internal/hosts/testdata/facts_oracle.py \
        internal/hosts/testdata/facts_oracle.json

Each case starts from the same saved hosts and runs a sequence of steps:
the authenticated greeting, an identity probe answer, a recorded attempt,
maintenance facts, settling a restart hint and greeting hints of the
overview. After every step the corpus holds the return value, the saved
hosts and the decisions identity_needed and reboot_hint_needs_check.
"""
import copy
import json
import os
import sys
import tempfile
from pathlib import Path

WS = Path(os.environ['WS'])
sys.path.insert(0, str(WS))
os.environ.setdefault('SECRET_KEY', '0' * 64)
os.environ['DATA_DIR'] = tempfile.mkdtemp(prefix='facts-oracle-')

import app.host_platform as hp  # noqa: E402
import app.profile_manager as pm  # noqa: E402

STORE = Path(tempfile.mkdtemp(prefix='facts-oracle-store-'))
USER = 3


def unwrap(module):
    for name in dir(module):
        value = getattr(module, name)
        if callable(value) and getattr(value, '__module__', None) == module.__name__ and hasattr(value, '__wrapped__'):
            setattr(module, name, value.__wrapped__)


unwrap(pm)
pm.get_user_profiles_file = lambda user_id: STORE / 'profiles.json'

STAMP = '2026-11-02T09:03:54.250000+00:00'
T0 = 1764000000.25
DAY = 24 * 3600


def host(pid, **extra):
    base = {'name': pid, 'host': f'{pid}.lan', 'port': 22, 'username': 'ops', 'auth_type': 'password',
            'key_id': None, 'startup_mode': 'none', 'id': pid, 'sort_order': 1, 'created_at': STAMP, 'updated_at': STAMP}
    base.update(extra)
    return base


BASE = [
    host('plain'),
    host('known', detected_platform='debian', detection_state='detected', platform_checked_at=T0 - 3 * DAY,
         detected_services=['docker', 'nginx'], services_checked_at=T0 - 3 * DAY, detected_os_version='12',
         greeting_platform='debian', authenticated_greeting='debian', detected_virt='vm', detected_guests=3),
    host('legacy', detected_platform='server'),
    host('manual', platform_icon='proxmox'),
    host('routed', jump_host_id='j1'),
    host('hinted', detected_maintenance={'reboot_required': True, 'updates': 4, 'security_updates': 1,
                                         'checked_at': T0 - DAY}),
    host('stale', detected_maintenance={'reboot_required': True, 'updates': None, 'security_updates': None,
                                        'checked_at': T0 - 9 * DAY}),
    host('noport'),
]

IDENT = {
    'debian': 'ID=debian\nVERSION_ID="12"\nkernel=Linux\nvirt=kvm\ntarget=multi-user.target\nunit=nginx\n',
    'proxmox': 'ID=debian\nVERSION_ID="12"\nkernel=Linux\nmarker=proxmox\nguests=4\nvirt=none\n',
    'bare': 'kernel=Linux\n',
    'unavailable': 'menu\n',
}
MAINT = {'updates': 'reboot=no\napt=12\naptsecurity=3\n', 'restart': 'reboot=yes\napt=0\naptsecurity=0\n'}

del BASE[-1]['port']

CASES = [
    ('greeting first', [('greeting', 'plain', 'ubuntu', T0), ('greeting', 'plain', 'ubuntu', T0 + 1),
                        ('greeting', 'plain', None, T0 + 2)]),
    ('greeting change makes the probe due', [('greeting', 'known', 'ubuntu', T0), ('greeting', 'known', 'debian', T0)]),
    ('alternating greetings within a day', [('identity', 'plain', 'debian', T0, False), ('greeting', 'plain', 'ubuntu', T0 + 10),
                                            ('greeting', 'plain', 'debian', T0 + 20), ('greeting', 'plain', 'ubuntu', T0 + 2 * DAY)]),
    ('windows greeting drops the facts', [('greeting', 'known', 'windows', T0)]),
    ('identity detected', [('identity', 'plain', 'debian', T0, False), ('identity', 'plain', 'proxmox', T0 + DAY, False)]),
    ('identity unavailable keeps facts', [('identity', 'known', 'unavailable', T0, False)]),
    ('silent keeps detected', [('identity', 'known', 'unavailable', T0, True)]),
    ('bare kernel drops facts', [('identity', 'known', 'bare', T0, False)]),
    ('legacy server', [('attempt', 'legacy', T0), ('identity', 'legacy', 'debian', T0)]),
    ('attempt only', [('attempt', 'known', T0)]),
    ('maintenance', [('maintenance', 'plain', 'updates', T0), ('maintenance', 'plain', 'restart', T0 + 5)]),
    ('settle cleared', [('settle', 'hinted', T0 - DAY, True), ('settle', 'hinted', T0 - DAY, True)]),
    ('settle stopped', [('settle', 'hinted', T0 - DAY, False), ('settle', 'hinted', T0 - DAY, True)]),
    ('settle other check', [('settle', 'hinted', T0, True)]),
    ('wrong endpoint', [('identity_wrong', 'plain', 'debian', T0), ('greeting_wrong', 'plain', 'ubuntu', T0)]),
    ('greeting hints', [('hints', {'plain': ['plain.lan', 22, 'ubuntu'], 'known': ['known.lan', 22, None],
                                   'routed': ['routed.lan', 22, 'debian'], 'manual': ['other.lan', 22, 'debian'],
                                   'noport': ['noport.lan', 22, 'alpinelinux']}),
                        ('hints', {'plain': ['plain.lan', 22, 'ubuntu']})]),
    ('missing host', [('attempt', 'gone', T0)]),
]
CHECK_TIMES = [T0, T0 + 6 * DAY, T0 + 8 * DAY, T0 - 2 * DAY]


def load():
    return json.loads((STORE / 'profiles.json').read_text())['profiles']


def endpoint_of(pid):
    for p in load():
        if p['id'] == pid:
            return list(hp.endpoint(p) or []) or None
    return ['gone.lan', 22, 'ops', None, None]


def run_step(step):
    kind = step[0]
    if kind in ('greeting', 'greeting_wrong'):
        _, pid, platform, now = step
        expected = endpoint_of(pid)
        if kind == 'greeting_wrong':
            expected = ['elsewhere.lan', 22, 'ops', None, None]
        profile, changed = pm.record_connect_greeting(USER, pid, tuple(expected) if expected else None, platform, now=now)
        return {'endpoint': expected, 'result': [profile is not None, changed]}
    if kind in ('identity', 'identity_wrong'):
        _, pid, name, now, *rest = step
        keep = rest[0] if rest else False
        expected = endpoint_of(pid)
        if kind == 'identity_wrong':
            expected = ['elsewhere.lan', 22, 'ops', None, None]
        identity = hp.parse_identity(IDENT[name])
        ok = pm.cache_detected_facts(USER, pid, tuple(expected) if expected else None, identity=identity, now=now,
                                     keep_detected=keep)
        return {'endpoint': expected, 'text': IDENT[name], 'result': ok}
    if kind == 'attempt':
        _, pid, now = step
        expected = endpoint_of(pid)
        return {'endpoint': expected, 'result': pm.record_identity_attempt(USER, pid, tuple(expected), now=now)}
    if kind == 'maintenance':
        _, pid, name, now = step
        expected = endpoint_of(pid)
        facts = hp.parse_maintenance(MAINT[name])
        return {'endpoint': expected, 'text': MAINT[name],
                'result': pm.cache_detected_facts(USER, pid, tuple(expected), maintenance=facts, now=now)}
    if kind == 'settle':
        _, pid, checked, cleared = step
        expected = endpoint_of(pid)
        return {'endpoint': expected, 'result': pm.settle_reboot_hint(USER, pid, tuple(expected), checked, cleared=cleared)}
    if kind == 'hints':
        observed = {pid: ((v[0], v[1]), v[2]) for pid, v in step[1].items()}
        return {'result': pm.cache_greeting_platforms(USER, observed)}
    raise ValueError(kind)


def main():
    cases = []
    for name, steps in CASES:
        (STORE / 'profiles.json').write_text(json.dumps({'schema_version': pm.CURRENT_STORAGE_VERSIONS['profiles'], 'profiles': copy.deepcopy(BASE)}, indent=2))
        out = []
        for step in steps:
            record = run_step(step)
            profiles = load()
            record.update(step=list(step), profiles=profiles, needed={
                p['id']: [hp.identity_needed(p, now=t) for t in CHECK_TIMES] for p in profiles},
                reboot={p['id']: [hp.reboot_hint_needs_check(p, now=t) for t in CHECK_TIMES] for p in profiles})
            out.append(record)
        cases.append({'name': name, 'steps': out})
    corpus = {'base': BASE, 'identities': IDENT, 'maintenance': MAINT, 'check_times': CHECK_TIMES, 'cases': cases}
    Path(sys.argv[1]).write_text(json.dumps(corpus, indent=0, ensure_ascii=True) + '\n')


main()
