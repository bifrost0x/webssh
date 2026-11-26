"""Record how the Python stores save, organize, move and delete hosts.

Writes a corpus with the expected results so the Go tests replay it without
Python. Run from the repository root with the project virtual environment:

    WS=$PWD .venv/bin/python -I internal/hosts/testdata/oracle.py \
        internal/hosts/testdata/oracle.json

The store functions run unchanged; only what lies outside the three stores
is replaced: the per-user file paths, the SSH key and command-set lookups,
the clock and the UUID source. Socket handlers are mirrored in handle_* with
the argument handling of app/socket_events.py.
"""
import copy
import itertools
import json
import os
import shutil
import sys
import tarfile
import tempfile
import uuid
from datetime import datetime, timezone
from pathlib import Path

WS = Path(os.environ['WS'])
sys.path.insert(0, str(WS))
os.environ.setdefault('SECRET_KEY', '0' * 64)
os.environ['DATA_DIR'] = tempfile.mkdtemp(prefix='hosts-oracle-')

import app.jump_host_manager as jm  # noqa: E402
import app.key_manager as km  # noqa: E402
import app.post_connect_manager as pcm  # noqa: E402
import app.profile_manager as pm  # noqa: E402
import app.socks_proxy_manager as sm  # noqa: E402

USER = 3
STORE = Path(tempfile.mkdtemp(prefix='hosts-oracle-store-'))
NOW = datetime(2026, 11, 26, 12, 30, 45, 123456, tzinfo=timezone.utc)


def unwrap(module):
    for name in dir(module):
        value = getattr(module, name)
        if callable(value) and getattr(value, '__module__', None) == module.__name__ and hasattr(value, '__wrapped__'):
            setattr(module, name, value.__wrapped__)


for module in (pm, jm, sm):
    unwrap(module)

pm.get_user_profiles_file = lambda user_id: STORE / 'profiles.json'
jm._get_file = lambda user_id: STORE / 'jump_hosts.json'
sm._get_file = lambda user_id: STORE / 'socks_proxies.json'

KEYS = {
    '9971eb1e-92db-4b73-93dd-b5c5d5d8387c', '80c09d20-daf6-4bf5-bc41-a41341ab13aa',
    'd12ad3cd-eb07-4418-8967-a3169ba3de68',
}
km.get_key = lambda user_id, key_id: {'id': key_id} if key_id in KEYS else None
SETS = {'867426f3-ca2f-40df-837c-6430d34fa3c9'}


def command_set(user_id, set_id):
    return ({'id': set_id}, None) if set_id in SETS else (None, 'Command set not found')


pcm.command_set_manager.get_command_set = command_set
pcm.command_set_manager._get_command_set_with_lock_held = command_set


class FixedClock(datetime):
    @classmethod
    def now(cls, tz=None):
        return NOW if tz else NOW.replace(tzinfo=None)


for module in (pm, jm, sm):
    module.datetime = FixedClock

IDS = None


def reset_ids():
    global IDS
    IDS = (f'00000000-0000-4000-8000-{n:012d}' for n in itertools.count(1))


uuid.uuid4 = lambda: uuid.UUID(next(IDS))


def golden_stores():
    tmp = Path(tempfile.mkdtemp(prefix='hosts-oracle-golden-'))
    with tarfile.open(WS / 'tests/golden/fixture/datadir.tar') as archive:
        archive.extractall(tmp, filter='data')
    base = tmp / 'data/users/user_3'
    return {name: json.loads((base / name).read_text()) for name in
            ('profiles.json', 'jump_hosts.json', 'socks_proxies.json')}


STAMP = '2026-11-02T09:03:54.250000+00:00'
SYNTHETIC = [
    {'name': 'Legacy extra', 'host': 'extra.golden.test', 'port': 22, 'username': 'x',
     'future_field': {'a': [1, 2.5, None], 'b': 'ü'}, 'auth_type': 'password', 'key_id': None,
     'startup_mode': 'none', 'id': 'syn-extra', 'sort_order': 7, 'created_at': STAMP, 'updated_at': STAMP,
     'detected_platform': 'debian', 'detected_os_id': 'debian', 'detected_virt': 'spaceship',
     'detection_state': 'detected', 'platform_checked_at': 1764000000.5,
     'detected_services': ['docker'], 'services_checked_at': 1764000000,
     'greeting_platform': 'ubuntu', 'authenticated_greeting': 'ubuntu', 'role_override': 'server',
     'platform_icon': 'debian', 'big_number': 12345678901234567890123},
    {'name': 'Legacy order A', 'host': 'a.golden.test', 'port': 22, 'username': 'a', 'auth_type': 'password',
     'key_id': None, 'startup_mode': 'none', 'group': 'Legacy', 'id': 'syn-order-a',
     'created_at': STAMP, 'updated_at': STAMP},
    {'name': 'Legacy order B', 'host': 'b.golden.test', 'username': 'b', 'auth_type': 'password',
     'key_id': None, 'startup_mode': 'none', 'group': 'legacy', 'id': 'syn-order-b',
     'created_at': STAMP, 'updated_at': STAMP},
    {'name': 'Herdr host', 'host': 'herdr.golden.test', 'port': 22, 'username': 'h', 'auth_type': 'password',
     'key_id': None, 'startup_mode': 'none', 'herdr': True, 'use_herdr': False, 'use_tmux': True,
     'id': 'syn-herdr', 'sort_order': 8, 'created_at': STAMP, 'updated_at': STAMP},
    {'name': 'Free text', 'host': '192.0.2.10', 'port': 2200, 'username': 'f', 'auth_type': 'password',
     'key_id': None, 'startup_mode': 'free_text', 'startup_commands': 'uptime\nwho',
     'id': 'syn-free', 'sort_order': 9, 'created_at': STAMP, 'updated_at': STAMP},
]


def base_files():
    stores = golden_stores()
    stores['profiles.json']['profiles'].extend(copy.deepcopy(SYNTHETIC))
    return stores


BASE = base_files()


def write_base():
    shutil.rmtree(STORE)
    STORE.mkdir()
    for name, document in BASE.items():
        (STORE / name).write_text(json.dumps(document, indent=2))


def dumps(value):
    return json.dumps(value, ensure_ascii=False, separators=(',', ':'))


def snapshot():
    write_base()
    return {
        'profiles': [dumps(p) for p in pm.load_profiles(USER)],
        'jump_hosts': [dumps(j) for j in jm.load_jump_hosts(USER)],
        'socks_proxies': [dumps(s) for s in sm.load_socks_proxies(USER)],
    }


def stored():
    return {
        'profiles': [dumps(p) for p in pm.load_profiles(USER)],
        'jump_hosts': [dumps(j) for j in jm.load_jump_hosts(USER)],
        'socks_proxies': [dumps(s) for s in sm.load_socks_proxies(USER)],
    }


def public(profile):
    profile = dict(profile)
    profile.pop('tailscale_authorized', None)
    return profile


def handle_save_profile(data):
    data = dict(data)
    data.pop('tailscale_authorized', None)
    profile, error = pm.upsert_profile(USER, data)
    return {'error': error} if error else {'ok': dumps({'profile': public(profile)})}


def handle_delete_profile(data):
    if not data.get('profile_id'):
        return {'error': 'Profile ID required'}
    _, error = pm.delete_profile(USER, data['profile_id'])
    return {'error': error} if error else {'ok': '{}'}


def handle_organize(data):
    profile_id = data.get('profile_id')
    if not isinstance(profile_id, str) or not profile_id:
        return {'error': 'Profile ID required'}
    patch = {key: data[key] for key in ('group', 'favorite') if key in data}
    profile, error = pm.update_profile_organization(USER, profile_id, patch)
    return {'error': error} if error else {'ok': dumps({'profile': public(profile)})}


def placements(profiles, with_updated):
    out = []
    for profile in profiles:
        if not isinstance(profile.get('id'), str):
            continue
        item = {'id': profile['id'], 'group': profile.get('group', ''), 'sort_order': profile.get('sort_order', 0)}
        if with_updated and 'updated_at' in profile:
            item['updated_at'] = profile['updated_at']
        out.append(item)
    return out


def handle_move(data):
    profile_id = data.get('profile_id')
    if not isinstance(profile_id, str) or not profile_id:
        return {'error': 'Profile ID required'}
    source, target = data.get('expected_source_group'), data.get('target_group')
    if not isinstance(source, str):
        return {'error': 'Invalid source group'}
    if not isinstance(target, str):
        return {'error': 'Invalid target group'}
    if len(source.strip()) > 64 or len(target.strip()) > 64:
        return {'error': 'Group must not exceed 64 characters'}
    index = data.get('target_index')
    if type(index) is not int or index < 0:
        return {'error': 'Invalid target index'}
    confirmed = data.get('confirm_source_group_removal', False)
    if type(confirmed) is not bool:
        return {'error': 'Invalid confirmation value'}
    result, error = pm.move_profile(USER, profile_id, source, target, index, confirm_source_group_removal=confirmed)
    if error:
        return {'error': error, 'details': dumps({
            'requires_confirmation': bool((result or {}).get('requires_confirmation')),
            'organization': placements((result or {}).get('profiles', ()), False)})}
    if result.get('requires_confirmation'):
        return {'error': 'confirmation', 'details': dumps({
            'requires_confirmation': True, 'profile_id': result.get('profile_id'),
            'profile_name': result.get('profile_name', ''), 'source_group': result.get('source_group', '')})}
    return {'ok': dumps({'requires_confirmation': False, 'organization': placements(result['profiles'], True)})}


def handle_save_jump(data):
    jump, error = jm.add_jump_host(
        user_id=USER, name=data.get('name'), host=data.get('host'), port=data.get('port', 22),
        username=data.get('username'), auth_type=data.get('auth_type'), key_id=data.get('key_id'),
        jump_host_id=data.get('jump_host_id'))
    return {'error': error} if error else {'ok': dumps({'jump_host': jump})}


def usage_result(success, error, usages):
    if success:
        return {'ok': '{}'}
    result = {'error': error}
    if usages:
        result['details'] = dumps({'usages': usages})
    return result


def handle_delete_jump(data):
    if not data.get('jump_host_id'):
        return {'error': 'Jump host ID required'}
    return usage_result(*jm.delete_jump_host(USER, data['jump_host_id']))


def handle_save_socks(data):
    proxy, error = sm.add_socks_proxy(
        user_id=USER, name=data.get('name'), host=data.get('host'), port=data.get('port', 1080),
        auth_type=data.get('auth_type', 'none'), username=data.get('username', ''),
        remote_dns=data.get('remote_dns', True), socks_proxy_id=data.get('socks_proxy_id'))
    return {'error': error} if error else {'ok': dumps({'socks_proxy': proxy})}


def handle_delete_socks(data):
    proxy_id = data.get('socks_proxy_id')
    if not isinstance(proxy_id, str) or not proxy_id or len(proxy_id) > 64:
        return {'error': 'SOCKS proxy ID required'}
    return usage_result(*sm.delete_socks_proxy(USER, proxy_id))


def command_set_code(error, usages=None):
    """The code _command_set_error of app/socket_events.py sends."""
    if usages:
        return 'in_use'
    if error in ('Command not found', 'Command set not found', 'Profile not found', 'Jump host not found'):
        return 'not_found'
    if error.startswith('Connection storage quota exceeded:'):
        return 'quota_exceeded'
    if 'unreadable' in error:
        return 'storage_error'
    return 'validation_error'


def with_code(handler, first_check):
    """Handlers that answer through _command_set_error after their own first check."""
    def run(data):
        result = handler(data)
        if 'error' in result and result['error'] != first_check:
            usages = json.loads(result['details'])['usages'] if 'details' in result else None
            result['code'] = command_set_code(result['error'], usages)
        return result
    return run


HANDLERS = {
    'hosts.profile.save': handle_save_profile,
    'hosts.profile.delete': with_code(handle_delete_profile, 'Profile ID required'),
    'hosts.profile.organize': handle_organize, 'hosts.profile.move': handle_move,
    'hosts.jump.save': with_code(handle_save_jump, None),
    'hosts.jump.delete': with_code(handle_delete_jump, 'Jump host ID required'),
    'hosts.socks.save': with_code(handle_save_socks, None),
    'hosts.socks.delete': with_code(handle_delete_socks, None),
}


def form_payload(profile):
    """What the profile editor sends for a stored host it did not change."""
    payload = {
        'name': profile['name'], 'platform_icon': profile.get('platform_icon') or 'auto',
        'group': profile.get('group') or '', 'host': profile['host'], 'port': profile.get('port') or 22,
        'username': profile['username'], 'auth_type': profile['auth_type'],
        'key_id': profile.get('key_id') or None, 'jump_host_id': profile.get('jump_host_id') or None,
        'socks_proxy_id': profile.get('socks_proxy_id') or None,
        'startup_mode': profile.get('startup_mode') or 'none', 'use_tmux': profile.get('use_tmux') is True,
        'id': profile['id'],
    }
    if payload['startup_mode'] == 'command_set':
        payload['command_set_id'] = profile.get('command_set_id', '')
    if payload['startup_mode'] == 'free_text':
        payload['startup_commands'] = profile.get('startup_commands', '')
    if profile.get('herdr') is not None:
        payload['herdr'] = profile['herdr']
        payload['use_herdr'] = profile.get('use_herdr') is True
    return payload


P = 'c11ae780-b6eb-4dac-a794-d27d0b23f255'
KEY = '9971eb1e-92db-4b73-93dd-b5c5d5d8387c'
JUMP = '2735737b-d93a-4e54-acd5-85b740b63526'
SOCKS = '45af77db-0c12-41d0-b28e-ea67984e5ebd'
SOCKS2 = 'ae5c7232-6f7d-4457-bfca-0cc84e323aeb'
UNI = '1bd77053-ce70-4437-9be1-c35f332d2f4c'
NEW = {'name': 'New', 'host': 'new.golden.test', 'port': 22, 'username': 'n', 'auth_type': 'password'}


def cases():
    out = []

    def add(name, op, payload):
        out.append((name, op, payload))

    write_base()
    for profile in pm.load_profiles(USER):
        add('unchanged ' + profile['id'], 'hosts.profile.save', form_payload(profile))
    add('create minimal', 'hosts.profile.save', NEW)
    add('create full', 'hosts.profile.save', {**NEW, 'group': '  Ops  ', 'favorite': True, 'use_tmux': True,
                                               'platform_icon': 'debian', 'greeting_platform': 'ubuntu',
                                               'role_override': 'web', 'key_id': None})
    add('create into unicode group', 'hosts.profile.save', {**NEW, 'group': 'grüppe/日本'})
    add('create key', 'hosts.profile.save', {**NEW, 'auth_type': 'key', 'key_id': KEY})
    add('create missing key', 'hosts.profile.save', {**NEW, 'auth_type': 'key', 'key_id': 'nope'})
    add('create key without id', 'hosts.profile.save', {**NEW, 'auth_type': 'key'})
    add('create via jump', 'hosts.profile.save', {**NEW, 'jump_host_id': JUMP})
    add('create via missing jump', 'hosts.profile.save', {**NEW, 'jump_host_id': 'gone'})
    add('create via socks', 'hosts.profile.save', {**NEW, 'socks_proxy_id': SOCKS})
    add('create via missing socks', 'hosts.profile.save', {**NEW, 'socks_proxy_id': 'gone'})
    add('create jump and socks', 'hosts.profile.save', {**NEW, 'jump_host_id': JUMP, 'socks_proxy_id': SOCKS})
    add('create long socks reference', 'hosts.profile.save', {**NEW, 'socks_proxy_id': 'x' * 65})
    add('create umlaut host', 'hosts.profile.save', {**NEW, 'host': 'bücher.example'})
    add('create ipv6 host', 'hosts.profile.save', {**NEW, 'host': ' 2001:DB8::1 '})
    add('create scoped ipv6 host', 'hosts.profile.save', {**NEW, 'host': 'fe80::1%eth0'})
    add('create bad label', 'hosts.profile.save', {**NEW, 'host': '-bad.example'})
    add('port string', 'hosts.profile.save', {**NEW, 'port': ' 2_222 '})
    add('port zero', 'hosts.profile.save', {**NEW, 'port': 0})
    add('port null', 'hosts.profile.save', {**NEW, 'port': None})
    add('port float', 'hosts.profile.save', {**NEW, 'port': 22.9})
    add('port too large', 'hosts.profile.save', {**NEW, 'port': 70000})
    add('port text', 'hosts.profile.save', {**NEW, 'port': 'ssh'})
    add('port true', 'hosts.profile.save', {**NEW, 'port': True})
    add('bad username', 'hosts.profile.save', {**NEW, 'username': 'a b'})
    add('long username', 'hosts.profile.save', {**NEW, 'username': 'u' * 33})
    add('blank name', 'hosts.profile.save', {**NEW, 'name': '   '})
    add('long name', 'hosts.profile.save', {**NEW, 'name': '  ' + 'ü' * 200})
    add('missing host', 'hosts.profile.save', {**NEW, 'host': ''})
    add('bad auth type', 'hosts.profile.save', {**NEW, 'auth_type': 'pin'})
    add('bad icon', 'hosts.profile.save', {**NEW, 'platform_icon': 'amiga'})
    add('bad greeting', 'hosts.profile.save', {**NEW, 'greeting_platform': 'auto'})
    add('bad role', 'hosts.profile.save', {**NEW, 'role_override': 'toaster'})
    add('bad group type', 'hosts.profile.save', {**NEW, 'group': 5})
    add('long group', 'hosts.profile.save', {**NEW, 'group': 'g' * 65})
    add('bad favorite', 'hosts.profile.save', {**NEW, 'favorite': 'yes'})
    add('bad tmux', 'hosts.profile.save', {**NEW, 'use_tmux': 1})
    add('bad herdr', 'hosts.profile.save', {**NEW, 'herdr': 'x'})
    add('herdr without option', 'hosts.profile.save', {**NEW, 'use_herdr': True})
    add('herdr with tmux', 'hosts.profile.save', {**NEW, 'herdr': True, 'use_herdr': True, 'use_tmux': True})
    add('herdr', 'hosts.profile.save', {**NEW, 'herdr': True, 'use_herdr': True})
    add('free text', 'hosts.profile.save', {**NEW, 'startup_mode': 'free_text', 'startup_commands': 'a\r\nb\rc'})
    add('free text inferred', 'hosts.profile.save', {**NEW, 'startup_commands': 'ls'})
    add('free text too long', 'hosts.profile.save', {**NEW, 'startup_mode': 'free_text', 'startup_commands': 'x' * 4097})
    add('free text not text', 'hosts.profile.save', {**NEW, 'startup_mode': 'free_text', 'startup_commands': 5})
    add('free text with nul', 'hosts.profile.save', {**NEW, 'startup_mode': 'free_text', 'startup_commands': 'a\x00'})
    add('bad mode', 'hosts.profile.save', {**NEW, 'startup_mode': 'macro'})
    add('conflicting references', 'hosts.profile.save', {**NEW, 'startup_mode': 'free_text', 'command_id': 'c'})
    add('herdr with startup', 'hosts.profile.save', {**NEW, 'herdr': True, 'use_herdr': True,
                                                     'startup_mode': 'free_text', 'startup_commands': 'ls'})
    add('update missing', 'hosts.profile.save', {**NEW, 'id': 'nope'})
    extra = next(p for p in pm.load_profiles(USER) if p['id'] == 'syn-extra')
    add('update extra same endpoint', 'hosts.profile.save', {**form_payload(extra), 'name': 'Renamed'})
    add('update extra new host', 'hosts.profile.save', {**form_payload(extra), 'host': 'other.golden.test'})
    add('update extra drops icon', 'hosts.profile.save', {**form_payload(extra), 'platform_icon': 'auto',
                                                          'role_override': 'auto'})
    add('update extra minimal payload', 'hosts.profile.save', {
        'id': 'syn-extra', 'name': 'Legacy extra', 'host': 'EXTRA.golden.test.', 'username': 'x',
        'auth_type': 'password'})
    add('update moves group', 'hosts.profile.save', {**form_payload(pm.load_profiles(USER)[0]), 'group': 'Grüppe/日本'})
    add('update legacy order', 'hosts.profile.save', {**form_payload(
        next(p for p in pm.load_profiles(USER) if p['id'] == 'syn-order-b')), 'name': 'B2'})
    add('update herdr keeps options', 'hosts.profile.save', {
        'id': 'syn-herdr', 'name': 'Herdr host', 'host': 'herdr.golden.test', 'username': 'h', 'auth_type': 'password'})
    add('update clears group', 'hosts.profile.save', {**form_payload(
        next(p for p in pm.load_profiles(USER) if p['id'] == UNI)), 'group': ''})

    add('delete', 'hosts.profile.delete', {'profile_id': P})
    add('delete missing', 'hosts.profile.delete', {'profile_id': 'nope'})
    add('delete empty', 'hosts.profile.delete', {'profile_id': ''})
    add('delete number', 'hosts.profile.delete', {'profile_id': 5})

    add('organize group', 'hosts.profile.organize', {'profile_id': P, 'group': ' Ops '})
    add('organize clear group', 'hosts.profile.organize', {'profile_id': UNI, 'group': ''})
    add('organize favorite', 'hosts.profile.organize', {'profile_id': P, 'favorite': True})
    add('organize unfavorite', 'hosts.profile.organize', {'profile_id': UNI, 'favorite': False})
    add('organize nothing', 'hosts.profile.organize', {'profile_id': P})
    add('organize bad group', 'hosts.profile.organize', {'profile_id': P, 'group': None})
    add('organize bad favorite', 'hosts.profile.organize', {'profile_id': P, 'favorite': 1})
    add('organize missing', 'hosts.profile.organize', {'profile_id': 'nope', 'favorite': True})
    add('organize no id', 'hosts.profile.organize', {'favorite': True})

    move = {'profile_id': P, 'expected_source_group': '', 'target_group': '', 'target_index': 3,
            'confirm_source_group_removal': False}
    add('move within', 'hosts.profile.move', move)
    add('move to front', 'hosts.profile.move', {**move, 'target_index': 0})
    add('move far', 'hosts.profile.move', {**move, 'target_index': 99})
    add('move into group', 'hosts.profile.move', {**move, 'target_group': 'legacy', 'target_index': 1})
    add('move last out', 'hosts.profile.move', {**move, 'profile_id': UNI, 'expected_source_group': 'Grüppe/日本'})
    add('move last out confirmed', 'hosts.profile.move', {**move, 'profile_id': UNI, 'expected_source_group': ' grüppe/日本 ',
                                                         'confirm_source_group_removal': True})
    add('move stale group', 'hosts.profile.move', {**move, 'expected_source_group': 'Ops'})
    add('move missing', 'hosts.profile.move', {**move, 'profile_id': 'nope'})
    add('move bad index', 'hosts.profile.move', {**move, 'target_index': -1})
    add('move bool index', 'hosts.profile.move', {**move, 'target_index': True})
    add('move bad confirm', 'hosts.profile.move', {**move, 'confirm_source_group_removal': 'yes'})
    add('move bad source', 'hosts.profile.move', {**move, 'expected_source_group': None})
    add('move bad target', 'hosts.profile.move', {**move, 'target_group': 3})
    add('move long group', 'hosts.profile.move', {**move, 'target_group': 'g' * 65})
    add('move legacy order', 'hosts.profile.move', {**move, 'profile_id': 'syn-order-b',
                                                    'expected_source_group': 'Legacy', 'target_group': 'LEGACY',
                                                    'target_index': 0})

    jump = {'name': 'Bastion', 'host': 'bastion2.golden.test', 'port': 2222, 'username': 'j', 'auth_type': 'password'}
    add('jump create', 'hosts.jump.save', jump)
    add('jump create key', 'hosts.jump.save', {**jump, 'auth_type': 'key', 'key_id': KEY})
    add('jump create missing key', 'hosts.jump.save', {**jump, 'auth_type': 'key', 'key_id': 'nope'})
    add('jump create password drops key', 'hosts.jump.save', {**jump, 'key_id': KEY})
    add('jump port null', 'hosts.jump.save', {**jump, 'port': None})
    add('jump port empty', 'hosts.jump.save', {**jump, 'port': ''})
    add('jump port absent', 'hosts.jump.save', {k: v for k, v in jump.items() if k != 'port'})
    add('jump port false', 'hosts.jump.save', {**jump, 'port': False})
    add('jump port text', 'hosts.jump.save', {**jump, 'port': 'x'})
    add('jump bad host', 'hosts.jump.save', {**jump, 'host': 'a_b'})
    add('jump bad user', 'hosts.jump.save', {**jump, 'username': 'a:b'})
    add('jump blank name', 'hosts.jump.save', {**jump, 'name': ' '})
    add('jump missing field', 'hosts.jump.save', {**jump, 'username': ''})
    add('jump bad auth', 'hosts.jump.save', {**jump, 'auth_type': 'none'})
    add('jump bad key ref', 'hosts.jump.save', {**jump, 'key_id': 5})
    add('jump long name', 'hosts.jump.save', {**jump, 'name': 'n' * 300})
    add('jump update', 'hosts.jump.save', {**jump, 'jump_host_id': JUMP})
    add('jump update missing', 'hosts.jump.save', {**jump, 'jump_host_id': 'nope'})
    add('jump delete in use', 'hosts.jump.delete', {'jump_host_id': JUMP})
    add('jump delete missing', 'hosts.jump.delete', {'jump_host_id': 'nope'})
    add('jump delete empty', 'hosts.jump.delete', {'jump_host_id': ''})

    socks = {'name': 'Office', 'host': 'office.example', 'port': 1080, 'username': '', 'auth_type': 'none',
             'remote_dns': True}
    add('socks create', 'hosts.socks.save', socks)
    add('socks create defaults', 'hosts.socks.save', {'name': 'Office', 'host': 'office.example'})
    add('socks create login', 'hosts.socks.save', {**socks, 'auth_type': 'password', 'username': 'proxy-user',
                                                   'remote_dns': False})
    add('socks user without login', 'hosts.socks.save', {**socks, 'username': 'u'})
    add('socks login without user', 'hosts.socks.save', {**socks, 'auth_type': 'password'})
    add('socks bad auth', 'hosts.socks.save', {**socks, 'auth_type': None})
    add('socks bad user', 'hosts.socks.save', {**socks, 'username': None})
    add('socks bad dns', 'hosts.socks.save', {**socks, 'remote_dns': 'yes'})
    add('socks port text', 'hosts.socks.save', {**socks, 'port': '1080'})
    add('socks port float', 'hosts.socks.save', {**socks, 'port': 1080.0})
    add('socks port zero', 'hosts.socks.save', {**socks, 'port': 0})
    add('socks bad host', 'hosts.socks.save', {**socks, 'host': 'bücher.example'})
    add('socks host spaces', 'hosts.socks.save', {**socks, 'host': ' office.example '})
    add('socks blank name', 'hosts.socks.save', {**socks, 'name': ''})
    add('socks name spaces', 'hosts.socks.save', {**socks, 'name': '  Office  '})
    add('socks long name', 'hosts.socks.save', {**socks, 'name': 'n' * 513})
    add('socks bad reference', 'hosts.socks.save', {**socks, 'socks_proxy_id': ''})
    add('socks update', 'hosts.socks.save', {**socks, 'socks_proxy_id': SOCKS2})
    add('socks update missing', 'hosts.socks.save', {**socks, 'socks_proxy_id': 'nope'})
    add('socks delete in use', 'hosts.socks.delete', {'socks_proxy_id': SOCKS})
    add('socks delete', 'hosts.socks.delete', {'socks_proxy_id': SOCKS2})
    add('socks delete missing', 'hosts.socks.delete', {'socks_proxy_id': 'nope'})
    add('socks delete long id', 'hosts.socks.delete', {'socks_proxy_id': 'x' * 65})
    return out


def preset_cases():
    from app.customer_workflows import valid_presets
    good = {'id': 'p1', 'name': 'Two hosts', 'layout': 2, 'profile_ids': [P, UNI]}
    values = [
        [], [good], [good, {**good, 'id': 'p2'}], [good, good], [good] * 13,
        [{**good, 'id': 'bad id'}], [{**good, 'id': 'x' * 129}], [{**good, 'name': '  '}],
        [{**good, 'name': 'n' * 80}], [{**good, 'name': 'n' * 81}], [{**good, 'name': 'tab\there'}],
        [{**good, 'name': 'Ünïcødé ✓ 🚀'}], [{**good, 'name': 'zero\u200bwidth'}],
        [{**good, 'layout': 3}], [{**good, 'layout': True}], [{**good, 'layout': 2.0}],
        [{**good, 'layout': 1}], [{**good, 'profile_ids': [P, P]}], [{**good, 'profile_ids': ['a/b']}],
        [{**good, 'profile_ids': [5]}], [{**good, 'extra': 1}], [{k: v for k, v in good.items() if k != 'name'}],
        [{**good, 'layout': 4, 'profile_ids': []}], {'presets': []}, None, 'x', [None],
    ]
    return [{'value': dumps(value), 'valid': valid_presets(value)} for value in values]


def main(target):
    base = snapshot()
    sizes = {name: (STORE / name).stat().st_size for name in BASE}
    raw = {name: [dumps(item) for item in document[next(k for k in document if k != 'schema_version')]] for name, document in BASE.items()}
    corpus = {'now': NOW.isoformat(), 'base': base, 'base_raw': raw, 'base_file_sizes': sizes, 'keys': sorted(KEYS),
              'command_sets': sorted(SETS), 'cases': [], 'presets': preset_cases()}
    for name, op, payload in cases():
        write_base()
        reset_ids()
        result = HANDLERS[op](payload)
        after = {key: value for key, value in stored().items() if value != base[key]}
        corpus['cases'].append({'name': name, 'type': op, 'payload': dumps(payload), **result, 'after': after})
    Path(target).write_text(json.dumps(corpus, ensure_ascii=False, indent=1) + '\n')


if __name__ == '__main__':
    main(sys.argv[1])
