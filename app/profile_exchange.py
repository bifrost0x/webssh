"""Bounded, metadata-only host exchange. Never evaluates SSH configuration."""

import json
import re
import shlex

from .profile_manager import _is_valid_host

MAX_INPUT_BYTES = 64 * 1024
MAX_RECORDS = 100
_FIELDS = {
    'name', 'host', 'port', 'username', 'group', 'favorite', 'use_tmux',
    'requires_key', 'jump_alias', 'auth_type',
}
_ALIAS = re.compile(r'^[a-zA-Z0-9_.-]{1,128}$')
_KNOWN_HOST = re.compile(
    r'^\s*(?:@(?:cert-authority|revoked)\s+)?\S+\s+'
    r'(?:ssh-|ecdsa-|sk-)[^\s]+\s+[A-Za-z0-9+/]+={0,2}(?:\s|$)'
)


class ExchangeError(ValueError):
    """An exchange document is invalid or exceeds its budget."""


def _text(value, maximum=128):
    return (
        isinstance(value, str) and len(value) <= maximum
        and all(character.isprintable() for character in value)
    )


def _username(value):
    if not _text(value):
        return False
    if ':' in value:
        from .ssh_gateway import parse_selector
        try:
            parse_selector(value)
            return True
        except ValueError:
            return False
    return not value or re.fullmatch(r'[a-zA-Z0-9_.-]{1,32}', value) is not None


def _record(values):
    row = {field: value for field, value in values.items() if field in _FIELDS}
    row.setdefault('name', '')
    row.setdefault('host', row['name'])
    row.setdefault('username', '')
    row.setdefault('port', 22)
    row.setdefault('requires_key', False)
    if row.get('auth_type') == 'key':
        row['requires_key'] = True
    row['warnings'] = []
    row['blocked'] = False
    if (
        not _text(row['name']) or not row['name'].strip()
        or not _text(row['host'], 253) or not _is_valid_host(row['host'])
        or not _username(row['username'])
        or type(row['port']) is not int or not 1 <= row['port'] <= 65535
        or type(row['requires_key']) is not bool
        or row.get('auth_type', 'password') not in ('password', 'key', 'tailscale')
        or ('group' in row and not _text(row['group'], 64))
        or any(type(row[field]) is not bool for field in ('favorite', 'use_tmux') if field in row)
    ):
        row['blocked'] = True
        row['warnings'].append('Invalid connection metadata.')
    jump = row.get('jump_alias', '')
    row['requires_jump'] = bool(jump)
    if row.get('auth_type') == 'tailscale' and (row['requires_key'] or jump):
        row['blocked'] = True
        row['warnings'].append('Tailscale cannot use a stored key or jump host.')
    if not _text(jump):
        row['blocked'] = True
        row['warnings'].append('This jump-host expression is unsupported.')
    if not row['username']:
        row['warnings'].append('Choose an SSH username before importing.')
    if row['requires_key']:
        row['warnings'].append('Map an existing stored key before importing.')
    if row['requires_jump']:
        row['warnings'].append('Map an existing jump host before importing.')
    return row


def _openssh(source):
    if any(
        _KNOWN_HOST.match(line) for line in source.splitlines()
        if not line.lstrip().startswith('#')
    ):
        raise ExchangeError(
            'This is known_hosts host-key data, not an OpenSSH config. '
            'Choose your SSH config file (usually ~/.ssh/config), or add hosts manually. '
            'Host keys are not imported or trusted by this tool.'
        )
    records = []
    warnings = []
    aliases = []
    values = {}
    unsafe = False
    supported = {'hostname': 'host', 'user': 'username', 'port': 'port', 'proxyjump': 'jump_alias'}

    def flush():
        for alias in aliases:
            row = _record({'name': alias, **values})
            jump = row.get('jump_alias', '')
            if jump and not _ALIAS.fullmatch(jump):
                row['blocked'] = True
                row['warnings'].append('This jump-host expression is unsupported.')
            records.append(row)
            if len(records) > MAX_RECORDS:
                raise ExchangeError('Import supports at most 100 hosts.')

    for line_number, line in enumerate(source.splitlines(), 1):
        try:
            parts = shlex.split(line, comments=True, posix=True)
        except ValueError as exc:
            raise ExchangeError(f'Invalid quoting on line {line_number}.') from exc
        if not parts:
            continue
        # OpenSSH permits both "Keyword value" and "Keyword=value".
        first = parts.pop(0)
        if '=' in first:
            keyword, value = first.split('=', 1)
            parts.insert(0, value)
        else:
            keyword = first
            if parts and parts[0] == '=':
                parts.pop(0)
        keyword = keyword.lower()
        if keyword == 'host':
            flush()
            values = {}
            aliases = [alias for alias in parts if _ALIAS.fullmatch(alias)]
            if not parts or len(aliases) != len(parts):
                unsafe = True
                warnings.append(f'Line {line_number}: patterns require manual configuration.')
            continue
        if not aliases:
            unsafe = True
            warnings.append(f'Line {line_number}: global or conditional settings require manual configuration.')
            continue
        if keyword == 'identityfile':
            values['requires_key'] = True
        elif keyword in supported and len(parts) == 1:
            field = supported[keyword]
            value = parts[0]
            if field == 'port':
                try:
                    value = int(value)
                except ValueError:
                    value = 0
            if field == 'jump_alias' and value.lower() == 'none':
                value = ''
            values.setdefault(field, value)
        else:
            # Unknown options can affect routing, authentication or local commands.
            # Do not silently reinterpret a potentially different connection.
            unsafe = True
            warnings.append(f'Line {line_number}: unsupported directive requires manual configuration.')
    flush()
    seen = set()
    for row in records:
        alias = row['name'].casefold()
        if alias in seen:
            unsafe = True
            warnings.append('Overlapping Host blocks require manual configuration.')
            break
        seen.add(alias)
    if unsafe:
        for row in records:
            row['blocked'] = True
            row['warnings'].append('Resolve unsupported configuration before importing this document.')
    return {'records': records, 'warnings': warnings}


def preview_import(source, format_name):
    if not isinstance(source, str):
        raise ExchangeError('Import must contain text.')
    try:
        size = len(source.encode('utf-8'))
    except UnicodeEncodeError as exc:
        raise ExchangeError('Import must contain valid UTF-8.') from exc
    if size > MAX_INPUT_BYTES:
        raise ExchangeError('Import exceeds 64 KiB.')
    if format_name == 'openssh':
        return _openssh(source)
    if format_name != 'json':
        raise ExchangeError('Unsupported import format.')
    try:
        document = json.loads(source)
    except (ValueError, RecursionError) as exc:
        raise ExchangeError('Invalid JSON document.') from exc
    if (
        not isinstance(document, dict)
        or set(document) != {'format', 'version', 'hosts'}
        or document['format'] != 'webssh-hosts'
        or type(document['version']) is not int or document['version'] != 1
        or not isinstance(document['hosts'], list)
        or len(document['hosts']) > MAX_RECORDS
    ):
        raise ExchangeError('Unsupported host exchange document.')
    rows = []
    for values in document['hosts']:
        if not isinstance(values, dict) or set(values) - _FIELDS:
            raise ExchangeError('Host document contains unsupported fields.')
        rows.append(_record(values))
    return {'records': rows, 'warnings': []}


def export_profiles(profiles, jump_hosts):
    jumps = {item['id']: item['name'] for item in jump_hosts}
    hosts = []
    for profile in profiles:
        row = {
            field: profile[field]
            for field in ('name', 'host', 'port', 'username', 'group', 'favorite', 'use_tmux', 'auth_type')
            if field in profile
        }
        row['requires_key'] = profile.get('auth_type') == 'key'
        if profile.get('jump_host_id'):
            row['jump_alias'] = jumps.get(profile['jump_host_id'], 'Unresolved jump host')
        hosts.append(row)
    return {'format': 'webssh-hosts', 'version': 1, 'hosts': hosts}


def export_batches(profiles, jump_hosts):
    """Split large exports into independently importable bounded documents."""
    document = export_profiles(profiles, jump_hosts)
    batches = []
    batch = {**document, 'hosts': []}
    for row in document['hosts']:
        candidate = {**batch, 'hosts': [*batch['hosts'], row]}
        if len(candidate['hosts']) > MAX_RECORDS or len(json.dumps(candidate).encode('utf-8')) > MAX_INPUT_BYTES:
            batches.append(batch)
            batch = {**document, 'hosts': [row]}
        else:
            batch = candidate
    if batch['hosts'] or not batches:
        batches.append(batch)
    return batches
