"""Host exchange treats imported configuration as untrusted data."""

import json

import pytest

from app.profile_exchange import ExchangeError, export_profiles, preview_import


def test_explicit_aliases_quotes_and_first_value_win():
    result = preview_import(
        'Host api api-alt\n HostName "api.example.com"\n User deploy\n'
        ' Port 2222\n Port 22\n IdentityFile "~/.ssh/private"\n', 'openssh'
    )
    assert [row['name'] for row in result['records']] == ['api', 'api-alt']
    assert all(row['host'] == 'api.example.com' for row in result['records'])
    assert all(row['port'] == 2222 for row in result['records'])
    assert all(row['requires_key'] for row in result['records'])
    assert 'private' not in json.dumps(result)


@pytest.mark.parametrize('line', [
    'server.example ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAA',
    '[server.example]:2222 ecdsa-sha2-nistp256 AAAAE2VjZHNh',
    '|1|c2FsdA==|aGFzaA== ssh-rsa AAAAB3NzaC1yc2E=',
    '@cert-authority *.example ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAA',
    '@revoked server.example sk-ssh-ed25519@openssh.com AAAAC3NzaA==',
])
def test_known_hosts_is_rejected_with_specific_format_guidance(line):
    for prefix in ('', 'Host valid\n User deploy\n'):
        with pytest.raises(ExchangeError, match='known_hosts'):
            preview_import(prefix + line, 'openssh')


@pytest.mark.parametrize('directive', [
    'ProxyCommand touch /tmp/never', 'Match exec "id"', 'Include ~/.ssh/*',
])
def test_unsupported_execution_or_includes_cannot_silently_change_routing(directive):
    result = preview_import(f'Host api\n HostName api.example.com\n User root\n {directive}', 'openssh')
    assert result['records'][0]['blocked']
    assert result['warnings']


def test_wildcard_defaults_are_not_silently_discarded():
    result = preview_import('Host *\n ProxyJump gateway\nHost api\n User deploy', 'openssh')
    assert result['records'][0]['blocked']


def test_overlapping_host_blocks_cannot_drop_later_routing_rules():
    result = preview_import('Host api\n User deploy\nHost api\n ProxyJump gateway', 'openssh')
    assert all(row['blocked'] for row in result['records'])


def test_supported_proxyjump_is_explicit_reference_not_direct_connection():
    result = preview_import('Host api\n User deploy\n ProxyJump gateway', 'openssh')
    assert result['records'][0]['jump_alias'] == 'gateway'
    assert result['records'][0]['requires_jump']


@pytest.mark.parametrize('value', ['a,b', '$(id)', '%h', 'user@host:22'])
def test_unsupported_jump_forms_are_blocked(value):
    assert preview_import(f'Host api\n User root\n ProxyJump {value}', 'openssh')['records'][0]['blocked']


@pytest.mark.parametrize('source', [
    'Host api\n Port nope', 'Host api\n Port 0', 'Host api\n HostName %h.example',
])
def test_invalid_connection_metadata_is_blocked(source):
    assert preview_import(source, 'openssh')['records'][0]['blocked']


def test_import_limits_utf8_and_count():
    with pytest.raises(ExchangeError):
        preview_import('é' * 32769, 'openssh')
    with pytest.raises(ExchangeError):
        preview_import('\n'.join(f'Host h{i}' for i in range(101)), 'openssh')


def test_export_does_not_include_credentials_ids_or_startup_commands():
    document = export_profiles([{
        'id': 'private-id', 'name': 'api', 'host': 'api.example.com',
        'port': 22, 'username': 'deploy', 'auth_type': 'key',
        'key_id': 'secret-key-id', 'password': 'secret', 'startup_commands': 'id',
        'command_set_id': 'set-id', 'jump_host_id': 'jump-id',
    }], [{'id': 'jump-id', 'name': 'Gateway'}])
    encoded = json.dumps(document)
    for secret in ('private-id', 'secret', 'set-id', 'jump-id', 'startup_commands'):
        assert secret not in encoded
    row = preview_import(encoded, 'json')['records'][0]
    assert row['requires_key'] and row['requires_jump']
    assert row['jump_alias'] == 'Gateway'


def test_unknown_json_fields_are_rejected_not_executed():
    with pytest.raises(ExchangeError):
        preview_import(json.dumps({
            'format': 'webssh-hosts', 'version': 1,
            'hosts': [{'name': 'api', 'host': 'api', 'username': 'root', 'password': 'secret'}],
        }), 'json')


def _login(app, client):
    from app.auth import register_user
    with app.app_context():
        user, error = register_user('importer', 'password123')
        assert error is None
        user_id = user.id
    assert client.post('/login', data={'username': 'importer', 'password': 'password123'}).status_code == 302
    return user_id


def test_routes_require_authentication(client):
    assert client.get('/api/profiles/exchange').status_code in (302, 401)


@pytest.mark.parametrize('endpoint', [
    '/api/profiles/exchange/preview', '/api/profiles/exchange',
])
def test_exchange_routes_never_return_unrecognized_exception_details(app, client, monkeypatch, endpoint):
    _login(app, client)

    def fail(*args, **kwargs):
        raise ExchangeError('Internal storage path and secret diagnostic marker')

    monkeypatch.setattr('app.profile_exchange_routes.preview_import', fail)
    response = client.post(endpoint, json={'source': '{}', 'format': 'json'})
    assert response.status_code == 400
    assert response.json == {'error': 'Invalid import document. Check its format and syntax.'}


@pytest.mark.parametrize('endpoint', [
    '/api/profiles/exchange/preview', '/api/profiles/exchange',
])
def test_exchange_routes_preserve_safe_actionable_errors(app, client, endpoint):
    _login(app, client)
    response = client.post(endpoint, json={'source': '{', 'format': 'json'})
    assert response.status_code == 400
    assert response.json == {'error': 'Invalid JSON document.'}


def test_import_revalidates_source_and_skips_duplicates(app, client):
    user_id = _login(app, client)
    data = {'format': 'openssh', 'source': 'Host api\n User deploy', 'selections': [{'index': 0}]}
    first = client.post('/api/profiles/exchange', json=data)
    assert first.status_code == 200
    assert first.json['results'][0]['status'] == 'imported'
    assert client.post('/api/profiles/exchange', json=data).json['results'][0]['status'] == 'skipped'
    data['source'] += '\n ProxyCommand malicious'
    assert client.post('/api/profiles/exchange', json=data).status_code == 400
    from app.profile_manager import load_profiles
    with app.app_context():
        assert len(load_profiles(user_id)) == 1


def test_import_rejects_forged_key_and_jump_references(app, client):
    _login(app, client)
    data = {'format': 'openssh', 'source': 'Host api\n User deploy\n IdentityFile ~/.ssh/id',
            'selections': [{'index': 0, 'key_id': 'not-owned'}]}
    result = client.post('/api/profiles/exchange', json=data)
    assert result.status_code == 200
    assert result.json['results'][0]['status'] == 'error'
    data.update(source='Host api\n User deploy\n ProxyJump gateway',
                selections=[{'index': 0, 'jump_host_id': 'not-owned'}])
    assert client.post('/api/profiles/exchange', json=data).json['results'][0]['status'] == 'error'


def test_import_does_not_accept_client_provided_commands_or_overwrite_ids(app, client):
    _login(app, client)
    data = {'format': 'openssh', 'source': 'Host api\n User deploy',
            'selections': [{'index': 0, 'startup_commands': 'id'}]}
    assert client.post('/api/profiles/exchange', json=data).status_code == 400


def test_large_exports_split_into_independently_importable_batches():
    from app.profile_exchange import export_batches
    profiles = [{
        'name': f'host-{index}', 'host': 'example.com', 'username': 'deploy',
        'port': 22, 'auth_type': 'password',
    } for index in range(250)]
    batches = export_batches(profiles, [])
    assert [len(batch['hosts']) for batch in batches] == [100, 100, 50]
    assert sum(len(preview_import(json.dumps(batch), 'json')['records']) for batch in batches) == 250


def test_named_jump_and_tailscale_exports_preserve_authentication_requirements():
    document = export_profiles([
        {'name': 'api', 'host': 'api', 'username': 'deploy', 'jump_host_id': 'j'},
        {'name': 'tail', 'host': 'tail', 'username': 'deploy', 'auth_type': 'tailscale'},
    ], [{'id': 'j', 'name': 'Production gateway'}])
    rows = preview_import(json.dumps(document), 'json')['records']
    assert not rows[0]['blocked'] and rows[0]['requires_jump']
    assert rows[1]['auth_type'] == 'tailscale'


def test_gateway_selector_metadata_roundtrip():
    document = export_profiles([{
        'name': 'Gateway target', 'host': 'gateway.example',
        'username': 'alice:server1', 'auth_type': 'password',
    }], [])
    row = preview_import(json.dumps(document), 'json')['records'][0]
    assert not row['blocked']
    assert row['username'] == 'alice:server1'


def test_herdr_options_roundtrip_through_export_and_import(app, client):
    user_id = _login(app, client)
    document = export_profiles([
        {'name': 'Agents', 'host': 'agents.example', 'username': 'deploy',
         'auth_type': 'password', 'herdr': True, 'use_herdr': True},
        {'name': 'Plain', 'host': 'plain.example', 'username': 'deploy', 'auth_type': 'password'},
    ], [])
    assert document['hosts'][0]['herdr'] is True and document['hosts'][0]['use_herdr'] is True
    assert 'herdr' not in document['hosts'][1] and 'use_herdr' not in document['hosts'][1]
    rows = preview_import(json.dumps(document), 'json')['records']
    assert not rows[0]['blocked'] and rows[0]['herdr'] is True and rows[0]['use_herdr'] is True
    result = client.post('/api/profiles/exchange', json={
        'format': 'json', 'source': json.dumps(document),
        'selections': [{'index': 0}, {'index': 1}],
    })
    assert result.status_code == 200
    assert [item['status'] for item in result.json['results']] == ['imported', 'imported']
    from app.profile_manager import load_profiles
    with app.app_context():
        stored = {profile['name']: profile for profile in load_profiles(user_id)}
    assert stored['Agents']['herdr'] is True and stored['Agents']['use_herdr'] is True
    assert 'herdr' not in stored['Plain'] and 'use_herdr' not in stored['Plain']


def test_import_cannot_combine_herdr_session_with_tmux(app, client):
    user_id = _login(app, client)
    document = {'format': 'webssh-hosts', 'version': 1, 'hosts': [
        {'name': 'Both', 'host': 'both.example', 'username': 'deploy', 'auth_type': 'password',
         'use_tmux': True, 'herdr': True, 'use_herdr': True},
        {'name': 'Mode only', 'host': 'mode.example', 'username': 'deploy', 'auth_type': 'password',
         'use_herdr': True},
    ]}
    result = client.post('/api/profiles/exchange', json={
        'format': 'json', 'source': json.dumps(document),
        'selections': [{'index': 0}, {'index': 1}],
    })
    assert result.status_code == 200
    assert [item['status'] for item in result.json['results']] == ['error', 'error']
    from app.profile_manager import load_profiles
    with app.app_context():
        assert load_profiles(user_id) == []


# The fields a release without Herdr exports, and accepts as the whole set.
RELEASED_EXPORT_FIELDS = {'name', 'host', 'port', 'username', 'group', 'favorite', 'use_tmux',
                          'auth_type', 'platform_icon', 'requires_key'}


@pytest.mark.parametrize('stored', [{}, {'herdr': False}, {'herdr': False, 'use_herdr': False}])
def test_host_without_herdr_exports_exactly_as_before(stored):
    profile = {'name': 'Renamed', 'host': 'plain.example', 'port': 22, 'username': 'deploy',
               'group': 'Lab', 'favorite': False, 'use_tmux': True, 'auth_type': 'password'}
    exported = export_profiles([{**profile, **stored}], [])['hosts'][0]
    assert exported == export_profiles([profile], [])['hosts'][0]
    assert set(exported) <= RELEASED_EXPORT_FIELDS


def test_only_enabled_herdr_options_are_exported():
    exported = export_profiles([{'name': 'Overview', 'host': 'agents.example', 'username': 'deploy',
                                 'auth_type': 'password', 'herdr': True, 'use_herdr': False}], [])
    assert exported['hosts'][0]['herdr'] is True
    assert 'use_herdr' not in exported['hosts'][0]


@pytest.mark.parametrize('field', ['herdr', 'use_herdr'])
@pytest.mark.parametrize('value', ['true', 1, None])
def test_import_blocks_non_boolean_herdr_options(field, value):
    document = {'format': 'webssh-hosts', 'version': 1, 'hosts': [{
        'name': 'Agents', 'host': 'agents.example', 'username': 'deploy', field: value,
    }]}
    row = preview_import(json.dumps(document), 'json')['records'][0]
    assert row['blocked']
    assert 'Invalid connection metadata.' in row['warnings']


def test_import_reports_conflicting_herdr_session_mode(app, client):
    user_id = _login(app, client)
    document = {'format': 'webssh-hosts', 'version': 1, 'hosts': [{
        'name': 'Agents', 'host': 'agents.example', 'username': 'deploy',
        'herdr': True, 'use_herdr': True, 'use_tmux': True,
    }]}
    result = client.post('/api/profiles/exchange', json={
        'format': 'json', 'source': json.dumps(document), 'selections': [{'index': 0}],
    })
    assert result.status_code == 200
    assert result.json['results'][0]['status'] == 'error'
    from app.profile_manager import load_profiles
    with app.app_context():
        assert load_profiles(user_id) == []
