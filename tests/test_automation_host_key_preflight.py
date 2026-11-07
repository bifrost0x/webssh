"""Reviews fail early, with host names, when a target's host key is not verified."""
import paramiko
import pytest

import config
from app.automation_store import AutomationError
from app.host_key_store import HostKeyStore
from tests.test_automation_service import context  # noqa: F401  (fixture)


@pytest.fixture
def real_trust(monkeypatch):
    # The shared fixture stubs trust; these tests use the real store.
    monkeypatch.setattr(HostKeyStore, 'has_trusted_key', HOST_KEY_CHECK)


HOST_KEY_CHECK = HostKeyStore.has_trusted_key


def _record(uid, name):
    key = paramiko.RSAKey.generate(1024)
    HostKeyStore(uid, config.KNOWN_HOSTS_FILE, config.USERS_DIR).record(name, key)


def test_unverified_host_key_stops_the_review_with_its_name(app, client, context, real_trust):
    uid, aid, book, profile = context
    service = app.extensions['automation']
    with pytest.raises(AutomationError) as raised:
        service.prepare_run(uid, aid, dict(runbook_id=book['id'], profile_ids=[profile['id']], groups=[]))
    assert raised.value.code == 'host_key_required'
    assert raised.value.hosts == [profile['name']]

    response = client.post('/api/automation/preview', json=dict(runbook_id=book['id'], profile_ids=[profile['id']], groups=[]),
                           base_url='https://localhost')
    assert response.status_code == 409
    assert response.json == dict(error='Automation request could not be completed.', code='host_key_required', hosts=[profile['name']])


def test_verified_host_key_passes_the_review(app, context, real_trust, monkeypatch):
    uid, aid, book, profile = context
    credentials = app.extensions['credentials']
    monkeypatch.setattr(credentials, 'generations', lambda *args: {'one': 'generation'})
    monkeypatch.setattr(credentials, 'password', lambda *args: 'test-only')
    _record(uid, profile['host'])
    preview = app.extensions['automation'].prepare_run(uid, aid, dict(runbook_id=book['id'], profile_ids=[profile['id']], groups=[]))
    assert preview['targets'][0]['host'] == profile['host']


def test_non_default_port_uses_the_bracketed_known_hosts_name(app, context, real_trust):
    uid, *_ = context
    store = HostKeyStore(uid, config.KNOWN_HOSTS_FILE, config.USERS_DIR)
    _record(uid, '[port.example]:2222')
    assert store.has_trusted_key('port.example', 2222) is True
    assert store.has_trusted_key('port.example', 22) is False
