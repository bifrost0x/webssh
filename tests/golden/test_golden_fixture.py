"""Verify the committed golden data set against the Python application.

Each check reads the fixture twice where it matters: once through the
application function and once through an independent implementation of the
parameters recorded in manifest.json. Both must agree, so the manifest is a
sufficient specification for another reader.
"""

import base64
import datetime as dt
import hashlib
import json
import pytest

from tests.golden import runtime
from tests.golden.determinism import Clock, frozen_clock
from tests.golden.packing import extract_data_dir

FIXTURE = runtime.FIXTURE_ROOT
MANIFEST = json.loads((FIXTURE / 'manifest.json').read_text(encoding='utf-8'))
VALUES = MANIFEST['values']
USERS = VALUES['users']


def _pbkdf2_fernet(password, salt):
    from cryptography.fernet import Fernet
    key = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, 600000, 32)
    return Fernet(base64.urlsafe_b64encode(key))


def _incarnation(username):
    return dt.datetime.fromisoformat(USERS[username]['created_at_db']).isoformat()


@pytest.fixture(scope='module')
def golden(tmp_path_factory):
    """The application started on a private copy of the fixture data."""
    work = tmp_path_factory.mktemp('golden')
    data_dir = extract_data_dir(FIXTURE / runtime.DATA_ARCHIVE, work)
    with pytest.MonkeyPatch.context() as patch:
        for name, value in runtime.environment(data_dir, work).items():
            if name != 'TZ':
                patch.setenv(name, value)
        config = runtime.reload_config()
        from app import app_settings
        patch.setattr(app_settings, '_SETTINGS_FILE', config.DATA_DIR / 'app_settings.json')
        application = runtime.create_application()
        application.config['TESTING'] = True
        try:
            yield application, data_dir
        finally:
            runtime.shutdown(application)
    runtime.reload_config()


@pytest.fixture
def ctx(golden):
    application, data_dir = golden
    with application.app_context():
        yield application, data_dir


@pytest.fixture(scope='module')
def pristine(tmp_path_factory):
    """Untouched extraction; the app fixture may rewrite files on start."""
    return extract_data_dir(FIXTURE / runtime.DATA_ARCHIVE, tmp_path_factory.mktemp('pristine'))


def test_manifest_inventory_matches_files(pristine):
    root = pristine.parent
    for entry in MANIFEST['files']:
        base = root if entry['path'].startswith('data/') else FIXTURE
        content = (base / entry['path']).read_bytes()
        assert len(content) == entry['size'], entry['path']
        if entry['deterministic']:
            assert hashlib.sha256(content).hexdigest() == entry['sha256'], entry['path']
    listed = {e['path'] for e in MANIFEST['files'] if e['path'].startswith('data/')}
    present = {'data/' + p.relative_to(pristine).as_posix() for p in pristine.rglob('*') if p.is_file()}
    assert listed == present
    assert (pristine / 'secret_key').read_text() == MANIFEST['secret_key']['value'] + '\n'
    assert MANIFEST['secret_key']['value'] == runtime.secret_key()


def test_password_login_is_accepted_by_the_app(golden):
    application, _ = golden
    client = application.test_client()
    response = runtime.password_login(client, 'local_user', USERS['local_user']['password'])
    assert response.status_code == 302 and response.headers['Location'] == '/'
    assert client.get('/').status_code == 200


def test_password_hashes_and_auth_kinds(ctx):
    import bcrypt
    from app.auth import authenticate_user, password_exceeds_bcrypt_limit
    from app.models import User
    for username, facts in USERS.items():
        user = User.query.filter_by(username=username).one()
        assert user.password_hash.startswith('$2b$12$')
        if facts['password'] is None:
            continue
        assert bcrypt.checkpw(facts['password'].encode(), user.password_hash.encode())
        expected = None if facts['is_locked'] else user
        assert authenticate_user(username, facts['password'])[0] == expected
    limit = USERS['limit_user']['password']
    assert len(limit.encode()) == 72 and not password_exceeds_bcrypt_limit(limit)
    assert password_exceeds_bcrypt_limit(limit + 'x')
    managed = User.query.filter_by(username='ldap_user').one()
    assert managed.is_ldap_managed and authenticate_user('ldap_user', 'x')[0] is None
    assert User.query.filter_by(username='octo_golden').one().is_github_managed
    assert User.query.filter_by(username='cfg_admin').one().is_admin


def test_ssh_keys_decrypt_with_app_and_manifest_parameters(ctx):
    from app.key_encryption import is_encrypted, read_key_content
    _, data_dir = ctx
    secret = MANIFEST['secret_key']['value']
    for entry in VALUES['ssh_keys']['stored']:
        user_id = int(entry['stored_file'].split('/')[1].removeprefix('user_'))
        path = data_dir / entry['stored_file']
        plaintext = base64.b64decode(entry['plaintext_b64']).decode()
        assert is_encrypted(path.read_bytes())
        assert read_key_content(user_id, str(path), migrate_legacy=False) == plaintext
        fernet = _pbkdf2_fernet(f'{secret}:{user_id}', b'webssh_key_encryption_v1')
        assert fernet.decrypt(path.read_bytes()).decode() == plaintext
    legacy = data_dir / VALUES['ssh_keys']['legacy_plaintext']['stored_file']
    assert not is_encrypted(legacy.read_bytes())


def test_rejected_key_formats_keep_their_error(ctx):
    from app.key_manager import save_key
    owner = USERS['local_user']['id']
    for entry in VALUES['ssh_keys']['rejected']:
        content = base64.b64decode(entry['plaintext_b64']).decode()
        assert save_key(owner, 'probe', content) == (None, entry['expected_error'])


def test_totp_secret_code_and_replay(ctx):
    from app.mfa_crypto import decrypt_totp_secret
    from app.models import TOTPAuthenticator
    from app.totp_service import _totp_code, verify_totp
    facts = VALUES['totp']
    user_id = USERS['totp_user']['id']
    row = TOTPAuthenticator.query.filter_by(user_id=user_id, active=True).one()
    assert decrypt_totp_secret(user_id, row.encrypted_secret) == facts['secret_base32']
    oracle = _pbkdf2_fernet(f"{MANIFEST['secret_key']['value']}:totp:{user_id}",
                            b'webssh-mfa-totp-v1')
    assert oracle.decrypt(bytes(row.encrypted_secret)).decode() == facts['secret_base32']
    step = facts['activation_step']
    assert row.last_accepted_step == step
    assert _totp_code(facts['secret_base32'], step) == facts['activation_code']
    at = dt.datetime.fromtimestamp(step * 30, dt.timezone.utc)
    assert not verify_totp(user_id, facts['activation_code'], now=at)
    later = at + dt.timedelta(seconds=30)
    assert verify_totp(user_id, _totp_code(facts['secret_base32'], step + 1), now=later)


def test_recovery_codes_are_domain_separated_hashes(ctx):
    from app.models import RecoveryCode
    user_id = USERS['totp_user']['id']
    stored = {bytes(r.code_hash) for r in RecoveryCode.query.filter_by(user_id=user_id)}
    digest = lambda code: hashlib.sha256(b'webssh-recovery-code-v1\x00' + code.encode()).digest()  # noqa: E731
    case = VALUES['edge_cases']['recovery_code']
    assert {digest(c) for c in case['remaining']} == stored
    assert digest(case['consumed']) not in stored


def test_github_client_secret(ctx):
    from app.github_auth_crypto import decrypt_client_secret
    from app.models import GitHubAuthConfiguration
    row = GitHubAuthConfiguration.query.one()
    assert decrypt_client_secret(row.encrypted_client_secret) == VALUES['github_client_secret']
    oracle = _pbkdf2_fernet(f"{MANIFEST['secret_key']['value']}:github-auth:configuration",
                            b'webssh-github-auth-config-v1')
    assert oracle.decrypt(bytes(row.encrypted_client_secret)).decode() == VALUES['github_client_secret']


def _named_oracle(user_id, record_id, ciphertext):
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF
    context = json.dumps(['webssh-named-credentials-v1', user_id,
                          _incarnation('local_user'), record_id],
                         separators=(',', ':')).encode()
    key = HKDF(hashes.SHA256(), 32, b'webssh-named-credential-master-v1',
               context).derive(MANIFEST['secret_key']['value'].encode())
    raw = base64.b64decode(ciphertext)
    return AESGCM(key).decrypt(raw[:12], raw[12:], context).decode()


def test_named_credentials(ctx):
    from app.credential_crypto import decrypt
    _, data_dir = ctx
    user_id = USERS['local_user']['id']
    document = json.loads((data_dir / f'users/user_{user_id}/credentials.json').read_text())
    cases = [VALUES['named_credential'],
             VALUES['edge_cases']['named_credentials']['unassigned_unicode']]
    for case in cases:
        ciphertext = document['credentials'][case['record_id']]['ciphertext']
        assert decrypt(user_id, case['record_id'], ciphertext) == case['password']
        assert _named_oracle(user_id, case['record_id'], ciphertext) == case['password']
    assert VALUES['edge_cases']['named_credentials']['deleted'] not in document['credentials']


def test_automation_vault(ctx):
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
    _, data_dir = ctx
    user_id = USERS['local_user']['id']
    document = json.loads((data_dir / f'users/user_{user_id}/automation-vault.json').read_text())
    assert document['version'] == 2 and document['kdf'] == 'scrypt-131072-8-1'
    key = Scrypt(salt=base64.b64decode(document['salt']), length=32, n=131072, r=8,
                 p=1).derive(VALUES['vault_passphrase'].encode())
    aad = f"webssh-automation-vault-v2:{user_id}:{_incarnation('local_user')}".encode()
    records = json.loads(AESGCM(key).decrypt(base64.b64decode(document['nonce']),
                                             base64.b64decode(document['ciphertext']), aad))
    expected = {v['profile_id']: v['password'] for v in VALUES['vault'].values()}
    long_case = VALUES['edge_cases']['vault_long_password']
    expected[long_case['profile_id']] = long_case['password']
    assert {k: v['password'] for k, v in records.items()} == expected


def test_webauthn_assertion_vectors_verify(ctx):
    from app.models import WebAuthnCredential, db
    from app.webauthn_service import verify_assertion
    from webauthn.helpers import base64url_to_bytes
    deleted = VALUES['edge_cases']['passkey_deleted']['id']
    assert db.session.get(WebAuthnCredential, deleted) is None
    live = [v for v in VALUES['webauthn_vectors'] if v['credential_row_id'] != deleted]
    assert sorted(v['cose_alg'] for v in live) == [-257, -8, -7]
    for vector in live:
        row = db.session.get(WebAuthnCredential, vector['credential_row_id'])
        assert row.sign_count == vector['stored_sign_count']
        challenge = base64url_to_bytes(vector['challenge_b64url'])
        verify_assertion(row, vector['assertion_response'], challenge)
        assert row.sign_count == vector['assertion_sign_count']
        tampered = json.loads(json.dumps(vector['assertion_response']))
        signature = bytearray(base64url_to_bytes(tampered['response']['signature']))
        signature[-1] ^= 1
        tampered['response']['signature'] = base64.urlsafe_b64encode(signature).rstrip(b'=').decode()
        with pytest.raises(Exception):
            verify_assertion(row, tampered, challenge)
        db.session.rollback()


def _cookie_accepted(application, value):
    import config
    client = application.test_client()
    client.environ_base['HTTP_USER_AGENT'] = 'golden-fixture-browser/1'
    client.set_cookie(config.SESSION_COOKIE_NAME, value)
    return client.get('/').status_code == 200


def test_session_cookies_at_reference_time(golden):
    application, _ = golden
    verify_at = dt.datetime.fromisoformat(MANIFEST['reference']['cookie_verify_at'])
    from itsdangerous import BadSignature, SignatureExpired
    serializer = application.session_interface.get_signing_serializer(application)
    max_age = int(application.permanent_session_lifetime.total_seconds())
    with frozen_clock(Clock(verify_at)):
        for cookie in VALUES['cookies']:
            assert _cookie_accepted(application, cookie['value']) is cookie['expected']['accepted'], cookie['name']
            reason = cookie['expected'].get('reason')
            if reason == 'signature_age':
                with pytest.raises(SignatureExpired):
                    serializer.loads(cookie['value'], max_age=max_age)
            elif reason == 'signature':
                with pytest.raises(BadSignature):
                    serializer.loads(cookie['value'], max_age=max_age)
            else:
                # Signature intact: server-side state rejects it.
                assert serializer.loads(cookie['value'], max_age=max_age) == cookie['decoded_payload']
    valid = next(c['value'] for c in VALUES['cookies'] if c['name'] == 'valid')
    with frozen_clock(Clock(verify_at + dt.timedelta(minutes=31))):
        assert not _cookie_accepted(application, valid)


def test_every_single_character_change_of_the_signature_is_rejected(golden):
    from itsdangerous import BadSignature
    application, _ = golden
    serializer = application.session_interface.get_signing_serializer(application)
    valid = next(c['value'] for c in VALUES['cookies'] if c['name'] == 'valid')
    head, signature = valid.rsplit('.', 1)
    for index, character in enumerate(signature):
        changed = 'A' if character != 'A' else 'B'
        with pytest.raises(BadSignature):
            serializer.loads(f'{head}.{signature[:index]}{changed}{signature[index + 1:]}')


def test_session_epoch_file(ctx):
    _, data_dir = ctx
    assert (data_dir / 'session_epoch').read_text() == VALUES['epochs']['rotated'] + '\n'
    assert VALUES['epochs']['initial'] != VALUES['epochs']['rotated']


def test_backup_archives_verify(ctx):
    from app.backup_manager import verify_backup
    for name, archive in (('export', 'export.zip'), ('online', 'online.zip'),
                          ('recovery_snapshot', 'online-recovery-snapshot.zip')):
        manifest = verify_backup(FIXTURE / 'artifacts' / 'backups' / archive)
        paths = {item.path for item in manifest.files}
        assert [item.path for item in manifest.files] == [f['path'] for f in VALUES['backups'][name]['files']]
        has_secrets = any('/keys/' in p or p.endswith(('credentials.json', 'automation-vault.json'))
                          for p in paths)
        assert has_secrets is (name == 'recovery_snapshot')


def test_deleted_and_boundary_entities(ctx):
    from app.key_manager import load_keys
    from app.profile_manager import load_profiles
    _, data_dir = ctx
    owner = USERS['local_user']['id']
    edge = VALUES['edge_cases']
    profiles = {p['id']: p for p in load_profiles(owner)}
    assert edge['profiles']['deleted'] not in profiles
    assert profiles[edge['profiles']['long_name']]['name'] == edge['profiles']['stored_long_name']
    assert len(edge['profiles']['stored_long_name']) == 128
    keys = {k['id'] for k in load_keys(owner)}
    assert edge['keys']['deleted'] not in keys and edge['keys']['unicode_128_chars'] in keys
    deleted = edge['deleted_account']
    assert (data_dir / deleted['quarantine_dir']).is_dir()
    assert USERS['jörg_ünïcødé']['id'] == deleted['former_id']
