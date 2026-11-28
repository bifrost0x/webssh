"""Environment of the Python release for the golden data set checks.

The checks import config and app of the Python release (tests/conftest.py
puts WEBSSH_PYTHON_ROOT on the import path); config reads this
environment when it is first imported.
"""

import os
import tempfile
from pathlib import Path

_ROOT = Path(tempfile.mkdtemp(prefix='webssh-golden-checks-'))
os.environ.update({
    'SECRET_KEY': 'golden-checks-secret-key-test-only',
    'DEBUG': 'True',
    'DEPLOYMENT_PROFILE': 'homelab',
    'DATA_DIR': str(_ROOT / 'data'),
    'TRANSFER_TEMP_DIR': str(_ROOT / 'transfers'),
    'BACKUP_TEMP_DIR': str(_ROOT / 'backups'),
    'BACKUP_RECOVERY_DURABLE': 'true',
    'RATELIMIT_STORAGE_URL': 'memory://',
    'LDAP_ENABLED': 'false',
    'LDAP_AUTO_PROVISION': 'false',
    'OIDC_ENABLED': 'false',
    'TAILSCALE_SSH_ENABLED': 'false',
})
