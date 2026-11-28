"""Pytest setup of the repository's tool and policy checks.

tests/golden checks the golden data sets against the Python release, which
is not part of this repository. Those checks run only when
WEBSSH_PYTHON_ROOT names a worktree of that release, with its interpreter
(tests/README.md); the release's app/ and config.py are then importable.
"""

import os
import sys

_release = os.environ.get('WEBSSH_PYTHON_ROOT')
if _release:
    # After this repository, so tests.golden comes from here.
    sys.path.append(os.path.abspath(_release))
else:
    collect_ignore = ['golden']
