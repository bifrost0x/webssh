"""Release version shown to signed-in users.

VERSION changes together with docs/releases/v<VERSION>.md; tests and the
tag-triggered image build reject a mismatch. The container build supplies
the source revision so builds between releases stay distinguishable.
"""

import os
import re


VERSION = '3.0.0'

_REVISION = re.compile(r'[0-9a-f]{40}')


def source_revision(environ=os.environ):
    """Return the short source revision, or '' when it is not a full commit id."""
    value = environ.get('WEBSSH_REVISION', '')
    return value[:7] if _REVISION.fullmatch(value) else ''


def display_version(environ=os.environ):
    revision = source_revision(environ)
    return f'{VERSION} ({revision})' if revision else VERSION
