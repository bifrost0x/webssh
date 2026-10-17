"""Gunicorn production defaults, loaded automatically from the working directory.

The container command pins the reviewed runtime contract (one gthread worker,
``GUNICORN_THREADS`` threads, port 5000) on the command line, and command-line
options always win over this file. This file only adds settings that the
command line does not cover. Override any of them with ``GUNICORN_CMD_ARGS``.
"""

import os


# SSH sessions, quotas, rate-limit fallbacks and share links are process-local.
# Recycling the worker would drop every live terminal, so it never happens.
max_requests = 0
max_requests_jitter = 0

# Idle keep-alive connections wait in the gthread poller, not on a thread.
# A few seconds lets reverse proxies reuse connections between requests.
keepalive = int(os.environ.get('GUNICORN_KEEPALIVE', '5'))

# Matches the application's bounded shutdown so live sessions close cleanly.
graceful_timeout = int(os.environ.get('GUNICORN_GRACEFUL_TIMEOUT', '30'))

# The worker heartbeat file must never wait on a slow or overlay filesystem.
if os.path.isdir('/dev/shm') and os.access('/dev/shm', os.W_OK):
    worker_tmp_dir = '/dev/shm'

# Access logs are off unless requested, e.g. GUNICORN_ACCESS_LOG=-.
# The format logs the path without its query string.
accesslog = os.environ.get('GUNICORN_ACCESS_LOG') or None
access_log_format = '%(h)s "%(m)s %(U)s %(H)s" %(s)s %(B)s %(M)sms'
