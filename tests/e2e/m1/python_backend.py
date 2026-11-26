"""Start the Python application on an existing DATA_DIR for the M1 specs.

``serve`` runs the server on 127.0.0.1:$PORT, ``cli <args>`` runs the Flask
maintenance commands (``create-admin`` and others). Both resolve SECRET_KEY
like ``entrypoint.sh``: the environment wins, otherwise ``DATA_DIR/secret_key``
is read or created with mode 0600. Nothing is seeded; the data directory is
what a real installation would hold.
"""
import os
from pathlib import Path
import secrets
import sys

from werkzeug.serving import WSGIRequestHandler

_PLACEHOLDERS = {'', '<your-secret-key>', 'changeme', 'secret', 'your-secret-key'}


class _QuietRequestHandler(WSGIRequestHandler):
    """Log failed requests only."""

    def log_request(self, code='-', size='-'):
        if str(code).isdigit() and int(code) < 400:
            return
        super().log_request(code, size)


def _data_dir():
    value = os.environ.get('DATA_DIR', '')
    path = Path(value)
    if not value or not path.is_absolute():
        raise SystemExit('DATA_DIR must be set to an absolute path.')
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    return path


def _resolve_secret(data_dir):
    if os.environ.get('SECRET_KEY', '').strip().lower() not in _PLACEHOLDERS:
        os.environ['WEBSSH_SECRET_KEY_SOURCE'] = 'environment'
        return
    secret_file = data_dir / 'secret_key'
    if not secret_file.exists():
        descriptor = os.open(secret_file, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(descriptor, 'w', encoding='utf-8') as handle:
            handle.write(secrets.token_hex(32) + '\n')
    os.environ['SECRET_KEY'] = secret_file.read_text(encoding='utf-8').strip()
    os.environ['WEBSSH_SECRET_KEY_SOURCE'] = 'file'


def main(argv):
    if not argv or argv[0] not in {'serve', 'cli'}:
        raise SystemExit('usage: python_backend.py serve | cli <flask command> ...')
    project_root = Path(__file__).resolve().parents[3]
    os.chdir(project_root)
    sys.path.insert(0, str(project_root))
    _resolve_secret(_data_dir())

    if argv[0] == 'cli':
        from flask.cli import main as flask_main

        sys.argv = ['flask', '--app', 'start:app', *argv[1:]]
        flask_main()
        return

    port = int(os.environ.get('PORT', '0'))
    if not 0 < port < 65536:
        raise SystemExit('PORT must be set to a TCP port.')
    # The same module the production entrypoint loads, including its
    # shutdown signal handling.
    from app import socketio
    from start import app

    socketio.run(
        app,
        host='127.0.0.1',
        port=port,
        debug=False,
        use_reloader=False,
        allow_unsafe_werkzeug=True,
        request_handler=_QuietRequestHandler,
    )


if __name__ == '__main__':
    main(sys.argv[1:])
