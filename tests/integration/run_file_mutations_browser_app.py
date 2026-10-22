"""Loopback-only browser fixture for the disposable OpenSSH integration lab."""
import os
from pathlib import Path
import sys
import tempfile


def main():
    if os.environ.get('PARAMIKO5_DISPOSABLE_LAB') != '1':
        raise RuntimeError('This fixture requires the disposable OpenSSH lab')
    root = Path(__file__).resolve().parents[2]
    sys.path.insert(0, str(root))
    with tempfile.TemporaryDirectory(prefix='webssh-browser-lab-', ignore_cleanup_errors=True) as data:
        port = os.environ.get('WEBSSH_E2E_PORT', '4184')
        os.environ.update(DATA_DIR=data, SECRET_KEY='disposable-browser-lab-secret', DEBUG='false',
            SESSION_COOKIE_SECURE='false', HOST='127.0.0.1', PORT=port,
            REGISTRATION_ENABLED='true', RATELIMIT_STORAGE_URL='memory://',
            CORS_ORIGINS=f'http://127.0.0.1:{port}', SFTP_CHMOD_ENABLED='true')
        from app import create_app, socketio, ssh_manager
        from app.auth import register_user
        app = create_app()
        with app.app_context():
            _, error = register_user('e2e_admin', 'browser-password')
            if error:
                raise RuntimeError(error)
        connect = ssh_manager.create_ssh_connection

        def lab_connect(**kwargs):
            if kwargs.get('host') != '127.0.0.1' or kwargs.get('port') != 2223:
                raise RuntimeError('Only the disposable lab destination is allowed')
            return connect(**kwargs)

        ssh_manager.create_ssh_connection = lab_connect
        socketio.run(app, host='127.0.0.1', port=int(port), debug=False,
            use_reloader=False, allow_unsafe_werkzeug=True)


if __name__ == '__main__':
    main()
