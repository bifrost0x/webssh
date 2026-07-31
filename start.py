import warnings
warnings.filterwarnings('ignore', message='.*TripleDES.*')

import os
import sys


_MAINTENANCE_COMMANDS = frozenset({
    'backup',
    'create-admin',
    'rotate-secret-key',
})


def _is_maintenance_cli_invocation(arguments=None):
    arguments = sys.argv[1:] if arguments is None else arguments
    return any(argument in _MAINTENANCE_COMMANDS for argument in arguments)


from app import create_app, socketio
import config

if _is_maintenance_cli_invocation():
    app = create_app(
        initialize_storage=False,
        start_runtime=False,
        initialize_oidc=False,
    )
else:
    app = create_app()
    app.extensions['runtime_lifecycle'].install_process_shutdown_signals(
        config.RUNTIME_SHUTDOWN_GRACE_SECONDS
    )

if __name__ == '__main__':
    host = os.environ.get('HOST', '127.0.0.1')
    port = int(os.environ.get('PORT', '5000'))
    print("Starting Web SSH Terminal...")
    print(f"Server running at http://{host}:{port}")
    if host == '127.0.0.1':
        print("Note: Listening on localhost only. Set HOST=0.0.0.0 to accept external connections.")
    print("Press Ctrl+C to stop the server")

    socketio.run(
        app,
        host=host,
        port=port,
        debug=config.DEBUG
    )
