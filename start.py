import warnings
warnings.filterwarnings('ignore', message='.*TripleDES.*')

import os
import sys


_MAINTENANCE_COMMANDS = frozenset({
    'backup',
    'create-admin',
    'rotate-secret-key',
})
_FLASK_OPTIONS_WITH_VALUES = frozenset({
    '--app',
    '-A',
    '--env-file',
})


def _is_flask_cli_process(program_name=None, main_module_name=None):
    if program_name is None:
        program_name = sys.argv[0]
    if main_module_name is None:
        main_module = sys.modules.get('__main__')
        main_module_spec = getattr(main_module, '__spec__', None)
        main_module_name = getattr(main_module_spec, 'name', None)

    executable_name = os.path.splitext(os.path.basename(program_name))[0].lower()
    return executable_name == 'flask' or main_module_name == 'flask.__main__'


def _flask_top_level_command(arguments):
    skip_next = False
    for index, argument in enumerate(arguments):
        if skip_next:
            skip_next = False
            continue
        if argument == '--':
            return arguments[index + 1] if index + 1 < len(arguments) else None
        if argument in _FLASK_OPTIONS_WITH_VALUES:
            skip_next = True
            continue
        if any(
            argument.startswith(f'{option}=')
            for option in _FLASK_OPTIONS_WITH_VALUES
            if option.startswith('--')
        ):
            continue
        if argument.startswith('-A') and argument != '-A':
            continue
        if argument.startswith('-'):
            continue
        return argument
    return None


def _is_maintenance_cli_invocation(
    arguments=None,
    program_name=None,
    main_module_name=None,
):
    arguments = sys.argv[1:] if arguments is None else arguments
    if not _is_flask_cli_process(program_name, main_module_name):
        return False
    return _flask_top_level_command(arguments) in _MAINTENANCE_COMMANDS


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
