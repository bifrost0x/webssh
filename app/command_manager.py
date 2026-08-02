"""
Command Library Manager
Handles system and user-specific command storage and retrieval.
"""
import json
import uuid
from datetime import datetime
import config
from .audit_logger import log_error
from .storage_utils import atomic_write_json, load_json_strict, storage_lock
from .storage_migrations import backup_before_migration


_PR_COMMAND_WRAPPER_VERSIONS = frozenset({1, 2})


def get_user_commands_file(user_id):
    from .models import User, db

    user = db.session.get(User, user_id)
    return user.get_data_dir() / 'commands.json' if user else None


def _valid_command(item):
    if not isinstance(item, dict):
        return False
    if not all(
        isinstance(item.get(field), str)
        for field in ('id', 'name', 'command')
    ):
        return False
    for field in ('parameters', 'description', 'category', 'createdAt'):
        if field in item and not isinstance(item[field], str):
            return False
    if 'os' in item and (
        not isinstance(item['os'], list)
        or not all(isinstance(value, str) for value in item['os'])
    ):
        return False
    if 'isSystem' in item and type(item['isSystem']) is not bool:
        return False
    if 'userId' in item and (
        item['userId'] is not None or type(item['userId']) is bool
    ) and type(item['userId']) is not int:
        return False
    return True


def _valid_commands(value):
    return isinstance(value, list) and all(_valid_command(item) for item in value)


def _valid_commands_document(value):
    return (
        isinstance(value, dict)
        and value.get('schema_version') in _PR_COMMAND_WRAPPER_VERSIONS
        and _valid_commands(value.get('commands'))
    )


def _valid_commands_storage(value):
    return _valid_commands(value) or _valid_commands_document(value)


def valid_user_command_input(
    name, command, parameters, description, os_list, category
):
    """Return whether client-controlled command fields have storable types."""
    return (
        isinstance(name, str)
        and isinstance(command, str)
        and isinstance(parameters, str)
        and isinstance(description, str)
        and isinstance(os_list, list)
        and all(isinstance(value, str) for value in os_list)
        and isinstance(category, str)
    )


def load_system_commands():
    """Load global system commands from JSON."""
    commands_file = config.SYSTEM_COMMANDS_FILE
    if commands_file.exists():
        with open(commands_file, 'r') as f:
            return json.load(f)

    legacy_file = config.DATA_DIR / 'commands' / 'system_commands.json'
    if legacy_file.exists():
        with open(legacy_file, 'r') as f:
            return json.load(f)
    return []

def _load_user_commands_with_lock_held(user_id):
    user_commands_file = get_user_commands_file(user_id)
    if not user_commands_file:
        return []
    data = load_json_strict(
        user_commands_file,
        list,
        _valid_commands_storage,
    )
    if isinstance(data, list):
        return data

    commands = data['commands']
    backup_before_migration(user_commands_file)
    atomic_write_json(user_commands_file, commands)
    return commands


def load_user_commands(user_id):
    """Load user-specific commands."""
    with storage_lock(f'commands:{user_id}'):
        return _load_user_commands_with_lock_held(user_id)


def _load_user_commands_for_write(user_id):
    """Load commands without converting corrupt storage into an empty list."""
    user_commands_file = get_user_commands_file(user_id)
    if not user_commands_file:
        return None, 'User not found'
    return _load_user_commands_with_lock_held(user_id), None

def save_user_commands(user_id, commands):
    """Save user-specific commands."""
    user_commands_file = get_user_commands_file(user_id)
    if not user_commands_file or not _valid_commands(commands):
        return False
    user_commands_file.parent.mkdir(parents=True, exist_ok=True)
    atomic_write_json(user_commands_file, commands)
    return True

def get_all_commands(user_id, os_filter=None):
    """Get both system and user commands, optionally filtered by OS."""
    system_cmds = load_system_commands()
    user_cmds = load_user_commands(user_id)

    for cmd in system_cmds:
        cmd['isSystem'] = True
        cmd['userId'] = None

    for cmd in user_cmds:
        cmd['isSystem'] = False
        cmd['userId'] = user_id

    all_commands = system_cmds + user_cmds

    if os_filter:
        all_commands = [
            cmd for cmd in all_commands
            if 'all' in cmd.get('os', ['all']) or os_filter.lower() in [o.lower() for o in cmd.get('os', [])]
        ]

    return all_commands


def _get_all_commands_with_lock_held(user_id, os_filter=None):
    system_cmds = load_system_commands()
    user_cmds = _load_user_commands_with_lock_held(user_id)
    for cmd in system_cmds:
        cmd['isSystem'] = True
        cmd['userId'] = None
    for cmd in user_cmds:
        cmd['isSystem'] = False
        cmd['userId'] = user_id
    all_commands = system_cmds + user_cmds
    if os_filter:
        all_commands = [
            cmd for cmd in all_commands
            if 'all' in cmd.get('os', ['all'])
            or os_filter.lower() in [
                value.lower() for value in cmd.get('os', [])
            ]
        ]
    return all_commands

def add_user_command(user_id, name, command, parameters, description, os_list, category):
    """Add a new user command."""
    if not valid_user_command_input(
        name, command, parameters, description, os_list, category
    ):
        return None
    new_cmd = {
        'id': str(uuid.uuid4()),
        'name': name,
        'command': command,
        'parameters': parameters or '',
        'description': description,
        'os': os_list,
        'category': category or 'custom',
        'isSystem': False,
        'userId': user_id,
        'createdAt': datetime.utcnow().isoformat()
    }

    with storage_lock(f'command-config:{user_id}'):
        with storage_lock(f'commands:{user_id}'):
            user_cmds, error = _load_user_commands_for_write(user_id)
            if error:
                return None
            user_cmds.append(new_cmd)
            return new_cmd if save_user_commands(user_id, user_cmds) else None

def update_user_command(user_id, command_id, name, command, parameters, description, os_list, category):
    """Update an existing user command."""
    if not valid_user_command_input(
        name, command, parameters, description, os_list, category
    ):
        return None, 'Invalid command data'
    with storage_lock(f'command-config:{user_id}'):
        with storage_lock(f'commands:{user_id}'):
            user_cmds, error = _load_user_commands_for_write(user_id)
            if error:
                return None, error

            for cmd in user_cmds:
                if cmd['id'] == command_id:
                    cmd['name'] = name
                    cmd['command'] = command
                    cmd['parameters'] = parameters or ''
                    cmd['description'] = description
                    cmd['os'] = os_list
                    cmd['category'] = category or 'custom'
                    break
            else:
                return None, 'Command not found'

            try:
                saved = save_user_commands(user_id, user_cmds)
            except OSError as exc:
                log_error(
                    'Error saving user command',
                    user_id=user_id,
                    error=str(exc),
                )
                return None, 'Failed to save command'
            if saved:
                return cmd, None
            return None, 'Failed to save command'

def delete_user_command(user_id, command_id):
    """Delete a user command."""
    from .command_set_manager import _get_command_usage_with_coordinator_held

    with storage_lock(f'command-config:{user_id}'):
        usages, error = _get_command_usage_with_coordinator_held(
            user_id, command_id
        )
        if error:
            return False, error, []
        if usages:
            usage_types = {usage.get('type') for usage in usages}
            if usage_types == {'command_set'}:
                noun = 'command set' if len(usages) == 1 else 'command sets'
            elif usage_types == {'profile'}:
                noun = 'profile' if len(usages) == 1 else 'profiles'
            else:
                noun = 'reference' if len(usages) == 1 else 'references'
            return False, f'Command is used by {len(usages)} {noun}', usages

        with storage_lock(f'commands:{user_id}'):
            user_cmds, error = _load_user_commands_for_write(user_id)
            if error:
                return False, error, []
            remaining = [cmd for cmd in user_cmds if cmd.get('id') != command_id]
            if len(remaining) == len(user_cmds):
                return False, 'Command not found', []
            if not save_user_commands(user_id, remaining):
                return False, 'Failed to delete command', []
    return True, None, []
