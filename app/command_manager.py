"""
Command Library Manager
Handles system and user-specific command storage and retrieval.
"""
import json
import uuid
from pathlib import Path
from datetime import datetime
import config
from .audit_logger import log_error
from .storage_utils import storage_lock, atomic_write_json

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

def load_user_commands(user_id):
    """Load user-specific commands."""
    from .models import User
    user = User.query.get(user_id)
    if not user:
        return []

    user_commands_file = user.get_data_dir() / 'commands.json'
    if user_commands_file.exists():
        try:
            with open(user_commands_file, 'r', encoding='utf-8') as f:
                data = json.load(f)
                return data if isinstance(data, list) else []
        except (ValueError, OSError) as e:
            # Corrupt/unreadable file: fail soft instead of crashing the whole
            # command feature. Do NOT overwrite it here, so the data can be
            # recovered manually.
            log_error("Error loading user commands", user_id=user_id, error=str(e))
            return []
    return []

def save_user_commands(user_id, commands):
    """Save user-specific commands."""
    from .models import User
    user = User.query.get(user_id)
    if not user:
        return False

    user_commands_file = user.get_data_dir() / 'commands.json'
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

def add_user_command(user_id, name, command, parameters, description, os_list, category):
    """Add a new user command."""
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

    with storage_lock(f'commands:{user_id}'):
        user_cmds = load_user_commands(user_id)
        user_cmds.append(new_cmd)
        save_user_commands(user_id, user_cmds)
    return new_cmd

def update_user_command(user_id, command_id, name, command, parameters, description, os_list, category):
    """Update an existing user command."""
    with storage_lock(f'commands:{user_id}'):
        user_cmds = load_user_commands(user_id)

        for cmd in user_cmds:
            if cmd['id'] == command_id:
                cmd['name'] = name
                cmd['command'] = command
                cmd['parameters'] = parameters or ''
                cmd['description'] = description
                cmd['os'] = os_list
                cmd['category'] = category or 'custom'
                break

        save_user_commands(user_id, user_cmds)
    return True

def delete_user_command(user_id, command_id):
    """Delete a user command."""
    from .command_set_manager import get_command_usage

    with storage_lock(f'command-config:{user_id}'):
        usages, error = get_command_usage(user_id, command_id)
        if error:
            return False, error, []
        if usages:
            noun = 'command set' if len(usages) == 1 else 'command sets'
            return False, f'Command is used by {len(usages)} {noun}', usages

        with storage_lock(f'commands:{user_id}'):
            user_cmds = load_user_commands(user_id)
            remaining = [cmd for cmd in user_cmds if cmd.get('id') != command_id]
            if len(remaining) == len(user_cmds):
                return False, 'Command not found', []
            if not save_user_commands(user_id, remaining):
                return False, 'Failed to delete command', []
    return True, None, []
