"""Per-user named command sets for post-connect SSH automation."""
import copy
import json
import uuid
from datetime import datetime, timezone

from .audit_logger import log_error
from .startup_commands import normalize_startup_commands
from .storage_utils import atomic_write_json, storage_lock


COMMAND_SET_NAME_MAX = 128
SUDO_TOKEN_BOUNDARIES = ' \t;&|()<>'


def _prefix_commands_with_sudo(value):
    lines = []
    for line in value.split('\n'):
        stripped = line.lstrip()
        leading = line[:len(line) - len(stripped)]
        already_sudo = (
            stripped == 'sudo'
            or (
                stripped.startswith('sudo')
                and len(stripped) > len('sudo')
                and stripped[len('sudo')] in SUDO_TOKEN_BOUNDARIES
            )
        )
        if not stripped or stripped.startswith('#') or already_sudo:
            lines.append(line)
        else:
            lines.append(f'{leading}sudo {stripped}')
    return '\n'.join(lines)


def _shell_token_positions(value):
    in_single_quote = False
    in_double_quote = False
    escaped = False
    at_word_start = True
    comment_on_line = False
    line_number = 0
    column_number = 0
    comment_positions = {}
    semicolon_positions = set()
    ampersand_positions = set()

    for character in value:
        if comment_on_line:
            if character == '\n':
                comment_on_line = False
                at_word_start = True
        elif escaped:
            escaped = False
            if character != '\n':
                at_word_start = False
        elif in_single_quote:
            if character == "'":
                in_single_quote = False
        elif in_double_quote:
            if character == '"':
                in_double_quote = False
            elif character == '\\':
                escaped = True
        elif character == '\\':
            escaped = True
        elif character == "'":
            in_single_quote = True
            at_word_start = False
        elif character == '"':
            in_double_quote = True
            at_word_start = False
        elif character == '\n' or character.isspace():
            at_word_start = True
        elif character == ';':
            semicolon_positions.add((line_number, column_number))
            at_word_start = True
        elif character == '&':
            ampersand_positions.add((line_number, column_number))
            at_word_start = True
        elif character in '|()<>':
            at_word_start = True
        elif character == '#' and at_word_start:
            comment_on_line = True
            comment_positions[line_number] = column_number
        else:
            at_word_start = False

        if character == '\n':
            line_number += 1
            column_number = 0
        else:
            column_number += 1

    return comment_positions, semicolon_positions, ampersand_positions


def _append_operator(command_text, line_number, semicolons, ampersands):
    terminal_position = (line_number, len(command_text) - 1)
    if terminal_position in semicolons:
        return f'{command_text[:-1].rstrip()} &&'
    if terminal_position in ampersands:
        return f'{command_text} : &&'
    return f'{command_text} &&'


def _prepare_step_for_chaining(value):
    """Trim boundary padding and make a comment-only step a shell no-op."""
    lines = value.split('\n')
    while lines and not lines[-1].strip():
        lines.pop()
    if not lines:
        return ':'

    trimmed = '\n'.join(lines)
    has_command = any(
        line.strip() and not line.lstrip().startswith('#') for line in lines
    )
    return trimmed if has_command else f':\n{trimmed}'


def _append_step_separator(value):
    """Append a boundary without letting trailing comments consume it."""
    lines = value.split('\n')
    comment_positions, semicolon_positions, ampersand_positions = (
        _shell_token_positions(value)
    )
    last_line = len(lines) - 1
    if last_line not in comment_positions:
        lines[last_line] = _append_operator(
            lines[last_line], last_line,
            semicolon_positions, ampersand_positions,
        )
        joined = '\n'.join(lines)
        return f'{joined} '

    command_line = None
    command_text = None
    comment_text = None
    for line_number in range(last_line, -1, -1):
        comment_at = comment_positions.get(line_number)
        before_comment = (
            lines[line_number][:comment_at]
            if comment_at is not None
            else lines[line_number]
        )
        if before_comment.strip():
            command_line = line_number
            command_text = before_comment.rstrip()
            comment_text = (
                lines[line_number][comment_at:]
                if comment_at is not None
                else None
            )
            break

    if command_line is None:
        lines.insert(0, ': &&')
    else:
        lines[command_line] = _append_operator(
            command_text, command_line,
            semicolon_positions, ampersand_positions,
        )
        if comment_text is not None:
            lines[command_line] += f' {comment_text}'

    joined = '\n'.join(lines)
    return f'{joined}\n'


def _command_sets_file(user_id):
    from .models import User

    user = User.query.get(user_id)
    if not user:
        return None
    return user.get_data_dir() / 'command_sets.json'


def load_command_sets(user_id):
    """Return ``(sets, error)`` without hiding corrupt storage as an empty list."""
    path = _command_sets_file(user_id)
    if path is None:
        return None, 'User not found'
    if not path.exists():
        return [], None
    try:
        data = json.loads(path.read_text(encoding='utf-8'))
        if not isinstance(data, dict) or not isinstance(data.get('command_sets'), list):
            raise ValueError('invalid command set storage shape')
        return data['command_sets'], None
    except (OSError, ValueError, TypeError) as exc:
        log_error('Error loading command sets', user_id=user_id, error=str(exc))
        return None, 'Command set storage is unreadable'


def _save_command_sets(user_id, command_sets):
    path = _command_sets_file(user_id)
    if path is None:
        return False, 'User not found'
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        atomic_write_json(path, {'command_sets': command_sets})
        return True, None
    except OSError as exc:
        log_error('Error saving command sets', user_id=user_id, error=str(exc))
        return False, 'Failed to save command sets'


def _command_index(user_id):
    from . import command_manager

    try:
        commands = command_manager.get_all_commands(user_id)
    except (OSError, ValueError, TypeError) as exc:
        log_error('Error loading commands for command set', user_id=user_id, error=str(exc))
        return None, 'Command library is unreadable'
    index = {}
    for command in commands:
        if not isinstance(command, dict):
            continue
        command_id = command.get('id')
        command_text = command.get('command')
        if isinstance(command_id, str) and isinstance(command_text, str):
            index[command_id] = command
    return index, None


def _normalize_steps(steps, commands):
    if not isinstance(steps, list) or not steps:
        return None, None, 'Command set must contain at least one step'

    normalized_steps = []
    resolved_parts = []
    for position, raw_step in enumerate(steps, start=1):
        if not isinstance(raw_step, dict):
            return None, None, f'Command set step {position} has an invalid type'
        step_type = raw_step.get('type')
        if step_type == 'inline':
            command = raw_step.get('command')
            if not isinstance(command, str):
                return None, None, f'Command set step {position} is empty'
            normalized, error = normalize_startup_commands(command)
            if error:
                return None, None, error
            if not normalized.strip():
                return None, None, f'Command set step {position} is empty'
            normalized_steps.append({'type': 'inline', 'command': normalized})
            resolved_parts.append(normalized)
            continue

        if step_type == 'library':
            command_id = raw_step.get('command_id')
            if not isinstance(command_id, str) or command_id not in commands:
                return None, None, f'Command set step {position} references a missing command'
            command = commands[command_id]
            normalized_step = {'type': 'library', 'command_id': command_id}
            if 'parameters_override' in raw_step:
                override = raw_step['parameters_override']
                if override is not None and not isinstance(override, str):
                    return None, None, f'Command set step {position} has invalid parameters'
                if isinstance(override, str) and '\x00' in override:
                    return None, None, 'Commands cannot contain NUL bytes'
                normalized_step['parameters_override'] = override
            parameters = normalized_step.get('parameters_override')
            if parameters is None:
                parameters = command.get('parameters', '')
            if not isinstance(parameters, str):
                return None, None, f'Command set step {position} has invalid parameters'
            text = command['command'] + (f' {parameters}' if parameters else '')
            normalized_steps.append(normalized_step)
            resolved_parts.append(text)
            continue

        return None, None, f'Command set step {position} has an invalid type'

    _validated, error = normalize_startup_commands('\n'.join(resolved_parts))
    if error:
        return None, None, error
    return normalized_steps, resolved_parts, None


def _validate_payload(user_id, payload, existing_sets):
    if not isinstance(payload, dict):
        return None, 'Invalid command set data'
    name = payload.get('name')
    if not isinstance(name, str) or not name.strip():
        return None, 'Command set name is required'
    name = name.strip()
    if len(name) > COMMAND_SET_NAME_MAX:
        return None, 'Command set name must be 128 characters or fewer'
    description = payload.get('description', '')
    if not isinstance(description, str):
        return None, 'Command set description must be text'
    use_sudo = payload.get('use_sudo', False)
    if not isinstance(use_sudo, bool):
        return None, 'Command set sudo option must be a boolean'

    command_set_id = payload.get('id')
    if command_set_id is not None and not isinstance(command_set_id, str):
        return None, 'Invalid command set id'
    for existing in existing_sets:
        if existing.get('id') != command_set_id and str(existing.get('name', '')).casefold() == name.casefold():
            return None, 'A command set with this name already exists'

    commands, error = _command_index(user_id)
    if error:
        return None, error
    steps, _resolved_parts, error = _normalize_steps(payload.get('steps'), commands)
    if error:
        return None, error
    return {
        'id': command_set_id,
        'name': name,
        'description': description.strip(),
        'use_sudo': use_sudo,
        'steps': steps,
    }, None


def get_command_set(user_id, command_set_id):
    if not isinstance(command_set_id, str) or not command_set_id:
        return None, 'Command set not found'
    command_sets, error = load_command_sets(user_id)
    if error:
        return None, error
    for command_set in command_sets:
        if isinstance(command_set, dict) and command_set.get('id') == command_set_id:
            return copy.deepcopy(command_set), None
    return None, 'Command set not found'


def upsert_command_set(user_id, payload):
    """Create or update one command set under the per-user coordinator lock."""
    with storage_lock(f'command-config:{user_id}'):
        with storage_lock(f'command-sets:{user_id}'):
            command_sets, error = load_command_sets(user_id)
            if error:
                return None, error
            validated, error = _validate_payload(user_id, payload, command_sets)
            if error:
                return None, error

            now = datetime.now(timezone.utc).isoformat()
            command_set_id = validated.get('id')
            if command_set_id:
                for index, existing in enumerate(command_sets):
                    if existing.get('id') == command_set_id:
                        updated = {
                            **validated,
                            'created_at': existing.get('created_at', now),
                            'updated_at': now,
                        }
                        command_sets[index] = updated
                        break
                else:
                    return None, 'Command set not found'
                result = updated
            else:
                result = {
                    **validated,
                    'id': str(uuid.uuid4()),
                    'created_at': now,
                    'updated_at': now,
                }
                command_sets.append(result)

            saved, error = _save_command_sets(user_id, command_sets)
            return (copy.deepcopy(result), None) if saved else (None, error)


def duplicate_command_set(user_id, command_set_id):
    with storage_lock(f'command-config:{user_id}'):
        with storage_lock(f'command-sets:{user_id}'):
            command_sets, error = load_command_sets(user_id)
            if error:
                return None, error
            source = next((item for item in command_sets if item.get('id') == command_set_id), None)
            if not source:
                return None, 'Command set not found'
            existing_names = {str(item.get('name', '')).casefold() for item in command_sets}
            suffix = ' Copy'
            copy_number = 1
            while True:
                extra = suffix if copy_number == 1 else f'{suffix} {copy_number}'
                candidate = f"{source['name'][:COMMAND_SET_NAME_MAX - len(extra)]}{extra}"
                if candidate.casefold() not in existing_names:
                    break
                copy_number += 1
            now = datetime.now(timezone.utc).isoformat()
            duplicate = {
                'id': str(uuid.uuid4()),
                'name': candidate,
                'description': source.get('description', ''),
                'use_sudo': source.get('use_sudo') is True,
                'steps': copy.deepcopy(source.get('steps', [])),
                'created_at': now,
                'updated_at': now,
            }
            command_sets.append(duplicate)
            saved, error = _save_command_sets(user_id, command_sets)
            return (copy.deepcopy(duplicate), None) if saved else (None, error)


def resolve_command_set(user_id, command_set_id):
    command_set, error = get_command_set(user_id, command_set_id)
    if error:
        return None, error
    commands, error = _command_index(user_id)
    if error:
        return None, error
    _steps, resolved_parts, error = _normalize_steps(
        command_set.get('steps'), commands
    )
    if error:
        if 'step ' in error:
            return None, f"Command set '{command_set['name']}' {error.removeprefix('Command set ').lower()}"
        return None, error
    if command_set.get('use_sudo') is True:
        resolved_parts = [
            _prefix_commands_with_sudo(part) for part in resolved_parts
        ]
    resolved_parts = [
        _prepare_step_for_chaining(part) for part in resolved_parts
    ]
    resolved = ''.join(
        _append_step_separator(part) for part in resolved_parts[:-1]
    ) + resolved_parts[-1]
    resolved, error = normalize_startup_commands(resolved)
    if error:
        return None, error
    return resolved, None


def get_command_usage(user_id, command_id):
    command_sets, error = load_command_sets(user_id)
    if error:
        return None, error
    usages = []
    for command_set in command_sets:
        steps = command_set.get('steps', []) if isinstance(command_set, dict) else []
        if any(step.get('type') == 'library' and step.get('command_id') == command_id
               for step in steps if isinstance(step, dict)):
            usages.append({'id': command_set.get('id'), 'name': command_set.get('name', '')})
    return usages, None


def _load_profile_references(user_id):
    from . import profile_manager

    path = profile_manager.get_user_profiles_file(user_id)
    if path is None or not path.exists():
        return [], None
    try:
        data = json.loads(path.read_text(encoding='utf-8'))
        if not isinstance(data, dict) or not isinstance(data.get('profiles'), list):
            raise ValueError('invalid profile storage shape')
        return data['profiles'], None
    except (OSError, ValueError, TypeError) as exc:
        log_error('Error checking command set profile usage', user_id=user_id, error=str(exc))
        return None, 'Profile storage is unreadable'


def delete_command_set(user_id, command_set_id):
    with storage_lock(f'command-config:{user_id}'):
        profiles, error = _load_profile_references(user_id)
        if error:
            return False, error, []
        usages = [str(profile.get('name', '')) for profile in profiles
                  if isinstance(profile, dict) and profile.get('command_set_id') == command_set_id]
        if usages:
            noun = 'profile' if len(usages) == 1 else 'profiles'
            return False, f'Command set is used by {len(usages)} {noun}', usages

        with storage_lock(f'command-sets:{user_id}'):
            command_sets, error = load_command_sets(user_id)
            if error:
                return False, error, []
            remaining = [item for item in command_sets if item.get('id') != command_set_id]
            if len(remaining) == len(command_sets):
                return False, 'Command set not found', []
            saved, error = _save_command_sets(user_id, remaining)
            return saved, error, []
