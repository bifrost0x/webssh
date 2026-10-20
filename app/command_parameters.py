"""Bounded, explicit argument vectors for interactive command sets.

Only whole argument placeholders are supported. Shell source is never parsed or
expanded. Arguments still retain the chosen program's normal option semantics.
"""
import re
import shlex

from .startup_commands import normalize_startup_commands


_NAME = re.compile(r'[A-Za-z_][A-Za-z0-9_]{0,31}\Z', re.ASCII)
_PROGRAM = re.compile(r'[A-Za-z0-9_./+\-]{1,256}\Z', re.ASCII)
_PLACEHOLDER = re.compile(r'\{\{([A-Za-z_][A-Za-z0-9_]{0,31})\}\}\Z', re.ASCII)
_INTERPRETERS = re.compile(
    r'(?:sh|bash|dash|zsh|ksh|fish|csh|tcsh|eval|exec|source|\.|env|sudo|'
    r'busybox|command|nohup|xargs|python[0-9.]*|perl|ruby|node|php|powershell|pwsh)\Z',
    re.IGNORECASE,
)


def _safe_text(value, maximum):
    if not isinstance(value, str) or len(value) > maximum:
        return False
    if any(ord(char) < 32 or 127 <= ord(char) <= 159 for char in value):
        return False
    try:
        value.encode('utf-8')
    except UnicodeEncodeError:
        return False
    return True


def validate_parameter_set(command_set):
    """Validate declarations and literal argv templates without user values."""
    declarations = command_set.get('parameters')
    if not isinstance(declarations, list) or not 1 <= len(declarations) <= 20:
        return 'Declare between 1 and 20 command parameters'
    names = set()
    for item in declarations:
        name = item.get('name') if isinstance(item, dict) else None
        if not isinstance(name, str) or not _NAME.fullmatch(name) or name in names:
            return 'Parameter names must be unique identifiers of at most 32 characters'
        if set(item) != {'name'}:
            return 'Command parameter declarations only support a name'
        names.add(name)
    steps = command_set.get('steps')
    if not isinstance(steps, list) or not 1 <= len(steps) <= 50:
        return 'Parameterized command sets require between 1 and 50 argument steps'
    used = set()
    total = 0
    for step in steps:
        argv = step.get('argv') if isinstance(step, dict) else None
        if not isinstance(step, dict) or step.get('type') != 'argv' or not isinstance(argv, list) or not 1 <= len(argv) <= 64:
            return 'Parameterized command sets only support argument steps'
        if not all(_safe_text(arg, 1024) for arg in argv):
            return 'Command arguments must be text without control characters, at most 1024 characters each'
        program = argv[0]
        if not _PROGRAM.fullmatch(program) or _INTERPRETERS.fullmatch(program.rsplit('/', 1)[-1]):
            return 'Use a fixed program name; shell interpreters and execution wrappers are unsupported'
        for argument in argv[1:]:
            match = _PLACEHOLDER.fullmatch(argument)
            if match:
                name = match.group(1)
                if name not in names:
                    return 'Command argument references an undeclared parameter'
                used.add(name)
            elif '{{' in argument or '}}' in argument:
                return 'A parameter placeholder must occupy one whole argument'
        total += sum(len(arg) for arg in argv)
    if used != names:
        return 'Every declared command parameter must be used in an argument'
    if total > 4096:
        return 'Command argument templates must not exceed 4096 characters'
    return None


def resolve_parameters(command_set, values, use_sudo=False):
    """Return one POSIX command with every input quoted as one argument."""
    error = validate_parameter_set(command_set)
    if error:
        return None, error
    names = {item['name'] for item in command_set['parameters']}
    if not isinstance(values, dict) or set(values) != names:
        return None, 'Provide exactly the declared command parameter values'
    if not all(_safe_text(value, 1024) for value in values.values()):
        return None, 'Parameter values must be text without control characters, at most 1024 characters each'
    commands = []
    for step in command_set['steps']:
        arguments = []
        for argument in step['argv']:
            match = _PLACEHOLDER.fullmatch(argument)
            arguments.append(values[match.group(1)] if match else argument)
        # Quote the program too: quoted words cannot become shell keywords.
        program = "'" + arguments[0].replace("'", "'\"'\"'") + "'"
        text = ' '.join([program, *(shlex.quote(arg) for arg in arguments[1:])])
        if use_sudo or command_set.get('use_sudo') is True:
            text = 'sudo ' + text
        commands.append(text)
    resolved, error = normalize_startup_commands(' && '.join(commands))
    return (None, error) if error else (resolved, None)
