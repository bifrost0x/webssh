"""Oracle for the differential tests of internal/config.

Reads one JSON request per line from stdin and writes one JSON answer per
line. A request is either {"env": {...}} (import config.py with exactly
that environment), {"fn": name, "arg": str} (one Python primitive) or
{"dotenv": base64, "env": {...}} (load_dotenv on a file with that content,
as config.py calls it).
The repository root is the first argument.
"""

import contextlib
import io
import ipaddress
import json
import os
import pathlib
import sys
import tempfile
import urllib.parse

ROOT = sys.argv[1]
sys.path.insert(0, ROOT)

SKIP = {
    'BASE_DIR', 'USERS_DIR', 'KEYS_DIR', 'PROFILES_FILE', 'KEYS_FILE',
    'SYSTEM_COMMANDS_FILE', 'KNOWN_HOSTS_FILE', 'OIDC_HTTP_TIMEOUT',
    'ALLOWLISTABLE_INTERNAL_NETWORKS', 'BACKGROUND_WORKERS_MAX',
    'RUNTIME_SHUTDOWN_GRACE_SECONDS_MAX', 'SSH_CONNECT_TIMEOUT', 'CHUNK_SIZE',
    'SESSION_COOKIE_HTTPONLY', 'SESSION_COOKIE_SAMESITE',
    'PERMANENT_SESSION_LIFETIME', 'WTF_CSRF_TIME_LIMIT',
    'REMEMBER_COOKIE_HTTPONLY', 'REMEMBER_COOKIE_SAMESITE',
    'REMEMBER_COOKIE_SECURE', 'REMEMBER_COOKIE_DURATION',
    'MIN_PASSWORD_LENGTH', 'MAX_PASSWORD_LENGTH', 'MAX_USERNAME_LENGTH',
    'SOCKETIO_ASYNC_MODE', 'SOCKETIO_ASYNC_HANDLERS', 'SOCKETIO_PING_TIMEOUT',
    'SOCKETIO_PING_INTERVAL', 'SECURITY_CONFIG_WARNINGS',
    'EXPLICIT_ENVIRONMENT_KEYS', 'SECRET_KEY',
}


def norm(value):
    if isinstance(value, bool):
        return value
    if isinstance(value, int):
        return str(value)
    if isinstance(value, (str, pathlib.PurePath)):
        return str(value)
    if isinstance(value, (set, frozenset)):
        return {'$set': sorted(str(v) for v in value)}
    if isinstance(value, (list, tuple)):
        return [str(v) for v in value]
    return None


def import_config(env):
    os.environ.clear()
    os.environ.update(env)
    os.environ['PYTHON_DOTENV_DISABLED'] = '1'
    sys.modules.pop('config', None)
    tempfile.tempdir = None
    out, err = io.StringIO(), io.StringIO()
    answer = {}
    try:
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            import config  # noqa: PLC0415
    except Exception as exc:  # the oracle reports every failure
        answer['error'] = str(exc)
        answer['error_type'] = type(exc).__name__
    else:
        view = {}
        for name in dir(config):
            if not name.isupper() or name.startswith('_') or name in SKIP:
                continue
            v = norm(getattr(config, name))
            if v is not None:
                view[name] = v
        answer['view'] = view
        answer['security_warnings'] = list(config.SECURITY_CONFIG_WARNINGS)
        answer['secret_key'] = config.SECRET_KEY
        answer['explicit'] = sorted(config.EXPLICIT_ENVIRONMENT_KEYS - {'PYTHON_DOTENV_DISABLED'})
    answer['printed'] = [line for line in (out.getvalue() + err.getvalue()).splitlines() if line]
    return answer


def primitive(fn, arg):
    try:
        if fn == 'int':
            return str(int(arg))
        if fn == 'strip':
            return arg.strip()
        if fn == 'lower':
            return arg.lower()
        if fn == 'ip_address':
            return str(ipaddress.ip_address(arg))
        if fn == 'ip_network':
            return str(ipaddress.ip_network(arg, strict=True))
        if fn == 'repr':
            return repr(arg)
        if fn == 'path':
            return str(pathlib.PurePosixPath(arg))
        if fn == 'urlsplit':
            u = urllib.parse.urlsplit(arg)
            try:
                port = u.port
                port = -1 if port is None else port
            except ValueError:
                port = 'error'
            return [u.scheme, u.netloc, u.path, u.query, u.fragment,
                    u.hostname or '', u.username is not None, port]
        if fn == 'tailscale':
            import config  # noqa: PLC0415
            host, port = config.parse_tailscale_ssh_target(arg)
            return [host, port]
        if fn == 'remote_dns':
            import config  # noqa: PLC0415
            return list(config.parse_remote_dns_allowlist(arg, 'X'))
        if fn == 'internal_networks':
            import config  # noqa: PLC0415
            return [str(n) for n in config.parse_internal_network_allowlist(arg)]
        if fn == 'realpath':
            return os.path.realpath(arg)
    except (ValueError, RuntimeError, UnicodeError):
        return None
    raise SystemExit('unknown function ' + fn)


def load_dotenv_file(data, env):
    import base64  # noqa: PLC0415
    import logging  # noqa: PLC0415
    import re  # noqa: PLC0415

    import dotenv  # noqa: PLC0415

    lines = []

    class Collect(logging.Handler):
        def emit(self, record):
            m = re.search(r'line (\d+)', record.getMessage())
            lines.append(int(m.group(1)) if m else -1)

    log = logging.getLogger('dotenv.main')
    handler = Collect()
    log.addHandler(handler)
    log.propagate = False
    answer = {}
    with tempfile.TemporaryDirectory() as tmp:
        path = os.path.join(tmp, '.env')
        with open(path, 'wb') as f:
            f.write(base64.b64decode(data))
        os.environ.clear()
        os.environ.update(env)
        before = dict(os.environ)
        try:
            dotenv.load_dotenv(path)
        except Exception as exc:  # the oracle reports every failure
            answer['error'] = type(exc).__name__
        else:
            answer['set'] = [[k, v] for k, v in os.environ.items() if k not in before]
            changed = [k for k, v in before.items() if os.environ.get(k) != v]
            if changed:
                answer['changed'] = changed
    log.removeHandler(handler)
    answer['bad_lines'] = lines
    return answer


def main():
    base_env = dict(os.environ)
    for line in sys.stdin:
        req = json.loads(line)
        if 'dotenv' in req:
            answer = load_dotenv_file(req['dotenv'], req['env'])
            os.environ.clear()
            os.environ.update(base_env)
        elif 'env' in req:
            answer = import_config(req['env'])
        else:
            os.environ.clear()
            os.environ.update(base_env)
            os.environ.setdefault('SECRET_KEY', 'x' * 40)
            with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                answer = {'result': primitive(req['fn'], req['arg'])}
        sys.stdout.write(json.dumps(answer, ensure_ascii=True) + '\n')
        sys.stdout.flush()


if __name__ == '__main__':
    main()
