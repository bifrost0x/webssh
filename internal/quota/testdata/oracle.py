"""Answer quota questions with app/quota_manager.py and app/storage_quota.py.

The Go tests start this script with the repository's virtual environment and
send one JSON request per line; each answer is one JSON line. The modules run
unchanged; only the configuration module they import is replaced by the
defaults of the Python release.

    {"op": "limits", "limits": {"transfer": [8, 2], ...}}
    {"op": "sequence", "limits": {...}, "steps": [["reserve", "transfer", 1, 1], ["release", 0]]}
    {"op": "bounded", "value": "abc", "max": 2, "legacy": null}
"""
import importlib.util
import json
import sys
import types

ROOT = sys.argv[1]

config = types.ModuleType('config')
for kind, (g, p) in {'SSH_SESSION': (10, 5), 'QUICK_CONNECTION': (12, 3), 'TRANSFER': (8, 2),
                     'TEMP_BYTES': (1 << 30, 512 << 20), 'BACKGROUND_JOB': (4, 1)}.items():
    setattr(config, f'QUOTA_{kind}_GLOBAL', g)
    setattr(config, f'QUOTA_{kind}_PER_USER', p)
sys.modules['config'] = config
package = types.ModuleType('app')
package.__path__ = [ROOT + '/app']
sys.modules['app'] = package


def load(name):
    spec = importlib.util.spec_from_file_location('app.' + name, f'{ROOT}/app/{name}.py')
    module = importlib.util.module_from_spec(spec)
    sys.modules['app.' + name] = module
    spec.loader.exec_module(module)
    return module


qm = load('quota_manager')
sq = load('storage_quota')


class StorageError(Exception):
    pass


def manager(limits):
    return qm.QuotaManager({qm.QuotaKind(k): {'global': g, 'per_user': p} for k, (g, p) in limits.items()})


def answer(req):
    op = req['op']
    if op == 'limits':
        try:
            manager(req['limits'])
            return {'ok': True}
        except ValueError as error:
            return {'ok': False, 'error': str(error)}
    if op == 'sequence':
        m = manager(req['limits'])
        held, out = [], []
        for step in req['steps']:
            if step[0] == 'reserve':
                try:
                    held.append(m.reserve(qm.QuotaKind(step[1]), step[2], step[3]))
                    out.append('ok')
                except qm.QuotaExceeded as error:
                    held.append(None)
                    out.append(str(error))
            else:
                if held[step[1]] is not None:
                    held[step[1]].release()
                out.append('released')
        return {'ok': True, 'results': out}
    try:
        sq.bounded_text(req.get('value', ''), req.get('max', 0), 'value', req.get('legacy'), error=StorageError)
        return {'ok': True}
    except StorageError as error:
        return {'ok': False, 'error': str(error)}


for line in sys.stdin:
    print(json.dumps(answer(json.loads(line))), flush=True)
