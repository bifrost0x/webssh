"""Answer cron questions with app/automation_cron.py of the Python release.

The Go tests start this script with the venv of the Python release and
send one JSON request per line; each answer is one JSON line. The module runs
unchanged; only its import of AutomationError is replaced, so the oracle needs
neither Flask nor a database.

    {"op": "parse", "expr": "*/5 * * * *", "zone": "UTC"}
    {"op": "next", "expr": "...", "zone": "...", "after": 1700000000, "after_us": 0, "n": 3}
"""
import importlib.util
import json
import sys
import types
from datetime import datetime, timedelta, timezone

ROOT = sys.argv[1]
if len(sys.argv) > 2:
    # A pinned zone database in place of the system's (zonedb_test.go).
    import zoneinfo
    zoneinfo.reset_tzpath(sys.argv[2:])


class AutomationError(Exception):
    pass


package = types.ModuleType('app')
package.__path__ = [ROOT + '/app']
sys.modules['app'] = package
store = types.ModuleType('app.automation_store')
store.AutomationError = AutomationError
sys.modules['app.automation_store'] = store
spec = importlib.util.spec_from_file_location('app.automation_cron', ROOT + '/app/automation_cron.py')
cron = importlib.util.module_from_spec(spec)
sys.modules['app.automation_cron'] = cron
spec.loader.exec_module(cron)

EPOCH = datetime(1970, 1, 1, tzinfo=timezone.utc)


def answer(req):
    try:
        if req['op'] == 'parse':
            cron.parse(req['expr'], req['zone'])
            return {'ok': True}
        after = EPOCH + timedelta(seconds=req['after'], microseconds=req.get('after_us', 0))
        runs = []
        for _ in range(req.get('n', 1)):
            after = cron.next_due(req['expr'], req['zone'], after)
            runs.append((after - EPOCH) // timedelta(seconds=1))
        return {'ok': True, 'runs': runs}
    except AutomationError as error:
        return {'ok': False, 'error': str(error), 'runs': locals().get('runs', [])}
    except Exception as error:  # a crash of the Python release, reported as such
        return {'ok': False, 'error': 'crash:' + type(error).__name__, 'runs': locals().get('runs', [])}


for line in sys.stdin:
    print(json.dumps(answer(json.loads(line))), flush=True)
