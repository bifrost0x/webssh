"""Build the legacy part of the golden data set (``fixture/legacy``).

Usage, from the repository root inside the project virtualenv, after
``python -m tests.golden.generate``::

    git worktree add --detach /tmp/webssh-oldver v1.0.0
    python -m tests.golden.legacy.build --worktree /tmp/webssh-oldver \\
        --python 2fcd38a=/tmp/venv-2fcd38a/bin/python \\
        --python v1.0.0=/tmp/venv-v1.0.0/bin/python \\
        --python 8c41517=/tmp/venv-8c41517/bin/python
    git worktree remove /tmp/webssh-oldver

Each virtualenv holds the requirements of that revision (see the legacy
manifest ``releases``). The worktree is checked out at each revision in turn.
The 3.3.x part (extended DATA_DIR, backups, variants) runs in this process.
"""

import argparse
import datetime as dt
import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

from .. import runtime
from ..determinism import Clock, deterministic
from ..packing import extract_data_dir, pack_data_dir

OUT = runtime.FIXTURE_ROOT / 'legacy'
STAGES = (('initial', '2fcd38a'), ('v1.0.0', 'v1.0.0'), ('backup_v1', '8c41517'))
SEED = 'webssh-golden-extended-v1'
START = dt.datetime(2026, 11, 2, 10, 0, 0, tzinfo=dt.timezone.utc)
_DRIVER = Path(__file__).resolve().parent / 'old_driver.py'
_PACKAGES = "import importlib.metadata as m, json, platform; print(json.dumps({'python': platform.python_version(), 'packages': dict(sorted((d.metadata['Name'].lower(), d.version) for d in m.distributions()))}))"


def _git(worktree, *args):
    return subprocess.run(['git', '-C', str(worktree), *args], check=True,
                          capture_output=True, text=True).stdout.strip()


def _old_environment(python, worktree, data_dir, work):
    return {'PATH': f'{Path(python).parent}:/usr/bin:/bin', 'HOME': str(work),
            'PYTHONHASHSEED': '0', 'TZ': 'UTC', 'PYTHONDONTWRITEBYTECODE': '1',
            'PYTHONPATH': str(worktree), 'SECRET_KEY': runtime.secret_key(),
            'DATA_DIR': str(data_dir), 'DEBUG': 'false',
            'BACKUP_TEMP_DIR': str(work / 'backup-work'),
            'TRANSFER_TEMP_DIR': str(work / 'transfers'),
            'SESSION_COOKIE_SECURE': 'false', 'RATELIMIT_STORAGE_URL': 'memory://'}


def _run_stage(stage, revision, python, worktree, data_dir, work, extra=()):
    _git(worktree, 'checkout', '--quiet', '--detach', revision)
    environment = _old_environment(python, worktree, data_dir, work)
    facts_path = work / f'{stage}.json'
    subprocess.run([python, str(_DRIVER), stage, str(data_dir), str(facts_path), *extra],
                   cwd=worktree, env=environment, check=True, stdout=subprocess.DEVNULL)
    info = json.loads(subprocess.run([python, '-c', _PACKAGES], env=environment,
                                     check=True, capture_output=True, text=True).stdout)
    info.update(revision=revision, commit=_git(worktree, 'rev-parse', 'HEAD'),
                committed_at=_git(worktree, 'log', '-1', '--format=%cI'))
    return json.loads(facts_path.read_text(encoding='utf-8')), info


def old_releases(worktree, pythons, work):
    data_dir = work / 'old' / 'data'
    data_dir.mkdir(parents=True, mode=0o700)
    result, releases = {}, {}
    out = work / 'out'
    stage, revision = STAGES[0]
    result[stage], releases[stage] = _run_stage(stage, revision, pythons[revision], worktree, data_dir, work)
    pack_data_dir(data_dir, out / 'datadir-2fcd38a.tar')
    # v1.0.0 entrypoint.sh: mkdir -p /app/data/logs /app/data/keys; chmod 700.
    for name in ('logs', 'keys'):
        (data_dir / name).mkdir(mode=0o700, exist_ok=True)
    stage, revision = STAGES[1]
    result[stage], releases[stage] = _run_stage(stage, revision, pythons[revision], worktree, data_dir, work)
    pack_data_dir(data_dir, out / 'datadir-v1.0.0.tar')
    copy = work / 'old-backup' / 'data'
    shutil.copytree(data_dir, copy, symlinks=True)
    stage, revision = STAGES[2]
    (out / 'backups').mkdir(parents=True, exist_ok=True)
    result[stage], releases[stage] = _run_stage(
        stage, revision, pythons[revision], worktree, copy, work,
        extra=(str(out / 'backups' / 'backup-v1-8c41517.zip'),))
    return result, releases


def _main_values():
    return json.loads((runtime.FIXTURE_ROOT / 'manifest.json').read_text(encoding='utf-8'))['values']


def extended(work, clock):
    from . import extend, variants
    values = _main_values()
    users = values['users']
    data_dir = extract_data_dir(runtime.FIXTURE_ROOT / runtime.DATA_ARCHIVE, work / 'ext')
    runtime.apply_environment(runtime.environment(data_dir, work / 'ext'))
    runtime.import_application_modules()
    key = next(i for i in values['ssh_keys']['stored'] if i['label'] == 'ed25519-openssh')
    import base64
    key_content = base64.b64decode(key['plaintext_b64']).decode()
    deleted_id = values['edge_cases']['deleted_account']['former_id']
    deleted_incarnation = (dt.datetime.fromisoformat(users['jörg_ünïcødé']['created_at_db'])
                           - dt.timedelta(seconds=1)).isoformat()
    owner = users['local_user']['id']
    facts = {}
    with deterministic(SEED, clock, bcrypt_rounds=runtime.BCRYPT_ROUNDS) as stream:
        application = runtime.create_application()
        with application.app_context():
            profile_ids = [p['id'] for p in values['connections']['profiles'].values()]
            facts['account_settings'] = extend.account_settings(owner, sorted(profile_ids))
            clock.advance(seconds=10)
            uid, facts['legacy_stores'], vault_profile = extend.legacy_store_versions(key_content)
            facts['vault_v1'] = extend.vault_version_1(uid, vault_profile, stream)
            clock.advance(seconds=10)
            facts['profiles_schema_2'] = extend.profiles_schema_2(clock)
            clock.advance(seconds=10)
            facts['created_at'] = extend.created_at_accounts()
            clock.advance(seconds=10)
            facts['schedules'] = extend.schedules(owner, deleted_id, deleted_incarnation, clock)
            facts['orphan_host_context'] = extend.orphan_host_context(
                owner, values['commands']['command_sets'][0]['id'])
            facts['persistent_sessions'] = extend.persistent_sessions(owner, stream)
            ca_line = '@cert-authority *.ca.golden.test ' + ' '.join(
                values['host_keys']['global_lines'][0].split()[1:3])
            facts['trust_and_fences'] = extend.global_trust_and_fences(
                application, users['ldap_user']['id'], ca_line)
            facts['restore_status'] = variants.restore_status_templates()
            # Last: any later key read would already reconcile the staged files.
            facts['interrupted_key_deletions'] = extend.interrupted_key_deletions(owner, key_content)
        runtime.shutdown(application)
        facts['database_objects'] = extend.database_objects(data_dir / 'app.db')
        facts['legacy_single_user_paths'] = extend.legacy_single_user_paths(data_dir, key_content)
        facts['deleted_account_incarnation'] = deleted_incarnation
        clock.advance(minutes=1)
        facts['backups'] = variants.backups(data_dir, work / 'out' / 'backups')
        facts['variants'] = variants.variants(data_dir)
    pack_data_dir(data_dir, work / 'out' / 'datadir-extended.tar')
    return facts


def _ensure_fixed_hash_seed(argv):
    if os.environ.get('PYTHONHASHSEED') == '0':
        return
    arguments = sys.argv[1:] if argv is None else list(argv)
    os.execve(sys.executable, [sys.executable, '-m', 'tests.golden.legacy.build', *arguments],
              dict(os.environ, PYTHONHASHSEED='0'))


def main(argv=None):
    _ensure_fixed_hash_seed(argv)
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument('--worktree', type=Path, required=True)
    parser.add_argument('--python', action='append', default=[], metavar='REV=PATH')
    parser.add_argument('--out', type=Path, default=OUT)
    args = parser.parse_args(argv)
    pythons = dict(item.split('=', 1) for item in args.python)
    missing = {revision for _stage, revision in STAGES} - set(pythons)
    if missing:
        raise SystemExit(f'missing --python for {sorted(missing)}')
    from .manifest import write_manifest
    with tempfile.TemporaryDirectory(prefix='webssh-golden-legacy-') as work:
        work = Path(work)
        (work / 'out').mkdir()
        old, releases = old_releases(args.worktree.resolve(), pythons, work)
        facts = extended(work, Clock(START))
        write_manifest(work / 'out', old, releases, facts)
        out = args.out.resolve()
        if out.exists():
            if not (out / 'manifest.json').is_file():
                raise SystemExit(f'refusing to replace {out}: not a legacy output')
            shutil.rmtree(out)
        shutil.copytree(work / 'out', out)
    return 0


if __name__ == '__main__':
    sys.exit(main())
