"""Coverage and failure contracts for the opt-in CI test partition."""

import json
import os
from pathlib import Path
import subprocess
import sys

import pytest


def test_partition_is_complete_disjoint_balanced_and_order_independent():
    from scripts.pytest_shard import partition_nodeids

    nodeids = [
        f'test_{file}.py::test_case[{case}]'
        for file, count in [('a', 7), ('b', 5), ('c', 3), ('d', 2), ('new', 1)]
        for case in range(count)
    ]
    shards = partition_nodeids(nodeids, 3)
    assert sorted(item for shard in shards for item in shard) == sorted(nodeids)
    assert [len(shard) for shard in shards] == [7, 6, 5]
    assert [set(shard) for shard in shards] == [
        set(shard) for shard in partition_nodeids(list(reversed(nodeids)), 3)
    ]
    for file in ['a', 'b', 'c', 'd', 'new']:
        assert sum(any(item.startswith(f'test_{file}.py::') for item in shard)
                   for shard in shards) == 1


@pytest.mark.parametrize('nodeids,count', [
    ([], 1), (['test_a.py::test_one'], 2),
    (['test_a.py::test_one'] * 2, 1), ([''], 1),
    (['test_a.py::test_one'], 0),
])
def test_partition_rejects_ambiguous_or_empty_coverage(nodeids, count):
    from scripts.pytest_shard import partition_nodeids

    with pytest.raises(ValueError):
        partition_nodeids(nodeids, count)


def _run_pytest(directory, *arguments):
    environment = os.environ.copy()
    root = str(Path(__file__).resolve().parents[1])
    environment['PYTHONPATH'] = root
    environment['PYTEST_DISABLE_PLUGIN_AUTOLOAD'] = '1'
    return subprocess.run(
        [sys.executable, '-m', 'pytest', '-p', 'scripts.pytest_shard',
         '-p', 'xdist.plugin', '-q', '--basetemp', str(directory / 'temp'),
         *arguments],
        cwd=directory, env=environment, text=True, capture_output=True,
        timeout=45, check=False,
    )


def test_real_pytest_shards_execute_every_test_once_and_preserve_failure(tmp_path):
    log = tmp_path / 'executed.jsonl'
    for file in range(3):
        (tmp_path / f'test_{file}.py').write_text(
            'import json\nfrom pathlib import Path\nimport pytest\n'
            '@pytest.mark.parametrize("case", [0, 1])\n'
            'def test_case(case):\n'
            f'    with Path({str(log)!r}).open("a") as output:\n'
            f'        output.write(json.dumps([{file}, case]) + "\\n")\n'
            f'    assert ({file}, case) != (1, 1)\n',
            encoding='utf-8',
        )
    results = [_run_pytest(tmp_path, f'--ci-shard={shard}/3', '-n', '2',
                           '--dist=loadscope') for shard in range(1, 4)]
    assert sorted(result.returncode for result in results) == [0, 0, 1], '\n'.join(
        result.stdout + result.stderr for result in results
    )
    assert sorted(json.loads(line) for line in log.read_text().splitlines()) == [
        [file, case] for file in range(3) for case in range(2)
    ]
    for shard, result in enumerate(results, 1):
        assert f'CI shard {shard}/3: selected 2 of 6 collected tests' in result.stdout
    log.unlink()
    default = _run_pytest(tmp_path)
    assert default.returncode == 1
    assert len(log.read_text().splitlines()) == 6
    assert 'CI shard' not in default.stdout


@pytest.mark.parametrize('value', ['0/3', '4/3', '1/0', '1', '1/2/3', '', '1/-2'])
def test_real_pytest_rejects_invalid_shard_option(tmp_path, value):
    result = _run_pytest(tmp_path, f'--ci-shard={value}')
    assert result.returncode == pytest.ExitCode.USAGE_ERROR
    assert 'ci-shard' in result.stderr


def test_real_pytest_rejects_empty_shard(tmp_path):
    (tmp_path / 'test_only.py').write_text('def test_one(): pass\n')
    result = _run_pytest(tmp_path, '--ci-shard=2/3')
    assert result.returncode == pytest.ExitCode.USAGE_ERROR
    assert 'empty' in result.stderr.lower()


def test_real_pytest_collection_reports_only_selected_nodeids(tmp_path):
    for file in ['a', 'b']:
        (tmp_path / f'test_{file}.py').write_text('def test_one(): pass\n')
    result = _run_pytest(tmp_path, '--ci-shard=1/2', '--collect-only')
    assert result.returncode == 0
    assert 'test_a.py::test_one' in result.stdout
    assert 'test_b.py::test_one' not in result.stdout
    assert '1 deselected' in result.stdout
    assert 'CI shard 1/2: selected 1 of 2 collected tests' in result.stdout
