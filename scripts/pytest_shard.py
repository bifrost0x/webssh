"""Opt-in, complete file-level CI partitions: -p scripts.pytest_shard --ci-shard=1/3.

Largest files are assigned first to the least populated partition. Counts come
from the current collection, so new tests need no manifest updates. Whole files
stay together to preserve module/class fixture locality with xdist loadscope.
"""

from collections import defaultdict
import re

import pytest


def partition_nodeids(nodeids, shard_count):
    """Return deterministic, disjoint partitions preserving collection order."""
    if shard_count < 1:
        raise ValueError('ci-shard count must be positive')
    files = defaultdict(list)
    seen = set()
    for nodeid in nodeids:
        if not nodeid or nodeid in seen:
            raise ValueError('ci-shard requires nonempty, unique collected node IDs')
        seen.add(nodeid)
        files[nodeid.split('::', 1)[0]].append(nodeid)
    if len(files) < shard_count:
        raise ValueError('ci-shard would produce an empty partition; reduce shard count')
    sizes = [0] * shard_count
    assignments = {}
    for filename in sorted(files, key=lambda name: (-len(files[name]), name)):
        shard = min(range(shard_count), key=lambda index: (sizes[index], index))
        assignments[filename] = shard
        sizes[shard] += len(files[filename])
    partitions = [[] for _ in range(shard_count)]
    for nodeid in nodeids:
        partitions[assignments[nodeid.split('::', 1)[0]]].append(nodeid)
    return partitions


def pytest_addoption(parser):
    parser.getgroup('CI').addoption(
        '--ci-shard', metavar='INDEX/TOTAL', default=None,
        help='Run one deterministic file partition (1-based); all partitions are required.',
    )


def pytest_configure(config):
    value = config.getoption('--ci-shard')
    config._ci_shard = None
    config._ci_shard_counts = None
    if value is None:
        return
    match = re.fullmatch(r'([1-9][0-9]*)/([1-9][0-9]*)', value)
    if not match:
        raise pytest.UsageError('--ci-shard must be INDEX/TOTAL with 1 <= INDEX <= TOTAL')
    index, total = map(int, match.groups())
    if index > total:
        raise pytest.UsageError('--ci-shard requires 1 <= INDEX <= TOTAL')
    config._ci_shard = (index, total)


@pytest.hookimpl(trylast=True)
def pytest_collection_modifyitems(config, items):
    if config._ci_shard is None:
        return
    index, total = config._ci_shard
    try:
        partitions = partition_nodeids([item.nodeid for item in items], total)
    except ValueError as error:
        raise pytest.UsageError(str(error)) from error
    selected = set(partitions[index - 1])
    config._ci_shard_counts = (len(selected), len(items))
    deselected = [item for item in items if item.nodeid not in selected]
    items[:] = [item for item in items if item.nodeid in selected]
    config.hook.pytest_deselected(items=deselected)


def pytest_sessionfinish(session):
    config = session.config
    if hasattr(config, 'workeroutput'):
        config.workeroutput['ci_shard_counts'] = config._ci_shard_counts


@pytest.hookimpl(optionalhook=True)
def pytest_testnodedown(node, error):
    counts = node.workeroutput.get('ci_shard_counts')
    if counts is not None:
        node.config._ci_shard_counts = counts


def pytest_terminal_summary(terminalreporter, config):
    if config._ci_shard is not None and config._ci_shard_counts is not None:
        index, total = config._ci_shard
        selected, collected = config._ci_shard_counts
        terminalreporter.write_line(
            f'CI shard {index}/{total}: selected {selected} of {collected} collected tests'
        )
