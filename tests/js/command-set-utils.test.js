const test = require('node:test');
const assert = require('node:assert/strict');

const { filterCommands, moveStep } = require('../../static/js/command-set-utils.js');

const commands = [
    {
        id: 'linux-update',
        name: 'Update packages',
        command: 'apt update',
        parameters: '-y',
        description: 'Refresh Debian repositories',
        category: 'system',
        os: ['linux'],
    },
    {
        id: 'network',
        name: 'Show interfaces',
        command: 'ip addr',
        parameters: '',
        description: 'Inspect network configuration',
        category: 'network',
        os: ['all'],
    },
    {
        id: 'windows-update',
        name: 'Windows updates',
        command: 'Get-WindowsUpdate',
        parameters: '-Install',
        description: 'Install operating system fixes',
        category: 'system',
        os: ['windows'],
    },
];

test('filterCommands searches every visible text field case-insensitively', () => {
    assert.deepEqual(filterCommands(commands, 'DEBIAN', 'all').map(c => c.id), ['linux-update']);
    assert.deepEqual(filterCommands(commands, 'apt update', 'all').map(c => c.id), ['linux-update']);
    assert.deepEqual(filterCommands(commands, '-install', 'all').map(c => c.id), ['windows-update']);
    assert.deepEqual(filterCommands(commands, 'network', 'all').map(c => c.id), ['network']);
    assert.deepEqual(filterCommands(commands, 'system', 'all').map(c => c.id), [
        'linux-update', 'windows-update',
    ]);
});

test('filterCommands combines OS filtering with full-text search', () => {
    assert.deepEqual(filterCommands(commands, '', 'linux').map(c => c.id), [
        'linux-update', 'network',
    ]);
    assert.deepEqual(filterCommands(commands, 'update', 'windows').map(c => c.id), [
        'windows-update',
    ]);
    assert.deepEqual(filterCommands(commands, 'interfaces', 'macos').map(c => c.id), [
        'network',
    ]);
});

test('filterCommands tolerates incomplete command records and input', () => {
    assert.deepEqual(filterCommands([{}, null], null, null), [{}]);
});

test('moveStep returns a reordered copy without mutating the source', () => {
    const source = [{ id: 'a' }, { id: 'b' }, { id: 'c' }];
    const moved = moveStep(source, 0, 2);

    assert.deepEqual(moved.map(step => step.id), ['b', 'c', 'a']);
    assert.deepEqual(source.map(step => step.id), ['a', 'b', 'c']);
});

test('moveStep clamps destinations and ignores invalid sources', () => {
    const source = ['a', 'b', 'c'];
    assert.deepEqual(moveStep(source, 1, 99), ['a', 'c', 'b']);
    assert.deepEqual(moveStep(source, 2, -10), ['c', 'a', 'b']);
    assert.deepEqual(moveStep(source, 9, 0), source);
    assert.notEqual(moveStep(source, 9, 0), source);
});
