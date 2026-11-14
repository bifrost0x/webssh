const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const Tools = require('../../static/js/automation-tools.js');

test('results are grouped per step by status, exit code and output', () => {
    const step = (stdout, exit_code = 0, status = 'succeeded') => ({name: 'Version', stdout, stderr: '', exit_code, status});
    const run = {targets: [
        {name: 'a', steps: [step('3.0.13\n')]}, {name: 'b', steps: [step('3.0.13')]},
        {name: 'c', steps: [step('3.0.2\n')]}, {name: 'd', steps: [step('', 1, 'failed')]},
        {name: 'e', steps: []},
    ]};
    const result = Tools.compareRun(run);
    assert.equal(result.hostCount, 5);
    assert.equal(result.steps.length, 1);
    const [first, ...rest] = result.steps[0].groups;
    assert.deepEqual(first.hosts, ['a', 'b']);
    assert.equal(first.output, '3.0.13');
    assert.deepEqual(rest.map(group => group.hosts), [['c'], ['d']]);
    assert.equal(result.steps[0].uniform, false);
    // Legacy runs without captured output still group by status and exit code.
    const legacy = Tools.compareRun({targets: [{name: 'x', steps: [{status: 'succeeded', exit_code: 0}]},
        {name: 'y', steps: [{status: 'succeeded', exit_code: 0}]}]});
    assert.equal(legacy.steps[0].uniform, true);
    assert.equal(legacy.steps[0].groups[0].output, null);
    assert.deepEqual(Tools.compareRun(null), {hostCount: 0, steps: []});
});

test('stderr splits groups and truncated output is never reported as uniform', () => {
    const base = {name: 'Check', status: 'succeeded', exit_code: 0, stdout: 'same'};
    const split = Tools.compareRun({targets: [{name: 'a', steps: [{...base, stderr: ''}]}, {name: 'b', steps: [{...base, stderr: 'warning: disk'}]}]});
    assert.equal(split.steps[0].groups.length, 2);
    assert.equal(split.steps[0].groups[1].errors, 'warning: disk');
    const cut = Tools.compareRun({targets: [{name: 'a', steps: [{...base, stderr: '', output_truncated: true}]}, {name: 'b', steps: [{...base, stderr: ''}]}]});
    assert.equal(cut.steps[0].groups.length, 1);
    assert.equal(cut.steps[0].uniform, false);
});

test('the maintenance template runs exactly the probe the server parses', () => {
    const Templates = require('../../static/js/automation-templates.js');
    const source = fs.readFileSync(path.join(__dirname, '../../app/host_platform.py'), 'utf8').replace(/\r\n/g, '\n');
    const start = source.indexOf("MAINTENANCE_COMMAND = r'''") + "MAINTENANCE_COMMAND = r'''".length;
    const probe = source.slice(start, source.indexOf("'''", start));
    assert.ok(probe.startsWith('LC_ALL=C\n'));
    assert.equal(Templates.MAINTENANCE_COMMAND, probe);
    const template = Templates.create('maintenance');
    assert.equal(template.writes, false);
    assert.equal(template.steps.at(-1).command, probe);
    assert.equal(template.steps.at(-1).sudo, false);
});
