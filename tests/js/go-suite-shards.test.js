const assert = require('node:assert/strict');
const {spawnSync} = require('node:child_process');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');
const {plan, choose, shardOptions} = require('../e2e/run-go-suite.js');
const {assign, phases, weigh} = require('../e2e/go-suite-shards.js');
const tiers = require('../e2e/go-suite-tiers.js');
const {summarize, format, testsOf} = require('../e2e/go-suite-report.js');
const {refresh, specSeconds} = require('../../scripts/refresh-go-suite-timing.js');

const ROOT = path.join(__dirname, '..', '..');
const suite = JSON.parse(fs.readFileSync(path.join(__dirname, '../e2e/go-suite.json'), 'utf8'));
const tierFile = JSON.parse(fs.readFileSync(path.join(__dirname, '../e2e/go-suite-tiers.json'), 'utf8'));
const timing = JSON.parse(fs.readFileSync(path.join(__dirname, '../e2e/go-suite-timing.json'), 'utf8'));
const exists = file => fs.existsSync(path.join(__dirname, '../e2e', file));
const suiteNames = suite.specs.map(spec => spec.file);
const file = name => path.join('tests', 'e2e', name);

test('every planned spec lands in exactly one shard and the shards are balanced', () => {
    const planned = plan(suite, new Set(Object.keys(suite.requires)), exists);
    for (const count of [1, 2, 4, 6, 8]) {
        const shards = assign(planned.all, count, timing);
        assert.equal(shards.length, count);
        const all = shards.flatMap(shard => shard.files);
        assert.deepEqual([...all].sort(), [...planned.all].sort());
        const loads = shards.map(shard => shard.seconds);
        const heaviest = Math.max(...weigh(planned.all, timing).values());
        // Greedy longest-first stays within one spec of the ideal split.
        assert.ok(Math.max(...loads) - Math.min(...loads) <= heaviest, `${count}: ${loads}`);
        // Files keep the plan's order inside a shard.
        for (const shard of shards) {
            const order = shard.files.map(name => planned.all.indexOf(name));
            assert.deepEqual(order, [...order].sort((left, right) => left - right));
        }
    }
    assert.deepEqual(assign(planned.all, 4, timing), assign(planned.all, 4, timing));
});

test('shards follow the measured weights and give unknown specs the median', () => {
    const weights = {specs: {'a.spec.js': 100, 'b.spec.js': 60, 'c.spec.js': 50, 'd.spec.js': 10}};
    const files = ['a', 'b', 'c', 'd', 'new'].map(name => file(`${name}.spec.js`));
    assert.equal(weigh(files, weights).get(file('new.spec.js')), 55);
    const shards = assign(files, 2, weights);
    assert.deepEqual(shards.map(shard => shard.seconds), [150, 125]);
    assert.deepEqual(shards[0].files, [file('a.spec.js'), file('c.spec.js')]);
    // Fewer files than shards: no empty shard.
    assert.equal(assign(files.slice(0, 2), 8, weights).length, 2);
    assert.throws(() => assign(files, 0, weights), /positive/);
    assert.throws(() => assign([], 2, weights), /no spec files/);
    assert.throws(() => weigh(files, {specs: {'a.spec.js': -1}}), /invalid duration/);
});

test('--shard i/N picks one shard of the same split', () => {
    assert.deepEqual(shardOptions(4, undefined), {count: 4, current: null});
    assert.deepEqual(shardOptions(1, '3/8'), {count: 8, current: 3});
    assert.deepEqual(shardOptions(8, '8/8'), {count: 8, current: 8});
    for (const value of ['0/8', '9/8', '3', 'a/b', '3/8/1']) assert.throws(() => shardOptions(1, value), /index/, value);
    assert.throws(() => shardOptions(4, '1/8'), /disagree/);
});

test('serial specs run after the others on one worker within a shard', () => {
    const files = ['a', 'b', 'c'].map(name => file(`${name}.spec.js`));
    assert.deepEqual(phases(files, [files[1]], 1), [{name: 'all', files, workers: 1}]);
    assert.deepEqual(phases(files, [files[1]], 3), [
        {name: 'parallel', files: [files[0], files[2]], workers: 3},
        {name: 'serial', files: [files[1]], workers: 1},
    ]);
    assert.deepEqual(phases([files[1]], [files[1]], 3), [{name: 'all', files: [files[1]], workers: 1}]);
    assert.deepEqual(phases(files, [], 3), [{name: 'all', files, workers: 3}]);
});

test('go-suite-timing.json measures the suite and names no unknown spec', () => {
    const unknown = Object.keys(timing.specs).filter(name => !suiteNames.includes(name));
    assert.deepEqual(unknown, []);
    // A handful of new specs may wait for the next refresh, most must be measured.
    assert.ok(Object.keys(timing.specs).length >= suiteNames.length * 0.9);
});

test('go-suite-tiers.json is valid and every path pattern still matches a file', () => {
    tiers.validate(tierFile, suiteNames);
    const tracked = spawnSync('git', ['ls-files'], {cwd: ROOT, encoding: 'utf8'}).stdout.split('\n').filter(Boolean);
    if (!tracked.length) return; // not a git checkout
    for (const area of tierFile.areas) {
        for (const glob of area.paths) assert.ok(tracked.some(name => tiers.matches(glob, name)), `${area.name}: ${glob}`);
    }
    const invalid = [
        {smoke: [{file: 'missing.spec.js', reason: 'r'}], areas: []},
        {smoke: [{file: 'mfa.spec.js', reason: ' '}], areas: []},
        {smoke: [{file: 'mfa.spec.js', reason: 'r'}, {file: 'mfa.spec.js', reason: 'r'}], areas: []},
        {smoke: [], areas: [{name: 'x', paths: ['a/**'], specs: ['nothing-*.spec.js']}]},
        {smoke: [], areas: [{name: 'x', paths: [], specs: ['mfa.spec.js']}]},
    ];
    for (const entry of invalid) assert.throws(() => tiers.validate(entry, suiteNames), undefined, JSON.stringify(entry));
});

test('globs keep * inside one path segment', () => {
    assert.ok(tiers.matches('static/js/file-*.js', 'static/js/file-preview.js'));
    assert.ok(!tiers.matches('static/js/file-*.js', 'static/js/i18n/file-x.js'));
    assert.ok(tiers.matches('internal/auth/**', 'internal/auth/webauthn/ceremony.go'));
    assert.ok(tiers.matches('static/js/i18n/**', 'static/js/i18n/de.json'));
    assert.ok(!tiers.matches('internal/auth/**', 'internal/authz/x.go'));
    assert.ok(!tiers.matches('a.b', 'aXb'));
});

test('the smoke tier is the curated list, narrowed to what the run enables', () => {
    const all = plan(suite, new Set(Object.keys(suite.requires)), exists);
    const smoke = choose(all, {tier: 'smoke'}, {tierFile, suiteNames}).planned;
    assert.deepEqual(smoke.all.map(name => path.basename(name)).sort(), tierFile.smoke.map(entry => entry.file).sort());
    assert.equal(smoke.parallel.length + smoke.serial.length, smoke.all.length);
    assert.deepEqual(smoke.excluded, all.excluded);
    // Without passkeys the passkey spec drops out instead of failing.
    const none = plan(suite, new Set(), exists);
    const reduced = choose(none, {tier: 'smoke'}, {tierFile, suiteNames}).planned;
    assert.ok(!reduced.all.includes(file('webauthn.spec.js')));
    assert.equal(choose(all, {}, {tierFile, suiteNames}).planned, all);
    assert.equal(choose(all, {tier: 'full'}, {tierFile, suiteNames}).planned, all);
    assert.throws(() => choose(all, {tier: 'quick'}, {tierFile, suiteNames}), /smoke or full/);
    assert.throws(() => choose(all, {tier: 'smoke', spec: 'mfa.spec.js'}, {tierFile, suiteNames}), /cannot be combined/);
});

test('--changed adds the specs of the touched areas to the smoke tier', () => {
    const all = plan(suite, new Set(Object.keys(suite.requires)), exists);
    const changedFiles = () => ['static/js/sftp-file-manager.js', 'tests/e2e/herdr.spec.js', 'internal/files/list_test.go', 'README.md'];
    const {planned, notes} = choose(all, {changed: 'origin/go...HEAD'}, {tierFile, suiteNames, changedFiles});
    const names = planned.all.map(name => path.basename(name));
    for (const name of ['file-workspace.spec.js', 'file-mutations.spec.js', 'herdr.spec.js', 'auth-submit.spec.js']) assert.ok(names.includes(name), name);
    assert.ok(!names.includes('account-theme-matrix.spec.js'));
    assert.ok(notes.some(note => note.includes('README.md')));
    assert.ok(!notes.some(note => note.includes('list_test.go')));
});

test('a git range that looks like an option is refused', () => {
    const run = () => { throw new Error('git must not run'); };
    assert.throws(() => tiers.gitChanged('--output=/tmp/x', {run}), /git range/);
    assert.throws(() => tiers.gitChanged('', {run}), /git range/);
    const ok = tiers.gitChanged('a...b', {run: (command, argv) => {
        assert.deepEqual(argv, ['diff', '--name-only', '--no-renames', 'a...b', '--']);
        return {status: 0, stdout: 'x.js\n\ny.go\n'};
    }});
    assert.deepEqual(ok, ['x.js', 'y.go']);
    assert.throws(() => tiers.gitChanged('a...b', {run: () => ({status: 128, stderr: 'bad revision'})}), /bad revision/);
});

const playwrightReport = (tests, errors = []) => ({
    errors,
    suites: [{title: 'a.spec.js', file: 'a.spec.js', specs: [], suites: [{title: 'group', specs: tests.map(([title, status, durations, message]) => ({
        title, file: 'a.spec.js', line: 7,
        tests: [{status, results: durations.map(duration => ({duration, error: message ? {message: `\u001b[31m${message}\u001b[39m\nstack`} : undefined}))}],
    }))}]}],
});

test('the summary merges shards and names every failure', () => {
    const reports = {
        one: playwrightReport([['passes', 'expected', [1000]], ['retried', 'flaky', [500, 700]]]),
        two: playwrightReport([['breaks', 'unexpected', [2000], 'expected 1 to be 2'], ['skips', 'skipped', [0]]]),
    };
    const summary = summarize([
        {index: 1, exitCode: 0, wallMs: 60_000, log: 'one.log', specs: 3, reports: ['one']},
        {index: 2, exitCode: 1, wallMs: 90_000, log: 'two.log', specs: 2, reports: ['two']},
    ], {readReport: name => reports[name]});
    assert.equal(summary.ok, false);
    assert.deepEqual([summary.passed, summary.failed, summary.flaky, summary.skipped], [1, 1, 1, 1]);
    assert.equal(summary.wallMs, 90_000);
    assert.deepEqual(summary.broken, []);
    assert.equal(summary.failures[0].title, 'group > breaks');
    assert.equal(summary.failures[0].error, 'expected 1 to be 2');
    const text = format(summary);
    assert.match(text, /FAILED in 1m30s on 2 shard/);
    assert.match(text, /FAILED \[shard 2\] a\.spec\.js:7 group > breaks/);
    assert.equal(testsOf(reports.one)[1].durationMs, 1200);
});

test('a shard without a report or with a failing exit and no failed test is broken', () => {
    const good = playwrightReport([['passes', 'expected', [1000]]]);
    const missing = summarize([{index: 1, exitCode: 1, wallMs: 1, log: 'x.log', specs: 1, reports: ['gone']}], {readReport: () => { throw new Error('ENOENT'); }});
    assert.equal(missing.ok, false);
    assert.match(missing.broken[0].reason, /no report/);
    const silent = summarize([{index: 1, exitCode: 1, wallMs: 1, log: 'x.log', specs: 1, reports: ['r']}], {readReport: () => good});
    assert.equal(silent.ok, false);
    const crashed = summarize([{index: 1, exitCode: 0, wallMs: 1, log: 'x.log', specs: 1, reports: ['r']}], {readReport: () => playwrightReport([['passes', 'expected', [1]]], [{message: 'webServer exited early'}])});
    assert.equal(crashed.ok, false);
    const empty = summarize([{index: 1, exitCode: 0, wallMs: 1, log: 'x.log', specs: 1, reports: ['r']}], {readReport: () => playwrightReport([])});
    assert.equal(empty.ok, false, 'a run without a single test is no pass');
    const passed = summarize([{index: 1, exitCode: 0, wallMs: 1, log: 'x.log', specs: 1, reports: ['r']}], {readReport: () => good});
    assert.equal(passed.ok, true);
});

test('the timing refresh reads both report formats and keeps unmeasured specs', () => {
    assert.deepEqual(specSeconds(playwrightReport([['x', 'expected', [1500]], ['y', 'expected', [500]]])), {'a.spec.js': 2});
    assert.deepEqual(specSeconds({version: 1, tests: [
        {identity: 'tests/e2e/b.spec.js::one', durationMs: 3000}, {identity: 'tests/e2e/b.spec.js::two', durationMs: 1000}]}), {'b.spec.js': 4});
    const next = refresh({description: 'd', specs: {'a.spec.js': 9, 'c.spec.js': 5, 'gone.spec.js': 1}},
        [playwrightReport([['x', 'expected', [1000]]])], ['a.spec.js', 'c.spec.js']);
    assert.deepEqual(next.specs, {'a.spec.js': 1, 'c.spec.js': 5});
    assert.throws(() => refresh({specs: {}}, [playwrightReport([['x', 'expected', [1]]]), playwrightReport([['x', 'expected', [1]]])], ['a.spec.js']), /twice/);
});
