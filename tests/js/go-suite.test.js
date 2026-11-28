const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');
const {plan, select, runPlaywright} = require('../e2e/run-go-suite.js');

const suite = JSON.parse(fs.readFileSync(path.join(__dirname, '../e2e/go-suite.json'), 'utf8'));
const exists = file => fs.existsSync(path.join(__dirname, '../e2e', file));

test('go-suite.json is valid: every exclusion names a reason and what unlocks it', () => {
    const all = plan(suite, new Set(Object.keys(suite.requires)), exists);
    assert.equal(all.all.length, suite.specs.length);
    assert.equal(all.parallel.length + all.serial.length, all.all.length);
    assert.ok(all.serial.length > 0);
    const none = plan(suite, new Set(), exists);
    assert.ok(none.excluded.includes('shows mixed MFA methods one at a time'));
    assert.ok(!none.all.some(file => file.endsWith('webauthn.spec.js')));
});

test('the runner refuses malformed entries', () => {
    const base = {requires: {passkeys: 'x'}, specs: []};
    const bad = [
        {file: 'mfa.spec.js', exclude: [{title: 't', reason: 'r'}]},
        {file: 'mfa.spec.js', exclude: [{title: 't', reason: 'r', package: 'XX9'}]},
        {file: 'mfa.spec.js', exclude: [{title: 't', package: 'ID1'}]},
        {file: 'mfa.spec.js', serial: 'e2e_user', exclude: []},
        {file: 'mfa.spec.js', requires: 'nothing', exclude: []},
        {file: 'missing.spec.js', exclude: []},
        {file: 'mfa.spec.js', exclude: [{title: 't', reason: 'r', decision: 'later'}]},
        {file: 'mfa.spec.js', exclude: [{title: 't', reason: 'r', decision: 'ADR 0005', package: 'FE1'}]},
    ];
    for (const spec of bad) {
        assert.throws(() => plan({...base, specs: [spec]}, new Set(), exists), undefined, JSON.stringify(spec));
    }
    assert.throws(() => plan({...base, specs: [{file: 'mfa.spec.js', exclude: []}, {file: 'mfa.spec.js', exclude: []}]}, new Set(), exists));
    assert.throws(() => plan(base, new Set(['unknown']), exists));
    const ok = plan({...base, specs: [{file: 'mfa.spec.js', exclude: [{title: 't', reason: 'r', package: 'ID1'}]}]}, new Set(), exists);
    assert.deepEqual(ok.excluded, ['t']);
    const decided = plan({...base, specs: [{file: 'mfa.spec.js', exclude: [
        {title: 'a', reason: 'r', decision: 'ADR 0005'}, {title: 'b', reason: 'r', decision: 'D-13'}]}]}, new Set(), exists);
    assert.deepEqual(decided.excluded, ['a', 'b']);
});

// After the last M2 package nothing waits for a package any more: what is
// left out is either a capability of the build or a decision.
test('no excluded test waits for FE1', () => {
    for (const spec of suite.specs) {
        for (const entry of spec.exclude) assert.notEqual(entry.package, 'FE1', `${spec.file}: ${entry.title}`);
    }
});

// Every spec of the main suite runs against Go; a test that does not is
// excluded by name with its reason, never by leaving its file out.
test('go-suite.json lists every spec of the main suite', () => {
    const listed = new Set(suite.specs.map(spec => spec.file));
    const missing = fs.readdirSync(path.join(__dirname, '../e2e')).filter(file => file.endsWith('.spec.js') && !listed.has(file));
    assert.deepEqual(missing, []);
});

test('go_only specs name a reason and are left out of the Python run only', () => {
    const goOnly = suite.specs.filter(spec => spec.go_only !== undefined);
    assert.deepEqual(goOnly.map(spec => spec.file).sort(), ['overview-host-order.spec.js', 'record-unique-names.spec.js']);
    const load = env => {
        const config = require.resolve('../../playwright.config.js');
        const saved = process.env.WEBSSH_E2E_SERVER_COMMAND;
        delete require.cache[config];
        if (env === undefined) delete process.env.WEBSSH_E2E_SERVER_COMMAND;
        else process.env.WEBSSH_E2E_SERVER_COMMAND = env;
        try {
            return require(config).testIgnore;
        } finally {
            delete require.cache[config];
            if (saved === undefined) delete process.env.WEBSSH_E2E_SERVER_COMMAND;
            else process.env.WEBSSH_E2E_SERVER_COMMAND = saved;
        }
    };
    const python = load(undefined);
    for (const spec of goOnly) assert.ok(python.includes(spec.file), spec.file);
    const go = load('.test-run.tmp/webssh-e2e e2e');
    for (const spec of goOnly) assert.ok(!go.includes(spec.file), spec.file);
    assert.throws(() => plan({requires: {}, specs: [{file: 'mfa.spec.js', go_only: ' ', exclude: []}]}, new Set(), exists), /go_only needs a reason/);
});

test('--spec narrows the plan to named files and refuses names outside it', () => {
    const planned = plan(suite, new Set(Object.keys(suite.requires)), exists);
    const [first, second] = planned.all.map(file => path.basename(file));
    const narrowed = select(planned, `${first},${second}`);
    assert.deepEqual(narrowed.all, planned.all.slice(0, 2));
    assert.equal(narrowed.parallel.length + narrowed.serial.length, 2);
    assert.equal(select(planned, null), planned);
    assert.throws(() => select(planned, 'no-such.spec.js'), /not in the Go suite plan/);
    assert.throws(() => select(planned, ','), /at least one/);
});

test('a signal to the runner stops Playwright and frees the backend port', async () => {
    const {spawn} = require('node:child_process');
    const {EventEmitter} = require('node:events');
    const net = require('node:net');
    const signals = new EventEmitter();
    let port;
    const ready = new Promise(resolve => {
        signals.ready = resolve;
    });
    const spawnChild = (command, argv, options) => {
        const child = spawn(process.execPath, [path.join(__dirname, 'fixtures', 'held-port.js')], {...options, stdio: ['ignore', 'pipe', 'inherit']});
        child.stdout.on('data', chunk => { port = Number(String(chunk).trim()); signals.ready(); });
        return child;
    };
    const done = runPlaywright([], {spawnChild, signals, graceMs: 300});
    await ready;
    signals.emit('SIGTERM');
    assert.equal(await done, 130);
    const open = await new Promise(resolve => {
        const socket = net.connect(port, '127.0.0.1');
        socket.on('connect', () => { socket.destroy(); resolve(true); });
        socket.on('error', () => resolve(false));
    });
    assert.equal(open, false, `port ${port} is still held`);
});
