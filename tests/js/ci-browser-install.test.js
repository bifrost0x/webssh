const assert = require('node:assert/strict');
const test = require('node:test');
const { installCiChromium, probeChromium } = require('../../scripts/install-ci-chromium');

function fixture({ failures = [], installFailure, depsFailure } = {}) {
    const events = [];
    return {
        events,
        runCli(args) {
            events.push(args);
            if (args[0] === 'install' && installFailure) throw installFailure;
            if (args[0] === 'install-deps' && depsFailure) throw depsFailure;
        },
        async probe() {
            events.push('probe');
            const failure = failures.shift();
            if (failure) throw failure;
        },
    };
}

test('downloads locked Chromium headless shell and avoids apt when it launches', async () => {
    const setup = fixture();
    await installCiChromium(setup);
    assert.deepEqual(setup.events, [['install', 'chromium', '--only-shell'], 'probe']);
});

test('installs runtime dependencies only after a missing dependency launch failure', async () => {
    const setup = fixture({ failures: [new Error('Host system is missing dependencies to run browsers.')] });
    await installCiChromium(setup);
    assert.deepEqual(setup.events, [
        ['install', 'chromium', '--only-shell'], 'probe', ['install-deps', 'chromium'], 'probe',
    ]);
});

test('recognizes the dynamic linker missing library failure', async () => {
    const setup = fixture({ failures: [new Error('error while loading shared libraries: libX11.so: cannot open shared object file')] });
    await installCiChromium(setup);
    assert.equal(setup.events.filter(event => event === 'probe').length, 2);
    assert.deepEqual(setup.events[2], ['install-deps', 'chromium']);
});

test('propagates browser download failure before any launch or dependency install', async () => {
    const failure = new Error('download failed');
    const setup = fixture({ installFailure: failure });
    await assert.rejects(installCiChromium(setup), error => error === failure);
    assert.deepEqual(setup.events, [['install', 'chromium', '--only-shell']]);
});

test('propagates unrelated launch failure without attempting apt', async () => {
    const failure = new Error('browser crashed unexpectedly');
    const setup = fixture({ failures: [failure] });
    await assert.rejects(installCiChromium(setup), error => error === failure);
    assert.deepEqual(setup.events, [['install', 'chromium', '--only-shell'], 'probe']);
});

test('propagates dependency installation failure without retrying launch', async () => {
    const failure = new Error('apt failed');
    const setup = fixture({ failures: [new Error('Host system is missing dependencies')], depsFailure: failure });
    await assert.rejects(installCiChromium(setup), error => error === failure);
    assert.deepEqual(setup.events, [['install', 'chromium', '--only-shell'], 'probe', ['install-deps', 'chromium']]);
});

test('fails closed when launch still fails after dependencies were installed', async () => {
    const failure = new Error('still cannot launch');
    const setup = fixture({ failures: [new Error('Host system is missing dependencies'), failure] });
    await assert.rejects(installCiChromium(setup), error => error === failure);
    assert.deepEqual(setup.events, [
        ['install', 'chromium', '--only-shell'], 'probe', ['install-deps', 'chromium'], 'probe',
    ]);
});

test('the real launch probe requests headless Chromium and closes it', async () => {
    const events = [];
    await probeChromium({ async launch(options) {
        events.push(options);
        return { async close() { events.push('close'); } };
    } });
    assert.deepEqual(events, [{ headless: true }, 'close']);
});
