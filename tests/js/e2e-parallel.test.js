const assert = require('node:assert/strict');
const { test } = require('node:test');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { EventEmitter } = require('node:events');
const modulePath = '../../scripts/run-e2e-ci-parallel';
function reachable(port, connect = require('node:net').connect) {
    return new Promise(resolve => {
        const socket = connect(port, '127.0.0.1');
        socket.once('connect', () => {
            // Linux can connect an ephemeral client port back to itself even
            // after the listener exits. Such a socket does not prove a server is listening.
            const selfConnected = socket.localAddress === socket.remoteAddress
                && socket.localPort === socket.remotePort;
            socket.destroy();
            resolve(!selfConnected);
        });
        socket.once('error', () => resolve(false));
    });
}

test('TCP reachability rejects a Linux self-connection without a listening server', {skip: process.platform !== 'linux'}, async () => {
    const net = require('node:net');
    const reservation = net.createServer();
    await new Promise(resolve => reservation.listen(0, '127.0.0.1', resolve));
    const port = reservation.address().port;
    await new Promise(resolve => reservation.close(resolve));
    let connected = false;
    const result = await reachable(port, (target, host) => {
        // Force the same endpoint deterministically rather than waiting for the
        // kernel's ephemeral allocator to choose it during an ordinary probe.
        const socket = net.connect({port: target, host, localPort: target});
        socket.once('connect', () => { connected = true; });
        return socket;
    });
    assert.equal(connected, true, 'Linux establishes this connection despite the absent listener');
    assert.equal(result, false, 'a connection to itself is not evidence of a surviving server');
});

test('all eight groups cover exactly 32 independent single-worker shards', () => {
    const { planGroup, parseArguments } = require(modulePath);
    const plans = Array.from({ length: 8 }, (_, index) => planGroup(parseArguments([
        `--group=${index + 1}/8`, '--lanes=4',
    ])));
    assert.deepEqual(plans.flat().map(lane => Number(lane.shard.split('/')[0])).sort((a, b) => a - b), Array.from({ length: 32 }, (_, i) => i + 1));
    assert.equal(new Set(plans[0].map(lane => lane.port)).size, 4);
    assert.deepEqual(plans[0].map(lane => lane.shard), ['1/32', '9/32', '17/32', '25/32']);
    // The two 20-terminal transport workloads occupy weighted shards 6 and 7.
    // Spread early/heavy partitions across jobs rather than creating 40 TUIs on one runner.
    assert.notEqual(plans.findIndex(plan => plan.some(lane => lane.shard === '6/32')),
        plans.findIndex(plan => plan.some(lane => lane.shard === '7/32')));
    for (const args of [[], ['--group=0/8'], ['--group=1/8', '--lanes=0'], ['--group=1/8', '--lanes=4', '--unknown']]) {
        assert.throws(() => parseArguments(args));
    }
    assert.throws(() => planGroup({ group: 1, groups: 8, lanes: 4, portBase: 65534 }));
});

test('real child processes isolate ports, temp data and artifacts, wait for every failure and preserve artifacts', async () => {
    const { runGroup } = require(modulePath);
    const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'e2e-parallel-test-'));
    try {
        const runner = path.join(directory, 'stub.js');
        fs.writeFileSync(runner, `
            const fs = require('node:fs');
            const path = require('node:path');
            const http = require('node:http');
            const env = process.env;
            const server = http.createServer((req, res) => res.end('ok'));
            server.listen(Number(env.WEBSSH_E2E_PORT), '127.0.0.1', () => {
                fs.mkdirSync(env.WEBSSH_E2E_OUTPUT_DIR, { recursive: true });
                fs.writeFileSync(path.join(env.WEBSSH_E2E_OUTPUT_DIR, 'result.json'), JSON.stringify(env));
                setTimeout(() => server.close(() => process.exit(env.WEBSSH_E2E_SHARD === '1/2' ? 3 : 0)), 100);
            });
        `);
        const result = await runGroup({ group: 1, groups: 1, lanes: 2, portBase: 24571 }, {
            runner, outputRoot: path.join(directory, 'artifacts'), temporaryParent: directory,
            platform: 'linux', signals: new EventEmitter(),
        });
        assert.equal(result, 1);
        const envs = [1, 2].map(n => JSON.parse(fs.readFileSync(path.join(directory, 'artifacts', `shard-${n}-of-2`, 'result.json'))));
        for (const key of ['WEBSSH_E2E_PORT', 'TMPDIR', 'BACKUP_TEMP_DIR', 'TRANSFER_TEMP_DIR', 'WEBSSH_E2E_OUTPUT_DIR']) {
            assert.notEqual(envs[0][key], envs[1][key], key);
        }
        for (const env of envs) {
            assert.equal(env.WEBSSH_E2E_FAST_HASHING, '1');
            assert.equal(fs.existsSync(env.TMPDIR), false);
            assert.equal(fs.existsSync(env.WEBSSH_E2E_OUTPUT_DIR), true);
        }
    } finally {
        fs.rmSync(directory, { recursive: true, force: true });
    }
});

test('spawn failures and signalled exits fail without abandoning other children', async () => {
    const { runGroup } = require(modulePath);
    let count = 0;
    let finished = false;
    const result = await runGroup({ group: 1, groups: 1, lanes: 2, portBase: 24581 }, {
        platform: 'linux', signals: new EventEmitter(),
        spawn() {
            const child = new EventEmitter();
            if (count++ === 0) setImmediate(() => child.emit('error', new Error('spawn failure')));
            else setTimeout(() => { finished = true; child.emit('close', null, 'SIGTERM'); }, 30);
            return child;
        },
    });
    assert.equal(result, 1);
    assert.equal(finished, true);
});

test('Playwright honors each shard output directory without changing its default worker count', () => {
    const { execFileSync } = require('node:child_process');
    const result = execFileSync(process.execPath, ['-e', "const c=require('./playwright.config'); console.log(JSON.stringify({ outputDir:c.outputDir,workers:c.workers }));"], {
        cwd: path.resolve(__dirname, '../..'),
        env: { ...process.env, WEBSSH_E2E_OUTPUT_DIR: 'isolated-output' }, encoding: 'utf8',
    });
    assert.deepEqual(JSON.parse(result), { outputDir: 'isolated-output', workers: 1 });
});

test('interrupt kills every owned process tree and waits for their closure', async () => {
    const { runGroup } = require(modulePath);
    const signals = new EventEmitter();
    const children = [];
    const killed = [];
    const running = runGroup({ group: 1, groups: 1, lanes: 2 }, {
        platform: 'linux', signals,
        spawn() { const child = new EventEmitter(); child.pid = 1000 + children.length; children.push(child); return child; },
        terminateTree(child) { killed.push(child.pid); setImmediate(() => child.emit('close', null, 'SIGKILL')); },
    });
    signals.emit('SIGTERM');
    assert.equal(await running, 1);
    assert.deepEqual(killed, children.map(child => child.pid));
    assert.equal(signals.listenerCount('SIGTERM'), 0);
});

test('interrupt stops a detached descendant TCP server and preserves an unrelated server', { skip: !['linux', 'win32'].includes(process.platform) }, async () => {
    const { spawn } = require('node:child_process');
    const net = require('node:net');
    const { runGroup, terminateTree } = require(modulePath);
    const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'e2e-detached-test-'));
    const unrelated = net.createServer(socket => socket.end());
    await new Promise(resolve => unrelated.listen(0, '127.0.0.1', resolve));
    const signals = new EventEmitter();
    let runnerChild;
    let descendant;
    let ready;
    const readiness = new Promise(resolve => { ready = resolve; });

    try {
        const runner = path.join(directory, 'runner.js');
        const serverScript = `const net=require('node:net'); const s=net.createServer(); s.listen(0,'127.0.0.1',()=>process.send({port:s.address().port,pid:process.pid}));`;
        fs.writeFileSync(runner, `const {spawn}=require('node:child_process'); const c=spawn(process.execPath,['-e',${JSON.stringify(serverScript)}],{detached:process.platform!=='win32',stdio:['ignore','ignore','ignore','ipc']}); c.on('message',value=>process.send(value)); setInterval(()=>{},1000);`);
        const running = runGroup({ group: 1, groups: 1, lanes: 1 }, {
            runner, signals, temporaryParent: directory,
            spawn(command, args, options) {
                runnerChild = spawn(command, args, { ...options, stdio: ['ignore', 'ignore', 'ignore', 'ipc'] });
                runnerChild.once('message', value => { descendant = value; ready(); });
                return runnerChild;
            },
        });
        await Promise.race([readiness, new Promise((_, reject) => {
            const timer = setTimeout(() => reject(new Error('descendant startup timeout')), 5000);
            readiness.finally(() => clearTimeout(timer));
        })]);
        assert.equal(await reachable(descendant.port), true);
        signals.emit('SIGTERM');
        assert.equal(await running, 1);
        assert.equal(await reachable(descendant.port), false, 'detached descendant must stop with its owning runner');
        assert.equal(await reachable(unrelated.address().port), true, 'unrelated server must remain available');
    } finally {
        if (runnerChild && runnerChild.exitCode === null && runnerChild.signalCode === null) await terminateTree(runnerChild);
        if (descendant) {
            try { process.kill(descendant.pid, 'SIGKILL'); } catch (error) { if (error.code !== 'ESRCH') throw error; }
        }
        await new Promise(resolve => unrelated.close(resolve));
        fs.rmSync(directory, { recursive: true, force: true });
    }
});

test('Linux cancellation checks start identities and excludes recycled PIDs and unrelated children', async () => {
    const { terminateLinuxTree } = require(modulePath);
    const processes = new Map([
        [10, { pid: 10, parent: 1, startTime: 'root' }],
        [11, { pid: 11, parent: 10, startTime: 'child' }],
        [12, { pid: 12, parent: 11, startTime: 'detached-server' }],
        [90, { pid: 90, parent: 1, startTime: 'unrelated' }],
    ]);
    const signals = [];
    await terminateLinuxTree(10, {
        readProcess: pid => processes.get(pid),
        listPids: () => [...processes.keys()],
        signal(pid, name) {
            signals.push([pid, name]);
            if (name === 'SIGKILL') processes.delete(pid);
            if (pid === 11 && name === 'SIGSTOP') {
                // A descendant exits and its numeric PID is reused before fallback.
                processes.set(12, { pid: 12, parent: 90, startTime: 'recycled' });
                processes.set(13, { pid: 13, parent: 12, startTime: 'unrelated-child' });
            }
        },
    });
    assert.deepEqual(signals, [[10, 'SIGSTOP'], [11, 'SIGSTOP'], [11, 'SIGKILL'], [10, 'SIGKILL']]);
});

test('unsupported platforms fail before spawning or creating temporary state', async () => {
    const { runGroup, assertSupportedPlatform } = require(modulePath);
    assert.doesNotThrow(() => assertSupportedPlatform('linux'));
    assert.doesNotThrow(() => assertSupportedPlatform('win32'));
    let spawned = false;
    await assert.rejects(runGroup({ group: 1, groups: 1, lanes: 1 }, {
        platform: 'darwin',
        // If filesystem setup runs before platform validation this fails with ENOENT.
        temporaryParent: path.join(os.tmpdir(), 'missing-e2e-parent', 'does-not-exist'),
        spawn() { spawned = true; throw new Error('must not spawn'); },
    }), /supports Linux and Windows/);
    assert.equal(spawned, false);
});

test('CI records traces on the first retry while keeping every assertion, retry and failure screenshot', () => {
    const { execFileSync } = require('node:child_process');
    for (const ci of ['', 'true']) {
        const result = execFileSync(process.execPath, ['-e', "const c=require('./playwright.config'); console.log(JSON.stringify({ trace:c.use.trace,retries:c.retries,screenshot:c.use.screenshot,workers:c.workers }));"], {
            cwd: path.resolve(__dirname, '../..'), env: { ...process.env, CI: ci }, encoding: 'utf8',
        });
        assert.deepEqual(JSON.parse(result), {
            trace: ci ? 'on-first-retry' : 'retain-on-failure', retries: ci ? 1 : 0,
            screenshot: 'only-on-failure', workers: 1,
        });
    }
});

test('interrupt waits for owned descendant teardown even when the lane root closes first', async () => {
    const { runGroup } = require(modulePath);
    const signals = new EventEmitter();
    const child = new EventEmitter();
    let releaseTeardown;
    let scratchDirectory;
    let completed = false;
    const teardown = new Promise(resolve => { releaseTeardown = resolve; });
    const running = runGroup({ group: 1, groups: 1, lanes: 1 }, {
        platform: 'linux', signals,
        spawn(_command, _args, options) { scratchDirectory = options.env.TMPDIR; return child; },
        terminateTree() {
            setImmediate(() => child.emit('close', null, 'SIGKILL'));
            return teardown;
        },
    }).then(code => { completed = true; return code; });
    signals.emit('SIGTERM');
    await new Promise(resolve => setImmediate(() => setImmediate(resolve)));
    assert.equal(completed, false, 'root closure must not announce completed descendant teardown');
    assert.equal(fs.existsSync(scratchDirectory), true, 'descendant scratch must survive until teardown completes');
    releaseTeardown();
    assert.equal(await running, 1);
    assert.equal(fs.existsSync(scratchDirectory), false);
});

test('Linux cancellation confirms delayed kernel exit without following a recycled identity', async () => {
    const { terminateLinuxTree } = require(modulePath);
    const processes = new Map([
        [10, { pid: 10, parent: 1, startTime: 'root', state: 'S' }],
        [11, { pid: 11, parent: 10, startTime: 'descendant', state: 'S' }],
        [90, { pid: 90, parent: 1, startTime: 'unrelated', state: 'S' }],
    ]);
    let descendantExited = false;
    await terminateLinuxTree(10, {
        readProcess: pid => processes.get(pid), listPids: () => [...processes.keys()],
        signal(pid, name) {
            assert.notEqual(pid, 90);
            if (name !== 'SIGKILL') return;
            if (pid === 10) processes.set(10, { pid: 10, parent: 90, startTime: 'recycled', state: 'S' });
            else setTimeout(() => {
                processes.get(11).state = 'Z';
                descendantExited = true;
            }, 15);
        },
    });
    assert.equal(descendantExited, true, 'signal delivery alone must not finish teardown');
    assert.equal(processes.get(90).state, 'S');
});

test('Linux cancellation fails when owned processes do not exit before the deadline', async () => {
    const { terminateLinuxTree } = require(modulePath);
    await assert.rejects(terminateLinuxTree(10, {
        readProcess: pid => pid === 10 ? { pid: 10, parent: 1, startTime: 'root', state: 'S' } : null,
        listPids: () => [10], signal() {}, timeoutMs: 0,
    }), /teardown did not complete before its deadline/);
});

test('exclusive cases finish serially before all four shared remainders, preserving failure aggregation and artifacts', async () => {
    const { runGroup } = require(modulePath);
    const children = new Map();
    const started = [];
    const phases = [];
    const outputs = [];
    const timings = [];
    const running = runGroup({ group: 1, groups: 1, lanes: 4 }, {
        exclusiveShards: ['2/4', '4/4'], signals: new EventEmitter(),
        spawn(_command, args, options) {
            const shard = options.env.WEBSSH_E2E_SHARD;
            started.push(shard);
            phases.push(args.find(arg => arg.startsWith('--phase=')));
            outputs.push(options.env.WEBSSH_E2E_OUTPUT_DIR);
            timings.push(options.env.WEBSSH_E2E_TIMING_FILE);
            const child = new EventEmitter();
            children.set(shard, child);
            return child;
        },
    });
    assert.deepEqual(started, ['2/4']);
    children.get('2/4').emit('close', 1, null);
    await new Promise(resolve => setImmediate(resolve));
    assert.deepEqual(started, ['2/4', '4/4']);
    children.get('4/4').emit('close', 0, null);
    await new Promise(resolve => setImmediate(resolve));
    assert.deepEqual(started, ['2/4', '4/4', '1/4', '2/4', '3/4', '4/4']);
    assert.deepEqual(phases, ['--phase=exclusive', '--phase=exclusive', undefined, '--phase=shared', undefined, '--phase=shared']);
    assert.equal(new Set(outputs).size, 6);
    assert.equal(new Set(timings).size, 6);
    for (const shard of ['1/4', '2/4', '3/4', '4/4']) children.get(shard).emit('close', 0, null);
    assert.equal(await running, 1);
    assert.equal(new Set(started).size, 4);
});

test('exclusive lane selection follows discovery and the same weighted assignment, never fixed shard numbers', () => {
    const { classifyExclusiveShards } = require(modulePath);
    const tests = [
        'tests/e2e/terminal-load.spec.js::20 active TUIs retain state without reconnecting over polling',
        'tests/e2e/terminal-load.spec.js::20 active TUIs retain state without reconnecting over websocket',
        'tests/e2e/a.spec.js::normal a', 'tests/e2e/b.spec.js::normal b',
        'tests/e2e/c.spec.js::normal c', 'tests/e2e/d.spec.js::normal d',
    ].map(identity => ({ identity, selector: identity }));
    const first = { tests: Object.fromEntries(tests.map((item, i) => [item.identity, 100 - i * 10])) };
    const second = { tests: Object.fromEntries(tests.map((item, i) => [item.identity, i < 2 ? 1 : 100 - i * 10])) };
    const before = classifyExclusiveShards(tests, 4, first);
    const after = classifyExclusiveShards(tests, 4, second);
    assert.notDeepEqual(before, after);
    const { assignTests } = require('../../scripts/e2e-sharding');
    for (const baseline of [first, second]) {
        const assignment = assignTests(tests, 4, baseline);
        const expected = assignment.shards.flatMap((items, index) => items.some(item => item.identity.includes('terminal-load.spec.js::')) ? [`${index + 1}/4`] : []);
        assert.deepEqual(classifyExclusiveShards(tests, 4, baseline), expected);
    }
    assert.throws(() => classifyExclusiveShards(tests.slice(1), 4, first), /missing.*resource|resource.*missing/i);
    assert.throws(() => classifyExclusiveShards([...tests, {
        identity: 'tests/e2e/terminal-load.spec.js::new unclassified workload', selector: 'unknown',
    }], 4, first), /unknown.*resource|resource.*unknown/i);
});

test('the production CLI always classifies the discovered inventory before launching lanes', async () => {
    const { main } = require(modulePath);
    const inventory = [
        'tests/e2e/terminal-load.spec.js::20 active TUIs retain state without reconnecting over polling',
        'tests/e2e/terminal-load.spec.js::20 active TUIs retain state without reconnecting over websocket',
    ].map(identity => ({ identity, selector: identity }));
    let discoveries = 0;
    let executions = 0;
    assert.equal(await main(['--group=1/1', '--lanes=2'], {
        discover() { discoveries++; return inventory; },
        runGroup(config, options) {
            executions++;
            assert.equal(config.groups * config.lanes, 2);
            assert.deepEqual(options.exclusiveShards, ['1/2', '2/2']);
            return 0;
        },
    }), 0);
    assert.equal(discoveries, 1);
    assert.equal(executions, 1);
    await assert.rejects(main(['--group=1/1', '--lanes=2'], {
        discover: () => inventory.slice(1),
        runGroup() { throw new Error('must not launch an unclassified inventory'); },
    }), /Missing exclusive resource test/);
});


test('weighted runner phase flags are finite and shared/exclusive exactly partition assigned tests', () => {
    const { parseArguments, selectAssignedTests } = require('../../scripts/run-e2e-ci');
    assert.equal(parseArguments(['--shard=1/2']).phase, 'all');
    for (const phase of ['all', 'exclusive', 'shared']) {
        assert.equal(parseArguments(['--shard=1/2', `--phase=${phase}`]).phase, phase);
    }
    for (const args of [
        ['--shard=1/2', '--phase='], ['--shard=1/2', '--phase=unknown'],
        ['--shard=1/2', '--phase=all', '--phase=shared'], ['--shard=1/2', '--unknown'],
    ]) assert.throws(() => parseArguments(args));
    const tests = [
        'tests/e2e/terminal-load.spec.js::20 active TUIs retain state without reconnecting over polling',
        'tests/e2e/terminal-load.spec.js::20 active TUIs retain state without reconnecting over websocket',
        'tests/e2e/a.spec.js::normal a', 'tests/e2e/b.spec.js::normal b',
    ].map(identity => ({ identity, selector: identity }));
    const shard = {current: 1, total: 1};
    const all = selectAssignedTests(tests, shard, 'all').selected;
    const exclusive = selectAssignedTests(tests, shard, 'exclusive').selected;
    const shared = selectAssignedTests(tests, shard, 'shared').selected;
    assert.equal(exclusive.length, 2);
    assert.equal(shared.length, 2);
    assert.deepEqual([...exclusive, ...shared].map(t => t.identity).sort(), all.map(t => t.identity).sort());
    assert.equal(new Set([...exclusive, ...shared].map(t => t.identity)).size, all.length);
    assert.throws(() => selectAssignedTests(tests, {current: 1, total: 4}, 'exclusive'), /has no assigned tests/);
});

test('interrupt during an exclusive case starts no queued phase and awaits owned teardown', async () => {
    const { runGroup } = require(modulePath);
    const signals = new EventEmitter();
    const child = new EventEmitter();
    const started = [];
    let release;
    let finished = false;
    const teardown = new Promise(resolve => { release = resolve; });
    const running = runGroup({group: 1, groups: 1, lanes: 4}, {
        exclusiveShards: ['2/4', '4/4'], signals,
        spawn(_command, args) { started.push(args); return child; },
        terminateTree() { setImmediate(() => child.emit('close', null, 'SIGKILL')); return teardown; },
    }).then(code => { finished = true; return code; });
    signals.emit('SIGTERM');
    await new Promise(resolve => setImmediate(() => setImmediate(resolve)));
    assert.equal(started.length, 1);
    assert.equal(finished, false);
    release();
    assert.equal(await running, 1);
    assert.equal(started.length, 1);
});

test('Linux cancellation waits for live sibling threads after the process leader becomes a zombie', async () => {
    const { terminateLinuxTree } = require(modulePath);
    const leader = { pid: 10, parent: 1, startTime: 'owned', state: 'S', threads: 2 };
    let threadsExited = false;
    await terminateLinuxTree(10, {
        readProcess: pid => pid === 10 ? leader : null,
        listPids: () => [10],
        signal(_pid, name) {
            if (name !== 'SIGKILL') return;
            leader.state = 'Z';
            // Linux can report a zombie leader while a sibling still owns the
            // shared listening socket. Only its exit releases that resource.
            setTimeout(() => { leader.threads = 1; threadsExited = true; }, 15);
        },
    });
    assert.equal(threadsExited, true, 'a zombie leader alone does not prove its threads released shared sockets');
});
