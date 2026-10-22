const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { spawn, spawnSync } = require('node:child_process');
const { assignTests, parseShard } = require('./e2e-sharding');
const { validateResourceInventory, isExclusiveTest } = require('./e2e-resources');

function parseArguments(argv) {
    const group = argv.find(argument => /^--group=\d+\/\d+$/.test(argument));
    const lanes = argv.find(argument => /^--lanes=\d+$/.test(argument));
    if (!group || !lanes || argv.length !== 2) {
        throw new Error('Usage: node scripts/run-e2e-ci-parallel.js --group=<current>/<total> --lanes=<count>');
    }
    const [current, total] = group.slice(8).split('/').map(Number);
    const config = { group: current, groups: total, lanes: Number(lanes.slice(8)), portBase: Number(process.env.WEBSSH_E2E_PORT || 4173) };
    planGroup(config);
    return config;
}

function planGroup({ group, groups, lanes, portBase = 4173 }) {
    if (![group, groups, lanes, portBase].every(value => Number.isSafeInteger(value) && value > 0)
        || group > groups || !Number.isSafeInteger(groups * lanes) || portBase + lanes - 1 > 65535) {
        throw new Error('Invalid E2E group, lane count or port range.');
    }
    return Array.from({ length: lanes }, (_, index) => {
        // Weighted shards start with the slowest individual cases. Interleave
        // them across runners so parallel terminal-load cases do not share a CPU.
        const current = index * groups + group;
        const total = groups * lanes;
        return { shard: `${current}/${total}`, name: `shard-${current}-of-${total}`, port: portBase + index };
    });
}

function classifyExclusiveShards(discovered, shardCount, baseline) {
    validateResourceInventory(discovered);
    const assignment = assignTests(discovered, shardCount, baseline);
    return assignment.shards.flatMap((items, index) => (
        items.some(isExclusiveTest) ? [`${index + 1}/${shardCount}`] : []
    ));
}

function readLinuxProcess(pid) {
    try {
        const stat = fs.readFileSync(`/proc/${pid}/stat`, 'utf8');
        // comm may contain spaces or parentheses; fields after its final ')' are stable.
        const fields = stat.slice(stat.lastIndexOf(')') + 2).trim().split(/\s+/);
        return { pid, state: fields[0], parent: Number(fields[1]), threads: Number(fields[17]), startTime: fields[19] };
    } catch (error) {
        if (['ENOENT', 'ESRCH', 'EACCES'].includes(error.code)) return null;
        throw error;
    }
}

async function terminateLinuxTree(pid, { readProcess = readLinuxProcess, listPids = () => fs.readdirSync('/proc').filter(name => /^\d+$/.test(name)).map(Number), signal = process.kill, timeoutMs = 5000 } = {}) {
    const root = readProcess(pid);
    if (!root) return;
    const owned = new Map([[pid, root]]);
    const stopped = new Set();
    const signalOwned = (entry, name) => {
        const current = readProcess(entry.pid);
        if (!current || current.startTime !== entry.startTime) return;
        try { signal(entry.pid, name); } catch (error) { if (error.code !== 'ESRCH') throw error; }
    };
    try {
        // Freeze ancestors before scanning again so they cannot spawn or reparent
        // more descendants while cancellation walks detached Playwright groups.
        for (let pass = 0; pass < 32; pass += 1) {
            for (const entry of owned.values()) {
                if (!stopped.has(entry.pid)) {
                    signalOwned(entry, 'SIGSTOP');
                    stopped.add(entry.pid);
                }
            }
            const snapshot = listPids().map(readProcess).filter(Boolean);
            const byPid = new Map(snapshot.map(entry => [entry.pid, entry]));
            let added = false;
            let expanded;
            do {
                expanded = false;
                for (const entry of snapshot) {
                    const parent = owned.get(entry.parent);
                    const currentParent = byPid.get(entry.parent);
                    if (!owned.has(entry.pid) && parent && currentParent?.startTime === parent.startTime) {
                        owned.set(entry.pid, entry);
                        added = true;
                        expanded = true;
                    }
                }
            } while (expanded);
            if (!added) break;
        }
    } finally {
        // Recheck kernel start times before each signal: recycled PIDs are not ours.
        // Descendants die first, including servers/browser groups detached by Playwright.
        for (const entry of [...owned.values()].reverse()) signalOwned(entry, 'SIGKILL');
    }
    // kill() queues a signal; the root's close event does not prove detached
    // descendants have released their sockets. A zombie process leader can still
    // have live sibling threads holding shared sockets, so also check num_threads.
    const deadline = Date.now() + timeoutMs;
    while ([...owned.values()].some(entry => {
        const current = readProcess(entry.pid);
        return current && current.startTime === entry.startTime
            && (!['Z', 'X'].includes(current.state) || current.threads > 1);
    })) {
        if (Date.now() >= deadline) throw new Error('Owned E2E process teardown did not complete before its deadline.');
        await new Promise(resolve => setTimeout(resolve, 5));
    }
}

function terminateTree(child) {
    if (!Number.isSafeInteger(child.pid) || child.pid <= 0) return;
    if (process.platform === 'win32') {
        // The runner uses synchronous children; killing only Node would leak its server.
        const result = spawnSync('taskkill', ['/PID', String(child.pid), '/T', '/F'], { stdio: 'ignore', windowsHide: true });
        if (result.error) throw result.error;
    } else if (process.platform === 'linux') {
        return terminateLinuxTree(child.pid);
    } else {
        try { process.kill(-child.pid, 'SIGKILL'); } catch (error) {
            if (error.code !== 'ESRCH') throw error;
        }
    }
}

function assertSupportedPlatform(platform = process.platform) {
    if (!['linux', 'win32'].includes(platform)) {
        throw new Error('The parallel E2E launcher supports Linux and Windows; use run-e2e-ci.js on this platform.');
    }
}

async function runGroup(config, options = {}) {
    assertSupportedPlatform(options.platform || process.platform);
    const plan = planGroup(config);
    const exclusive = new Set(options.exclusiveShards || []);
    for (const shard of exclusive) {
        if (parseShard(shard).total !== config.groups * config.lanes) {
            throw new Error('Exclusive resource shard does not match the planned partition count.');
        }
    }
    console.log(`E2E runner resources: ${os.availableParallelism()} available CPUs, `
        + `${(os.totalmem() / 1024 ** 3).toFixed(1)} GiB RAM, ${plan.length} browser lanes.`);
    const runner = options.runner || path.join(__dirname, 'run-e2e-ci.js');
    const spawnChild = options.spawn || spawn;
    const killTree = options.terminateTree || terminateTree;
    const signals = options.signals || process;
    const outputRoot = path.resolve(options.outputRoot || 'test-results');
    const temporaryRoot = fs.mkdtempSync(path.join(options.temporaryParent || os.tmpdir(), 'webssh-e2e-group-'));
    const children = new Set();
    const terminationTasks = [];
    let failed = false;
    let interrupted = false;
    const interrupt = () => {
        interrupted = true;
        failed = true;
        for (const child of children) {
            try {
                terminationTasks.push(Promise.resolve(killTree(child)).catch(error => {
                    failed = true;
                    console.error(error.message);
                }));
            } catch (error) { console.error(error.message); }
        }
    };
    signals.on('SIGINT', interrupt);
    signals.on('SIGTERM', interrupt);
    const runLane = (lane, phase = 'all') => new Promise(resolve => {
            if (interrupted) { resolve(); return; }
            let child;
            try {
                const phaseName = phase === 'all' ? lane.name : `${lane.name}-${phase}`;
                const temporaryDirectory = path.join(temporaryRoot, phaseName);
                fs.mkdirSync(temporaryDirectory);
                child = spawnChild(process.execPath, [runner, `--shard=${lane.shard}`, ...(phase === 'all' ? [] : [`--phase=${phase}`])], {
                    cwd: process.cwd(),
                    env: {
                        ...process.env,
                        WEBSSH_E2E_PORT: String(lane.port),
                        WEBSSH_E2E_SHARD: lane.shard,
                        WEBSSH_E2E_OUTPUT_DIR: path.join(outputRoot, phaseName),
                        WEBSSH_E2E_TIMING_FILE: path.join(outputRoot, `e2e-timing-${phaseName}.json`),
                        WEBSSH_E2E_FAST_HASHING: '1',
                        BACKUP_TEMP_DIR: path.join(temporaryDirectory, 'backups'),
                        TRANSFER_TEMP_DIR: path.join(temporaryDirectory, 'transfers'),
                        TMPDIR: temporaryDirectory, TMP: temporaryDirectory, TEMP: temporaryDirectory,
                    },
                    stdio: 'inherit',
                    detached: process.platform !== 'win32',
                    windowsHide: true,
                });
            } catch (error) {
                failed = true;
                console.error(error.message);
                resolve();
                return;
            }
            children.add(child);
            child.once('error', error => {
                failed = true;
                console.error(error.message);
                children.delete(child);
                resolve();
            });
            child.once('close', (code, signal) => {
                if (code !== 0 || signal) failed = true;
                children.delete(child);
                resolve();
            });
        });
    try {
        // A 20-terminal renderer/transport workload needs the runner's CPU.
        // Run only their resource cases first, then every lane's remaining cases.
        const exclusiveLanes = plan.filter(lane => exclusive.has(lane.shard));
        const parallelLanes = plan;
        console.log(`E2E resource schedule: exclusive [${exclusiveLanes.map(lane => lane.shard).join(', ')}], `
            + `then ${parallelLanes.length} parallel lanes.`);
        for (const lane of exclusiveLanes) await runLane(lane, 'exclusive');
        await Promise.all(parallelLanes.map(lane => runLane(lane, exclusive.has(lane.shard) ? 'shared' : 'all')));
    } finally {
        await Promise.all(terminationTasks);
        signals.removeListener('SIGINT', interrupt);
        signals.removeListener('SIGTERM', interrupt);
        fs.rmSync(temporaryRoot, { recursive: true, force: true });
    }
    return failed ? 1 : 0;
}

async function main(argv, options = {}) {
    const config = parseArguments(argv);
    const discover = options.discover || require('./run-e2e-ci').discover;
    const baseline = require('../tests/e2e/timing-baseline.json');
    const exclusiveShards = classifyExclusiveShards(discover(), config.groups * config.lanes, baseline);
    return (options.runGroup || runGroup)(config, { exclusiveShards });
}

if (require.main === module) {
    Promise.resolve().then(() => main(process.argv.slice(2)))
        .then(code => { process.exitCode = code; })
        .catch(error => { console.error(error.message); process.exitCode = 1; });
}

module.exports = { main, classifyExclusiveShards, parseArguments, planGroup, runGroup, terminateTree, terminateLinuxTree, assertSupportedPlatform };
