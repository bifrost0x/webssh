const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { spawn, spawnSync } = require('node:child_process');

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
        const current = (group - 1) * lanes + index + 1;
        const total = groups * lanes;
        return { shard: `${current}/${total}`, name: `shard-${current}-of-${total}`, port: portBase + index };
    });
}

function readLinuxProcess(pid) {
    try {
        const stat = fs.readFileSync(`/proc/${pid}/stat`, 'utf8');
        // comm may contain spaces or parentheses; fields after its final ')' are stable.
        const fields = stat.slice(stat.lastIndexOf(')') + 2).trim().split(/\s+/);
        return { pid, parent: Number(fields[1]), startTime: fields[19] };
    } catch (error) {
        if (['ENOENT', 'ESRCH', 'EACCES'].includes(error.code)) return null;
        throw error;
    }
}

function terminateLinuxTree(pid, { readProcess = readLinuxProcess, listPids = () => fs.readdirSync('/proc').filter(name => /^\d+$/.test(name)).map(Number), signal = process.kill } = {}) {
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
}

function terminateTree(child) {
    if (!Number.isSafeInteger(child.pid) || child.pid <= 0) return;
    if (process.platform === 'win32') {
        // The runner uses synchronous children; killing only Node would leak its server.
        const result = spawnSync('taskkill', ['/PID', String(child.pid), '/T', '/F'], { stdio: 'ignore', windowsHide: true });
        if (result.error) throw result.error;
    } else if (process.platform === 'linux') {
        terminateLinuxTree(child.pid);
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
    const runner = options.runner || path.join(__dirname, 'run-e2e-ci.js');
    const spawnChild = options.spawn || spawn;
    const killTree = options.terminateTree || terminateTree;
    const signals = options.signals || process;
    const outputRoot = path.resolve(options.outputRoot || 'test-results');
    const temporaryRoot = fs.mkdtempSync(path.join(options.temporaryParent || os.tmpdir(), 'webssh-e2e-group-'));
    const children = new Set();
    let failed = false;
    let interrupted = false;
    const interrupt = () => {
        interrupted = true;
        failed = true;
        for (const child of children) {
            try { killTree(child); } catch (error) { console.error(error.message); }
        }
    };
    signals.on('SIGINT', interrupt);
    signals.on('SIGTERM', interrupt);
    try {
        await Promise.all(plan.map(lane => new Promise(resolve => {
            if (interrupted) { resolve(); return; }
            let child;
            try {
                const temporaryDirectory = path.join(temporaryRoot, lane.name);
                fs.mkdirSync(temporaryDirectory);
                child = spawnChild(process.execPath, [runner, `--shard=${lane.shard}`], {
                    cwd: process.cwd(),
                    env: {
                        ...process.env,
                        WEBSSH_E2E_PORT: String(lane.port),
                        WEBSSH_E2E_SHARD: lane.shard,
                        WEBSSH_E2E_OUTPUT_DIR: path.join(outputRoot, lane.name),
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
        })));
    } finally {
        signals.removeListener('SIGINT', interrupt);
        signals.removeListener('SIGTERM', interrupt);
        fs.rmSync(temporaryRoot, { recursive: true, force: true });
    }
    return failed ? 1 : 0;
}

if (require.main === module) {
    Promise.resolve().then(() => runGroup(parseArguments(process.argv.slice(2))))
        .then(code => { process.exitCode = code; })
        .catch(error => { console.error(error.message); process.exitCode = 1; });
}

module.exports = { parseArguments, planGroup, runGroup, terminateTree, terminateLinuxTree, assertSupportedPlatform };
