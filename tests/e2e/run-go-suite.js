// Runs the main-suite specs selected for the Go server (go-suite.json)
// with the main configuration. The backend comes from
// WEBSSH_E2E_SERVER_COMMAND as for every other run of the main suite.
//   node tests/e2e/run-go-suite.js [--with passkeys,e2e_hooks] [--spec a.spec.js,b.spec.js] [--list] [--workers N] [playwright options]
// With --workers above 1, the specs marked serial run afterwards in a
// second invocation on one worker, because they change the stored
// settings of a seed account other specs read. --spec runs only the named
// files of the plan. SIGINT or SIGTERM (for example from timeout) stops
// Playwright and its backend, so the port is free again afterwards.
const {spawn} = require('node:child_process');
const fs = require('node:fs');
const path = require('node:path');
const {terminateTree} = require('../../scripts/run-e2e-ci-parallel');

// The packages of the M2 plan (section 3) that can unlock an excluded test.
const PACKAGES = new Set(['ID1', 'ID2', 'ID3', 'ID4', 'NW1', 'NW2', 'RT1', 'SM0', 'TM1', 'HO1', 'HO2', 'HO3',
    'FS1', 'FS2', 'FS3', 'VA1', 'TR1', 'CM1', 'AU1', 'AU2', 'OP1', 'OP2', 'OP3', 'PF1', 'PF2', 'PF3', 'FE1', 'MG1',
    'DOC1']);
const SERIAL_ACCOUNTS = new Set(['e2e_admin']);
// A decision that drops what a test checks (an ADR under docs/adr or a
// product decision D-xx); such a test stays out of the Go suite for good.
const DECISION = /^(ADR \d{4}|D-\d{2})$/;

// Checks the file and returns the Playwright file lists and the titles to
// leave out. Exported for tests/js.
function plan(suite, enabled, specExists) {
    const unknown = [...enabled].filter(name => !(name in suite.requires));
    if (unknown.length) throw new Error(`unknown requirement: ${unknown.join(', ')}`);
    const available = entry => !entry.requires || enabled.has(entry.requires);
    const all = [];
    const parallel = [];
    const serial = [];
    const excluded = [];
    const seen = new Set();
    for (const spec of suite.specs) {
        if (seen.has(spec.file)) throw new Error(`spec listed twice: ${spec.file}`);
        seen.add(spec.file);
        if (spec.requires && !(spec.requires in suite.requires)) throw new Error(`${spec.file}: unknown requirement ${spec.requires}`);
        if (spec.serial !== undefined && !SERIAL_ACCOUNTS.has(spec.serial)) throw new Error(`${spec.file}: unknown serial account ${spec.serial}`);
        for (const entry of spec.exclude) {
            if (!entry.title || !entry.reason) throw new Error(`${spec.file}: an excluded test needs a title and a reason`);
            const unlocked = entry.requires ? entry.requires in suite.requires : PACKAGES.has(entry.package);
            const decided = entry.decision !== undefined && DECISION.test(entry.decision) && !entry.requires && !entry.package;
            if (!(entry.decision === undefined ? unlocked : decided)) {
                throw new Error(`${spec.file}: "${entry.title}" names neither a decision nor what unlocks it`);
            }
        }
        if (!available(spec)) continue;
        if (!specExists(spec.file)) throw new Error(`missing spec ${spec.file}`);
        const file = path.join('tests', 'e2e', spec.file);
        all.push(file);
        (spec.serial ? serial : parallel).push(file);
        for (const entry of spec.exclude) {
            if (!entry.requires || !available(entry)) excluded.push(entry.title);
        }
    }
    return {all, parallel, serial, excluded};
}

// Narrows the planned files to the named specs. A name outside the plan
// (unknown, or left out by a missing --with) is an error, not an empty run.
function select(planned, names) {
    if (!names) return planned;
    const wanted = names.split(',').filter(Boolean).map(name => path.join('tests', 'e2e', name));
    if (!wanted.length) throw new Error('--spec needs at least one spec file');
    const missing = wanted.filter(file => !planned.all.includes(file));
    if (missing.length) throw new Error(`not in the Go suite plan: ${missing.join(', ')}`);
    const keep = files => files.filter(file => wanted.includes(file));
    return {...planned, all: keep(planned.all), parallel: keep(planned.parallel), serial: keep(planned.serial)};
}

// Runs one Playwright invocation in its own process group. A signal to
// the runner is passed on to the group as SIGINT, which lets Playwright
// stop its backend gracefully. After graceMs the group and the tree under
// its leader are killed: a backend that ignores SIGINT would otherwise
// keep the port, also after the leader exited. Resolves with the exit
// status (130 after a signal).
function runPlaywright(argv, {spawnChild = spawn, signals = process, killTree = terminateTree, graceMs = 15_000,
    command = 'npx', cwd = path.resolve(__dirname, '../..')} = {}) {
    return new Promise(resolve => {
        const child = spawnChild(command, argv, {stdio: 'inherit', cwd, detached: true});
        const group = signal => {
            try { process.kill(-child.pid, signal); } catch { /* the group is gone */ }
        };
        let interrupted = false;
        let timer;
        const interrupt = () => {
            if (interrupted) return;
            interrupted = true;
            group('SIGINT');
            timer = setTimeout(() => {
                Promise.resolve(killTree(child)).catch(error => console.error(error.message));
                group('SIGKILL');
            }, graceMs);
        };
        signals.on('SIGINT', interrupt);
        signals.on('SIGTERM', interrupt);
        child.on('close', code => {
            signals.off('SIGINT', interrupt);
            signals.off('SIGTERM', interrupt);
            clearTimeout(timer);
            if (interrupted) group('SIGKILL');
            resolve(interrupted ? 130 : code ?? 1);
        });
    });
}

async function main() {
    const suite = JSON.parse(fs.readFileSync(path.join(__dirname, 'go-suite.json'), 'utf8'));
    const args = process.argv.slice(2);
    let enabled = new Set();
    const withIndex = args.indexOf('--with');
    if (withIndex >= 0) {
        enabled = new Set((args[withIndex + 1] || '').split(',').filter(Boolean));
        args.splice(withIndex, 2);
    }
    let workers = 1;
    const workersIndex = args.indexOf('--workers');
    if (workersIndex >= 0) {
        workers = Number(args[workersIndex + 1]);
        if (!Number.isSafeInteger(workers) || workers < 1) throw new Error('--workers needs a positive number');
        args.splice(workersIndex, 2);
    }
    let only = null;
    const specIndex = args.indexOf('--spec');
    if (specIndex >= 0) {
        only = args[specIndex + 1] || '';
        args.splice(specIndex, 2);
    }
    const {all, parallel, serial, excluded} = select(plan(suite, enabled, file => fs.existsSync(path.join(__dirname, file))), only);
    const escape = value => value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
    const run = (files, count) => {
        const command = ['playwright', 'test', ...files, `--workers=${count}`];
        if (excluded.length) command.push('--grep-invert', excluded.map(escape).join('|'));
        command.push(...args);
        return runPlaywright(command);
    };
    if (workers === 1 || !parallel.length || !serial.length) process.exit(await run(all, workers === 1 ? 1 : (serial.length ? 1 : workers)));
    const first = await run(parallel, workers);
    if (first === 130) process.exit(first);
    const second = await run(serial, 1);
    process.exit(first || second);
}

if (require.main === module) {
    main().catch(error => {
        console.error(error.message);
        process.exit(2);
    });
}

module.exports = {plan, select, runPlaywright, PACKAGES};
