// Runs the main-suite specs selected for the Go server (go-suite.json)
// with the main configuration. The backend comes from
// WEBSSH_E2E_SERVER_COMMAND as for every other run of the main suite.
//   node tests/e2e/run-go-suite.js [--with passkeys,e2e_hooks] [--spec a.spec.js,b.spec.js]
//       [--tier smoke] [--changed <git range>] [--shards N | --shard i/N] [--workers N] [--screenshots] [--list]
//       [playwright options]
// --shards N splits the specs by their measured duration
// (go-suite-timing.json) into N shards that run in parallel. Every shard
// is its own Playwright run with its own backend, so it gets a fresh
// data directory and seed, its own port (WEBSSH_E2E_PORT + index), its
// own temporary directory and its own output directory. --shard i/N runs
// only shard i of that split, for one shard per CI job. Specs that change
// installation-wide settings therefore never see another shard's changes.
// Within a shard, --workers above 1 runs the specs marked serial
// afterwards on one worker, because they change the stored settings of a
// seed account other specs read. --tier smoke runs the curated selection
// of go-suite-tiers.json, --changed adds the specs of the areas a git
// range touched. --spec runs only the named files of the plan. Every run
// ends with a merged summary (summary.txt and summary.json in the output
// directory). --screenshots keeps the review screenshots that are never
// compared (helpers.js reviewScreenshot). SIGINT or SIGTERM (for example from timeout) stops every
// Playwright run and its backend, so all ports are free again afterwards.
const {spawn} = require('node:child_process');
const fs = require('node:fs');
const net = require('node:net');
const os = require('node:os');
const path = require('node:path');
const {terminateTree} = require('../../scripts/run-e2e-ci-parallel');
const {ensureOutputDir} = require('./output-dir');
const shards = require('./go-suite-shards');
const tiers = require('./go-suite-tiers');
const report = require('./go-suite-report');

const ROOT = path.resolve(__dirname, '../..');

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
        if (spec.go_only !== undefined && (typeof spec.go_only !== 'string' || !spec.go_only.trim())) throw new Error(`${spec.file}: go_only needs a reason`);
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
    command = 'npx', cwd = ROOT, env = process.env, stdio = 'inherit'} = {}) {
    return new Promise(resolve => {
        const child = spawnChild(command, argv, {stdio, cwd, env, detached: true});
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

// Takes "--name value" out of args; returns the value or undefined.
function take(args, name) {
    const index = args.indexOf(name);
    if (index < 0) return undefined;
    const value = args[index + 1];
    if (value === undefined || value.startsWith('--')) throw new Error(`${name} needs a value`);
    args.splice(index, 2);
    return value;
}

function count(value, name) {
    if (value === undefined) return 1;
    const number = Number(value);
    if (!Number.isSafeInteger(number) || number < 1) throw new Error(`${name} needs a positive number`);
    return number;
}

function portFree(port) {
    return new Promise(resolve => {
        const server = net.createServer();
        server.once('error', () => resolve(false));
        server.listen(port, '127.0.0.1', () => server.close(() => resolve(true)));
    });
}

// --shards N and --shard i/N: how many shards the split has and which
// one runs (null for all). Exported for tests/js.
function shardOptions(shardCount, only) {
    if (only === undefined) return {count: shardCount, current: null};
    const match = /^(\d+)\/(\d+)$/.exec(only);
    const [index, total] = match ? [Number(match[1]), Number(match[2])] : [0, 0];
    if (!match || index < 1 || index > total) throw new Error('--shard needs <index>/<total>, for example 3/8');
    if (shardCount !== 1 && shardCount !== total) throw new Error('--shard i/N and --shards M disagree');
    return {count: total, current: index};
}

// Narrows the plan to what the options ask for. Exported for tests/js.
function choose(planned, {spec, tier, changed}, {tierFile, suiteNames, changedFiles = tiers.gitChanged} = {}) {
    if (tier !== undefined && tier !== 'smoke' && tier !== 'full') throw new Error('--tier is smoke or full');
    if (spec && (tier === 'smoke' || changed)) throw new Error('--spec cannot be combined with --tier smoke or --changed');
    if (spec) return {planned: select(planned, spec), notes: []};
    if (tier !== 'smoke' && !changed) return {planned, notes: []};
    tiers.validate(tierFile, suiteNames);
    const names = planned.all.map(shards.specName);
    const wanted = tierFile.smoke.map(entry => entry.file);
    const notes = [];
    if (changed) {
        const {specs, unmapped} = tiers.changedSpecs(tierFile, names, changedFiles(changed));
        wanted.push(...specs);
        notes.push(`--changed ${changed}: ${specs.length} specs from the changed areas`);
        if (unmapped.length) notes.push(`no area for ${unmapped.length} changed paths: ${unmapped.slice(0, 10).join(', ')}${unmapped.length > 10 ? ', ...' : ''}`);
    }
    return {planned: tiers.narrow(planned, wanted), notes};
}

async function main() {
    const suite = JSON.parse(fs.readFileSync(path.join(__dirname, 'go-suite.json'), 'utf8'));
    const args = process.argv.slice(2);
    const enabled = new Set((take(args, '--with') || '').split(',').filter(Boolean));
    const workers = count(take(args, '--workers'), '--workers');
    const {count: shardCount, current} = shardOptions(count(take(args, '--shards'), '--shards'), take(args, '--shard'));
    if (args.some(arg => arg.startsWith('--shard'))) throw new Error('use --shards N or --shard i/N; Playwright sharding would bypass the isolated backends');
    const screenshots = args.includes('--screenshots');
    if (screenshots) args.splice(args.indexOf('--screenshots'), 1);
    const options = {spec: take(args, '--spec'), tier: take(args, '--tier'), changed: take(args, '--changed')};
    if (options.spec === '') throw new Error('--spec needs at least one spec file');
    const tierFile = JSON.parse(fs.readFileSync(path.join(__dirname, 'go-suite-tiers.json'), 'utf8'));
    const full = plan(suite, enabled, file => fs.existsSync(path.join(__dirname, file)));
    const {planned, notes} = choose(full, options, {tierFile, suiteNames: suite.specs.map(spec => spec.file)});
    if (!planned.all.length) throw new Error('the selection is empty');
    const timing = JSON.parse(fs.readFileSync(path.join(__dirname, 'go-suite-timing.json'), 'utf8'));
    const assigned = shards.assign(planned.all, shardCount, timing).map((shard, index) => ({...shard, number: index + 1}));
    if (current > assigned.length) throw new Error(`the selection has only ${assigned.length} shard(s)`);
    // --shard i/N runs one shard of the split, for example one per CI job.
    const running = current ? [assigned[current - 1]] : assigned;
    const listing = args.includes('--list');
    const portBase = Number(process.env.WEBSSH_E2E_PORT || 4173);
    if (!Number.isSafeInteger(portBase) || portBase < 1 || portBase + running.length - 1 > 65535) throw new Error('invalid WEBSSH_E2E_PORT');
    for (let index = 0; index < running.length; index += 1) {
        if (!await portFree(portBase + index)) throw new Error(`port ${portBase + index} is in use; set WEBSSH_E2E_PORT to a free base port`);
    }

    const outputRoot = path.resolve(ensureOutputDir());
    const scratch = fs.mkdtempSync(path.join(os.tmpdir(), 'webssh-go-suite-'));
    const escape = value => value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
    let interrupted = false;
    const stop = () => { interrupted = true; };
    process.on('SIGINT', stop);
    process.on('SIGTERM', stop);
    for (const note of notes) console.log(note);
    console.log(`Go suite: ${planned.all.length} specs on ${assigned.length} shard(s)${current ? `, running shard ${current}` : ''}, output in ${outputRoot}`);
    const runShard = async (shard, index) => {
        const {number} = shard;
        const dir = path.join(outputRoot, `shard-${number}`);
        const tmp = path.join(scratch, `shard-${number}`);
        fs.mkdirSync(dir, {recursive: true});
        fs.mkdirSync(tmp);
        const log = path.join(dir, 'output.log');
        const own = running.length > 1;
        console.log(`  shard ${number}: ${shard.files.length} specs, about ${Math.ceil(shard.seconds / 60)} min, port ${portBase + index}${own ? `, log ${log}` : ''}`);
        const started = Date.now();
        const result = {index: number, specs: shard.files.length, log, reports: [], exitCode: 0};
        for (const phase of shards.phases(shard.files, planned.serial, workers)) {
            if (interrupted) break;
            const suffix = phase.name === 'all' ? '' : `-${phase.name}`;
            const jsonReport = path.join(dir, `report${suffix}.json`);
            result.reports.push(jsonReport);
            const command = ['playwright', 'test', ...phase.files, `--workers=${phase.workers}`];
            if (planned.excluded.length) command.push('--grep-invert', planned.excluded.map(escape).join('|'));
            command.push(...args);
            const fd = own ? fs.openSync(log, 'a') : null;
            try {
                const code = await runPlaywright(command, {
                    stdio: own ? ['ignore', fd, fd] : 'inherit',
                    env: {
                        ...process.env,
                        WEBSSH_E2E_PORT: String(portBase + index),
                        WEBSSH_E2E_SHARD: `${number}/${assigned.length}`,
                        WEBSSH_E2E_PHASE: phase.name,
                        WEBSSH_E2E_OUTPUT_DIR: path.join(dir, `results${suffix}`),
                        WEBSSH_E2E_TIMING_FILE: path.join(dir, `timing${suffix}.json`),
                        WEBSSH_E2E_JSON_REPORT: jsonReport,
                        // Review screenshots are never compared; --screenshots keeps them.
                        WEBSSH_E2E_REVIEW_SCREENSHOTS: screenshots ? '1' : '0',
                        TMPDIR: tmp, TMP: tmp, TEMP: tmp,
                    },
                });
                if (code === 130) interrupted = true;
                if (code !== 0 && !result.exitCode) result.exitCode = code;
            } finally {
                if (fd !== null) fs.closeSync(fd);
            }
        }
        result.wallMs = Date.now() - started;
        if (own) console.log(`  shard ${number} finished in ${Math.round(result.wallMs / 1000)} s, exit ${result.exitCode}`);
        return result;
    };
    let results;
    try {
        results = await Promise.all(running.map(runShard));
    } finally {
        process.off('SIGINT', stop);
        process.off('SIGTERM', stop);
        // The backends remove their data directories on a graceful stop;
        // this also catches what a killed backend left behind.
        fs.rmSync(scratch, {recursive: true, force: true});
    }
    if (interrupted) return 130;
    if (listing) return results.some(result => result.exitCode) ? 1 : 0;
    const summary = report.summarize(results);
    process.stdout.write(report.write(outputRoot, summary));
    return summary.ok && results.every(result => result.exitCode === 0) ? 0 : 1;
}

if (require.main === module) {
    main().then(code => process.exit(code), error => {
        console.error(error.message);
        process.exit(2);
    });
}

module.exports = {plan, select, choose, shardOptions, runPlaywright, PACKAGES};
