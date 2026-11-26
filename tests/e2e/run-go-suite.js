// Runs the main-suite specs selected for the Go server (go-suite.json)
// with the main configuration. The backend comes from
// WEBSSH_E2E_SERVER_COMMAND as for every other run of the main suite.
//   node tests/e2e/run-go-suite.js [--with passkeys,e2e_hooks] [--list] [--workers N] [playwright options]
// With --workers above 1, the specs marked serial run afterwards in a
// second invocation on one worker, because they change the stored
// settings of a seed account other specs read.
const {spawnSync} = require('node:child_process');
const fs = require('node:fs');
const path = require('node:path');

// The packages of the M2 plan (section 3) that can unlock an excluded test.
const PACKAGES = new Set(['ID1', 'ID2', 'ID3', 'ID4', 'NW1', 'NW2', 'RT1', 'SM0', 'TM1', 'HO1', 'HO2', 'HO3',
    'FS1', 'FS2', 'FS3', 'VA1', 'TR1', 'CM1', 'AU1', 'AU2', 'OP1', 'OP2', 'OP3', 'PF1', 'PF2', 'PF3', 'FE1', 'MG1',
    'DOC1']);
const SERIAL_ACCOUNTS = new Set(['e2e_admin']);

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
            if (entry.requires ? !(entry.requires in suite.requires) : !PACKAGES.has(entry.package)) {
                throw new Error(`${spec.file}: "${entry.title}" names no package that unlocks it`);
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

function main() {
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
    const {all, parallel, serial, excluded} = plan(suite, enabled, file => fs.existsSync(path.join(__dirname, file)));
    const escape = value => value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
    const run = (files, count) => {
        const command = ['playwright', 'test', ...files, `--workers=${count}`];
        if (excluded.length) command.push('--grep-invert', excluded.map(escape).join('|'));
        command.push(...args);
        return spawnSync('npx', command, {stdio: 'inherit', cwd: path.resolve(__dirname, '../..')}).status ?? 1;
    };
    if (workers === 1) process.exit(run(all, 1));
    const first = run(parallel, workers);
    const second = run(serial, 1);
    process.exit(first || second);
}

if (require.main === module) main();

module.exports = {plan, PACKAGES};
