// Runs the main-suite specs selected for the Go preview (go-subset.json)
// with the main configuration. The backend comes from
// WEBSSH_E2E_SERVER_COMMAND as for every other run of the main suite.
//   node tests/e2e/m1/run-go-subset.js [--with passkeys,e2e_hooks] [--list] [playwright options]
const {spawnSync} = require('node:child_process');
const fs = require('node:fs');
const path = require('node:path');

const subset = JSON.parse(fs.readFileSync(path.join(__dirname, 'go-subset.json'), 'utf8'));
const args = process.argv.slice(2);
let enabled = new Set();
const withIndex = args.indexOf('--with');
if (withIndex >= 0) {
    enabled = new Set((args[withIndex + 1] || '').split(',').filter(Boolean));
    args.splice(withIndex, 2);
}
const unknown = [...enabled].filter(name => !(name in subset.requires));
if (unknown.length) throw new Error(`unknown requirement: ${unknown.join(', ')}`);

const available = entry => !entry.requires || enabled.has(entry.requires);
const files = [];
const excluded = [];
for (const spec of subset.specs) {
    if (!available(spec)) continue;
    const file = path.join('tests', 'e2e', spec.file);
    if (!fs.existsSync(path.join(__dirname, '..', spec.file))) throw new Error(`missing spec ${spec.file}`);
    files.push(file);
    for (const entry of spec.exclude) {
        if (!entry.requires || !available(entry)) excluded.push(entry.title);
    }
}
const escape = value => value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
const command = ['playwright', 'test', ...files];
if (excluded.length) command.push('--grep-invert', excluded.map(escape).join('|'));
command.push(...args);
const result = spawnSync('npx', command, {stdio: 'inherit', cwd: path.resolve(__dirname, '../../..')});
process.exit(result.status ?? 1);
