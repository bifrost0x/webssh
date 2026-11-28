// The shorter selections of the Go suite (go-suite-tiers.json): the smoke
// tier and the specs of the areas a git range changed.
const {spawnSync} = require('node:child_process');
const path = require('node:path');
const {specName} = require('./go-suite-shards');

// A glob with * inside one path segment and ** across segments.
function globPattern(glob) {
    let source = '';
    for (let index = 0; index < glob.length; index += 1) {
        const char = glob[index];
        if (char === '*' && glob[index + 1] === '*') {
            source += '.*';
            index += 1;
            if (glob[index + 1] === '/') index += 1;
        } else if (char === '*') {
            source += '[^/]*';
        } else {
            source += char.replace(/[.+?^${}()|[\]\\]/g, '\\$&');
        }
    }
    return new RegExp(`^${source}$`);
}

const matches = (glob, value) => globPattern(glob).test(value);

// Checks the file against the specs of go-suite.json. Exported for tests/js.
function validate(tiers, suiteFiles) {
    const known = new Set(suiteFiles);
    const seen = new Set();
    for (const entry of tiers.smoke) {
        if (!known.has(entry.file)) throw new Error(`go-suite-tiers.json: smoke spec ${entry.file} is not in go-suite.json`);
        if (typeof entry.reason !== 'string' || !entry.reason.trim()) throw new Error(`go-suite-tiers.json: smoke spec ${entry.file} needs a reason`);
        if (seen.has(entry.file)) throw new Error(`go-suite-tiers.json: smoke spec ${entry.file} listed twice`);
        seen.add(entry.file);
    }
    for (const area of tiers.areas) {
        if (!area.name || !area.paths?.length || !area.specs?.length) throw new Error('go-suite-tiers.json: an area needs a name, paths and specs');
        for (const glob of area.specs) {
            if (!suiteFiles.some(file => matches(glob, file))) throw new Error(`go-suite-tiers.json: area ${area.name}: ${glob} matches no spec`);
        }
    }
}

// Spec names (as in go-suite.json) of the areas the changed paths touch.
// Returns the names and the paths no area claims, so a run can say what
// it did not map.
function changedSpecs(tiers, suiteFiles, changed) {
    const selected = new Set();
    const unmapped = [];
    for (const file of changed) {
        // Go tests cannot change what the browser sees.
        if (file.endsWith('_test.go')) continue;
        let claimed = false;
        const name = file.startsWith('tests/e2e/') ? file.slice('tests/e2e/'.length) : null;
        if (name && suiteFiles.includes(name)) {
            selected.add(name);
            claimed = true;
        }
        for (const area of tiers.areas) {
            if (!area.paths.some(glob => matches(glob, file))) continue;
            claimed = true;
            for (const spec of suiteFiles) if (area.specs.some(glob => matches(glob, spec))) selected.add(spec);
        }
        if (!claimed) unmapped.push(file);
    }
    return {specs: [...selected], unmapped};
}

// Narrows the plan to the smoke specs plus the given extra names. Specs
// the plan leaves out (a capability the run did not enable) stay out.
function narrow(planned, names) {
    const wanted = new Set(names);
    const keep = files => files.filter(file => wanted.has(specName(file)));
    return {...planned, all: keep(planned.all), parallel: keep(planned.parallel), serial: keep(planned.serial)};
}

function gitChanged(range, {cwd = path.resolve(__dirname, '../..'), run = spawnSync} = {}) {
    // A range starting with - would be read as an option of git diff.
    if (!range || range.startsWith('-')) throw new Error('--changed needs a git range such as origin/go...HEAD');
    const result = run('git', ['diff', '--name-only', '--no-renames', range, '--'], {cwd, encoding: 'utf8'});
    if (result.error) throw result.error;
    if (result.status !== 0) throw new Error(`git diff ${range} failed: ${(result.stderr || '').trim()}`);
    return result.stdout.split('\n').map(line => line.trim()).filter(Boolean);
}

module.exports = {changedSpecs, gitChanged, globPattern, matches, narrow, validate};
