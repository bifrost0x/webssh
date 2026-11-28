// Refreshes tests/e2e/go-suite-timing.json, the measured duration of every
// Go suite spec that run-go-suite.js --shards balances by.
//   node scripts/refresh-go-suite-timing.js <run directory | report.json>...
// A run directory is the output directory of run-go-suite.js; its shard
// reports (shard-*/report*.json, Playwright JSON reporter) are read. The
// timing reports of tests/e2e/timing-reporter.js are accepted as well.
// Measured specs replace their old value, specs without a measurement
// keep theirs, and specs no longer in go-suite.json are dropped.
const fs = require('node:fs');
const path = require('node:path');
const {testsOf} = require('../tests/e2e/go-suite-report');

const ROOT = path.resolve(__dirname, '..');
const TIMING = path.join(ROOT, 'tests', 'e2e', 'go-suite-timing.json');

function reportFiles(input) {
    if (!fs.statSync(input).isDirectory()) return [input];
    const files = [];
    for (const entry of fs.readdirSync(input, {withFileTypes: true})) {
        if (!entry.isDirectory() || !/^shard-\d+$/.test(entry.name)) continue;
        const dir = path.join(input, entry.name);
        for (const name of fs.readdirSync(dir)) if (/^report(-\w+)?\.json$/.test(name)) files.push(path.join(dir, name));
    }
    if (!files.length) throw new Error(`${input}: no shard reports`);
    return files;
}

// Seconds per spec file name of one report. Exported for tests/js.
function specSeconds(report) {
    const seconds = {};
    const add = (file, ms) => {
        const name = file.replaceAll('\\', '/').replace(/^.*tests\/e2e\//, '');
        seconds[name] = (seconds[name] || 0) + ms / 1000;
    };
    if (report.version === 1 && Array.isArray(report.tests)) {
        for (const test of report.tests) add(test.identity.split('::')[0], test.durationMs);
    } else {
        for (const test of testsOf(report)) add(test.file, test.durationMs);
    }
    return seconds;
}

function refresh(current, reports, suiteFiles) {
    const measured = {};
    for (const report of reports) {
        for (const [name, value] of Object.entries(specSeconds(report))) {
            if (Object.hasOwn(measured, name)) throw new Error(`${name} is measured twice`);
            measured[name] = value;
        }
    }
    const specs = {};
    for (const name of [...suiteFiles].sort()) {
        const value = Object.hasOwn(measured, name) ? measured[name] : current.specs?.[name];
        if (value !== undefined) specs[name] = Math.round(value * 10) / 10;
    }
    return {
        description: current.description,
        measured: new Date().toISOString().slice(0, 10),
        specs,
    };
}

function main(argv) {
    if (!argv.length) throw new Error('usage: node scripts/refresh-go-suite-timing.js <run directory | report.json>...');
    const suite = JSON.parse(fs.readFileSync(path.join(ROOT, 'tests', 'e2e', 'go-suite.json'), 'utf8'));
    const current = JSON.parse(fs.readFileSync(TIMING, 'utf8'));
    const reports = argv.flatMap(reportFiles).map(file => JSON.parse(fs.readFileSync(file, 'utf8')));
    const next = refresh(current, reports, suite.specs.map(spec => spec.file));
    fs.writeFileSync(TIMING, `${JSON.stringify(next, null, 2)}\n`);
    console.log(`${Object.keys(next.specs).length} specs in ${path.relative(ROOT, TIMING)}`);
}

if (require.main === module) {
    try {
        main(process.argv.slice(2));
    } catch (error) {
        console.error(error.message);
        process.exitCode = 1;
    }
}

module.exports = {refresh, specSeconds};
