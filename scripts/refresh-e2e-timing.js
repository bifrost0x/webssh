const fs = require('node:fs');
const path = require('node:path');

const { DEFAULT_FALLBACK_SECONDS } = require('./e2e-sharding');
const { parseShard } = require('./e2e-sharding');
const { validateResourceInventory, isExclusiveTest } = require('./e2e-resources');

const BASELINE_PATH = path.join('tests', 'e2e', 'timing-baseline.json');

function buildBaseline(reports, sources) {
    if (reports.length === 0 || reports.length !== sources.length) {
        throw new Error('Timing refresh requires one source name per report.');
    }
    const shardCoordinates = [];
    const shardReports = new Map();
    for (let index = 0; index < reports.length; index += 1) {
        const report = reports[index];
        const source = sources[index];
        if (report.status !== 'passed') {
            throw new Error(`${source} is not a successful Playwright report.`);
        }
        if (!Number.isSafeInteger(report.discovered)
                || report.discovered !== report.tests?.length) {
            throw new Error(
                `${source} discovered ${report.discovered} tests but recorded `
                + `${report.tests?.length ?? 0}.`,
            );
        }
        for (const observed of report.tests) {
            const finalAttempt = observed.attempts?.at(-1);
            if (!finalAttempt || finalAttempt.status !== 'passed') {
                throw new Error(`${source} contains a test without a final passed attempt.`);
            }
        }
        const phase = report.phase ?? 'all';
        if (!['all', 'exclusive', 'shared'].includes(phase)) throw new Error(`${source} has an unknown timing phase.`);
        if (!report.shard && phase !== 'all') throw new Error('Phased timing reports require shard coordinates.');
        const identities = report.tests.map(test => test.identity);
        if (new Set(identities).size !== identities.length) throw new Error(`${source} contains duplicate test identities.`);
        if (report.shard) {
            if (report.discovered < 1) throw new Error(`${source} contains an empty shard phase.`);
            const coordinate = parseShard(report.shard);
            shardCoordinates.push(coordinate);
            const shardKey = `${coordinate.current}/${coordinate.total}`;
            const entries = shardReports.get(shardKey) || [];
            entries.push({report, phase});
            shardReports.set(shardKey, entries);
            if (phase !== 'all' && report.tests.some(test => isExclusiveTest(test) !== (phase === 'exclusive'))) {
                throw new Error(`${source} contains tests assigned to the wrong resource phase.`);
            }
        }
    }
    if (shardCoordinates.length > 0) {
        if (shardCoordinates.length !== reports.length) {
            throw new Error('Do not mix full-suite and sharded timing reports.');
        }
        const totals = new Set(shardCoordinates.map(shard => shard.total));
        const currents = new Set(shardCoordinates.map(shard => shard.current));
        const total = shardCoordinates[0].total;
        if (totals.size !== 1 || currents.size !== total) {
            throw new Error('Timing refresh requires one complete shard set with no duplicates.');
        }
        for (const entries of shardReports.values()) {
            const phases = entries.map(entry => entry.phase).sort();
            if (!(phases.length === 1 && phases[0] === 'all')
                    && JSON.stringify(phases) !== JSON.stringify(['exclusive', 'shared'])) {
                throw new Error('Each shard requires one all report or a complete exclusive/shared phase pair.');
            }
        }
        const tests = reports.flatMap(report => report.tests);
        if (new Set(tests.map(test => test.identity)).size !== tests.length) {
            throw new Error('Sharded timing reports contain overlapping test identities.');
        }
        if (reports.some(report => report.phase === 'exclusive' || report.phase === 'shared')) {
            validateResourceInventory(tests);
        }
    }

    const observations = new Map();
    for (const report of reports) {
        for (const test of report.tests || []) {
            if (!test.identity || !Number.isFinite(test.durationMs) || test.durationMs <= 0) {
                throw new Error('Timing reports require positive durationMs and stable identities.');
            }
            const values = observations.get(test.identity) || [];
            values.push(test.durationMs / 1000);
            observations.set(test.identity, values);
        }
    }
    if (observations.size === 0) {
        throw new Error('Timing reports did not contain any completed tests.');
    }

    const tests = {};
    for (const identity of [...observations.keys()].sort((a, b) => a.localeCompare(b, 'en'))) {
        const values = observations.get(identity);
        const average = values.reduce((total, value) => total + value, 0) / values.length;
        tests[identity] = Number(average.toFixed(3));
    }
    return {
        version: 1,
        fallbackSeconds: DEFAULT_FALLBACK_SECONDS,
        sources,
        tests,
    };
}

function defaultReportFiles() {
    const directory = path.resolve('test-results');
    if (!fs.existsSync(directory)) return [];
    return fs.readdirSync(directory)
        .filter(name => /^e2e-timing-.*\.json$/.test(name))
        .sort()
        .map(name => path.join(directory, name));
}

function main(argv) {
    const reportFiles = argv.length > 0 ? argv.map(file => path.resolve(file)) : defaultReportFiles();
    if (reportFiles.length === 0) {
        throw new Error('No E2E timing reports found. Pass report JSON paths explicitly.');
    }
    const reports = reportFiles.map(file => JSON.parse(fs.readFileSync(file, 'utf8')));
    const sources = reportFiles.map(file => path.relative(process.cwd(), file).replaceAll('\\', '/'));
    const baseline = buildBaseline(reports, sources);
    fs.writeFileSync(BASELINE_PATH, `${JSON.stringify(baseline, null, 2)}\n`, 'utf8');
    console.log(`Updated ${BASELINE_PATH} with ${Object.keys(baseline.tests).length} tests.`);
}

if (require.main === module) {
    try {
        main(process.argv.slice(2));
    } catch (error) {
        console.error(error.message);
        process.exitCode = 1;
    }
}

module.exports = { buildBaseline };
