const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const test = require('node:test');

const TimingReporter = require('../../tests/e2e/timing-reporter');
const { buildBaseline } = require('../../scripts/refresh-e2e-timing');

test('timing reporter persists attempts when the run fails', () => {
    const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'webssh-e2e-timing-'));
    const outputFile = path.join(directory, 'e2e-timing-shard-1-of-2.json');
    const previousPhase = process.env.WEBSSH_E2E_PHASE;
    try {
        process.env.WEBSSH_E2E_PHASE = 'shared';
        const reporter = new TimingReporter({ outputFile });
        const testCase = {
            location: { file: path.join(process.cwd(), 'tests/e2e/example.spec.js') },
            titlePath: () => ['', 'example.spec.js', 'outer suite', 'example test'],
        };
        reporter.onBegin({ workers: 1 }, { allTests: () => [testCase] });
        reporter.onTestEnd(testCase, { duration: 1250, retry: 0, status: 'failed' });
        reporter.onTestEnd(testCase, { duration: 750, retry: 1, status: 'passed' });
        reporter.onEnd({ status: 'failed' });

        const report = JSON.parse(fs.readFileSync(outputFile, 'utf8'));
        assert.equal(report.status, 'failed');
        assert.equal(report.phase, 'shared');
        assert.equal(report.tests.length, 1);
        assert.equal(
            report.tests[0].identity,
            'tests/e2e/example.spec.js::outer suite::example test',
        );
        assert.deepEqual(report.tests[0].attempts, [
            { retry: 0, status: 'failed', durationMs: 1250 },
            { retry: 1, status: 'passed', durationMs: 750 },
        ]);
        assert.equal(report.tests[0].durationMs, 2000);
    } finally {
        if (previousPhase === undefined) delete process.env.WEBSSH_E2E_PHASE;
        else process.env.WEBSSH_E2E_PHASE = previousPhase;
        fs.rmSync(directory, { recursive: true, force: true });
    }
});

test('baseline refresh averages observed durations and keeps a conservative fallback', () => {
    const baseline = buildBaseline([
        {
            status: 'passed',
            discovered: 2,
            shard: null,
            tests: [
                { identity: 'tests/e2e/a.spec.js::one', durationMs: 1500,
                    attempts: [{ status: 'passed' }] },
                { identity: 'tests/e2e/b.spec.js::two', durationMs: 5000,
                    attempts: [{ status: 'passed' }] },
            ],
        },
        {
            status: 'passed',
            discovered: 1,
            shard: null,
            tests: [
                { identity: 'tests/e2e/a.spec.js::one', durationMs: 2500,
                    attempts: [{ status: 'passed' }] },
            ],
        },
    ], ['first.json', 'second.json']);

    assert.equal(baseline.fallbackSeconds, 30);
    assert.deepEqual(baseline.tests, {
        'tests/e2e/a.spec.js::one': 2,
        'tests/e2e/b.spec.js::two': 5,
    });
    assert.deepEqual(baseline.sources, ['first.json', 'second.json']);
});

test('baseline refresh rejects failed, incomplete and partial shard reports', () => {
    const completeTest = {
        identity: 'tests/e2e/a.spec.js::one',
        durationMs: 1000,
        attempts: [{ retry: 0, status: 'passed', durationMs: 1000 }],
    };
    assert.throws(() => buildBaseline([{
        status: 'failed', discovered: 1, shard: null, tests: [completeTest],
    }], ['failed.json']), /successful/i);
    assert.throws(() => buildBaseline([{
        status: 'passed', discovered: 2, shard: null, tests: [completeTest],
    }], ['incomplete.json']), /discovered 2.*recorded 1/i);
    assert.throws(() => buildBaseline([{
        status: 'passed', discovered: 1, shard: '1/2', tests: [completeTest],
    }], ['shard-1.json']), /complete shard set/i);
});

function phasedShardReports() {
    const reports = Array.from({length: 32}, (_, i) => ({
        status: 'passed', discovered: 1, shard: `${i + 1}/32`, phase: 'all',
        tests: [{identity: `tests/e2e/normal.spec.js::case-${i + 1}`, durationMs: 1000, attempts: [{status: 'passed'}]}],
    }));
    for (const [index, transport] of [[5, 'polling'], [6, 'websocket']]) {
        reports[index].phase = 'shared';
        reports.push({status: 'passed', discovered: 1, shard: `${index + 1}/32`, phase: 'exclusive',
            tests: [{identity: `tests/e2e/terminal-load.spec.js::20 active TUIs retain state without reconnecting over ${transport}`,
                durationMs: 12000, attempts: [{status: 'passed'}]}]});
    }
    return reports;
}

function refreshReports(reports) {
    return buildBaseline(reports, reports.map((_, i) => `report-${i}.json`));
}

test('timing refresh accepts complete phased 32-shard sets and legacy unphased sets', () => {
    assert.equal(Object.keys(refreshReports(phasedShardReports()).tests).length, 34);
    const legacy = phasedShardReports().slice(0, 32).map(({phase, ...report}) => report);
    assert.equal(Object.keys(refreshReports(legacy).tests).length, 32);
});

test('timing refresh rejects missing phases, duplicate phases, overlaps and wrong resource membership', () => {
    const invalid = [];
    invalid.push(phasedShardReports().filter(r => !(r.shard === '6/32' && r.phase === 'exclusive')));
    invalid.push(phasedShardReports().filter(r => !(r.shard === '6/32' && r.phase === 'shared')));
    const duplicate = phasedShardReports(); duplicate.push({...duplicate[32]}); invalid.push(duplicate);
    const alias = phasedShardReports(); alias.push({...alias[0], shard: '01/32', tests: [{...alias[0].tests[0], identity: 'tests/e2e/normal.spec.js::alias'}]}); invalid.push(alias);
    const mixed = phasedShardReports(); mixed.push({...mixed[5], phase: 'all'}); invalid.push(mixed);
    const overlap = phasedShardReports(); overlap[5].tests = overlap[32].tests; invalid.push(overlap);
    const repeated = phasedShardReports(); repeated[1].tests = repeated[0].tests; invalid.push(repeated);
    const unknown = phasedShardReports(); unknown[0].phase = 'unknown'; invalid.push(unknown);
    const empty = phasedShardReports(); empty[5].tests = []; empty[5].discovered = 0; invalid.push(empty);
    for (const reports of invalid) assert.throws(() => refreshReports(reports));
});
