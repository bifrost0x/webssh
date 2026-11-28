// Merges the Playwright JSON reports of all shards of one run into a short
// summary: how many tests passed, failed, were flaky or skipped, how long
// each shard took, and which tests failed with their location and the
// shard log to look at. Nobody has to read the shard logs to know the
// result.
const fs = require('node:fs');
const path = require('node:path');

const firstLine = message => (message || '').replace(/\u001b\[[0-9;]*m/g, '').split('\n')[0];

// Walks the suites of a Playwright JSON report and returns one entry per
// test with its final outcome. Exported for tests/js.
function testsOf(report) {
    const found = [];
    const walk = (suite, titles) => {
        const here = suite.title && !suite.title.endsWith('.spec.js') ? [...titles, suite.title] : titles;
        for (const spec of suite.specs || []) {
            for (const test of spec.tests || []) {
                const results = test.results || [];
                const last = results.at(-1);
                found.push({
                    file: spec.file,
                    line: spec.line,
                    title: [...here, spec.title].join(' > '),
                    status: test.status,
                    durationMs: results.reduce((sum, result) => sum + (result.duration || 0), 0),
                    error: firstLine(last?.error?.message || last?.errors?.[0]?.message),
                    at: last?.error?.location ? `${path.basename(last.error.location.file)}:${last.error.location.line}` : '',
                });
            }
        }
        for (const child of suite.suites || []) walk(child, here);
    };
    for (const suite of report.suites || []) walk(suite, []);
    return found;
}

// shards: [{index, exitCode, wallMs, log, reports: [file]}]. A shard
// that left no report (its backend did not start, Playwright crashed) is
// a failure of its own, so a broken shard can never look like a pass.
function summarize(shards, {readReport = file => JSON.parse(fs.readFileSync(file, 'utf8'))} = {}) {
    const counts = {passed: 0, failed: 0, flaky: 0, skipped: 0};
    const failures = [];
    const broken = [];
    const perShard = [];
    for (const shard of shards) {
        const tests = [];
        let missing = false;
        for (const file of shard.reports) {
            try {
                const report = readReport(file);
                tests.push(...testsOf(report));
                for (const error of report.errors || []) {
                    broken.push({shard: shard.index, log: shard.log, reason: firstLine(error.message) || 'Playwright error'});
                }
            } catch {
                missing = true;
            }
        }
        if (missing || (shard.exitCode !== 0 && !tests.some(test => test.status === 'unexpected'))) {
            broken.push({shard: shard.index, log: shard.log, reason: missing ? `no report (exit code ${shard.exitCode})` : `exit code ${shard.exitCode} without a failed test`});
        }
        for (const test of tests) {
            if (test.status === 'expected') counts.passed += 1;
            else if (test.status === 'flaky') counts.flaky += 1;
            else if (test.status === 'skipped') counts.skipped += 1;
            else {
                counts.failed += 1;
                failures.push({...test, shard: shard.index, log: shard.log});
            }
        }
        perShard.push({index: shard.index, tests: tests.length, wallMs: shard.wallMs, exitCode: shard.exitCode, specs: shard.specs});
    }
    const wallMs = Math.max(0, ...shards.map(shard => shard.wallMs));
    const ok = !failures.length && !broken.length && counts.passed + counts.flaky > 0;
    return {ok, ...counts, wallMs, shards: perShard, failures, broken};
}

const minutes = ms => `${Math.floor(ms / 60_000)}m${String(Math.round((ms % 60_000) / 1000)).padStart(2, '0')}s`;

function format(summary) {
    const lines = [
        `Go suite: ${summary.ok ? 'PASSED' : 'FAILED'} in ${minutes(summary.wallMs)} on ${summary.shards.length} shard(s)`,
        `  ${summary.passed} passed, ${summary.failed} failed, ${summary.flaky} flaky, ${summary.skipped} skipped`,
    ];
    for (const shard of summary.shards) {
        lines.push(`  shard ${shard.index}: ${shard.specs} specs, ${shard.tests} tests, ${minutes(shard.wallMs)}, exit ${shard.exitCode}`);
    }
    for (const entry of summary.broken) lines.push(`  BROKEN shard ${entry.shard}: ${entry.reason} (${entry.log})`);
    for (const failure of summary.failures) {
        lines.push(`  FAILED [shard ${failure.shard}] ${failure.file}:${failure.line} ${failure.title}`);
        if (failure.error) lines.push(`         ${failure.at ? `${failure.at} ` : ''}${failure.error.slice(0, 200)}`);
    }
    return `${lines.join('\n')}\n`;
}

function write(root, summary) {
    fs.writeFileSync(path.join(root, 'summary.json'), `${JSON.stringify(summary, null, 2)}\n`);
    const text = format(summary);
    fs.writeFileSync(path.join(root, 'summary.txt'), text);
    return text;
}

module.exports = {format, summarize, testsOf, write};
