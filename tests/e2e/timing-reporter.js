const fs = require('node:fs');
const path = require('node:path');

function identityFromTest(test) {
    const relativeFile = path.relative(process.cwd(), test.location.file).replaceAll('\\', '/');
    const fileName = path.basename(relativeFile);
    let titles = test.titlePath().map(title => String(title).trim()).filter(Boolean);
    const fileIndex = titles.findIndex(title => (
        title.replaceAll('\\', '/').endsWith(fileName)
    ));
    if (fileIndex >= 0) titles = titles.slice(fileIndex + 1);
    return [relativeFile, ...titles].join('::');
}

class TimingReporter {
    constructor(options = {}) {
        this.outputFile = options.outputFile
            || process.env.WEBSSH_E2E_TIMING_FILE
            || path.join('test-results', 'e2e-timing-full.json');
        this.tests = new Map();
        this.discovered = 0;
        this.workers = 0;
    }

    onBegin(config, suite) {
        this.discovered = suite.allTests().length;
        this.workers = config.workers;
    }

    onTestEnd(test, result) {
        const identity = identityFromTest(test);
        const entry = this.tests.get(identity) || { identity, attempts: [], durationMs: 0 };
        const attempt = {
            retry: result.retry,
            status: result.status,
            durationMs: result.duration,
        };
        entry.attempts.push(attempt);
        entry.durationMs += result.duration;
        this.tests.set(identity, entry);
    }

    onEnd(result) {
        const report = {
            version: 1,
            generatedAt: new Date().toISOString(),
            status: result.status,
            shard: process.env.WEBSSH_E2E_SHARD || null,
            phase: process.env.WEBSSH_E2E_PHASE || 'all',
            workers: this.workers,
            discovered: this.discovered,
            tests: [...this.tests.values()].sort(
                (left, right) => left.identity.localeCompare(right.identity, 'en'),
            ),
        };
        const outputFile = path.resolve(this.outputFile);
        fs.mkdirSync(path.dirname(outputFile), { recursive: true });
        const temporaryFile = `${outputFile}.${process.pid}.tmp`;
        fs.writeFileSync(temporaryFile, `${JSON.stringify(report, null, 2)}\n`, 'utf8');
        fs.renameSync(temporaryFile, outputFile);
    }
}

module.exports = TimingReporter;
module.exports.identityFromTest = identityFromTest;
