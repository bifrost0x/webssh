class NoSkippedReporter {
    constructor() {
        this.skipped = [];
    }

    onTestEnd(test, result) {
        if (result.status === 'skipped') {
            this.skipped.push(test.titlePath().join(' > '));
        }
    }

    onEnd(result) {
        if (this.skipped.length === 0) {
            return;
        }
        console.error(`Browser gate skipped ${this.skipped.length} test(s):`);
        this.skipped.forEach(title => console.error(`- ${title}`));
        process.exitCode = 1;
        return { status: 'failed' };
    }
}

module.exports = NoSkippedReporter;
