const path = require('node:path');
const base = require('../../playwright.config');

const timingFile = path.resolve(__dirname, '../../test-results/e2e-timing-herdr-browser.json');

module.exports = {
    ...base,
    testDir: __dirname,
    testMatch: 'herdr-session-browser.spec.js',
    retries: 0,
    reporter: base.reporter.map(([name, ...options]) => (name.endsWith('timing-reporter.js')
        ? [path.resolve(__dirname, '../..', name), { outputFile: timingFile }]
        : [name.startsWith('.') ? path.resolve(__dirname, '../..', name) : name, ...options])),
    outputDir: path.resolve(__dirname, '../../test-results/herdr-browser'),
    webServer: {
        ...base.webServer,
        cwd: path.resolve(__dirname, '../..'),
        // The Go server under test, on the Herdr host of run-go-browser.sh.
        command: `"${process.execPath}" tests/integration/run_herdr_browser_go.js`,
    },
};
