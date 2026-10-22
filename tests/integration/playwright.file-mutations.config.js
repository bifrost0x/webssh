const path = require('node:path');
const base = require('../../playwright.config');

module.exports = {
    ...base,
    testDir: __dirname,
    testMatch: 'file-mutations-browser.spec.js',
    retries: 0,
    reporter: base.reporter.map(([name, ...options]) => [
        name.startsWith('.') ? path.resolve(__dirname, '../..', name) : name,
        ...options,
    ]),
    outputDir: path.resolve(__dirname, '../../test-results/ssh-browser'),
    webServer: {
        ...base.webServer,
        cwd: path.resolve(__dirname, '../..'),
        command: base.webServer.command.replace('tests/e2e/run_app.py', 'tests/integration/run_file_mutations_browser_app.py'),
    },
};
