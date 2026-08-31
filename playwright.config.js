const path = require('node:path');
const os = require('node:os');

const python = process.env.PYTHON
    || (process.platform === 'win32'
        ? path.join('.venv', 'Scripts', 'python.exe')
        : 'python');
const e2ePort = process.env.WEBSSH_E2E_PORT || '4173';
const e2eBaseUrl = `http://127.0.0.1:${e2ePort}`;

module.exports = {
    testDir: './tests/e2e',
    // Test-level sharding keeps both isolated CI servers evenly loaded.
    fullyParallel: true,
    workers: 1,
    forbidOnly: true,
    retries: process.env.CI ? 1 : 0,
    outputDir: process.env.CI
        ? 'test-results'
        : path.join(os.tmpdir(), 'webssh-playwright-results'),
    reporter: [
        ['line'],
        ['./tests/e2e/no-skipped-reporter.js'],
    ],
    use: {
        baseURL: e2eBaseUrl,
        trace: 'retain-on-failure',
        screenshot: 'only-on-failure',
    },
    webServer: {
        command: `"${python}" tests/e2e/run_app.py`,
        url: `${e2eBaseUrl}/login`,
        reuseExistingServer: false,
        timeout: 120_000,
        stdout: 'pipe',
        stderr: 'pipe',
    },
};
