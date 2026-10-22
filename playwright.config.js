const path = require('node:path');
const os = require('node:os');

const python = process.env.PYTHON
    || (process.platform === 'win32'
        ? path.join('.venv', 'Scripts', 'python.exe')
        : 'python');
const e2ePort = process.env.WEBSSH_E2E_PORT || '4173';
const e2eBaseUrl = `http://127.0.0.1:${e2ePort}`;
const outputDir = process.env.WEBSSH_E2E_OUTPUT_DIR || (process.env.CI
    ? 'test-results'
    : path.join(os.tmpdir(), 'webssh-playwright-results'));
const timingOutput = process.env.WEBSSH_E2E_TIMING_FILE
    || path.join(outputDir, 'e2e-timing-full.json');

module.exports = {
    testDir: './tests/e2e',
    // Test-level sharding keeps independent CI servers evenly loaded.
    fullyParallel: true,
    workers: 1,
    forbidOnly: true,
    retries: process.env.CI ? 1 : 0,
    outputDir,
    reporter: [
        ['line'],
        ['./tests/e2e/no-skipped-reporter.js'],
        ['./tests/e2e/timing-reporter.js', { outputFile: timingOutput }],
    ],
    use: {
        baseURL: e2eBaseUrl,
        // Passing CI cases need no DOM snapshot stream. Failed first attempts
        // keep screenshots; their existing retry records a complete trace.
        trace: process.env.CI ? 'on-first-retry' : 'retain-on-failure',
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
