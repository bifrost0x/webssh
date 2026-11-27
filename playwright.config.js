const path = require('node:path');
const {ensureOutputDir} = require('./tests/e2e/output-dir');

const python = process.env.PYTHON
    || (process.platform === 'win32'
        ? path.join('.venv', 'Scripts', 'python.exe')
        : 'python');
const e2ePort = process.env.WEBSSH_E2E_PORT || '4173';
// Specs and helpers build loopback URLs from the port, so the host is fixed.
const e2eBaseUrl = `http://127.0.0.1:${e2ePort}`;
// Every local run gets its own output directory (tests/e2e/output-dir.js);
// CI keeps test-results.
const outputDir = process.env.WEBSSH_E2E_OUTPUT_DIR || (process.env.CI ? 'test-results' : ensureOutputDir());
const timingOutput = process.env.WEBSSH_E2E_TIMING_FILE
    || path.join(outputDir, 'e2e-timing-full.json');

module.exports = {
    testDir: './tests/e2e',
    // The M1 acceptance specs start their own backends (tests/e2e/m1).
    testIgnore: ['m1/**'],
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
        // Another backend replaces the default runner via
        // WEBSSH_E2E_SERVER_COMMAND; tests/e2e/README.md has the contract.
        command: process.env.WEBSSH_E2E_SERVER_COMMAND
            || `"${python}" tests/e2e/run_app.py`,
        env: { WEBSSH_E2E_PORT: e2ePort },
        url: `${e2eBaseUrl}/login`,
        reuseExistingServer: false,
        // Without it Playwright kills the server with SIGKILL and the
        // backend's scratch data directory stays behind in the temp dir.
        gracefulShutdown: { signal: 'SIGINT', timeout: 5000 },
        timeout: Number(process.env.WEBSSH_E2E_SERVER_TIMEOUT_MS || 120_000),
        stdout: 'pipe',
        stderr: 'pipe',
    },
};
