// Acceptance specs of the M2 packages that need their own backend and the
// test lab. Each spec file starts its own server (../m1/backend.js). Run
// from the repository root:
//   npx playwright test -c tests/e2e/m2/playwright.config.js
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

// Every run gets its own output directory unless one is given; the worker
// inherits the choice of the main process through the environment.
if (!process.env.WEBSSH_E2E_OUTPUT_DIR) {
    process.env.WEBSSH_E2E_OUTPUT_DIR = fs.mkdtempSync(path.join(os.tmpdir(), 'webssh-playwright-results-'));
}

module.exports = {
    testDir: __dirname,
    testMatch: '*.spec.js',
    fullyParallel: false,
    workers: 1,
    forbidOnly: true,
    retries: 0,
    timeout: 180_000,
    expect: {timeout: 10_000},
    outputDir: path.join(process.env.WEBSSH_E2E_OUTPUT_DIR, 'm2'),
    reporter: [['list']],
    use: {
        actionTimeout: 20_000,
        trace: 'retain-on-failure',
        screenshot: 'only-on-failure',
        viewport: {width: 1440, height: 900},
    },
};
