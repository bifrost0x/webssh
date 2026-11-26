// Acceptance specs of the M1 preview. Each spec file starts its own backend
// (backend.js); there is no shared web server. Run from the repository root:
//   npx playwright test -c tests/e2e/m1/playwright.config.js
const os = require('node:os');
const path = require('node:path');

module.exports = {
    testDir: __dirname,
    testMatch: '*.spec.js',
    fullyParallel: false,
    workers: 1,
    forbidOnly: true,
    retries: 0,
    timeout: 180_000,
    expect: {timeout: 10_000},
    outputDir: process.env.WEBSSH_E2E_OUTPUT_DIR
        ? path.join(process.env.WEBSSH_E2E_OUTPUT_DIR, 'm1')
        : path.join(os.tmpdir(), 'webssh-playwright-results-m1'),
    reporter: [['list']],
    use: {
        actionTimeout: 20_000,
        trace: 'retain-on-failure',
        screenshot: 'only-on-failure',
        viewport: {width: 1440, height: 900},
    },
};
