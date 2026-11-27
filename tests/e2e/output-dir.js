// The output directory of a local Playwright run: traces, screenshots and
// the timing report. Without WEBSSH_E2E_OUTPUT_DIR every run gets its own
// directory under .test-run.tmp/playwright in the repository, so that runs
// side by side never clean up each other's artifacts and large traces do
// not fill a memory-backed /tmp. The workers inherit the choice of the
// main process through the environment.
const fs = require('node:fs');
const path = require('node:path');

const ROOT = path.join(__dirname, '..', '..');

function ensureOutputDir() {
    if (!process.env.WEBSSH_E2E_OUTPUT_DIR) {
        const parent = path.join(ROOT, '.test-run.tmp', 'playwright');
        fs.mkdirSync(parent, {recursive: true});
        process.env.WEBSSH_E2E_OUTPUT_DIR = fs.mkdtempSync(path.join(parent, 'run-'));
    }
    return process.env.WEBSSH_E2E_OUTPUT_DIR;
}

module.exports = {ensureOutputDir};
