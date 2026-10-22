const { spawnSync } = require('node:child_process');
const { resolvePlaywrightCli } = require('./e2e-process');

function runPlaywrightCli(args) {
    const result = spawnSync(process.execPath, [resolvePlaywrightCli(), ...args], {
        stdio: 'inherit',
    });
    if (result.error || result.status !== 0) {
        const error = new Error('Playwright browser setup command failed.');
        error.exitCode = result.status > 0 ? result.status : 1;
        throw error;
    }
}

async function probeChromium(chromium = require('playwright').chromium) {
    const browser = await chromium.launch({ headless: true });
    await browser.close();
}

async function installCiChromium({ runCli = runPlaywrightCli, probe = probeChromium } = {}) {
    // The E2E configuration uses the default headless Chromium shell.
    runCli(['install', 'chromium', '--only-shell']);
    try {
        await probe();
    } catch (error) {
        const missingRuntime = /Host system is missing dependencies|error while loading shared libraries|cannot open shared object file/i;
        if (!missingRuntime.test(String(error.message))) throw error;
        runCli(['install-deps', 'chromium']);
        await probe();
    }
}

if (require.main === module) {
    installCiChromium().catch(error => {
        console.error('CI Chromium installation or launch verification failed.');
        process.exitCode = error.exitCode || 1;
    });
}

module.exports = { installCiChromium, probeChromium };
