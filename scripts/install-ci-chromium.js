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

async function installCiBrowser(browserName, { runCli = runPlaywrightCli, probe } = {}) {
    if (!['chromium', 'firefox', 'webkit'].includes(browserName)) {
        throw new Error(`Unsupported CI browser: ${browserName}`);
    }
    const launchProbe = probe || (() => probeChromium(require('playwright')[browserName]));
    // Probe the locked browser first: --with-deps also installs optional media
    // libraries and fonts already present on hosted runners, forcing apt I/O.
    runCli(['install', browserName, ...(browserName === 'chromium' ? ['--only-shell'] : [])]);
    try {
        await launchProbe();
    } catch (error) {
        const missingRuntime = /Host system is missing dependencies|error while loading shared libraries|cannot open shared object file/i;
        if (!missingRuntime.test(String(error.message))) throw error;
        runCli(['install-deps', browserName]);
        await launchProbe();
    }
}

async function installCiChromium(options) {
    return installCiBrowser('chromium', options);
}

if (require.main === module) {
    const args = process.argv.slice(2);
    const browserName = args[0] || 'chromium';
    Promise.resolve().then(() => {
        if (args.length > 1) throw new Error('Usage: node scripts/install-ci-chromium.js [chromium|firefox|webkit]');
        return installCiBrowser(browserName);
    }).catch(error => {
        console.error('CI browser installation or launch verification failed.');
        process.exitCode = error.exitCode || 1;
    });
}

module.exports = { installCiBrowser, installCiChromium, probeChromium };
