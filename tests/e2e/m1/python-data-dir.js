// Lab fixture: the Python release writes a DATA_DIR the way a user would,
// through its interface: an administrator with a password and TOTP, an
// uploaded SSH key, two saved hosts and a host key accepted on the test lab.
// The migration spec starts the server under test on a copy of it.
//
// Also usable on its own, e.g. for the smoke test of the image:
//   node tests/e2e/m1/python-data-dir.js <empty target directory>
// It prints the account details (synthetic, valid for this lab run only)
// as JSON on stdout.
const fs = require('node:fs');
const path = require('node:path');
const {Backend, scratchRoot, removeScratch} = require('./backend');
const {loadLab} = require('./lab');
const ui = require('./ui');

const legacy = {username: 'legacyadmin', password: 'Legacy-admin-password-5'};
const keyName = 'Legacy ed25519';
const hosts = {key: 'Legacy key host', password: 'Legacy password host'};

// Always the Python release, whatever server the suite tests.
function pythonBackend(label) {
    const backend = new Backend(scratchRoot(label), label);
    const python = process.env.PYTHON || 'python';
    backend.serverCommand = `"${python}" tests/e2e/m1/python_backend.py serve`;
    backend.adminCommand = `"${python}" tests/e2e/m1/python_backend.py cli`;
    return backend;
}

async function createPythonDataDir(browser) {
    const lab = loadLab();
    const backend = pythonBackend('python-fixture');
    const usedSteps = new Set();
    try {
        const created = await backend.createAdmin(legacy.username, legacy.password);
        if (created.code !== 0) throw new Error(`create-admin failed:\n${created.output}`);
        await backend.start();
        const context = await browser.newContext({baseURL: backend.baseURL});
        const page = await context.newPage();
        try {
            await ui.signIn(page, legacy.username, legacy.password);
            await ui.enableSecurityFeature(page, 'totp', legacy.password);
            const totpSecret = await ui.enrolTotp(page, legacy.password, usedSteps);
            await page.goto('/');
            await ui.dismissTour(page);
            await ui.uploadKey(page, {name: keyName, content: lab.clientKey('ed25519'), password: legacy.password});
            const modern = lab.service('ssh-modern');
            await ui.createHost(page, {
                name: hosts.password, host: modern.host, port: modern.port, username: 'pwuser',
            });
            await ui.createHost(page, {
                name: hosts.key, host: modern.host, port: modern.port, username: 'keyuser', auth: 'key', key: keyName,
            });
            const session = await ui.connectSavedHost(page, hosts.key, {acceptHostKeys: 1, fingerprints: lab.fingerprints('ssh-modern')});
            await ui.shellRoundTrip(page, session, 'legacy-python');
            await ui.closeSessionTab(page, session);
            await ui.signOut(page);
            return {
                dataDir: backend.dataDir, root: backend.root, username: legacy.username, password: legacy.password,
                totpSecret, usedSteps, keyName, hosts,
            };
        } finally {
            await context.close();
        }
    } catch (error) {
        error.message += `\n--- Python server output ---\n${backend.logTail()}`;
        await backend.stop();
        removeScratch(backend.root);
        throw error;
    } finally {
        await backend.stop();
    }
}

module.exports = {createPythonDataDir, legacy};

if (require.main === module) {
    (async () => {
        const target = process.argv[2];
        if (!target) throw new Error('usage: node tests/e2e/m1/python-data-dir.js <empty target directory>');
        if (fs.existsSync(target) && fs.readdirSync(target).length) throw new Error(`${target} is not empty`);
        const {chromium} = require('playwright');
        const browser = await chromium.launch();
        try {
            const fixture = await createPythonDataDir(browser);
            fs.cpSync(fixture.dataDir, target, {recursive: true, preserveTimestamps: true, verbatimSymlinks: true});
            removeScratch(fixture.root);
            const {usedSteps, dataDir, root, ...details} = fixture;
            process.stdout.write(`${JSON.stringify({...details, dataDir: path.resolve(target)}, null, 2)}\n`);
        } finally {
            await browser.close();
        }
    })().catch(error => {
        process.stderr.write(`${error.stack || error}\n`);
        process.exit(1);
    });
}
