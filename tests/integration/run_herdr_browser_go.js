// Loopback Go server for the Herdr browser spec. It starts the server
// under test (the Go build of tests/e2e/m1/backend.js) on a new data directory with
// the administrator the spec signs in as, on WEBSSH_E2E_PORT, and removes
// the directory when Playwright stops it. Started by
// playwright.herdr.config.js; herdr/run-go-browser.sh sets the variables.
const {freshBackend} = require('../e2e/m1/backend');

async function main() {
    if (!process.env.WEBSSH_HERDR_PORT) {
        throw new Error('run through tests/integration/herdr/run-go-browser.sh');
    }
    const backend = freshBackend('herdr');
    backend.port = Number(process.env.WEBSSH_E2E_PORT);
    let stopping = false;
    const stop = async code => {
        if (stopping) return;
        stopping = true;
        await backend.dispose();
        process.exit(code);
    };
    process.on('SIGINT', () => stop(0));
    process.on('SIGTERM', () => stop(0));
    try {
        const created = await backend.createAdmin('e2e_admin', 'browser-password');
        if (created.code !== 0) throw new Error(`create-admin failed:\n${created.output}`);
        await backend.start();
    } catch (error) {
        console.error(error.message);
        await stop(1);
    }
    backend.child.once('close', code => {
        console.error(`server exited with ${code}:\n${backend.logTail()}`);
        stop(1);
    });
}

main();
