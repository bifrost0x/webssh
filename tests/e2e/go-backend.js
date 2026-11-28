// The default backend of the main suite: the Go server's e2e build
// (tests/e2e/README.md). Builds it from this checkout unless
// WEBSSH_E2E_GO_BINARY names one, then runs "webssh e2e" and passes
// Playwright's stop signal on, so the server removes its scratch data.
const {spawn} = require('node:child_process');
const {webssh} = require('./go-binary');

const child = spawn(webssh('e2e'), ['e2e'], {stdio: 'inherit'});
for (const signal of ['SIGINT', 'SIGTERM']) {
    process.on(signal, () => child.kill(signal));
}
child.on('error', error => {
    console.error(`go-backend: ${error.message}`);
    process.exit(1);
});
child.on('exit', (code, signal) => process.exit(code ?? (signal ? 1 : 0)));
