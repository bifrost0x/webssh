// Stands in for Playwright with its backend: listens on a port in a child
// that ignores SIGINT, like a backend that does not stop, and reports the
// port on stdout.
const {spawn} = require('node:child_process');
if (process.argv[2] === 'backend') {
    process.on('SIGINT', () => {});
    const server = require('node:net').createServer();
    server.listen(0, '127.0.0.1', () => process.stdout.write(`${server.address().port}\n`));
} else {
    const backend = spawn(process.execPath, [__filename, 'backend'], {stdio: ['ignore', 'inherit', 'inherit']});
    process.on('SIGINT', () => process.exit(130));
    backend.on('exit', () => process.exit(1));
}
