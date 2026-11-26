// Disposable backends for the M1 acceptance specs. Unlike the main suite,
// every spec file starts its own server on a data directory it prepared
// (fresh, or written by the Python release), so first start, the admin CLI
// and the migration run exactly as on a real installation.
const {spawn} = require('node:child_process');
const fs = require('node:fs');
const net = require('node:net');
const os = require('node:os');
const path = require('node:path');

const repoRoot = path.resolve(__dirname, '../../..');
const python = process.env.PYTHON || 'python';
const launcher = path.join('tests', 'e2e', 'm1', 'python_backend.py');

const serverCommand = process.env.WEBSSH_E2E_SERVER_COMMAND || `"${python}" ${launcher} serve`;
const adminCommand = process.env.WEBSSH_E2E_ADMIN_COMMAND
    || (process.env.WEBSSH_E2E_SERVER_COMMAND ? null : `"${python}" ${launcher} cli`);

// The suite runs against Python unless a server command is given; that is
// how the Go server is started (tests/e2e/README.md).
const kind = process.env.WEBSSH_E2E_SERVER_COMMAND ? 'go' : 'python';

// Configuration both servers document. It makes the loopback fixture work
// (plain HTTP, lab targets on 127.0.0.1) and lets one spec sign in often.
function baseEnvironment(port, root) {
    return {
        HOST: '127.0.0.1',
        PORT: String(port),
        WEBSSH_E2E_PORT: String(port),
        SESSION_COOKIE_SECURE: 'false',
        BLOCK_INTERNAL_SSH: 'false',
        RATELIMIT_LOGIN_LIMIT: '100 per minute',
        RATELIMIT_REAUTH: '100 per minute',
        CORS_ORIGINS: `http://127.0.0.1:${port},http://localhost:${port}`,
        WEBAUTHN_ENABLED: 'true',
        WEBAUTHN_RP_ID: 'localhost',
        WEBAUTHN_RP_NAME: 'WebSSH M1',
        WEBAUTHN_ORIGIN: `http://localhost:${port}`,
        TOTP_ENABLED: 'true',
        BACKUP_TEMP_DIR: path.join(root, 'backups'),
        TRANSFER_TEMP_DIR: path.join(root, 'transfers'),
    };
}

// Variables of the calling shell that would change the server under test.
const inheritedBlocklist = /^(SECRET_KEY|DATA_DIR|DEPLOYMENT_PROFILE|ADMIN_USERS|REGISTRATION_ENABLED|BOOTSTRAP_REGISTRATION_ENABLED|WEBSSH_E2E_SEED|WEBSSH_E2E_FAST_HASHING)$/;

function cleanEnvironment() {
    return Object.fromEntries(Object.entries(process.env).filter(([name]) => !inheritedBlocklist.test(name)));
}

function freePort() {
    return new Promise((resolve, reject) => {
        const server = net.createServer();
        server.unref();
        server.on('error', reject);
        server.listen(0, '127.0.0.1', () => {
            const {port} = server.address();
            server.close(() => resolve(port));
        });
    });
}

// A private scratch tree: <root>/data is DATA_DIR, the rest stays beside it.
function scratchRoot(label) {
    const root = fs.mkdtempSync(path.join(os.tmpdir(), `webssh-m1-${label}-`));
    fs.chmodSync(root, 0o700);
    for (const name of ['backups', 'transfers']) fs.mkdirSync(path.join(root, name), {mode: 0o700});
    return root;
}

function removeScratch(root) {
    if (root && path.basename(root).startsWith('webssh-m1-') && path.dirname(root) === os.tmpdir()) {
        fs.rmSync(root, {recursive: true, force: true});
    }
}

class Output {
    constructor(limit = 64 * 1024) { this.limit = limit; this.text = ''; }
    push(chunk) {
        this.text = (this.text + chunk.toString()).slice(-this.limit);
    }
}

function run(command, args, env) {
    return new Promise((resolve, reject) => {
        const child = spawn(`${command} ${args.map(quote).join(' ')}`, {
            cwd: repoRoot, env, shell: true, stdio: ['ignore', 'pipe', 'pipe'],
        });
        const out = new Output();
        child.stdout.on('data', chunk => out.push(chunk));
        child.stderr.on('data', chunk => out.push(chunk));
        const timer = setTimeout(() => child.kill('SIGKILL'), 120_000);
        child.on('error', error => { clearTimeout(timer); reject(error); });
        child.on('close', code => { clearTimeout(timer); resolve({code, output: out.text}); });
    });
}

function quote(value) {
    return `'${String(value).replace(/'/g, `'\\''`)}'`;
}

async function waitForLogin(url, child, out, timeoutMs) {
    const deadline = Date.now() + timeoutMs;
    while (Date.now() < deadline) {
        if (child.exitCode !== null) {
            throw new Error(`backend exited with ${child.exitCode} before it served /login:\n${out.text}`);
        }
        try {
            const response = await fetch(url, {redirect: 'manual', signal: AbortSignal.timeout(2000)});
            if (response.status === 200) return;
        } catch {
            // Not listening yet.
        }
        await new Promise(resolve => setTimeout(resolve, 200));
    }
    throw new Error(`backend did not serve /login within ${timeoutMs} ms:\n${out.text}`);
}

class Backend {
    constructor(root, label) {
        this.root = root;
        this.label = label;
        this.dataDir = path.join(root, 'data');
        this.child = null;
        this.out = new Output();
        this.port = null;
        this.serverCommand = serverCommand;
        this.adminCommand = adminCommand;
    }

    get baseURL() { return `http://127.0.0.1:${this.port}`; }
    get localhostURL() { return `http://localhost:${this.port}`; }

    environment(extra = {}) {
        return {...cleanEnvironment(), ...baseEnvironment(this.port, this.root), DATA_DIR: this.dataDir, ...extra};
    }

    async start(extra = {}) {
        if (this.child) throw new Error('backend already running');
        this.port ??= await freePort();
        this.out = new Output();
        this.child = spawn(this.serverCommand, {
            cwd: repoRoot, env: this.environment(extra), shell: true, detached: true,
            stdio: ['ignore', 'pipe', 'pipe'],
        });
        this.child.stdout.on('data', chunk => this.out.push(chunk));
        this.child.stderr.on('data', chunk => this.out.push(chunk));
        await waitForLogin(`${this.baseURL}/login`, this.child, this.out,
            Number(process.env.WEBSSH_E2E_SERVER_TIMEOUT_MS || 60_000));
    }

    // SIGINT to the process group, as Playwright stops the main suite's server.
    async stop() {
        const child = this.child;
        if (!child) return;
        this.child = null;
        if (child.exitCode !== null) return;
        const closed = new Promise(resolve => child.once('close', resolve));
        const signal = name => { try { process.kill(-child.pid, name); } catch { /* already gone */ } };
        signal('SIGINT');
        const timer = setTimeout(() => signal('SIGKILL'), 15_000);
        await closed;
        clearTimeout(timer);
    }

    // Runs "<admin command> <args>" against this data directory.
    async admin(args) {
        if (!this.adminCommand) {
            throw new Error('WEBSSH_E2E_ADMIN_COMMAND is required when WEBSSH_E2E_SERVER_COMMAND is set');
        }
        this.port ??= await freePort();
        return run(this.adminCommand, args, this.environment());
    }

    async createAdmin(username, password) {
        const file = path.join(this.root, `password-${username}`);
        fs.writeFileSync(file, `${password}\n`, {mode: 0o600});
        try {
            return await this.admin(['create-admin', '--username', username, '--password-file', file]);
        } finally {
            fs.rmSync(file, {force: true});
        }
    }

    logTail(bytes = 8000) { return this.out.text.slice(-bytes); }

    async dispose() {
        await this.stop();
        removeScratch(this.root);
    }
}

// A backend on a new, empty data directory.
function freshBackend(label) {
    return new Backend(scratchRoot(label), label);
}

// A backend on a copy of an existing data directory. The copy keeps file
// modes, so the source of a migration test stays untouched.
function backendFromDataDir(label, source) {
    const root = scratchRoot(label);
    fs.cpSync(source, path.join(root, 'data'), {recursive: true, preserveTimestamps: true, verbatimSymlinks: true});
    return new Backend(root, label);
}

// Attaches the server output to a failed test.
async function attachLogOnFailure(testInfo, backend) {
    if (backend && testInfo.status !== testInfo.expectedStatus) {
        await testInfo.attach(`${backend.label}-server.log`, {body: backend.logTail(32_000), contentType: 'text/plain'});
    }
}

module.exports = {
    kind, repoRoot, attachLogOnFailure, freshBackend, backendFromDataDir, scratchRoot, removeScratch, Backend,
};
