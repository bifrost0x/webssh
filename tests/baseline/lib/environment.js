'use strict';

// Disposable measurement environment: an OpenSSH target container and a
// WebSSH instance, either the published image (Docker) or the worktree .venv
// started with the same Gunicorn command as the Dockerfile CMD.

const { spawn, execFileSync } = require('node:child_process');
const crypto = require('node:crypto');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

const REPO_ROOT = path.resolve(__dirname, '..', '..', '..');
const SSHD_IMAGE = 'lscr.io/linuxserver/openssh-server@sha256:c8431b8982e7eb3935ebf9c46607d19c6417e39c12ce884cc66945df2e9334e8';
const NETWORK = 'webssh-baseline';
const SSHD_NAME = 'webssh-baseline-sshd';
const APP_NAME = 'webssh-baseline-app';
const SSH_USER = 'bench';

function docker(args, options = {}) {
    return execFileSync('docker', args, { encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'], ...options }).trim();
}

function dockerQuiet(args) {
    try {
        return docker(args);
    } catch {
        return null;
    }
}

function randomSecret(bytes = 24) {
    return crypto.randomBytes(bytes).toString('hex');
}

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

async function waitFor(check, timeoutMs, intervalMs = 50) {
    const deadline = Date.now() + timeoutMs;
    while (Date.now() < deadline) {
        if (await check()) return true;
        await sleep(intervalMs);
    }
    return false;
}

function ensureNetwork() {
    if (dockerQuiet(['network', 'inspect', NETWORK]) === null) docker(['network', 'create', NETWORK]);
}

async function startSshd(sshPort) {
    ensureNetwork();
    dockerQuiet(['rm', '-f', SSHD_NAME]);
    const password = randomSecret(12);
    docker([
        'run', '-d', '--name', SSHD_NAME, '--network', NETWORK,
        '-p', `127.0.0.1:${sshPort}:2222`,
        '-e', 'PUID=1000', '-e', 'PGID=1000', '-e', 'TZ=Etc/UTC',
        '-e', 'PASSWORD_ACCESS=true', '-e', `USER_NAME=${SSH_USER}`,
        '-e', `USER_PASSWORD=${password}`,
        SSHD_IMAGE,
    ]);
    const ready = await waitFor(() => {
        const logs = dockerQuiet(['logs', SSHD_NAME]) || '';
        return logs.includes('[ls.io-init] done.');
    }, 60000, 250);
    if (!ready) throw new Error('sshd container did not finish initialisation');
    await sleep(1000);
    return { password, user: SSH_USER, containerHost: SSHD_NAME, containerPort: 2222, hostPort: sshPort };
}

// Text files keep the terminal path free of UTF-8 replacement work, so the
// byte count received equals the file size plus CR inserted by the pty.
function createTargetFile(name, bytes) {
    const target = `/config/${name}`;
    docker(['exec', SSHD_NAME, 'sh', '-c',
        `head -c ${Math.ceil(bytes * 0.76) + 4096} /dev/urandom | base64 -w 76 | head -c ${bytes} > ${target}`
        + ` && chown ${SSH_USER}:${SSH_USER} ${target} && chmod 644 ${target}`]);
    return target;
}

function targetFileDigest(target) {
    return docker(['exec', SSHD_NAME, 'sha256sum', target]).split(/\s+/)[0];
}

function removeTargetFile(target) {
    dockerQuiet(['exec', SSHD_NAME, 'rm', '-f', target]);
}

function stopSshd() {
    dockerQuiet(['rm', '-f', SSHD_NAME]);
    dockerQuiet(['network', 'rm', NETWORK]);
}

function baseAppEnvironment(extra) {
    return {
        SECRET_KEY: randomSecret(32),
        // Plain HTTP on loopback: the measurement client keeps its own
        // cookie jar, so the Secure flag is left at its production default.
        REGISTRATION_ENABLED: 'true',
        RATELIMIT_LOGIN_LIMIT: '1000 per minute',
        RATELIMIT_DEFAULT: '10000 per hour',
        ...extra,
    };
}

async function pollReady(baseUrl, timeoutMs) {
    const ok = await waitFor(async () => {
        try {
            const response = await fetch(`${baseUrl}/ready`, { signal: AbortSignal.timeout(1000) });
            await response.arrayBuffer();
            return response.status === 200;
        } catch {
            return false;
        }
    }, timeoutMs, 20);
    return ok;
}

class DockerApp {
    constructor({ image, port, environment }) {
        this.kind = 'docker';
        this.image = image;
        this.port = port;
        this.environment = environment;
        this.baseUrl = `http://127.0.0.1:${port}`;
        this.volume = null;
    }

    // Measures docker run (container creation included) until /ready is 200.
    async start({ keepVolume = false } = {}) {
        dockerQuiet(['rm', '-f', APP_NAME]);
        if (!keepVolume || !this.volume) {
            if (this.volume) dockerQuiet(['volume', 'rm', this.volume]);
            this.volume = `webssh-baseline-data-${randomSecret(4)}`;
        }
        const envArgs = Object.entries(this.environment).flatMap(([key, value]) => ['-e', `${key}=${value}`]);
        const started = process.hrtime.bigint();
        docker([
            'run', '-d', '--name', APP_NAME, '--network', NETWORK,
            '-p', `127.0.0.1:${this.port}:5000`, '-v', `${this.volume}:/app/data`,
            ...envArgs, this.image,
        ]);
        const ready = await pollReady(this.baseUrl, 120000);
        const elapsedMs = Number(process.hrtime.bigint() - started) / 1e6;
        if (!ready) throw new Error(`WebSSH container not ready: ${dockerQuiet(['logs', '--tail', '40', APP_NAME])}`);
        return elapsedMs;
    }

    sshTarget(sshd) {
        return { host: sshd.containerHost, port: sshd.containerPort };
    }

    rootPid() {
        return Number(docker(['inspect', '--format', '{{.State.Pid}}', APP_NAME]));
    }

    memory() {
        const stats = docker(['stats', '--no-stream', '--format', '{{.MemUsage}}', APP_NAME]);
        return { container_mem_usage: stats.split('/')[0].trim(), ...processTreeMemory(this.rootPid()) };
    }

    logs() {
        return dockerQuiet(['logs', APP_NAME]) || '';
    }

    async stop() {
        dockerQuiet(['rm', '-f', APP_NAME]);
    }

    cleanup() {
        dockerQuiet(['rm', '-f', APP_NAME]);
        if (this.volume) dockerQuiet(['volume', 'rm', this.volume]);
        this.volume = null;
    }
}

class LocalApp {
    constructor({ port, environment }) {
        this.kind = 'local';
        this.port = port;
        this.environment = environment;
        this.baseUrl = `http://127.0.0.1:${port}`;
        this.dataRoot = null;
        this.child = null;
        this.output = '';
    }

    async start({ keepVolume = false } = {}) {
        if (!keepVolume || !this.dataRoot) {
            this.cleanup();
            this.dataRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'webssh-baseline-'));
            fs.mkdirSync(path.join(this.dataRoot, 'data'), { mode: 0o700 });
        }
        const threads = this.environment.GUNICORN_THREADS || '64';
        const environment = {
            PATH: `${path.join(REPO_ROOT, '.venv', 'bin')}:${process.env.PATH}`,
            HOME: process.env.HOME,
            LANG: 'C.UTF-8',
            PYTHONDONTWRITEBYTECODE: '1',
            PYTHONUNBUFFERED: '1',
            HOST: '127.0.0.1',
            PORT: String(this.port),
            GUNICORN_THREADS: threads,
            MAX_SOCKET_CONNECTIONS: '48',
            MAX_SOCKET_CONNECTIONS_PER_USER: '8',
            DATA_DIR: path.join(this.dataRoot, 'data'),
            BACKUP_TEMP_DIR: path.join(this.dataRoot, 'backups'),
            TRANSFER_TEMP_DIR: path.join(this.dataRoot, 'transfers'),
            ...this.environment,
        };
        this.output = '';
        const started = process.hrtime.bigint();
        // Same arguments as the Dockerfile CMD; only the bind address differs.
        this.child = spawn(path.join(REPO_ROOT, '.venv', 'bin', 'gunicorn'), [
            '--worker-class', 'gthread', '--workers', '1', '--threads', threads,
            '--bind', `127.0.0.1:${this.port}`, 'start:app',
        ], { cwd: REPO_ROOT, env: environment, stdio: ['ignore', 'pipe', 'pipe'] });
        const collect = (chunk) => {
            this.output = (this.output + chunk.toString()).slice(-20000);
        };
        this.child.stdout.on('data', collect);
        this.child.stderr.on('data', collect);
        const ready = await pollReady(this.baseUrl, 120000);
        const elapsedMs = Number(process.hrtime.bigint() - started) / 1e6;
        if (!ready) throw new Error(`local WebSSH not ready: ${this.output.slice(-3000)}`);
        return elapsedMs;
    }

    sshTarget(sshd) {
        return { host: '127.0.0.1', port: sshd.hostPort };
    }

    memory() {
        return processTreeMemory(this.child.pid);
    }

    logs() {
        return this.output;
    }

    async stop() {
        if (!this.child || this.child.exitCode !== null) return;
        const exited = new Promise((resolve) => this.child.once('exit', resolve));
        this.child.kill('SIGTERM');
        const done = await Promise.race([exited.then(() => true), sleep(30000).then(() => false)]);
        if (!done) this.child.kill('SIGKILL');
        this.child = null;
    }

    cleanup() {
        if (this.dataRoot) fs.rmSync(this.dataRoot, { recursive: true, force: true });
        this.dataRoot = null;
    }
}

function childPids(pid) {
    const result = [];
    let tasks = [];
    try {
        tasks = fs.readdirSync(`/proc/${pid}/task`);
    } catch {
        return result;
    }
    for (const task of tasks) {
        try {
            const children = fs.readFileSync(`/proc/${pid}/task/${task}/children`, 'utf8').trim();
            if (children) result.push(...children.split(/\s+/).map(Number));
        } catch {
            // The task exited between listing and reading.
        }
    }
    return result;
}

function statusField(pid, field) {
    const status = fs.readFileSync(`/proc/${pid}/status`, 'utf8');
    const match = new RegExp(`^${field}:\\s+(\\d+) kB`, 'm').exec(status);
    return match ? Number(match[1]) : 0;
}

// Sum of VmRSS over the process tree, read from /proc/<pid>/status, which
// stays readable for rootless containers. Shared pages count once per
// process, exactly as RSS does.
function processTreeMemory(rootPid) {
    const pids = [];
    const queue = [rootPid];
    while (queue.length) {
        const pid = queue.shift();
        pids.push(pid);
        queue.push(...childPids(pid));
    }
    const processes = [];
    for (const pid of pids) {
        try {
            const comm = fs.readFileSync(`/proc/${pid}/comm`, 'utf8').trim();
            processes.push({ pid, comm, rss_kib: statusField(pid, 'VmRSS'), threads: Number(/^Threads:\s+(\d+)/m.exec(fs.readFileSync(`/proc/${pid}/status`, 'utf8'))[1]) });
        } catch {
            // Process exited while being sampled.
        }
    }
    return {
        rss_total_kib: processes.reduce((sum, item) => sum + item.rss_kib, 0),
        processes,
    };
}

module.exports = {
    REPO_ROOT, SSHD_IMAGE, NETWORK, APP_NAME, SSHD_NAME,
    DockerApp, LocalApp, baseAppEnvironment, startSshd, stopSshd,
    createTargetFile, targetFileDigest, removeTargetFile, docker, dockerQuiet, sleep, waitFor, randomSecret,
};
