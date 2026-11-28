#!/usr/bin/env node
'use strict';

// Browser measurement of WebSSH backends through the real page: Playwright
// Chromium signs in through /login, opens a saved host in the workspace and
// measures in the page itself, so Python and Go are driven by the same
// frontend code over their own realtime transport.
//
//   node tests/baseline/browser-terminal.js --python ghcr.io/bifrost0x/webssh:latest \
//        --go webssh:3.4.0-rc1 [--order pggppg] [--phases login,terminal,files,memory]
//
// Options: --echo-samples 500  --cat-runs 5  --login-runs 20  --list-runs 10
//          --sftp-runs 3  --smoke true (5 samples, 1 run each)  --out <file.json>
//
// Both backends run at the same time against one sshd (webssh-baseline-sshd);
// the blocks of --order run one after the other, so only one backend is
// under load while the other rests. Memory is sampled while both rest.

const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { chromium } = require('playwright');

const environment = require('./lib/environment');
const { rawDir } = require('./lib/output');
const { summarize } = require('./lib/stats');
const { sampleMemory } = require('./lib/measure-terminal');
const ui = require('../e2e/m1/ui');
const { waitForInventory } = require('../e2e/helpers');

const SSH_PORT = 22873;
const PORTS = { python: 15873, go: 15874 };
let CAT_BYTES = 50 * 1024 * 1024;
const SFTP_BYTES = 200 * 1024 * 1024;
const LIST_FILES = 2000;
const ACCOUNT = { username: 'bench', password: `Bench-${environment.randomSecret(12)}` };
const HOST_NAME = 'baseline-sshd';

function parseArgs(argv) {
    const options = {
        python: 'ghcr.io/bifrost0x/webssh:latest', go: 'webssh:3.4.0-rc1', order: 'pggppg',
        phases: 'login,terminal,files,memory', 'echo-samples': '500', 'cat-runs': '5', 'login-runs': '20',
        'list-runs': '10', 'sftp-runs': '3', 'cat-mib': '50', smoke: 'false', out: null,
    };
    for (let index = 0; index < argv.length; index += 2) {
        const key = argv[index].replace(/^--/, '');
        if (!(key in options)) throw new Error(`unknown option --${key}`);
        options[key] = argv[index + 1];
    }
    options.phases = options.phases.split(',');
    CAT_BYTES = Number(options['cat-mib']) * 1024 * 1024;
    if (options.smoke === 'true') {
        Object.assign(options, { 'echo-samples': '5', 'cat-runs': '1', 'login-runs': '2', 'list-runs': '1', 'sftp-runs': '1' });
    }
    return options;
}

// Settings shared by both backends: the realtime origin of the published
// port, open registration for the first account, sign-in limits that 20
// sign-ins and 40 connections do not reach, room for 40 terminals of one account (Python wants the per-user quota below the global one) and for
// 200 MiB transfers.
function appEnvironment(port) {
    const limit = String(256 * 1024 * 1024);
    return environment.baseAppEnvironment({
        CORS_ORIGINS: `http://127.0.0.1:${port}`,
        QUOTA_SSH_SESSION_GLOBAL: '41',
        QUOTA_SSH_SESSION_PER_USER: '40',
        SSH_CONNECT_RATELIMIT: '1000 per minute',
        // Every page load lists the keys; 20 sign-ins with a reload each
        // exceed the default of 30 per minute.
        SSH_KEY_LIST_RATELIMIT: '1000 per minute',
        MAX_UPLOAD_SIZE: limit,
        MAX_DOWNLOAD_SIZE: limit,
    });
}

const loadavg = () => os.loadavg()[0];

// --- page helpers -----------------------------------------------------

async function register(page) {
    await page.goto('/register');
    await page.locator('#username').fill(ACCOUNT.username);
    await page.locator('#password').fill(ACCOUNT.password);
    await page.locator('#registerForm [name="confirm_password"]').fill(ACCOUNT.password);
    await page.locator('#registerForm button[type="submit"]').click();
    await page.waitForURL((url) => url.pathname === '/');
}

// Echo latency inside the page: a character goes in through the
// terminal's own input path (xterm onData, as a key press) and the clock
// stops when the remote echo is in the xterm buffer. Every 40 characters
// the line is cleared with ^U.
async function echoLatency(page, sessionId, samples, warmup) {
    return page.evaluate(async ({ id, samples, warmup }) => {
        const term = TerminalManager.terminals[id];
        const buffer = () => term.buffer.active;
        const line = (offset = 0) => (buffer().getLine(buffer().cursorY + buffer().baseY - offset)?.translateToString(true) ?? '').trimEnd();
        const waitFor = (test, timeout) => new Promise((resolve, reject) => {
            if (test()) return resolve();
            const timer = setTimeout(() => { listener.dispose(); reject(new Error(`echo timeout: ${JSON.stringify(line())}`)); }, timeout);
            const listener = term.onWriteParsed(() => {
                if (!test()) return;
                clearTimeout(timer);
                listener.dispose();
                resolve();
            });
        });
        term.input("export PS1='$ '; stty -ixon; echo PREPARED_\"\"OK\r", true);
        await waitFor(() => [0, 1, 2].some((offset) => line(offset) === 'PREPARED_OK'), 30000);
        await waitFor(() => line() === '$', 30000);
        await new Promise((resolve) => setTimeout(resolve, 200));
        const values = [];
        let typed = '';
        for (let index = 0; index < samples + warmup; index += 1) {
            const character = String.fromCharCode(97 + (index % 26));
            typed += character;
            const expected = `$ ${typed}`;
            const started = performance.now();
            term.input(character, true);
            await waitFor(() => line() === expected, 10000);
            if (index >= warmup) values.push(performance.now() - started);
            if (typed.length >= 40) {
                term.input('\x15', true);
                typed = '';
                await waitFor(() => line() === '$', 10000);
            }
        }
        term.input('\x15', true);
        await waitFor(() => line() === '$', 10000);
        return values;
    }, { id: sessionId, samples, warmup });
}

// cat of a text file until the end marker is in the xterm buffer.
async function catThroughput(page, sessionId, file, bytes) {
    return page.evaluate(async ({ id, file, bytes }) => {
        const term = TerminalManager.terminals[id];
        const buffer = () => term.buffer.active;
        const line = (offset) => (buffer().getLine(buffer().cursorY + buffer().baseY - offset)?.translateToString(true) ?? '').trimEnd();
        // The file does not end with a line feed, so the marker ends its last line.
        const done = () => [0, 1, 2, 3].some((offset) => line(offset).endsWith('END_MARK'));
        const started = performance.now();
        await new Promise((resolve, reject) => {
            const timer = setTimeout(() => { listener.dispose(); reject(new Error('cat timeout')); }, 600000);
            const listener = term.onWriteParsed(() => {
                if (!done()) return;
                clearTimeout(timer);
                listener.dispose();
                resolve();
            });
            term.input(`cat ${file}; echo END_""MARK\r`, true);
        });
        const seconds = (performance.now() - started) / 1000;
        term.input('clear\r', true);
        await new Promise((resolve) => setTimeout(resolve, 500));
        return { seconds, mib_per_s: bytes / 1048576 / seconds };
    }, { id: sessionId, file, bytes });
}

// Lists a directory through list_directory, every page, as the file
// manager does.
async function listDirectory(page, sessionId, remotePath) {
    return page.evaluate(async ({ id, remotePath }) => {
        const socket = window.socket;
        // The file manager retires every cursor it did not ask for; while the
        // measurement pages through its own listing that is held back.
        const sockets = [...new Set([socket, window.sftpFileManager?.socket].filter(Boolean))];
        const originals = sockets.map((item) => item.emit);
        sockets.forEach((item, index) => {
            item.emit = function emit(event, payload, ...rest) {
                if (event === 'cancel_directory_listing' && payload?.source_id === `sftp-session:${id}`) return this;
                return originals[index].call(this, event, payload, ...rest);
            };
        });
        try {
            const started = performance.now();
            let cursor = 0;
            let files = 0;
            let pages = 0;
            for (;;) {
                const requestId = `list_${Date.now()}_${pages}`;
                const listing = await new Promise((resolve, reject) => {
                    const timer = setTimeout(() => finish(reject, new Error('list timeout')), 30000);
                    const finish = (settle, value) => {
                        clearTimeout(timer);
                        socket.off('directory_listing', onListing);
                        socket.off('error', onError);
                        settle(value);
                    };
                    const onListing = (data) => { if (data?.request_id === requestId) finish(resolve, data); };
                    const onError = (data) => { if (data?.request_id === requestId) finish(reject, new Error(`list error ${JSON.stringify(data)}`)); };
                    socket.on('directory_listing', onListing);
                    socket.on('error', onError);
                    socket.emit('list_directory', { source_id: `sftp-session:${id}`, request_id: requestId, remote_path: remotePath, cursor });
                });
                files += listing.files.length;
                pages += 1;
                if (!listing.next_cursor) break;
                cursor = listing.next_cursor;
            }
            return { ms: performance.now() - started, files, pages };
        } finally {
            sockets.forEach((item, index) => { item.emit = originals[index]; });
        }
    }, { id: sessionId, remotePath });
}

// prepare_transfer and one HTTP request, as binary-transfer-client.js
// does. The digests are computed outside the timed part.
async function transfer(page, sessionId, direction, remotePath, bytes) {
    return page.evaluate(async ({ id, direction, remotePath, bytes }) => {
        const csrf = document.querySelector('meta[name="csrf-token"]').content;
        if (direction === 'upload' && !window.__baselineUpload) {
            const data = new Uint8Array(bytes);
            for (let offset = 0; offset < bytes; offset += 65536) crypto.getRandomValues(data.subarray(offset, Math.min(bytes, offset + 65536)));
            const digest = new Uint8Array(await crypto.subtle.digest('SHA-256', data));
            window.__baselineUpload = { blob: new Blob([data]), sha256: [...digest].map((b) => b.toString(16).padStart(2, '0')).join('') };
        }
        const started = performance.now();
        const prepared = await new Promise((resolve, reject) => {
            const timer = setTimeout(() => reject(new Error('prepare_transfer timeout')), 15000);
            window.socket.emit('prepare_transfer', {
                direction, source_id: `sftp-session:${id}`, remote_path: remotePath,
                request_id: `transfer_${Date.now()}`, ...(direction === 'upload' ? { conflict_policy: 'replace' } : {}),
            }, (ack) => {
                clearTimeout(timer);
                if (ack?.success) resolve(ack); else reject(new Error(`prepare_transfer ${JSON.stringify(ack)}`));
            });
        });
        if (direction === 'upload') {
            const response = await fetch(prepared.url, { method: 'POST', body: window.__baselineUpload.blob, headers: { 'X-CSRFToken': csrf }, credentials: 'same-origin' });
            const text = await response.text();
            const seconds = (performance.now() - started) / 1000;
            return { ok: response.ok, status: response.status, seconds, sha256: window.__baselineUpload.sha256, body: response.ok ? undefined : text.slice(0, 300) };
        }
        const response = await fetch(prepared.url, { credentials: 'same-origin' });
        if (!response.ok) return { ok: false, status: response.status, body: (await response.text()).slice(0, 300) };
        const reader = response.body.getReader();
        const data = new Uint8Array(bytes);
        let received = 0;
        for (;;) {
            const { done, value } = await reader.read();
            if (done) break;
            if (received + value.length <= bytes) data.set(value, received);
            received += value.length;
        }
        const seconds = (performance.now() - started) / 1000;
        const digest = received === bytes ? new Uint8Array(await crypto.subtle.digest('SHA-256', data)) : new Uint8Array();
        return { ok: true, status: response.status, seconds, bytes: received, sha256: [...digest].map((b) => b.toString(16).padStart(2, '0')).join('') };
    }, { id: sessionId, direction, remotePath, bytes });
}

// --- backend --------------------------------------------------------------

class Backend {
    constructor(kind, image, browser, sshd) {
        this.kind = kind;
        this.image = image;
        this.browser = browser;
        this.sshd = sshd;
        this.app = new environment.DockerApp({ image, port: PORTS[kind], environment: appEnvironment(PORTS[kind]), name: `webssh-baseline-${kind}` });
        this.result = { image, blocks: [] };
    }

    async start() {
        this.result.start_ms = await this.app.start();
        this.result.image_id = environment.docker(['inspect', '--format', '{{.Image}}', this.app.name]);
    }

    async newPage() {
        const context = await this.browser.newContext({ baseURL: this.app.baseUrl, viewport: { width: 1600, height: 900 } });
        return { context, page: await context.newPage() };
    }

    // The account, the saved host and the workspace page with one
    // terminal, used by every block.
    async setUp() {
        const { context, page } = await this.newPage();
        this.context = context;
        this.page = page;
        // The registration signs the new account in.
        await register(page);
        await ui.dismissTour(page);
        await waitForInventory(page);
        await ui.createHost(page, { name: HOST_NAME, host: this.sshd.containerHost, port: this.sshd.containerPort, username: this.sshd.user, auth: 'password' });
        this.sessionId = await ui.connectSavedHost(page, HOST_NAME, { password: this.sshd.password, acceptHostKeys: 1 });
        this.sessions = [this.sessionId];
        await page.evaluate((id) => SessionManager.switchSession(id), this.sessionId);
    }

    async openTerminals(total) {
        while (this.sessions.length < total) {
            this.sessions.push(await ui.connectSavedHost(this.page, HOST_NAME, { password: this.sshd.password }));
        }
    }

    async loginRuns(runs) {
        const pageLoad = [];
        const signIn = [];
        const workspace = [];
        for (let run = 0; run < runs; run += 1) {
            const { context, page } = await this.newPage();
            try {
                await page.goto('/login', { waitUntil: 'load' });
                pageLoad.push(await page.evaluate(() => performance.getEntriesByType('navigation')[0].loadEventEnd));
                await page.locator('#username').fill(ACCOUNT.username);
                await page.locator('#password').fill(ACCOUNT.password);
                const started = Date.now();
                await page.locator('form button[type="submit"]').click();
                await page.waitForURL((url) => url.pathname === '/', { waitUntil: 'load' });
                signIn.push(Date.now() - started);
                // Reload of the signed-in page until the workspace has its
                // inventory and realtime connection (waitForInventory).
                const reloaded = Date.now();
                await page.reload({ waitUntil: 'load' });
                await page.waitForFunction(() => window.ProfileManager?.profilesLoaded === true && window.ProfileManager?.keysLoaded === true
                    && window.JumpHostManager?.loaded === true && window.socket?.connected === true, null, { timeout: 30000 })
                    .catch(async (error) => {
                        const state = await page.evaluate(() => ({
                            url: location.pathname, profiles: window.ProfileManager?.profilesLoaded, keys: window.ProfileManager?.keysLoaded,
                            jumpHosts: window.JumpHostManager?.loaded, socket: window.socket?.connected,
                        })).catch(() => null);
                        throw new Error(`run ${run}: workspace not ready ${JSON.stringify(state)}: ${error.message}`);
                    });
                workspace.push(Date.now() - reloaded);
            } finally {
                // A closed tab whose socket the server has not noticed yet
                // still counts against the per-user socket limit of Python.
                await page.evaluate(() => window.socket?.disconnect()).catch(() => {});
                await context.close();
            }
        }
        return {
            description: 'new browser context per run; /login load event; submit until the signed-in page fired load; reload of / until inventory and realtime connection are ready',
            login_page_load_ms: summarize(pageLoad), sign_in_ms: summarize(signIn), workspace_ready_ms: summarize(workspace),
            samples: { pageLoad, signIn, workspace },
        };
    }

    async block(options, files) {
        const block = { loadavg_start: loadavg(), started_at: new Date().toISOString() };
        const phases = options.phases;
        if (phases.includes('login')) block.login = await this.loginRuns(Number(options['login-runs']));
        if (phases.includes('terminal')) {
            await this.page.evaluate((id) => SessionManager.switchSession(id), this.sessionId);
            const echo = await echoLatency(this.page, this.sessionId, Number(options['echo-samples']), 20);
            const cat = [];
            for (let run = 0; run < Number(options['cat-runs']); run += 1) cat.push(await catThroughput(this.page, this.sessionId, files.cat, CAT_BYTES));
            block.terminal = {
                echo_ms: summarize(echo), echo_samples: echo,
                cat_50mib_s: summarize(cat.map((item) => item.seconds)), cat_mib_per_s: summarize(cat.map((item) => item.mib_per_s)), cat_runs: cat,
            };
        }
        if (phases.includes('files')) {
            const list = [];
            for (let run = 0; run < Number(options['list-runs']); run += 1) list.push(await listDirectory(this.page, this.sessionId, files.list));
            const uploads = [];
            const downloads = [];
            for (let run = 0; run < Number(options['sftp-runs']); run += 1) {
                const upload = await transfer(this.page, this.sessionId, 'upload', '/config/browser-upload.bin', SFTP_BYTES);
                upload.target_sha256_matches = upload.ok && environment.targetFileDigest('/config/browser-upload.bin') === upload.sha256;
                uploads.push(upload);
                const download = await transfer(this.page, this.sessionId, 'download', files.download, SFTP_BYTES);
                download.sha256_matches = download.sha256 === files.downloadDigest;
                downloads.push(download);
            }
            environment.removeTargetFile('/config/browser-upload.bin');
            const rate = (list) => summarize(list.filter((item) => item.ok).map((item) => SFTP_BYTES / 1048576 / item.seconds));
            block.files = {
                list_ms: summarize(list.map((item) => item.ms)), list_runs: list,
                upload_mib_per_s: rate(uploads), download_mib_per_s: rate(downloads), uploads, downloads,
            };
        }
        block.loadavg_end = loadavg();
        this.result.blocks.push(block);
    }

    async memoryUnderLoad() {
        const out = {};
        for (const total of [10, 40]) {
            await this.openTerminals(total);
            await environment.sleep(10000);
            out[`terminals_${total}`] = await sampleMemory(this.app);
        }
        return out;
    }

    async dispose() {
        await this.context?.close().catch(() => {});
        this.app.cleanup();
    }
}

async function main() {
    const options = parseArgs(process.argv.slice(2));
    const sshd = await environment.startSshd(SSH_PORT);
    const files = {
        cat: environment.createTargetFile('cat-50m.txt', CAT_BYTES),
        download: environment.createTargetFile('download-200m.txt', SFTP_BYTES),
        list: '/config/list-2000',
    };
    files.downloadDigest = environment.targetFileDigest(files.download);
    environment.docker(['exec', environment.SSHD_NAME, 'sh', '-c',
        `mkdir -p ${files.list} && cd ${files.list} && i=0; while [ $i -lt ${LIST_FILES} ]; do : > file-$i.txt; i=$((i+1)); done; chown -R ${sshd.user}:${sshd.user} ${files.list}`]);
    const browser = await chromium.launch();
    const backends = { python: new Backend('python', options.python, browser, sshd), go: new Backend('go', options.go, browser, sshd) };
    const result = { host: { cpu: os.cpus()[0].model, logical_cpus: os.cpus().length, node: process.version }, options, backends: {} };
    try {
        for (const backend of Object.values(backends)) await backend.start();
        // Both backends are up and idle, nobody is signed in.
        await environment.sleep(10000);
        for (const backend of Object.values(backends)) backend.result.memory_idle = await sampleMemory(backend.app);
        for (const backend of Object.values(backends)) await backend.setUp();
        for (const letter of options.order) {
            const backend = letter === 'p' ? backends.python : backends.go;
            await backend.block(options, files);
            process.stderr.write(`block ${backend.kind} done (load ${loadavg().toFixed(2)})\n`);
        }
        if (options.phases.includes('memory')) {
            for (const backend of Object.values(backends)) backend.result.memory_load = await backend.memoryUnderLoad();
        }
    } finally {
        for (const backend of Object.values(backends)) {
            result.backends[backend.kind] = backend.result;
            await backend.dispose();
        }
        await browser.close();
        environment.stopSshd();
        const out = options.out || path.join(rawDir(), `browser-${new Date().toISOString().slice(0, 10)}.json`);
        fs.mkdirSync(path.dirname(out), { recursive: true });
        fs.writeFileSync(out, `${JSON.stringify(result, null, 2)}\n`);
        process.stderr.write(`written ${out}\n`);
    }
}

if (require.main === module) {
    main().catch((error) => {
        process.stderr.write(`${error.stack || error}\n`);
        process.exitCode = 1;
    });
}

module.exports = { Backend, echoLatency, catThroughput, listDirectory, transfer, appEnvironment };
