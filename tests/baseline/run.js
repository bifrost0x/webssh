#!/usr/bin/env node
'use strict';

// Baseline measurement of a running WebSSH backend.
//
//   node tests/baseline/run.js --target docker [--image ghcr.io/bifrost0x/webssh:latest]
//   node tests/baseline/run.js --target local
//
// Options: --phases startup,memory,limits,terminal,sftp  --startup-runs 10
//          --memory-runs 3  --echo-samples 500  --cat-runs 5  --sftp-runs 5
//          --out <file.json>
// Everything runs serially; measurements never overlap.

const crypto = require('node:crypto');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { execFileSync } = require('node:child_process');

const environment = require('./lib/environment');
const { createAccounts } = require('./lib/accounts');
const terminal = require('./lib/measure-terminal');
const sftp = require('./lib/measure-sftp');
const { summarize } = require('./lib/stats');

const APP_PORT = 15873;
const SSH_PORT = 22873;
const CAT_BYTES = 50 * 1024 * 1024;
const SFTP_BYTES = 200 * 1024 * 1024;
const RAISED_TRANSFER_LIMIT = String(256 * 1024 * 1024);

function parseArgs(argv) {
    const options = {
        target: 'docker',
        image: 'ghcr.io/bifrost0x/webssh:latest',
        phases: 'startup,memory,limits,terminal,sftp',
        'startup-runs': '10',
        'memory-runs': '3',
        'echo-samples': '500',
        'cat-runs': '5',
        'sftp-runs': '5',
        out: null,
    };
    for (let index = 0; index < argv.length; index += 2) {
        const key = argv[index].replace(/^--/, '');
        if (!(key in options)) throw new Error(`unknown option --${key}`);
        options[key] = argv[index + 1];
    }
    options.phases = options.phases.split(',');
    return options;
}

function command(file, args) {
    try {
        return execFileSync(file, args, { encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'] }).trim();
    } catch {
        return null;
    }
}

function hostInfo() {
    const cpuinfo = fs.readFileSync('/proc/cpuinfo', 'utf8');
    return {
        cpu_model: /^model name\s*:\s*(.+)$/m.exec(cpuinfo)?.[1] || null,
        logical_cpus: os.cpus().length,
        memory_total_mib: Math.round(os.totalmem() / 1048576),
        uname: command('uname', ['-srvmo']),
        os_release: /^PRETTY_NAME="?([^"\n]+)/m.exec(fs.readFileSync('/etc/os-release', 'utf8'))?.[1] || null,
        node: process.version,
        docker: command('docker', ['version', '--format', '{{.Server.Version}}']),
        docker_context: command('docker', ['context', 'show']),
        venv_python: command(path.join(environment.REPO_ROOT, '.venv', 'bin', 'python'), ['-V']),
        worktree_revision: command('git', ['-C', environment.REPO_ROOT, 'rev-parse', 'HEAD']),
    };
}

function makeApp(options, extra) {
    const env = { ...extra };
    if (options.target === 'docker') return new environment.DockerApp({ image: options.image, port: APP_PORT, environment: env });
    return new environment.LocalApp({ port: APP_PORT, environment: env });
}

const origin = { CORS_ORIGINS: `http://127.0.0.1:${APP_PORT}` };
const defaultConfig = () => environment.baseAppEnvironment(origin);
const raisedConfig = () => environment.baseAppEnvironment({
    ...origin,
    QUOTA_SSH_SESSION_GLOBAL: '40',
    MAX_UPLOAD_SIZE: RAISED_TRANSFER_LIMIT,
    MAX_DOWNLOAD_SIZE: RAISED_TRANSFER_LIMIT,
});

async function withApp(options, config, body) {
    const app = makeApp(options, config);
    try {
        await app.start();
        return await body(app);
    } finally {
        await app.stop();
        app.cleanup();
    }
}

async function phaseStartup(options) {
    // Production start without any optional setting. The image generates and
    // persists SECRET_KEY itself; the local start receives one, like the
    // entrypoint would export it.
    const config = options.target === 'docker' ? {} : { SECRET_KEY: environment.randomSecret(32) };
    const runs = Number(options['startup-runs']);
    const cold = [];
    const warm = [];
    const app = makeApp(options, config);
    try {
        for (let run = 0; run < runs; run += 1) {
            cold.push(await app.start());
            await app.stop();
            warm.push(await app.start({ keepVolume: true }));
            await app.stop();
            app.cleanup();
        }
    } finally {
        await app.stop();
        app.cleanup();
    }
    return {
        description: 'process start until GET /ready returns 200, polled every 20 ms',
        cold_empty_data_dir_ms: summarize(cold),
        warm_existing_data_dir_ms: summarize(warm),
        samples: { cold, warm },
    };
}

async function phaseMemory(options, sshd) {
    const runs = Number(options['memory-runs']);
    const defaultRuns = [];
    const raisedRuns = [];
    for (let run = 0; run < runs; run += 1) {
        defaultRuns.push(await withApp(options, defaultConfig(), async (app) => {
            const accounts = await createAccounts(app.baseUrl, 2);
            return terminal.memoryScenario(app, sshd, accounts, [10], 10000);
        }));
        raisedRuns.push(await withApp(options, raisedConfig(), async (app) => {
            const accounts = await createAccounts(app.baseUrl, 8);
            return terminal.memoryScenario(app, sshd, accounts, [10, 40], 10000);
        }));
    }
    const pick = (list, key, field) => summarize(list.map((item) => item[key][field]).filter((value) => value !== null));
    const table = {};
    for (const [name, list, keys] of [['default', defaultRuns, ['idle', 'sessions_10']], ['raised_quota', raisedRuns, ['idle', 'sessions_10', 'sessions_40']]]) {
        table[name] = {};
        for (const key of keys) {
            table[name][key] = { rss_total_mib: pick(list, key, 'rss_total_mib'), container_mib: pick(list, key, 'container_mib'), threads_total: pick(list, key, 'threads_total') };
        }
    }
    return { description: 'median of 5 samples (1 s apart) after 10 s settle; 5 terminals per account, one socket per account', summary: table, runs: { default: defaultRuns, raised_quota: raisedRuns } };
}

function writeRandomFile(bytes) {
    const file = path.join(fs.mkdtempSync(path.join(os.tmpdir(), 'webssh-baseline-sftp-')), 'upload.bin');
    const handle = fs.openSync(file, 'w', 0o600);
    const chunk = 4 * 1024 * 1024;
    for (let written = 0; written < bytes; written += chunk) fs.writeSync(handle, crypto.randomBytes(Math.min(chunk, bytes - written)));
    fs.closeSync(handle);
    return file;
}

function fileDigest(file) {
    return crypto.createHash('sha256').update(fs.readFileSync(file)).digest('hex');
}

async function phaseLimits(options, sshd, uploadFile) {
    return withApp(options, defaultConfig(), async (app) => {
        const accounts = await createAccounts(app.baseUrl, 7);
        const sockets = await terminal.socketLimit(app, accounts, 8);
        const sessions = await terminal.sessionQuota(app, sshd, accounts.slice(0, 3), 6);
        const opened = await terminal.openTerminals([accounts[0]], 1, 1, terminal.sshTarget(app, sshd)).catch((error) => ({ error }));
        let transfer = { error: opened.error?.message || null };
        if (!opened.error) {
            const [term] = opened.terminals;
            const big = environment.createTargetFile('limit-200m.txt', SFTP_BYTES);
            transfer = {
                upload_200mib: await sftp.upload(accounts[0].session, opened.sockets[0], term.sessionId, uploadFile, '/config/limit-upload.bin'),
                download_200mib: await sftp.download(accounts[0].session, opened.sockets[0], term.sessionId, big),
            };
            environment.removeTargetFile(big);
            environment.removeTargetFile('/config/limit-upload.bin');
            await terminal.closeTerminals(opened);
        }
        return { sockets, ssh_sessions: sessions, transfer_size_default: transfer };
    });
}

async function phaseTerminal(options, sshd) {
    return withApp(options, defaultConfig(), async (app) => {
        const [account] = await createAccounts(app.baseUrl, 1);
        const opened = await terminal.openTerminals([account], 1, 1, terminal.sshTarget(app, sshd));
        const [term] = opened.terminals;
        const file = environment.createTargetFile('cat-50m.txt', CAT_BYTES);
        try {
            const echo = await terminal.echoLatency(term, Number(options['echo-samples']), 20);
            const cat = await terminal.outputThroughput(term, file, CAT_BYTES, Number(options['cat-runs']));
            return { echo_rtt: echo, cat_50mib: cat };
        } finally {
            environment.removeTargetFile(file);
            await terminal.closeTerminals(opened);
        }
    });
}

async function phaseSftp(options, sshd, uploadFile) {
    return withApp(options, raisedConfig(), async (app) => {
        const [account] = await createAccounts(app.baseUrl, 1);
        const opened = await terminal.openTerminals([account], 1, 1, terminal.sshTarget(app, sshd));
        const [term] = opened.terminals;
        const socket = opened.sockets[0];
        const expected = fileDigest(uploadFile);
        const remote = '/config/sftp-upload.bin';
        const uploads = [];
        const downloads = [];
        try {
            for (let run = 0; run < Number(options['sftp-runs']); run += 1) {
                const result = await sftp.upload(account.session, socket, term.sessionId, uploadFile, remote);
                if (result.ok) result.sha256_match = environment.targetFileDigest(remote) === expected;
                uploads.push(result);
            }
            for (let run = 0; run < Number(options['sftp-runs']); run += 1) {
                const result = await sftp.download(account.session, socket, term.sessionId, remote);
                if (result.ok) result.sha256_match = result.sha256 === expected;
                downloads.push(result);
            }
        } finally {
            environment.removeTargetFile(remote);
            await terminal.closeTerminals(opened);
        }
        return {
            description: 'prepare_transfer + HTTP body, timed end to end; sha256 verified',
            upload_200mib: sftp.throughput(uploads, SFTP_BYTES),
            download_200mib: sftp.throughput(downloads, SFTP_BYTES),
        };
    });
}

async function main() {
    const options = parseArgs(process.argv.slice(2));
    const result = {
        schema: 1,
        started_at: new Date().toISOString(),
        target: options.target,
        image: options.target === 'docker' ? {
            reference: options.image,
            digest: command('docker', ['image', 'inspect', '--format', '{{index .RepoDigests 0}}', options.image]),
            revision: command('docker', ['image', 'inspect', '--format', '{{index .Config.Labels "org.opencontainers.image.revision"}}', options.image]),
        } : null,
        sshd_image: environment.SSHD_IMAGE,
        host: hostInfo(),
        loadavg_start: os.loadavg(),
        options,
        phases: {},
    };
    const out = options.out || path.join(environment.REPO_ROOT, 'plans', 'baseline', 'raw', `${options.target}-${result.started_at.slice(0, 10)}.json`);
    fs.mkdirSync(path.dirname(out), { recursive: true });
    const save = () => fs.writeFileSync(out, `${JSON.stringify(result, null, 2)}\n`);
    let sshd = null;
    let uploadFile = null;
    const needsSshd = options.phases.some((phase) => phase !== 'startup');
    try {
        if (needsSshd) sshd = await environment.startSshd(SSH_PORT);
        if (options.phases.includes('limits') || options.phases.includes('sftp')) uploadFile = writeRandomFile(SFTP_BYTES);
        const phases = { startup: () => phaseStartup(options), memory: () => phaseMemory(options, sshd), limits: () => phaseLimits(options, sshd, uploadFile), terminal: () => phaseTerminal(options, sshd), sftp: () => phaseSftp(options, sshd, uploadFile) };
        for (const phase of options.phases) {
            const started = Date.now();
            process.stderr.write(`[baseline] ${options.target}: ${phase} ...\n`);
            try {
                result.phases[phase] = await phases[phase]();
            } catch (error) {
                result.phases[phase] = { error: String(error.stack || error) };
                process.stderr.write(`[baseline] ${phase} failed: ${error.message}\n`);
            }
            result.phases[phase].duration_s = (Date.now() - started) / 1000;
            save();
        }
    } finally {
        if (uploadFile) fs.rmSync(path.dirname(uploadFile), { recursive: true, force: true });
        if (sshd) environment.stopSshd();
        result.finished_at = new Date().toISOString();
        result.loadavg_end = os.loadavg();
        save();
        process.stderr.write(`[baseline] wrote ${out}\n`);
    }
}

main().catch((error) => {
    process.stderr.write(`${error.stack || error}\n`);
    process.exitCode = 1;
});
