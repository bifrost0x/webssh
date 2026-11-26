'use strict';

const { TerminalSession } = require('./terminal');
const { summarize, median } = require('./stats');
const { sleep } = require('./environment');

function parseMiB(text) {
    const match = /^([\d.]+)\s*([KMG]i?B|B)$/.exec(String(text).trim());
    if (!match) return null;
    const factor = { B: 1 / 1048576, KiB: 1 / 1024, KB: 1 / 1024, MiB: 1, MB: 1, GiB: 1024, GB: 1024 }[match[2]];
    return Number(match[1]) * factor;
}

async function sampleMemory(app, samples = 5, intervalMs = 1000) {
    const raw = [];
    for (let index = 0; index < samples; index += 1) {
        if (index) await sleep(intervalMs);
        const memory = app.memory();
        raw.push({
            rss_total_mib: memory.rss_total_kib / 1024,
            container_mib: memory.container_mem_usage ? parseMiB(memory.container_mem_usage) : null,
            processes: memory.processes.map((item) => ({ comm: item.comm, rss_mib: item.rss_kib / 1024, threads: item.threads })),
        });
    }
    const containers = raw.map((item) => item.container_mib).filter((value) => value !== null);
    return {
        rss_total_mib: median(raw.map((item) => item.rss_total_mib)),
        container_mib: containers.length ? median(containers) : null,
        threads_total: raw.at(-1).processes.reduce((sum, item) => sum + item.threads, 0),
        samples: raw,
    };
}

function sshTarget(app, sshd) {
    return { ...app.sshTarget(sshd), username: sshd.user, password: sshd.password };
}

// One socket per account (one browser tab), perUser terminals on each.
async function openTerminals(accounts, perUser, total, target) {
    const sockets = [];
    const terminals = [];
    for (const account of accounts) {
        if (terminals.length >= total) break;
        const socket = await account.session.openSocket();
        sockets.push(socket);
        for (let index = 0; index < perUser && terminals.length < total; index += 1) {
            const terminal = await TerminalSession.open(socket, target);
            await terminal.prepare();
            terminals.push(terminal);
        }
    }
    if (terminals.length !== total) throw new Error(`opened ${terminals.length} of ${total} terminals`);
    return { sockets, terminals };
}

async function closeTerminals({ sockets, terminals }) {
    for (const terminal of terminals) terminal.close();
    await sleep(500);
    for (const socket of sockets) socket.close();
    await sleep(1000);
}

async function memoryScenario(app, sshd, accounts, counts, settleMs) {
    const result = {};
    await sleep(settleMs);
    result.idle = await sampleMemory(app);
    for (const count of counts) {
        const opened = await openTerminals(accounts, 5, count, sshTarget(app, sshd));
        await sleep(settleMs);
        result[`sessions_${count}`] = await sampleMemory(app);
        await closeTerminals(opened);
    }
    return result;
}

async function readyLatency(baseUrl, samples) {
    const values = [];
    const failures = [];
    for (let index = 0; index < samples; index += 1) {
        const started = process.hrtime.bigint();
        try {
            const response = await fetch(`${baseUrl}/ready`, { signal: AbortSignal.timeout(10000) });
            await response.arrayBuffer();
            if (response.status !== 200) failures.push(response.status);
            else values.push(Number(process.hrtime.bigint() - started) / 1e6);
        } catch (error) {
            failures.push(`${error.name}:${error.cause?.code || error.cause?.message || error.message}`);
        }
    }
    return { ms: summarize(values), failures };
}

// Opens sockets until the server refuses; records where and how.
async function socketLimit(app, accounts, perUser) {
    const sockets = [];
    const attempts = [];
    for (const account of accounts) {
        for (let index = 0; index < perUser; index += 1) {
            const attempt = { number: attempts.length + 1, user: account.username };
            try {
                sockets.push(await account.session.openSocket(10000));
                attempt.result = 'connected';
            } catch (error) {
                attempt.result = error.message;
                if (error.description) attempt.description = String(error.description);
            }
            attempts.push(attempt);
        }
    }
    const held = sockets.length;
    const readyWhileHeld = await readyLatency(app.baseUrl, 20);
    const logs = app.logs();
    const rejectionLog = logs.split('\n').filter((line) => /capacity|admission|rejected/i.test(line)).slice(-5);
    sockets.pop()?.close();
    await sleep(1000);
    let reopen = 'not_attempted';
    try {
        const socket = await accounts.at(-1).session.openSocket(10000);
        reopen = 'connected';
        sockets.push(socket);
    } catch (error) {
        reopen = error.message;
    }
    for (const socket of sockets) socket.close();
    await sleep(1000);
    const firstRejection = attempts.find((item) => item.result !== 'connected') || null;
    return { attempts, held, first_rejection: firstRejection, ready_while_held: readyWhileHeld, reopen_after_release: reopen, server_log_lines: rejectionLog };
}

// Opens terminals past the SSH session quota and records the refusal.
async function sessionQuota(app, sshd, accounts, perUserAttempts) {
    const target = sshTarget(app, sshd);
    const opened = [];
    const attempts = [];
    const sockets = [];
    for (const account of accounts) {
        const socket = await account.session.openSocket();
        sockets.push(socket);
        for (let index = 0; index < perUserAttempts; index += 1) {
            const attempt = { number: attempts.length + 1, user: account.username };
            try {
                opened.push(await TerminalSession.open(socket, target));
                attempt.result = 'connected';
            } catch (error) {
                attempt.result = error.message;
                attempt.error_code = error.payload?.error_code || error.payload?.code || null;
            }
            attempts.push(attempt);
        }
    }
    await closeTerminals({ sockets, terminals: opened });
    return { attempts, connected: opened.length };
}

// Round trip of one typed character until its echo arrives.
async function echoLatency(terminal, samples, warmup) {
    const values = [];
    const alphabet = 'abcdefghijklmnopqrstuvwxyz';
    for (let index = 0; index < samples + warmup; index += 1) {
        if (index && index % 40 === 0) {
            terminal.send('\x15');
            await sleep(100);
        }
        const character = alphabet[index % alphabet.length];
        terminal.buffer = '';
        const started = process.hrtime.bigint();
        terminal.send(character);
        await terminal.waitForText(character, 10000);
        const elapsed = Number(process.hrtime.bigint() - started) / 1e6;
        if (index >= warmup) values.push(elapsed);
        await sleep(10);
    }
    terminal.send('\x15');
    await sleep(200);
    return { ms: summarize(values), samples: values };
}

// Time from Enter until the end marker of `cat <file>` arrives.
async function outputThroughput(terminal, file, fileBytes, runs) {
    const results = [];
    for (let run = 0; run < runs; run += 1) {
        terminal.buffer = '';
        await sleep(300);
        terminal.buffer = '';
        const before = terminal.received;
        const started = process.hrtime.bigint();
        terminal.send(`cat ${file}; echo CAT_""DONE_${run}\r`);
        await terminal.waitForText(`CAT_DONE_${run}`, 600000);
        const seconds = Number(process.hrtime.bigint() - started) / 1e9;
        results.push({
            seconds,
            mib_per_s: fileBytes / 1048576 / seconds,
            received_chars: terminal.received - before,
        });
    }
    return {
        file_bytes: fileBytes,
        seconds: summarize(results.map((item) => item.seconds)),
        mib_per_s: summarize(results.map((item) => item.mib_per_s)),
        runs: results,
    };
}

module.exports = {
    sampleMemory, openTerminals, closeTerminals, memoryScenario, socketLimit,
    sessionQuota, echoLatency, outputThroughput, sshTarget, readyLatency,
};
