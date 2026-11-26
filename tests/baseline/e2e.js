#!/usr/bin/env node
'use strict';

// Wall-clock runtime of the Playwright suite with tracing off.
//
//   node tests/baseline/e2e.js [--out file.json] [-- <extra playwright args, e.g. spec files>]
//
// Uses the repository Playwright config unchanged (one worker, the app from
// tests/e2e/run_app.py) and the worktree .venv unless PYTHON is set.

const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { spawn } = require('node:child_process');

const REPO_ROOT = path.resolve(__dirname, '..', '..');
const { resolvePlaywrightCli } = require(path.join(REPO_ROOT, 'scripts', 'e2e-process'));

function main() {
    const argv = process.argv.slice(2);
    const split = argv.indexOf('--');
    const own = split === -1 ? argv : argv.slice(0, split);
    const extra = split === -1 ? [] : argv.slice(split + 1);
    const outIndex = own.indexOf('--out');
    const startedAt = new Date().toISOString();
    const out = outIndex === -1
        ? path.join(REPO_ROOT, 'plans', 'baseline', 'raw', `e2e-${startedAt.slice(0, 10)}.json`)
        : own[outIndex + 1];
    const outputDir = fs.mkdtempSync(path.join(os.tmpdir(), 'webssh-baseline-e2e-'));
    const args = [resolvePlaywrightCli(), 'test', '--trace', 'off', '--reporter', 'line', ...extra];
    const started = process.hrtime.bigint();
    const child = spawn(process.execPath, args, {
        cwd: REPO_ROOT,
        env: {
            ...process.env,
            PYTHON: process.env.PYTHON || path.join(REPO_ROOT, '.venv', 'bin', 'python'),
            WEBSSH_E2E_OUTPUT_DIR: outputDir,
        },
        stdio: ['ignore', 'pipe', 'pipe'],
    });
    let tail = '';
    const keep = (chunk) => {
        process.stdout.write(chunk);
        tail = (tail + chunk.toString()).slice(-20000);
    };
    child.stdout.on('data', keep);
    child.stderr.on('data', keep);
    child.on('exit', (code, signal) => {
        const seconds = Number(process.hrtime.bigint() - started) / 1e9;
        const count = (word) => Number(new RegExp(`(\\d+) ${word}`).exec(tail)?.[1] || 0);
        const result = {
            started_at: startedAt,
            command: ['playwright', ...args.slice(1)].join(' '),
            exit_code: code,
            signal,
            wall_seconds: seconds,
            passed: count('passed'),
            failed: count('failed'),
            flaky: count('flaky'),
            skipped: count('skipped'),
            did_not_run: count('did not run'),
            output_tail: tail.slice(-4000),
        };
        fs.mkdirSync(path.dirname(out), { recursive: true });
        fs.writeFileSync(out, `${JSON.stringify(result, null, 2)}\n`);
        fs.rmSync(outputDir, { recursive: true, force: true });
        process.stderr.write(`[baseline] wrote ${out}\n`);
        process.exitCode = code === null ? 1 : code;
    });
}

main();
