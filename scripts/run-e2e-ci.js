const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { spawnSync } = require('node:child_process');

const baseline = require('../tests/e2e/timing-baseline.json');
const { resolvePlaywrightCli } = require('./e2e-process');
const { assignTests, parsePlaywrightList, parseShard } = require('./e2e-sharding');
const { validateResourceInventory, selectPhase } = require('./e2e-resources');

const playwrightCli = resolvePlaywrightCli();

function runPlaywright(args, options = {}) {
    const result = spawnSync(process.execPath, [playwrightCli, 'test', ...args], {
        cwd: process.cwd(),
        env: { ...process.env, ...options.env },
        encoding: options.capture ? 'utf8' : undefined,
        stdio: options.capture ? ['ignore', 'pipe', 'pipe'] : 'inherit',
    });
    if (result.error) throw result.error;
    if (result.status !== 0 && options.capture) {
        process.stdout.write(result.stdout || '');
        process.stderr.write(result.stderr || '');
    }
    return result;
}

function discover(extraArgs = []) {
    const result = runPlaywright([
        '--list',
        '--forbid-only',
        '--reporter=line',
        ...extraArgs,
    ], { capture: true });
    if (result.status !== 0) {
        throw new Error(`Playwright discovery failed with exit code ${result.status}.`);
    }
    return parsePlaywrightList(result.stdout);
}

function assertNoSharedExecutionGroups() {
    const testDirectory = path.resolve('tests', 'e2e');
    const sharedGroupPattern = /test\.(?:beforeAll|afterAll)\s*\(|test\.describe\.serial\s*\(|describe\.configure\s*\(\s*\{[^}]*mode\s*:\s*['"]serial['"]/s;
    const pending = [testDirectory];
    const specFiles = [];
    while (pending.length > 0) {
        const directory = pending.pop();
        for (const entry of fs.readdirSync(directory, { withFileTypes: true })) {
            const entryPath = path.join(directory, entry.name);
            if (entry.isDirectory()) pending.push(entryPath);
            if (entry.isFile() && entry.name.endsWith('.spec.js')) specFiles.push(entryPath);
        }
    }
    for (const specFile of specFiles) {
        const source = fs.readFileSync(specFile, 'utf8');
        if (sharedGroupPattern.test(source)) {
            const name = path.relative(testDirectory, specFile).replaceAll('\\', '/');
            throw new Error(
                `${name} defines a shared serial/beforeAll group; teach the weighted runner `
                + 'its group boundary before sharding it.',
            );
        }
    }
}

function parseArguments(argv) {
    const shardArgs = argv.filter(argument => argument.startsWith('--shard='));
    const phaseArgs = argv.filter(argument => argument.startsWith('--phase='));
    if (shardArgs.length !== 1 || phaseArgs.length > 1 || argv.length !== 1 + phaseArgs.length) {
        throw new Error('Usage: npm run test:e2e:ci -- --shard=<current>/<total> [--phase=all|exclusive|shared]');
    }
    const shard = parseShard(shardArgs[0].slice('--shard='.length));
    const phase = phaseArgs.length ? phaseArgs[0].slice('--phase='.length) : 'all';
    if (!['all', 'exclusive', 'shared'].includes(phase)) throw new Error(`Unknown E2E phase: ${phase}`);
    return { shard, phase };
}

function selectAssignedTests(discovered, shard, phase, timingBaseline = baseline) {
    if (shard.total > discovered.length) {
        throw new Error(`Cannot divide ${discovered.length} tests into ${shard.total} non-empty shards.`);
    }
    if (phase !== 'all') validateResourceInventory(discovered);
    const assignment = assignTests(discovered, shard.total, timingBaseline);
    const selected = selectPhase(assignment.shards[shard.current - 1], phase);
    return { assignment, selected };
}

function main(argv) {
    const { shard, phase } = parseArguments(argv);
    assertNoSharedExecutionGroups();
    const discovered = discover();
    const { assignment, selected } = selectAssignedTests(discovered, shard, phase);

    const temporaryDirectory = fs.mkdtempSync(path.join(os.tmpdir(), 'webssh-e2e-shard-'));
    const testList = path.join(temporaryDirectory, `shard-${shard.current}-of-${shard.total}.txt`);
    try {
        fs.writeFileSync(testList, `${selected.map(test => test.selector).join('\n')}\n`, 'utf8');

        const verified = discover([`--test-list=${testList}`]);
        const expectedIdentities = selected.map(test => test.identity).sort();
        const verifiedIdentities = verified.map(test => test.identity).sort();
        if (JSON.stringify(verifiedIdentities) !== JSON.stringify(expectedIdentities)) {
            throw new Error(
                `Shard ${shard.current}/${shard.total} verification did not rediscover its exact selection.`,
            );
        }

        const loadSummary = assignment.loads.map(value => value.toFixed(3)).join('s, ');
        console.log(
            `Weighted E2E shard ${shard.current}/${shard.total} phase ${phase}: ${selected.length} of `
            + `${discovered.length} tests (estimated shard loads: ${loadSummary}s).`,
        );
        const timingFile = process.env.WEBSSH_E2E_TIMING_FILE || path.join(
            'test-results',
            `e2e-timing-shard-${shard.current}-of-${shard.total}${phase === 'all' ? '' : `-${phase}`}.json`,
        );
        const result = runPlaywright([
            '--forbid-only',
            `--test-list=${testList}`,
        ], {
            env: {
                WEBSSH_E2E_SHARD: `${shard.current}/${shard.total}`,
                WEBSSH_E2E_PHASE: phase,
                WEBSSH_E2E_TIMING_FILE: timingFile,
            },
        });
        process.exitCode = result.status ?? 1;
    } finally {
        fs.rmSync(temporaryDirectory, { recursive: true, force: true });
    }
}

if (require.main === module) {
    try {
        main(process.argv.slice(2));
    } catch (error) {
        console.error(error.message);
        process.exitCode = 1;
    }
}

module.exports = { assertNoSharedExecutionGroups, discover, main, parseArguments, selectAssignedTests };
