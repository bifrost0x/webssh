// Builds the webssh binary the browser suites start, from this checkout.
// WEBSSH_E2E_GO_BINARY (e2e build) and WEBSSH_E2E_GO_RELEASE_BINARY
// (release build) name a prebuilt binary instead, as CI does once per job.
// Parallel lanes share the build directory, so staging and building run
// under a lock directory; the Go build cache makes the later builds cheap.
const {execFileSync} = require('node:child_process');
const fs = require('node:fs');
const path = require('node:path');

const repoRoot = path.resolve(__dirname, '../..');
const buildDir = path.join(repoRoot, '.test-run.tmp');
const lockDir = path.join(buildDir, 'webssh-build.lock');
const lockTimeoutMs = 10 * 60_000;

// The release version of the image (ARG VERSION of the Dockerfile). The
// account menu spec expects a release version, not "dev".
function releaseVersion() {
    const versions = new Set([...fs.readFileSync(path.join(repoRoot, 'Dockerfile'), 'utf8')
        .matchAll(/^ARG VERSION=(\S+)$/gm)].map(match => match[1]));
    if (versions.size !== 1) throw new Error('Dockerfile: expected one ARG VERSION value');
    return [...versions][0];
}

function revision() {
    try {
        return execFileSync('git', ['rev-parse', 'HEAD'], {cwd: repoRoot, encoding: 'utf8'}).trim();
    } catch {
        return '';
    }
}

function sleep(ms) {
    Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, ms);
}

function withLock(work) {
    fs.mkdirSync(buildDir, {recursive: true});
    const deadline = Date.now() + lockTimeoutMs;
    for (;;) {
        try {
            fs.mkdirSync(lockDir);
            break;
        } catch (error) {
            if (error.code !== 'EEXIST') throw error;
            if (Date.now() > deadline) throw new Error(`build lock ${lockDir} held for too long; remove it if no build runs`);
            sleep(200);
        }
    }
    try {
        return work();
    } finally {
        fs.rmSync(lockDir, {recursive: true, force: true});
    }
}

// Returns the path of the binary: kind "e2e" (build tag e2e, with the
// seed applier and test hooks) or "release".
function webssh(kind) {
    const prebuilt = process.env[kind === 'e2e' ? 'WEBSSH_E2E_GO_BINARY' : 'WEBSSH_E2E_GO_RELEASE_BINARY'];
    if (prebuilt) return path.resolve(prebuilt);
    const output = path.join(buildDir, kind === 'e2e' ? 'webssh-e2e' : 'webssh');
    const rev = revision();
    const ldflags = [`-X github.com/bifrost0x/webssh/internal/buildinfo.version=${releaseVersion()}`];
    if (/^[0-9a-f]{40}$/.test(rev)) ldflags.push(`-X github.com/bifrost0x/webssh/internal/buildinfo.revision=${rev}`);
    withLock(() => {
        execFileSync('sh', [path.join('scripts', 'stage-webassets.sh')], {cwd: repoRoot, stdio: 'inherit'});
        const args = ['build', '-trimpath', '-o', output, '-ldflags', ldflags.join(' ')];
        if (kind === 'e2e') args.push('-tags', 'e2e');
        execFileSync('go', [...args, './cmd/webssh'], {cwd: repoRoot, stdio: 'inherit'});
    });
    return output;
}

module.exports = {webssh, releaseVersion};
