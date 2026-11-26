#!/usr/bin/env node
'use strict';

// Static image figures: uncompressed size (local image store), compressed
// size (registry manifest of one platform), layer count and package counts.
//
//   node tests/baseline/image.js [--image ref] [--platform linux/amd64] [--out file.json]

const fs = require('node:fs');
const path = require('node:path');
const { rawDir } = require('./lib/output');
const { execFileSync } = require('node:child_process');

const REPO_ROOT = path.resolve(__dirname, '..', '..');

function parseArgs(argv) {
    const options = { image: 'ghcr.io/bifrost0x/webssh:latest', platform: 'linux/amd64', out: null };
    for (let index = 0; index < argv.length; index += 2) {
        const key = argv[index].replace(/^--/, '');
        if (!(key in options)) throw new Error(`unknown option --${key}`);
        options[key] = argv[index + 1];
    }
    return options;
}

const run = (args) => execFileSync('docker', args, { encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'], maxBuffer: 64 * 1024 * 1024 }).trim();

function inContainer(image, script) {
    return run(['run', '--rm', '--network', 'none', '--entrypoint', 'sh', image, '-c', script]);
}

function main() {
    const options = parseArgs(process.argv.slice(2));
    const [os, architecture] = options.platform.split('/');
    const repoDigest = run(['image', 'inspect', '--format', '{{index .RepoDigests 0}}', options.image]);
    const index = JSON.parse(run(['buildx', 'imagetools', 'inspect', '--raw', repoDigest]));
    const entry = (index.manifests || []).find((item) => item.platform?.os === os && item.platform?.architecture === architecture);
    const manifest = entry
        ? JSON.parse(run(['buildx', 'imagetools', 'inspect', '--raw', `${repoDigest.split('@')[0]}@${entry.digest}`]))
        : index;
    const layers = manifest.layers || [];
    const compressed = layers.reduce((sum, layer) => sum + layer.size, 0) + (manifest.config?.size || 0);
    const dpkg = inContainer(options.image, "dpkg-query -W -f '${Package} ${Version}\\n'").split('\n').filter(Boolean);
    const python = inContainer(options.image, 'python -c "import importlib.metadata as m; print(\\"\\n\\".join(sorted(d.metadata[\\"Name\\"] + \\" \\" + d.version for d in m.distributions())))"').split('\n').filter(Boolean);
    const result = {
        measured_at: new Date().toISOString(),
        image: options.image,
        repo_digest: repoDigest,
        platform: options.platform,
        platform_manifest_digest: entry?.digest || null,
        uncompressed_bytes: Number(run(['image', 'inspect', '--platform', options.platform, '--format', '{{.Size}}', options.image])),
        compressed_bytes: compressed,
        layer_count: layers.length,
        debian_packages: dpkg.length,
        python_distributions: python.length,
        packages: { debian: dpkg, python },
    };
    const out = options.out || path.join(rawDir(), `image-${result.measured_at.slice(0, 10)}.json`);
    fs.mkdirSync(path.dirname(out), { recursive: true });
    fs.writeFileSync(out, `${JSON.stringify(result, null, 2)}\n`);
    process.stderr.write(`[baseline] wrote ${out}\n`);
}

main();
