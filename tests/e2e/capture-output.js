const fs = require('node:fs');
const path = require('node:path');

const ROOT = path.resolve(__dirname, '..', '..');
const ASSET_DIRECTORY = path.join(ROOT, 'assets');
const TRANSIENT_CAPTURE_DIRECTORY = path.join(ROOT, '.test-run.tmp', 'captures');

// Only captures consumed by a public repository surface belong in assets/.
const PUBLISHED_CAPTURE_ASSETS = new Set([
    'mobile-workspace.png',
    'multi-session.png',
    'security-center.png',
    'session-workspace.png',
    'sftp-workspace.png',
    'workspace-overview.png',
]);

function captureOutputPath(filename) {
    if (typeof filename !== 'string'
        || path.basename(filename) !== filename
        || !filename.endsWith('.png')) {
        throw new TypeError('Capture filename must be a plain PNG filename');
    }
    const directory = PUBLISHED_CAPTURE_ASSETS.has(filename)
        ? ASSET_DIRECTORY
        : TRANSIENT_CAPTURE_DIRECTORY;
    fs.mkdirSync(directory, { recursive: true });
    return path.join(directory, filename);
}

module.exports = {
    PUBLISHED_CAPTURE_ASSETS,
    captureOutputPath,
};
