'use strict';

// Where baseline measurements are written. Raw results go to <dir>/raw,
// reports to <dir>. The directory is chosen with --dir (report.js) or
// WEBSSH_BASELINE_DIR; the default lies in the ignored test-results/ tree,
// so measurements never end up in a commit by accident.

const path = require('node:path');

const REPO_ROOT = path.resolve(__dirname, '..', '..', '..');
const DEFAULT_DIR = path.join(REPO_ROOT, 'test-results', 'baseline');

function baselineDir(explicit) {
    const dir = explicit || process.env.WEBSSH_BASELINE_DIR || DEFAULT_DIR;
    return path.resolve(dir);
}

function rawDir(explicit) {
    return path.join(baselineDir(explicit), 'raw');
}

module.exports = { baselineDir, rawDir, DEFAULT_DIR };
