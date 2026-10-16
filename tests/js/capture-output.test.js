const assert = require('node:assert/strict');
const path = require('node:path');
const test = require('node:test');

const {
    PUBLISHED_CAPTURE_ASSETS,
    captureOutputPath,
} = require('../e2e/capture-output');

test('public product captures are the only captures written to assets', () => {
    const root = path.resolve(__dirname, '..', '..');
    assert.equal(
        captureOutputPath('workspace-overview.png'),
        path.join(root, 'assets', 'workspace-overview.png'),
    );
    assert.equal(
        captureOutputPath('connection-panel.png'),
        path.join(root, '.test-run.tmp', 'captures', 'connection-panel.png'),
    );
    assert.deepEqual(
        [...PUBLISHED_CAPTURE_ASSETS].sort(),
        [
            'mobile-workspace.png',
            'multi-session.png',
            'security-center.png',
            'session-workspace.png',
            'sftp-workspace.png',
            'workspace-overview.png',
        ],
    );
});

test('capture filenames cannot escape their output directory', () => {
    assert.throws(() => captureOutputPath('../outside.png'), TypeError);
    assert.throws(() => captureOutputPath('nested/outside.png'), TypeError);
    assert.throws(() => captureOutputPath('capture.jpg'), TypeError);
});

test('retired product screenshots remain transient captures', () => {
    const root = path.resolve(__dirname, '..', '..');
    for (const filename of ['keys.png', 'filemanager.png']) {
        assert.equal(
            captureOutputPath(filename),
            path.join(root, '.test-run.tmp', 'captures', filename),
        );
    }
});
