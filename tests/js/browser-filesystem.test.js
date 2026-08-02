const assert = require('node:assert/strict');
const test = require('node:test');

global.window = { showDirectoryPicker() {} };
require('../../static/js/browser-filesystem.js');
const BrowserFileSystem = global.window.BrowserFileSystem;

test('creates a writable sink in the captured browser directory', async () => {
    const writable = { write() {}, close() {} };
    let requested;
    const directory = {
        async getFileHandle(name, options) {
            requested = { name, options };
            return { async createWritable() { return writable; } };
        },
    };
    const browserFS = new BrowserFileSystem();

    const sink = await browserFS.createWritableSink('report.bin', directory);

    assert.deepEqual(requested, {
        name: 'report.bin',
        options: { create: true },
    });
    assert.equal(sink, writable);
});
