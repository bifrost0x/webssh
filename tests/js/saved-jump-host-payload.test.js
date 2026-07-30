const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');

test('saved jump host payload sends its stable id for server-side resolution', () => {
    const source = fs.readFileSync('static/js/app.js', 'utf8');
    const start = source.indexOf('const jumpHostId =');
    const end = source.indexOf('pendingPaneIndex = null;', start);
    const submit = source.slice(start, end);

    assert.match(
        submit,
        /proxyJump\s*=\s*\{[\s\S]*jump_host_id:\s*jumpHostId/,
    );
});
