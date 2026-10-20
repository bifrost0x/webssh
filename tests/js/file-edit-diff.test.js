const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
const path = require('node:path');

function diff(original, edited) {
    const context = { window: {} };
    const filename = path.join(__dirname, '../../static/js/file-edit-diff.js');
    if (fs.existsSync(filename)) vm.runInNewContext(fs.readFileSync(filename, 'utf8'), context);
    assert.equal(typeof context.window.FileEditDiff?.compare, 'function', 'bounded file comparison is available');
    return context.window.FileEditDiff.compare(original, edited);
}

test('diff shows removed and added lines and preserves terminal newline changes', () => {
    const result = diff('first\nold\nlast\n', 'first\nnew\nlast\n');
    assert.equal(result.changed, true);
    assert.equal(result.limited, false);
    assert.equal(result.originalLine, 2);
    assert.match(result.text, /-old\n/);
    assert.match(result.text, /\+new\n/);
    assert.equal(diff('same', 'same').changed, false);
    assert.equal(diff('same\n', 'same').changed, true);
});

test('diff bounds output for five MiB dissimilar long lines and millions of tiny lines', () => {
    for (const original of ['a'.repeat(5 * 1024 * 1024), 'a\n'.repeat(2500000)]) {
        const started = performance.now();
        const result = diff(original, original.replaceAll('a', 'b'));
        assert.equal(result.limited, true);
        assert.ok(result.text.length <= 66000);
        assert.ok(performance.now() - started < 3000, 'comparison is bounded and linear');
        assert.match(result.text, /-a/);
        assert.match(result.text, /\+b/);
    }
});

test('diff includes the first character when replacing or removing a leading newline', () => {
    for (const [original, edited] of [['\n', 'x'], ['\nabc\n', 'xabc\n'], ['\nabc', 'abc']]) {
        const result = diff(original, edited);
        assert.equal(result.originalLine, 1);
        assert.match(result.text, /^-\n/);
        assert.match(result.text, new RegExp(`\\+${edited.startsWith('x') ? 'x' : 'a'}`));
    }
});
