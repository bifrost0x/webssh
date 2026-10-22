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

test('colored review renders bounded literal text with separate old and new line numbers', () => {
    const context = { window: {} };
    vm.runInNewContext(fs.readFileSync(path.join(__dirname, '../../static/js/file-edit-diff.js'), 'utf8'), context);
    const make = () => ({ children: [], dataset: {}, appendChild(child) { this.children.push(child); } });
    const target = { ownerDocument: { createElement: make, createDocumentFragment: make }, replaceChildren(fragment) { this.children = fragment.children; } };
    const result = context.window.FileEditDiff.compare('same\n<script>old</script>\nlast\n', 'same\n<img onerror=evil>\nlast\n');
    assert.equal(typeof context.window.FileEditDiff.render, 'function');
    context.window.FileEditDiff.render(target, result);
    assert.equal(target.children[1].className, 'editor-diff-line editor-diff-removed');
    assert.equal(target.children[1].textContent, '-<script>old</script>\n');
    assert.equal(target.children[1].dataset.oldLine, '2');
    assert.equal(target.children[1].dataset.newLine, '');
    assert.equal(target.children[2].className, 'editor-diff-line editor-diff-added');
    assert.equal(target.children[2].textContent, '+<img onerror=evil>\n');
    assert.equal(target.children[2].dataset.newLine, '2');
    assert.ok(target.children.every(row => row.innerHTML === undefined));
    const large = context.window.FileEditDiff.compare('a\n'.repeat(100000), 'b\n'.repeat(100000));
    context.window.FileEditDiff.render(target, large);
    assert.ok(target.children.length <= 403);
    const longLine = context.window.FileEditDiff.compare('a'.repeat(40000), 'b'.repeat(40000));
    context.window.FileEditDiff.render(target, longLine);
    assert.equal(longLine.limited, true);
    assert.ok(target.children.some(row => row.className.endsWith('editor-diff-removed') && row.textContent.startsWith('-aaa')));
    assert.ok(target.children.some(row => row.className.endsWith('editor-diff-added') && row.textContent.startsWith('+bbb')));
    assert.ok(!target.children.find(row => row.className.endsWith('editor-diff-removed')).textContent.includes('+bbb'));
});
