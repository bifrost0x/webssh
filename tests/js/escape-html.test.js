const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { loadEscapeHtml } = require('./support/escape-html');

const escapeHtml = loadEscapeHtml();
const read = file => fs.readFileSync(path.join(__dirname, '../../static/js', file), 'utf8');

test('the shared escaper keeps falsy values that are not missing', () => {
    assert.equal(escapeHtml(0), '0');
    assert.equal(escapeHtml(false), 'false');
    assert.equal(escapeHtml(''), '');
    assert.equal(escapeHtml(null), '');
    assert.equal(escapeHtml(undefined), '');
});

test('the shared escaper covers text and quoted attribute contexts', () => {
    assert.equal(
        escapeHtml(`<img src=x onerror="a('b')">&amp;`),
        '&lt;img src=x onerror=&quot;a(&#39;b&#39;)&quot;&gt;&amp;amp;',
    );
    assert.equal(escapeHtml(42), '42');
});

test('workspace scripts delegate to the shared escaper', () => {
    for (const file of ['command-library.js', 'sftp-file-manager.js']) {
        assert.match(read(file), /escapeHtml\(text\) \{[^}]*return window\.escapeHtml\(text\);/, file);
    }
});

test('shortcut rows and file context menus escape their text', () => {
    assert.match(read('app.js'), /<strong>\$\{window\.escapeHtml\(shortcut\.keys\)\}<\/strong>/);
    assert.match(read('app.js'), /<span>\$\{window\.escapeHtml\(label\)\}<\/span>/);
    const manager = read('sftp-file-manager.js');
    assert.match(manager, /data-action="\$\{this\.escapeHtml\(item\.action\)\}"/);
    assert.match(manager, /aria-hidden="true">\$\{this\.escapeHtml\(item\.icon\)\}<\/span> \$\{this\.escapeHtml\(item\.text\)\}/);
});
