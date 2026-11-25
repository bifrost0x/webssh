const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const source = fs.readFileSync(path.join(__dirname, '../../static/js/sftp-file-manager.js'), 'utf8');

// Collects the interpolations of every template literal whose own text
// contains markup. Strings, comments and regular expressions in this file
// never contain backticks or unbalanced braces, which keeps the scan simple.
function markupInterpolations(text) {
    const found = [];
    let i = 0;
    const readTemplate = () => {
        const template = { markup: '', expressions: [] };
        i += 1;
        while (i < text.length) {
            if (text[i] === '\\') { template.markup += text.slice(i, i + 2); i += 2; continue; }
            if (text[i] === '`') { i += 1; break; }
            if (text[i] === '$' && text[i + 1] === '{') {
                i += 2;
                const start = i;
                readCode('}');
                template.expressions.push({ expression: text.slice(start, i - 1).trim(), line: text.slice(0, start).split('\n').length });
                continue;
            }
            template.markup += text[i];
            i += 1;
        }
        if (/<[a-z]/i.test(template.markup)) found.push(...template.expressions);
    };
    const readCode = closing => {
        let depth = 0;
        while (i < text.length) {
            const char = text[i];
            if (char === '`') { readTemplate(); continue; }
            if (char === '\'' || char === '"') {
                const quote = char;
                i += 1;
                while (i < text.length && text[i] !== quote) i += text[i] === '\\' ? 2 : 1;
                i += 1;
                continue;
            }
            if (char === '/' && text[i + 1] === '/') { i = text.indexOf('\n', i); continue; }
            if (char === '/' && text[i + 1] === '*') { i = text.indexOf('*/', i) + 2; continue; }
            if (char === '{') depth += 1;
            if (char === '}') {
                if (depth === 0 && closing === '}') { i += 1; return; }
                depth -= 1;
            }
            i += 1;
        }
    };
    readCode(null);
    return found;
}

// Reviewed interpolations that are not escaped here: fixed literals chosen by
// a condition, booleans, allowlisted class names and fragments that were
// escaped where they were built.
const REVIEWED = new Set([
    "source.disabled ? ' is-disabled' : ''",
    'disabled',
    'icon',
    'rows',
    'renderedGroups.map(group => group.html).join(\'\')',
    'paneBadge',
    "this.sourceAccessState(tab.source) === 'readonly' ? 'lock' : this.sourceAccessState(tab.source) === 'write' ? 'edit' : 'help_outline'",
    "activeTab?.id === tab.id ? ' active' : ''",
    'activeTab?.id === tab.id',
    "state.focusedIndex === -1 ? '0' : '-1'",
    "file.is_dir ? 'directory' : ''",
    "state.selected.has(originalIndex) ? 'selected' : ''",
    "file.is_dir ? 'directory' : 'file'",
    'state.selected.has(originalIndex)',
    "state.focusedIndex === originalIndex ? '0' : '-1'",
    'this.supportsNativeFileDrag()',
    "state.selected.has(originalIndex) ? 'check_box' : 'check_box_outline_blank'",
    "file.is_dir ? 'folder' : 'file'",
    'statusClass',
    'typeClass',
    'reason',
    "t.type === 'upload' ? '⬆️' : t.type === 'download' ? '⬇️' : '↔️'",
    'cancelLabel',
    "item.danger ? 'danger' : ''",
    `this.smbEnabled ? '' : ' disabled aria-disabled="true"'`,
    "this.smbEnabled ? '' : 'hidden'",
    "this.smbEnabled ? 'hidden' : ''",
]);

function isEscaped(expression) {
    return /^this\.escapeHtml\(/.test(expression)
        // Conditional fragments are templates themselves and checked on their own.
        || /^[^`]*\?\s*`[\s\S]*`\s*:\s*''$/.test(expression);
}

test('every markup interpolation in the file manager is escaped or reviewed', () => {
    const interpolations = markupInterpolations(source);
    assert.ok(interpolations.length > 100, `only ${interpolations.length} interpolations found`);
    const unreviewed = interpolations
        .filter(({ expression }) => !isEscaped(expression) && !REVIEWED.has(expression.replace(/\s+/g, ' ')))
        .map(({ expression, line }) => `${line}: ${expression}`);
    assert.deepEqual(unreviewed, []);
});

test('source groups, pane states and upload summaries escape their text', () => {
    assert.match(source, /aria-labelledby="fm-source-group-\$\{this\.escapeHtml\(group\.id\)\}"/);
    assert.match(source, /data-pane="\$\{this\.escapeHtml\(pane\)\}"/);
    assert.match(source, /\$\{this\.escapeHtml\(this\.t\('fm\.emptyDirectory', 'Empty directory'\)\)\}/);
    assert.match(source, /\$\{this\.escapeHtml\(presentation\.heading\)\}/);
    assert.match(source, /\$\{this\.escapeHtml\(presentation\.details\)\}/);
});
