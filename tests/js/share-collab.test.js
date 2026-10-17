const test = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');

const QR = require('../../static/js/qr-code.js');
const collab = require('../../static/js/share-collab.js');
const owner = require('../../static/js/terminal-share.js');

const SHARE_URL = `https://ssh.example.com/share#${'A'.repeat(43)}`;

function matrixText(code) {
    let rows = '';
    for (let y = 0; y < code.size; y += 1) {
        for (let x = 0; x < code.size; x += 1) rows += code.isDark(x, y) ? '1' : '0';
        rows += '\n';
    }
    return rows;
}

function bchRemainder(value, generator, degree) {
    let remainder = value;
    for (let bit = 14 + (degree - 10); bit >= degree; bit -= 1) {
        if ((remainder >>> bit) & 1) remainder ^= generator << (bit - degree);
    }
    return remainder;
}

function finderAt(code, left, top) {
    for (let dy = 0; dy < 7; dy += 1) {
        for (let dx = 0; dx < 7; dx += 1) {
            const ring = Math.min(dx, dy, 6 - dx, 6 - dy);
            assert.equal(code.isDark(left + dx, top + dy), ring !== 1, `finder ${left},${top} (${dx},${dy})`);
        }
    }
}

test('share links encode to a stable, verified QR matrix', () => {
    const code = QR.encode(SHARE_URL);
    assert.equal(code.version, 5);
    assert.equal(code.size, 37);
    assert.equal(code.level, 'M');
    // Pinned after decoding with two independent readers (jsQR, zxing-cpp).
    assert.equal(
        crypto.createHash('sha256').update(matrixText(code)).digest('hex'),
        '70dd6f89742298298af3e07bb00f386658b4180811d08dbd263b78b4b0555a10',
    );
});

test('function patterns follow the specification', () => {
    const code = QR.encode(SHARE_URL);
    const size = code.size;
    finderAt(code, 0, 0);
    finderAt(code, size - 7, 0);
    finderAt(code, 0, size - 7);
    for (let i = 8; i < size - 8; i += 1) {
        assert.equal(code.isDark(i, 6), i % 2 === 0, `timing row ${i}`);
        assert.equal(code.isDark(6, i), i % 2 === 0, `timing column ${i}`);
    }
    assert.equal(code.isDark(8, size - 8), true, 'dark module');
});

test('format information is BCH-valid and duplicated', () => {
    for (const level of ['L', 'M', 'Q', 'H']) {
        const code = QR.encode('format check', { level });
        const size = code.size;
        let first = 0;
        const firstPositions = [
            [8, 0], [8, 1], [8, 2], [8, 3], [8, 4], [8, 5], [8, 7], [8, 8],
            [7, 8], [5, 8], [4, 8], [3, 8], [2, 8], [1, 8], [0, 8],
        ];
        firstPositions.forEach(([x, y], index) => {
            if (code.isDark(x, y)) first |= 1 << index;
        });
        let second = 0;
        for (let i = 0; i < 8; i += 1) if (code.isDark(size - 1 - i, 8)) second |= 1 << i;
        for (let i = 8; i < 15; i += 1) if (code.isDark(8, size - 15 + i)) second |= 1 << i;
        assert.equal(first, second, `${level} copies match`);
        const unmasked = first ^ 0x5412;
        assert.equal(bchRemainder(unmasked, 0x537, 10), 0, `${level} BCH`);
        const levelBits = { L: 1, M: 0, Q: 3, H: 2 }[level];
        assert.equal(unmasked >>> 13, levelBits);
        assert.equal((unmasked >>> 10) & 7, code.mask);
    }
});

test('version information is BCH-valid from version 7', () => {
    const code = QR.encode('x'.repeat(150));
    assert.equal(code.version, 8);
    let bits = 0;
    for (let i = 0; i < 18; i += 1) {
        if (code.isDark(code.size - 11 + (i % 3), Math.floor(i / 3))) bits |= 1 << i;
    }
    assert.equal(bits >>> 12, 8);
    assert.equal(bchRemainder(bits, 0x1f25, 12), 0);
});

test('version selection grows with data and rejects oversized input', () => {
    assert.equal(QR.encode('x').version, 1);
    assert.equal(QR.encode('x'.repeat(14)).version, 1);
    assert.equal(QR.encode('x'.repeat(15)).version, 2);
    assert.equal(QR.encode('x'.repeat(2331)).version, 40);
    assert.throws(() => QR.encode('x'.repeat(2332)), RangeError);
    assert.equal(QR.encode('共享').size, 21);
});

test('svg path draws one square per dark module inside the quiet zone', () => {
    const code = QR.encode('svg');
    const path = QR.toPath(code, 4);
    let dark = 0;
    for (let y = 0; y < code.size; y += 1) {
        for (let x = 0; x < code.size; x += 1) if (code.isDark(x, y)) dark += 1;
    }
    assert.equal((path.match(/M/g) || []).length, dark);
    assert.match(path, /^M4,4h1v1h-1z/);
});

test('clicks map to live-screen cells, not scrollback', () => {
    const rect = { left: 100, top: 50, width: 800, height: 480 };
    const grid = { cols: 80, rows: 24, viewportY: 120, baseY: 120 };
    assert.deepEqual(collab.cellFromPoint(rect, grid, 100, 50), { col: 0, row: 0 });
    assert.deepEqual(collab.cellFromPoint(rect, grid, 899, 529), { col: 79, row: 23 });
    assert.equal(collab.cellFromPoint(rect, grid, 99, 60), null);
    assert.equal(collab.cellFromPoint(rect, grid, 905, 60), null);
    // Scrolled up by 5 lines: the top 5 visible rows are history.
    const scrolled = { ...grid, viewportY: 115 };
    assert.equal(collab.cellFromPoint(rect, scrolled, 110, 55), null);
    assert.deepEqual(collab.cellFromPoint(rect, scrolled, 110, 50 + 20 * 5), { col: 1, row: 0 });
    assert.equal(collab.cellFromPoint({ ...rect, width: 0 }, grid, 1, 1), null);
});

test('cell boxes account for the local scroll position', () => {
    const rect = { left: 0, top: 0, width: 800, height: 480 };
    const grid = { cols: 80, rows: 24, viewportY: 200, baseY: 200 };
    assert.deepEqual(collab.cellBox(rect, grid, 10, 3), { left: 100, top: 60, width: 10, height: 20 });
    assert.deepEqual(
        collab.cellBox(rect, { ...grid, viewportY: 198 }, 10, 3),
        { left: 100, top: 100, width: 10, height: 20 },
    );
    assert.deepEqual(
        collab.cellBox(rect, { ...grid, viewportY: 180 }, 10, 3),
        { left: 100, top: 460, width: 10, height: 20 },
    );
    assert.equal(collab.cellBox(rect, { ...grid, viewportY: 170 }, 10, 3), null);
    assert.equal(collab.cellBox(rect, grid, 80, 0), null);
});

test('chat log keeps server order and drops duplicates', () => {
    const log = collab.createChatLog(3);
    assert.equal(log.add({ id: 2, text: 'b' }), true);
    assert.equal(log.add({ id: 1, text: 'a' }), true);
    assert.equal(log.add({ id: 2, text: 'b again' }), false);
    assert.equal(log.add({ text: 'no id' }), false);
    assert.deepEqual(log.list().map(item => item.text), ['a', 'b']);
    log.add({ id: 3, text: 'c' });
    log.add({ id: 4, text: 'd' });
    assert.deepEqual(log.list().map(item => item.id), [2, 3, 4]);
    log.replace([{ id: 9, text: 'z' }]);
    assert.equal(log.size, 1);
    assert.equal(log.add({ id: 9, text: 'z' }), false);
});

test('chat messages render text, never markup', () => {
    const created = [];
    const makeNode = tag => {
        const node = {
            tag,
            children: [],
            className: '',
            dataset: {},
            textContent: '',
            classList: { toggle(name, on) { if (on) node.className += ` ${name}`; } },
            append(...items) { node.children.push(...items); },
            appendChild(item) { node.children.push(item); },
        };
        created.push(node);
        return node;
    };
    const doc = { createElement: makeNode };
    const item = collab.renderMessage(doc, {
        id: 1, name: '<img src=x>', role: 'owner', text: '<script>alert(1)</script>', at: '2026-01-01T10:00:00Z',
    }, { labels: { owner: 'Owner', you: 'You' } });
    assert.match(item.className, /is-owner/);
    const text = created.find(node => node.className === 'cv-message-text');
    assert.equal(text.textContent, '<script>alert(1)</script>');
    assert.ok(created.every(node => !('innerHTML' in node)));
});

test('invites carry the link, access and expiry', () => {
    const t = key => ({
        'share.inviteIntro': '{owner} invited you: {title}',
        'share.inviteAccessView': 'View only',
        'share.inviteAccessControl': 'You can type',
        'share.inviteExpiry': 'Expires in {time}',
    })[key];
    const text = owner.inviteText(
        { title: 'Deploy', mode: 'control' },
        { owner: 'ana', url: SHARE_URL, remainingSeconds: 3600 },
        t,
    );
    assert.equal(text, `ana invited you: Deploy\n${SHARE_URL}\nYou can type · Expires in 1h 00m`);
    assert.match(owner.inviteText({ title: 'x', mode: 'view' }, { url: 'u', remainingSeconds: 90 }, t), /View only · Expires in 1m$/);
});
