const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const {hardenXtermLinks} = require('../../scripts/xterm-link-hardening');
const original = fs.readFileSync(path.join(__dirname, '../../static/vendor/xterm/xterm.js'), 'utf8');
const {Terminal} = require('../../static/vendor/xterm/xterm.js');
const write = (terminal, data) => new Promise(resolve => terminal.write(data, resolve));
const open = (id = '', uri = 'https://example.invalid/') => `\x1b]8;${id ? `id=${id}` : ''};${uri}\x1b\\`;
const close = '\x1b]8;;\x1b\\';
const churn = (count = 10000) => (open() + 'X' + close + '\r').repeat(count);
const service = terminal => terminal._core._inputHandler._oscLinkService;
const cellId = (terminal, buffer, row = 0, col = 0) => terminal._core._bufferService.buffers[buffer].lines.get(row)._extendedAttrs[col].urlId;

test('same-line OSC8 replacements remain bounded and line deletion disposes entries', async () => {
  const terminal = new Terminal({cols: 80, rows: 24});
  try {
    await write(terminal, churn());
    assert.ok(service(terminal)._dataByLinkId.size <= 1024);
    assert.ok(terminal._core._bufferService.buffer.markers.length <= 1024);
    await write(terminal, '\rreplacement\x1b[K');
    await write(terminal, '\x1b[1;1H\x1b[M');
    assert.equal(service(terminal)._dataByLinkId.size, 0);
  } finally { terminal.dispose(); }
});

test('pruning preserves links in normal and alternate buffers and keyed reuse', async () => {
  const terminal = new Terminal({cols: 80, rows: 24});
  try {
    await write(terminal, open('normal') + 'normal' + close);
    const normal = cellId(terminal, 'normal');
    await write(terminal, '\x1b[?1049h\x1b[H' + open('alternate') + 'alternate' + close + '\r\n' + churn());
    const alternate = cellId(terminal, 'alt');
    assert.equal(service(terminal).getLinkData(normal).id, 'normal');
    assert.equal(service(terminal).getLinkData(alternate).id, 'alternate');
    await write(terminal, '\x1b[?1049l\r\n' + open('normal') + 'reused' + close);
    assert.equal(cellId(terminal, 'normal', 1), normal);
  } finally { terminal.dispose(); }
});

test('active and saved attribute roots survive pruning without visible cells', async () => {
  const terminal = new Terminal({cols: 80, rows: 24});
  try {
    await write(terminal, open('active'));
    const active = terminal._core._inputHandler._getCurrentLinkId();
    await write(terminal, close + open('saved') + close);
    const links = service(terminal);
    const saved = links._entriesWithId.get('saved;;https://example.invalid/').id;
    terminal._core._bufferService.buffers.normal.savedCurAttrData.extended.urlId = saved;
    await write(terminal, churn(1022));
    links._linkPruneThreshold = 0;
    links.pruneUnusedLinks(active);
    assert.ok(links.getLinkData(active));
    assert.ok(links.getLinkData(saved));
  } finally { terminal.dispose(); }
});

test('live entries increase the pruning threshold and malformed upstream anchors fail closed', async () => {
  const terminal = new Terminal({cols: 80, rows: 24, scrollback: 100});
  try {
    let data = '';
    for (let i = 0; i < 1100; i++) data += open(String(i)) + 'X' + close;
    await write(terminal, data);
    const links = service(terminal);
    assert.equal(links._dataByLinkId.size, 1100);
    assert.ok(links._linkPruneThreshold >= 2048);
    assert.equal(hardenXtermLinks(hardenXtermLinks(original)), hardenXtermLinks(original));
    assert.throws(() => hardenXtermLinks('upstream changed'), /lifecycle changed/);
  } finally { terminal.dispose(); }
});

test('cursor restoration and reflowed visible links survive collection', async () => {
    const terminal = new Terminal({cols:80,rows:24,scrollback:100});
    try {
        await write(terminal, open('saved-cursor') + '\x1b7' + close + '\r\n');
        await write(terminal, open('reflow') + 'X'.repeat(160) + close + '\r\n');
        terminal.resize(40,24);
        await write(terminal, '\x1b8');
        const restoredRow = terminal._core._bufferService.buffer.y;
        await write(terminal, '\x1b[20;1H');
        await write(terminal, churn());
        const links = service(terminal);
        assert.ok([...links._dataByLinkId.values()].some(entry => entry.data.id === 'reflow'));
        await write(terminal, '\x1b8Z');
        // Upstream saves cursor coordinates/colors, not the OSC8 link attribute.
        assert.equal(terminal._core._bufferService.buffer.x, 1);
        assert.equal(terminal._core._bufferService.buffer.y, restoredRow);
        assert.equal(terminal._core._bufferService.buffer.lines.get(restoredRow).getString(0), 'Z');
    } finally {terminal.dispose();}
});
