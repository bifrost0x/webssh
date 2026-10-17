const test = require('node:test');
const assert = require('node:assert/strict');

const viewer = require('../../static/js/share-viewer.js');
const owner = require('../../static/js/terminal-share.js');

test('event-stream parser handles frames split across arbitrary chunks', () => {
    const events = [];
    const parser = viewer.createEventStreamParser(event => events.push(event));
    const stream = [
        ': ping\n\n',
        'id: 4\nevent: output\ndata: {"data":"a\\r\\nb","seq":4}\n\n',
        'event: presence\ndata: {"viewers":2}\n\n',
    ].join('');
    for (let index = 0; index < stream.length; index += 7) {
        parser.push(stream.slice(index, index + 7));
    }
    assert.deepEqual(events, [
        { event: 'output', id: '4', data: '{"data":"a\\r\\nb","seq":4}' },
        { event: 'presence', id: null, data: '{"viewers":2}' },
    ]);
    assert.equal(parser.pendingLength(), 0);
});

test('event-stream parser joins multi-line data and ignores comments', () => {
    const events = [];
    const parser = viewer.createEventStreamParser(event => events.push(event));
    parser.push(': hello\nevent: x\ndata: one\ndata:two\n\n');
    assert.deepEqual(events, [{ event: 'x', id: null, data: 'one\ntwo' }]);
});

test('input queue keeps keystrokes ordered with a single request in flight', async () => {
    const sent = [];
    let release;
    let first = true;
    const queue = viewer.createInputQueue(chunk => {
        sent.push(chunk);
        if (first) {
            first = false;
            return new Promise(resolve => { release = resolve; });
        }
        return Promise.resolve({});
    });
    queue.push('l');
    queue.push('s');
    queue.push('\r');
    assert.deepEqual(sent, ['l']);
    release({});
    await new Promise(resolve => setImmediate(resolve));
    await new Promise(resolve => setImmediate(resolve));
    assert.deepEqual(sent, ['l', 's\r']);
    assert.equal(queue.flushed(), true);
});

test('input queue retries rate-limited chunks before later input', async () => {
    const sent = [];
    const waits = [];
    let attempts = 0;
    const queue = viewer.createInputQueue(
        async chunk => {
            sent.push(chunk);
            attempts += 1;
            return attempts === 1 ? { retryAfterMs: 120 } : {};
        },
        { wait: async ms => { waits.push(ms); } },
    );
    queue.push('abc');
    for (let index = 0; index < 5; index += 1) {
        await new Promise(resolve => setImmediate(resolve));
    }
    assert.deepEqual(waits, [120]);
    assert.deepEqual(sent, ['abc', 'abc']);
});

test('input queue drops everything once closed or told to stop', async () => {
    const sent = [];
    const queue = viewer.createInputQueue(async chunk => {
        sent.push(chunk);
        return { stop: true };
    });
    queue.push('x');
    queue.push('y');
    await new Promise(resolve => setImmediate(resolve));
    await new Promise(resolve => setImmediate(resolve));
    assert.deepEqual(sent, ['x']);
    queue.close();
    assert.equal(queue.push('z'), false);
});

test('input queue bounds pending keystrokes', () => {
    const queue = viewer.createInputQueue(() => new Promise(() => {}));
    assert.equal(queue.push('a'), true);
    assert.equal(queue.push('b'.repeat(300 * 1024)), false);
});

test('link tokens are read from the fragment and validated', () => {
    const token = 'A'.repeat(43);
    assert.equal(viewer.readToken(`#${token}`), token);
    assert.equal(viewer.readToken(`#t=${token}`), token);
    assert.equal(viewer.readToken('#short'), null);
    assert.equal(viewer.readToken('#<script>alert(1)</script>'), null);
    assert.equal(viewer.readToken(''), null);
    assert.equal(viewer.readToken('#%E0%A4%A'), null);
});

test('every end reason maps to a literal translation key', () => {
    for (const reason of [
        'revoked', 'expired', 'session_closed', 'removed', 'owner_signed_out',
        'left', 'timed_out', 'link_invalid', 'share_full', 'capacity',
        'sharing_disabled', 'rate_limited',
    ]) {
        assert.match(viewer.reasonKey(reason), /^share\.viewer\./, reason);
    }
    assert.equal(viewer.reasonKey('mystery'), 'share.viewer.reason.unknown');
});

test('remaining time is compact', () => {
    assert.equal(viewer.formatRemaining(3_725_000), '1h 02m');
    assert.equal(viewer.formatRemaining(125_000), '2m');
    assert.equal(viewer.formatRemaining(9_000), '9s');
    assert.equal(viewer.formatRemaining(-5), '0s');
    assert.equal(owner.formatRemaining(3600), '1h 00m');
});

test('browser language is used only when the visitor has no saved choice', () => {
    const i18n = {
        currentLang: 'en',
        getLanguages: () => [{ code: 'en' }, { code: 'de' }, { code: 'fr' }],
    };
    viewer.pickLanguage(i18n, { getItem: () => null }, { languages: ['pt-BR', 'de-AT'] });
    assert.equal(i18n.currentLang, 'de');
    i18n.currentLang = 'en';
    viewer.pickLanguage(i18n, { getItem: () => 'en' }, { languages: ['fr'] });
    assert.equal(i18n.currentLang, 'en');
});

test('owner share links keep the token in the fragment', () => {
    assert.equal(
        owner.shareUrl('https://ssh.example', '/webssh/', 'tok_en-1'),
        'https://ssh.example/webssh/share#tok_en-1',
    );
    assert.equal(owner.shareUrl('https://ssh.example', '', 'x'), 'https://ssh.example/share#x');
});

test('owner notices describe presence events', () => {
    const t = key => ({
        'share.joined': '{name} joined',
        'share.pendingJoin': '{name} asks',
        'share.left': '{name} left',
    })[key] || key;
    assert.deepEqual(owner.describeEvent({ kind: 'joined', viewer: 'Ada' }, t), {
        type: 'success',
        message: 'Ada joined',
    });
    assert.equal(owner.describeEvent({ kind: 'pending', viewer: 'Bo' }, t).approve, true);
    assert.equal(owner.describeEvent({ kind: 'updated' }, t), null);
    assert.equal(owner.errorMessage('too_many_links', t), 'share.tooManyLinks');
    assert.equal(owner.errorMessage('weird', t), 'share.error');
});

test('owner badge counts only admitted viewers', () => {
    assert.equal(owner.viewerCount([
        { viewers: [{ status: 'active' }, { status: 'pending' }] },
        { viewers: [{ status: 'active' }] },
    ]), 2);
    assert.equal(owner.initial(' zoë'), 'Z');
    assert.equal(owner.initial(''), '?');
});
