const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');
const catalog = require('../../static/js/realtime-catalog.js');

const ROOT = path.join(__dirname, '../..');
const read = file => fs.readFileSync(path.join(ROOT, file), 'utf8');

// Socket.IO events of the Python release that the Go server does not
// answer, each with its decision: no page sends them (D-13).
const DROPPED = {check_exists: 'D-13', get_file_stat: 'D-13'};
// Connection lifecycle events of Socket.IO, not requests.
const LIFECYCLE = ['connect', 'disconnect'];

const terminal = read('static/js/realtime-terminal.js');
const answered = event => Object.hasOwn(catalog.REQUESTS, event) || new RegExp(`\\b${event}: `).test(terminal);

// The handlers of the Python release, recorded when it left the
// repository; that release no longer changes.
function pythonEvents() {
    return new Set(JSON.parse(read('tests/js/fixtures/python-socketio-events.json')).events);
}

// The events the pages send on the socket (socket.emit, socket.timeout(…).emit,
// socket.volatile.emit); the realtime client itself is left out.
function pageEvents() {
    const events = new Set();
    for (const file of fs.readdirSync(path.join(ROOT, 'static/js')).filter(f => f.endsWith('.js') && !f.startsWith('realtime-'))) {
        const source = read(`static/js/${file}`);
        for (const match of source.matchAll(/socket(?:\.volatile|\.timeout\([^)]*\))?\.emit\(\s*['"]([a-z0-9_]+)['"]/g)) {
            events.add(match[1]);
        }
    }
    return events;
}

test('every Socket.IO event of the Python release has a v1 type or a decision', () => {
    const events = pythonEvents();
    assert.ok(events.size > 60, `only ${events.size} Python events found`);
    const open = [...events].filter(event => !LIFECYCLE.includes(event) && !answered(event) && !DROPPED[event]);
    assert.deepEqual(open, [], 'answered locally with unknown_type');
    for (const event of Object.keys(DROPPED)) {
        assert.ok(events.has(event), `${event} is not an event of the Python release`);
        assert.ok(!answered(event), `${event} is dropped and answered`);
    }
});

test('every event the pages send reaches the server', () => {
    const events = pageEvents();
    assert.ok(events.size > 40, `only ${events.size} page events found`);
    assert.deepEqual([...events].filter(event => !answered(event)), []);
    for (const event of Object.keys(DROPPED)) assert.ok(!events.has(event), `a page sends the dropped ${event}`);
});

// No page text or script of the Go build names the preview any more.
test('the frontend has no preview notice left', () => {
    const files = [
        ...fs.readdirSync(path.join(ROOT, 'static/js')).map(f => `static/js/${f}`),
        ...fs.readdirSync(path.join(ROOT, 'static/js/i18n')).map(f => `static/js/i18n/${f}`),
        ...fs.readdirSync(path.join(ROOT, 'internal/httpapi/pages')).map(f => `internal/httpapi/pages/${f}`),
    ].filter(file => /\.(js|gohtml)$/.test(file));
    for (const file of files) {
        const source = read(file);
        assert.doesNotMatch(source, /previewNotice|preview-notice|websshPreview|not_available_in_preview|preview-unavailable/, file);
        assert.doesNotMatch(source, /in this preview|in dieser Vorschau/i, file);
    }
    assert.ok(!fs.existsSync(path.join(ROOT, 'static/css/preview-notice.css')));
});
