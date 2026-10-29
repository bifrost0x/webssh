const assert = require('node:assert/strict');
const test = require('node:test');
const sync = require('../../static/js/session-directory-sync.js');

function harness(options = {}) {
    const requests = [], sent = [], moves = [], blocked = [], timers = new Map();
    const delays = new Map();
    let seq = 0, ready = true, version = 0, source = 'sftp-session:a';
    const indicator = {hidden: true};
    const inputListeners = {};
    const checkbox = {
        checked: false,
        disabled: true,
        addEventListener(type, listener) { inputListeners[type] = listener; },
    };
    const panel = {dataset: {}};
    const manager = {
        panes: {left: {path: '/old'}},
        isEmbeddedOpen: () => true,
        getPaneSourceId: () => source,
        navigatePaneTo(pane, path, options) {
            moves.push([pane, path, options]); manager.panes.left.path = path;
        },
    };
    const controller = sync.createController({
        socket: {emit(event, data, callback) { requests.push({event, data, callback}); }},
        manager, indicator, input: checkbox, panel,
        canSend: () => ready, inputVersion: () => version,
        sendInput: (...args) => sent.push(args),
        onNavigationBlocked: reason => blocked.push(reason), ...options,
        setTimeout(fn, delay) {timers.set(++seq, fn); delays.set(seq, delay); return seq;},
        clearTimeout(id) {timers.delete(id);},
    });
    controller.setContext('a', true);
    function reply(index, path='/tmp', shell_ready=true, shell='bash', extra={}) {
        requests[index].callback({success:true, directory:{path, shell_ready, shell_id:'42', shell, ...extra}});
    }
    return {controller, requests, sent, moves, blocked, timers, delays, indicator, checkbox, panel, reply, manager,
        ready(value) {ready=value;}, input() {version++;}, source(id) {source=`sftp-session:${id}`;},
        toggle(value) {checkbox.checked = value; inputListeners.change();}};
}

test('personal setting off leaves folder navigation independent', () => {
    const h=harness({enabledByDefault: false});
    assert.equal(h.requests.length,0);
    assert.equal(h.controller.navigate('a','/tmp'),false);
    assert.equal(h.indicator.hidden, false);
    assert.equal(h.checkbox.checked, false);
    assert.equal(h.panel.dataset.directorySyncEnabled, 'false');
});

test('personal setting on checks the per-session switch and follows automatically', () => {
    const h = harness({});
    assert.equal(h.requests.length, 1);
    h.reply(0);
    assert.deepEqual(h.moves, [['left', '/tmp', {directorySync:true}]]);
    assert.deepEqual(h.sent, []);
    assert.equal(h.indicator.hidden, false);
    assert.equal(h.checkbox.checked, true);
    assert.equal(h.panel.dataset.directorySyncEnabled, 'true');
    h.source('b'); h.controller.setContext('b', true);
    assert.equal(h.requests.length, 2);
});

test('the panel switch overrides the default for each session', () => {
    const h = harness({enabledByDefault: false});
    h.toggle(true);
    assert.equal(h.checkbox.checked, true);
    assert.equal(h.requests.length, 1);
    h.toggle(false);
    assert.equal(h.checkbox.checked, false);
    assert.equal(h.controller.navigate('a', '/tmp'), false);
    h.source('b'); h.controller.setContext('b', true);
    assert.equal(h.checkbox.checked, false);
    h.toggle(true);
    assert.equal(h.requests.length, 2);
    h.source('a'); h.controller.setContext('a', true);
    assert.equal(h.checkbox.checked, false);
});

test('default on starts after the embedded source finishes mounting', () => {
    const h = harness({});
    h.reply(0);
    h.source('loading'); h.controller.setContext('b', true);
    assert.equal(h.requests.length, 1);
    h.source('b'); h.controller.setContext('b', true);
    assert.equal(h.requests.length, 2);
    h.controller.setContext('b', true);
    assert.equal(h.requests.length, 2);
});

test('folder navigation probes again and targets exactly its SSH session', () => {
    const h=harness();h.reply(0);
    h.controller.navigate('a',"/tmp/O'Brien $HOME");
    assert.equal(h.sent.length,0);h.reply(1);
    assert.deepEqual(h.sent,[['a',"cd -- '/tmp/O'\\''Brien $HOME'\r"]]);
    assert.equal(h.manager.panes.left.path,'/tmp');
});

test('busy foreground application or concurrent typing prevents terminal input', () => {
    for (const mode of ['busy','typing','dirty']) {
        const h=harness();h.reply(0);
        if(mode==='dirty') h.ready(false);
        h.controller.navigate('a','/elsewhere');
        if(mode==='typing') h.input();
        h.reply(1,'/tmp',mode!=='busy');
        assert.deepEqual(h.sent,[]);
        assert.deepEqual(h.blocked,['prompt']);
    }
});

test('hide, session switch and source changes invalidate late replies', () => {
    for(const mode of ['hide','switch','source']) {
        const h=harness();h.reply(0);
        h.controller.navigate('a','/elsewhere');
        if(mode==='hide') h.controller.setContext('a',false);
        if(mode==='switch') {h.source('b');h.controller.setContext('b',true);}
        if(mode==='source') h.source('other');
        h.reply(1);
        assert.deepEqual(h.sent,[]);
    }
});

test('superseded folder requests do not send stale cd', () => {
    const h=harness();h.reply(0);
    h.controller.navigate('a','/first');h.controller.navigate('a','/second');
    assert.equal(h.requests.length, 2);
    h.reply(1);assert.deepEqual(h.sent,[]);h.reply(2);
    assert.deepEqual(h.sent,[['a',"cd -- '/second'\r"]]);
});

test('paths reject relative, control and oversized input and quote metacharacters', () => {
    for(const value of ['relative','/tmp\nwhoami','/tmp\r', '/\x1b[31m', '/\x85', '/'+ 'é'.repeat(4096)]) {
        assert.equal(sync.cdCommand(value),null);
    }
    assert.equal(sync.cdCommand('/tmp/$(touch nope); *'),"cd -- '/tmp/$(touch nope); *'\r");
    assert.equal(
        sync.cdCommand("/tmp/back\\slash'quoted; touch nope", 'fish'),
        "cd -- '/tmp/back\\\\slash\\'quoted; touch nope'\r",
    );
});

test('OSC 7 accepts encoded absolute paths and keeps the host informational', () => {
    assert.deepEqual(sync.parseOsc7('file://server.example/srv/My%20Files/%23release'), {
        host: 'server.example', path: '/srv/My Files/#release',
    });
    assert.deepEqual(sync.parseOsc7('file://foreign-host/tmp'), {
        host: 'foreign-host', path: '/tmp',
    });
    for (const value of [
        'https://server.example/tmp',
        'file://user@server.example/tmp',
        'file://server.example/tmp?query=1',
        'file://server.example/%ZZ',
        'file://server.example/tmp%0Awhoami',
    ]) assert.equal(sync.parseOsc7(value), null);
});

test('fresh OSC 7 locations move Files without writing to the terminal', () => {
    const h = harness();
    h.controller.observe('a', '/srv/app', 'remote-hostname');
    assert.deepEqual(h.moves, [['left', '/srv/app', {directorySync: true}]]);
    assert.deepEqual(h.sent, []);
    assert.equal(h.controller.getDirectory().path, '/srv/app');
    h.controller.observe('other', '/wrong-session');
    assert.equal(h.moves.length, 1);
    h.controller.dispose();
});

test('rapid OSC 7 updates are coalesced to the newest path', () => {
    let clock = 1000;
    const h = harness({now: () => clock, oscFollowInterval: 300});
    h.controller.observe('a', '/one');
    clock += 10;
    h.controller.observe('a', '/two');
    h.controller.observe('a', '/three');
    assert.deepEqual(h.moves.map(move => move[1]), ['/one']);
    const pending = Array.from(h.timers.values()).at(-1);
    clock += 300;
    pending();
    assert.deepEqual(h.moves.map(move => move[1]), ['/one', '/three']);
    h.controller.dispose();
});

test('OSC 7 ignores transcript replay and alternate-screen applications', () => {
    const h = harness();
    let osc;
    const terminal = {
        parser: {
            registerCsiHandler() { return {dispose() {}}; },
            registerOscHandler(id, handler) { assert.equal(id, 7); osc = handler; return {dispose() {}}; },
        },
        onData() { return {dispose() {}}; },
        buffer: {active: {type: 'normal'}},
        modes: {bracketedPasteMode: true},
    };
    const tracked = sync.trackTerminal('a', terminal);
    osc('file://host/live');
    assert.deepEqual(h.moves, [['left', '/live', {directorySync: true}]]);
    sync.beginReplay('a');
    osc('file://host/replayed');
    sync.endReplay('a');
    terminal.buffer.active.type = 'alternate';
    osc('file://host/editor');
    assert.equal(h.moves.length, 1);
    tracked.dispose();
    h.controller.dispose();
});

test('prompt tracking starts conservatively and pauses on typed input and alternate screen', () => {
    let mode, onData;
    const terminal={parser:{registerCsiHandler(_id,fn){mode=fn;}},onData(fn){onData=fn;},buffer:{active:{type:'normal'}},modes:{bracketedPasteMode:true}};
    sync.trackTerminal('tracked',terminal);
    assert.equal(sync.canSend('tracked'),false);
    assert.equal(mode([2004]),false);assert.equal(sync.canSend('tracked'),true);
    onData('echo unfinished');assert.equal(sync.canSend('tracked'),false);
    mode([2004]);terminal.buffer.active.type='alternate';assert.equal(sync.canSend('tracked'),false);
});

test('replayed prompt history stays unsafe until a new live prompt boundary', () => {
    let mode;
    const terminal = {
        parser: {registerCsiHandler(_id, fn) { mode = fn; }},
        onData() {},
        buffer: {active: {type: 'normal'}},
        modes: {bracketedPasteMode: true},
    };
    sync.trackTerminal('restored', terminal);
    sync.beginReplay('restored');
    mode([2004]);
    sync.endReplay('restored');
    assert.equal(sync.canSend('restored'), false);
    mode([2004]);
    assert.equal(sync.canSend('restored'), true);
});

test('terminal colour replies preserve readiness but never clear actual input', () => {
    let mode;
    const terminal = {
        parser: {registerCsiHandler(_id, handler) {mode = handler;}}, onData() {},
        buffer: {active: {type: 'normal'}}, modes: {bracketedPasteMode: true},
    };
    const tracked = sync.trackTerminal('colours', terminal);
    const replies = ['\x1b[?1;2c', '\x1b[>0;276;0c',
        '\x1b]10;rgb:ffff/ffff/ffff\x1b\\', '\x1b]11;rgb:0000/0000/0000\x1b\\',
        '\x1b]12;rgb:FF/80/00\x07'];
    try {
        for (const reply of replies) {
            mode([2004]); sync.noteInput('colours', reply);
            assert.equal(sync.canSend('colours'), true);
            sync.noteInput('colours', 'unfinished'); sync.noteInput('colours', reply);
            assert.equal(sync.canSend('colours'), false);
        }
        // Partial/malformed replies, pasted escape strings and any additional
        // user text or Enter must remain input, even if they contain a reply.
        for (const data of ['\x1b]11;rgb:0000/0000/0000', '\x1b]11;rgb:gg/00/00\x07',
            'text' + replies[2], replies[2] + 'text', replies[2] + '\n', replies[2] + '\r',
            '\x1b[200~' + replies[2] + '\x1b[201~']) {
            mode([2004]); sync.noteInput('colours', data);
            assert.equal(sync.canSend('colours'), false);
        }
    } finally { tracked.dispose(); }
});

test('unsupported probes never move Files or write to the shell', () => {
    const h=harness();
    h.requests[0].callback({success:false,reason:'unsupported'});
    assert.deepEqual(h.moves,[]);assert.deepEqual(h.sent,[]);
});

test('a late read-only poll cannot undo a newer folder navigation', () => {
    const h=harness();
    h.controller.navigate('a','/wanted');
    assert.equal(h.requests.length,1);
    h.reply(0,'/stale');assert.deepEqual(h.moves,[]);
    h.reply(1,'/actual');
    assert.deepEqual(h.sent,[['a',"cd -- '/wanted'\r"]]);
});

test('typing while a navigation waits for a background probe cancels the intent', () => {
    const h = harness();
    h.controller.navigate('a', '/wanted');
    h.input();
    h.reply(0);
    assert.equal(h.requests.length, 1);
    assert.deepEqual(h.sent, []);
    assert.deepEqual(h.blocked, ['prompt']);
});

test('OSC locations cannot swallow a folder click during its fresh probe', () => {
    const h = harness(); h.reply(0);
    h.controller.navigate('a', '/wanted');
    h.controller.observe('a', '/tmp');
    h.reply(1);
    assert.deepEqual(h.sent, [['a', "cd -- '/wanted'\r"]]);
});

test('recent OSC data does not delay acknowledgement of an explicit cd by 15 seconds', () => {
    const h = harness({now: () => 1000});
    h.controller.observe('a', '/tmp');
    h.controller.navigate('a', '/wanted');
    h.reply(1);
    assert.equal(Array.from(h.delays.values()).at(-1), 350);
    assert.deepEqual(h.sent, [['a', "cd -- '/wanted'\r"]]);
});

test('an unavailable navigation probe reports the problem without sending delayed input', () => {
    const h = harness(); h.reply(0);
    h.controller.navigate('a', '/wanted');
    h.requests[1].callback({success: false, reason: 'unsupported'});
    assert.deepEqual(h.blocked, ['unavailable']);
    Array.from(h.timers.values()).at(-1)();
    h.reply(2);
    assert.deepEqual(h.sent, []);
});

test('a lost acknowledgement expires instead of blocking every future folder action', () => {
    const h = harness(); h.reply(0);
    h.controller.navigate('a', '/wanted'); h.reply(1);
    Array.from(h.timers.values()).at(-1)(); // Verification probe.
    Array.from(h.timers.values()).at(-1)(); // Its response timeout.
    assert.deepEqual(h.blocked, ['unavailable']);
    h.controller.navigate('a', '/retry');
    assert.equal(h.requests.length, 4);
    h.reply(2, '/late'); // Timed-out reply cannot affect the new request.
    assert.equal(h.sent.length, 1);
    h.reply(3);
    assert.equal(h.sent.length, 2);
});

test('ordinary shells wait for a live prompt after a synchronized directory change', () => {
    let mode;
    const terminal = {
        parser: {registerCsiHandler(_id, handler) {mode = handler;}},
        onData() {}, buffer: {active: {type: 'normal'}},
        modes: {bracketedPasteMode: true},
    };
    const tracked = sync.trackTerminal('a', terminal);
    mode([2004]);
    const sent = [];
    const h = harness({canSend: sync.canSend, inputVersion: undefined,
        sendInput(id, command) {sent.push([id, command]); sync.noteInput(id, command);}});
    try {
        h.reply(0);
        h.controller.navigate('a', '/first');
        h.reply(1);
        assert.equal(sent.length, 1);
        // A prompt hook can still be running after the shell has changed cwd.
        Array.from(h.timers.values()).at(-1)();
        h.reply(2, '/first');
        assert.equal(sync.canSend('a'), false);
        h.controller.navigate('a', '/second');
        assert.equal(h.requests.length, 3);
        assert.equal(sent.length, 1);
        assert.deepEqual(h.blocked, ['pending']);
        // Only a fresh live DEC 2004 prompt signal permits the next command.
        mode([2004]);
        Array.from(h.timers.values()).at(-1)();
        h.reply(3, '/first');
        assert.equal(sync.canSend('a'), true);
        h.controller.navigate('a', '/second');
        h.reply(4, '/first');
        assert.deepEqual(sent.map(entry => entry[1]), ["cd -- '/first'\r", "cd -- '/second'\r"]);
    } finally {
        h.controller.dispose(); tracked.dispose();
    }
});

test('legacy tmux recovers after submitted input without weakening prompt guards', () => {
    let mode, line;
    const terminal = {
        parser: {registerCsiHandler(_id, handler) {mode = handler;}},
        onData() {}, onLineFeed(handler) {line = handler;},
        buffer: {active: {type: 'alternate'}}, modes: {bracketedPasteMode: true},
    };
    const pane = {tmux: true, shell_ready: true};
    const tracked = sync.trackTerminal('legacy', terminal);
    try {
        assert.equal(sync.canSend('legacy', pane), false);
        mode([2004]);
        sync.noteInput('legacy', 'cd /tmp');
        line();
        assert.equal(sync.canSend('legacy', pane), false);
        sync.noteInput('legacy', '\r');
        assert.equal(sync.canSend('legacy', pane), false);
        line();
        assert.equal(sync.canSend('legacy', pane), true);
        assert.equal(sync.canSend('legacy', {...pane, shell_ready: false}), false);
        terminal.modes.bracketedPasteMode = false;
        assert.equal(sync.canSend('legacy', pane), false);
        terminal.modes.bracketedPasteMode = true;
        sync.noteInput('legacy', 'unfinished');
        assert.equal(sync.canSend('legacy', pane), false);
        sync.noteInput('legacy', '\r'); line();
        sync.beginReplay('legacy'); sync.endReplay('legacy');
        assert.equal(sync.canSend('legacy', pane), false);
        sync.noteInput('legacy', '\x1b[200~paste');
        sync.noteInput('legacy', '\r'); line();
        assert.equal(sync.canSend('legacy', pane), false);
        sync.noteInput('legacy', '\x1b[201~');
        assert.equal(sync.canSend('legacy', pane), false);
    } finally { tracked.dispose(); }
});

for (const submit of ['\r', '\n', '\x03']) {
test(`tmux accepts a manual submission ${JSON.stringify(submit)} only after live output and a ready pane`, () => {
    let mode, line;
    const terminal = {
        parser: {registerCsiHandler(_id, handler) {mode = handler;}},
        onData() {}, onLineFeed(handler) {line = handler;},
        buffer: {active: {type: 'alternate'}}, modes: {bracketedPasteMode: true},
    };
    const pane = {tmux: true, shell_ready: true, bracketed_paste: true};
    const tracked = sync.trackTerminal('manual', terminal);
    try {
        assert.equal(sync.canSend('manual', pane), false); // Unknown reconnect state.
        mode([2004]);
        sync.noteInput('manual', 'pwd');
        line(); // Echo or wrapping a partial input is not a submitted command.
        assert.equal(sync.canSend('manual', pane), false);
        sync.noteInput('manual', submit);
        assert.equal(sync.canSend('manual', pane), false); // No response yet.
        line();
        assert.equal(sync.canSend('manual', {...pane, shell_ready: false}), false);
        assert.equal(sync.canSend('manual', {...pane, bracketed_paste: false}), false);
        assert.equal(sync.canSend('manual', {...pane, bracketed_paste: undefined}), true);
        assert.equal(sync.canSend('manual', {...pane, tmux: false}), false);
        assert.equal(sync.canSend('manual', pane), true); // No new outer DEC 2004.
        sync.noteInput('manual', 'next unfinished');
        assert.equal(sync.canSend('manual', pane), false);
        sync.noteInput('manual', submit);
        sync.beginReplay('manual'); line(); sync.endReplay('manual');
        assert.equal(sync.canSend('manual', pane), false);
        sync.noteInput('manual', submit); line();
        assert.equal(sync.canSend('manual', pane), true); // A live action recovers after replay.
        sync.noteInput('manual', '\x1b[200~paste');
        sync.noteInput('manual', '\r'); line();
        assert.equal(sync.canSend('manual', pane), false);
        sync.noteInput('manual', '\x1b[201~'); line();
        assert.equal(sync.canSend('manual', pane), false);
    } finally { tracked.dispose(); }
});
}

for (const bracketed_paste of [undefined, true]) {
test(`tmux (${bracketed_paste}) submission output invalidates navigation probes started before it`, () => {
    let mode, line;
    const terminal = {
        parser: {registerCsiHandler(_id, handler) {mode = handler;}},
        onData() {}, onLineFeed(handler) {line = handler;},
        buffer: {active: {type: 'alternate'}}, modes: {bracketedPasteMode: true},
    };
    const tracked = sync.trackTerminal('a', terminal);
    const pane = {tmux: true, bracketed_paste};
    const h = harness({canSend: sync.canSend, inputVersion: undefined});
    try {
        mode([2004]); h.reply(0, '/tmp', true, 'bash', pane);
        sync.noteInput('a', 'pwd'); sync.noteInput('a', '\r');
        h.controller.navigate('a', '/wanted');
        line();
        h.reply(1, '/tmp', true, 'bash', pane);
        assert.deepEqual(h.sent, []);
        assert.deepEqual(h.blocked, ['prompt']);
        h.controller.navigate('a', '/wanted');
        h.reply(2, '/tmp', true, 'bash', pane);
        assert.deepEqual(h.sent, [['a', "cd -- '/wanted'\r"]]);
    } finally { h.controller.dispose(); tracked.dispose(); }
});
}

for (const bracketed_paste of [undefined, true]) {
for (const interruption of ['typing', 'replay']) {
test(`tmux (${bracketed_paste === undefined ? "legacy" : "pane mode"}) repeated cd respects ${interruption} without repeated prompt signals`, () => {
    const pane = {tmux: true, shell_ready: true, bracketed_paste};
    let mode;
    const terminal = {
        parser: {registerCsiHandler(_id, handler) {mode = handler;}},
        onData() {}, buffer: {active: {type: 'alternate'}},
        modes: {bracketedPasteMode: true},
    };
    const tracked = sync.trackTerminal('a', terminal);
    mode([2004]);
    const sent = [];
    const h = harness({canSend: sync.canSend, inputVersion: undefined,
        sendInput(id, command) {sent.push([id, command]); sync.noteInput(id, command);}});
    h.reply(0);
    assert.equal(sync.canSend('a'), false);
    h.controller.navigate('a', '/first');
    h.reply(1, '/tmp', true, 'bash', pane);
    assert.equal(sent.length, 1);
    assert.equal(sync.canSend('a', pane), false);
    // tmux redraws the prompt without forwarding another DEC 2004 enable.
    Array.from(h.timers.values()).at(-1)();
    h.reply(2, '/first', true, 'bash', pane);
    assert.equal(sync.canSend('a', pane), true);
    h.controller.navigate('a', '/second');
    h.reply(3, '/first', true, 'bash', pane);
    assert.deepEqual(sent.map(entry => entry[1]), ["cd -- '/first'\r", "cd -- '/second'\r"]);
    // Neither new input nor replay may be cleared by an old cd acknowledgement.
    if (interruption === 'typing') sync.noteInput('a', 'unfinished');
    else { sync.beginReplay('a'); sync.endReplay('a'); }
    Array.from(h.timers.values()).at(-1)();
    h.reply(4, '/second', true, 'bash', pane);
    assert.equal(sync.canSend('a', pane), false);
    h.controller.dispose(); tracked.dispose();
});
}
}
