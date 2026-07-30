const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');

const ROOT = path.resolve(__dirname, '..', '..');
const JS_DIRECTORY = path.join(ROOT, 'static', 'js');

function tokenize(source) {
    const tokens = [];
    let index = 0;

    while (index < source.length) {
        const character = source[index];
        if (/\s/.test(character)) {
            index += 1;
            continue;
        }
        if (character === '/' && source[index + 1] === '/') {
            index = source.indexOf('\n', index + 2);
            if (index === -1) break;
            continue;
        }
        if (character === '/' && source[index + 1] === '*') {
            index = source.indexOf('*/', index + 2);
            if (index === -1) break;
            index += 2;
            continue;
        }
        if (character === '\'' || character === '"' || character === '`') {
            const quote = character;
            let value = '';
            index += 1;
            while (index < source.length && source[index] !== quote) {
                if (source[index] === '\\' && index + 1 < source.length) {
                    value += source[index + 1];
                    index += 2;
                } else {
                    value += source[index];
                    index += 1;
                }
            }
            tokens.push({ type: 'string', value });
            index += 1;
            continue;
        }
        if (/[A-Za-z_$]/.test(character)) {
            const start = index;
            index += 1;
            while (index < source.length && /[A-Za-z0-9_$]/.test(source[index])) {
                index += 1;
            }
            tokens.push({ type: 'identifier', value: source.slice(start, index) });
            continue;
        }
        tokens.push({ type: 'symbol', value: character });
        index += 1;
    }
    return tokens;
}

function directSocketContracts(source) {
    const tokens = tokenize(source);
    const contracts = { emit: new Set(), on: new Set(), once: new Set() };

    for (let index = 0; index < tokens.length; index += 1) {
        if (tokens[index]?.value !== 'socket') continue;
        const propertyOwner = tokens[index - 2]?.value;
        if (tokens[index - 1]?.value === '.' && !['window', 'this'].includes(propertyOwner)) {
            continue;
        }

        let cursor = index + 1;
        if (tokens[cursor]?.value === '?') cursor += 1;
        if (tokens[cursor]?.value !== '.') continue;
        const method = tokens[cursor + 1]?.value;
        const event = tokens[cursor + 3];
        if (
            (method === 'emit' || method === 'on' || method === 'once')
            && tokens[cursor + 2]?.value === '('
            && event?.type === 'string'
        ) {
            contracts[method].add(event.value);
        }
    }
    return contracts;
}

function ownJavascriptContracts() {
    const combined = { emit: new Set(), on: new Set(), once: new Set() };
    for (const file of fs.readdirSync(JS_DIRECTORY)) {
        if (!file.endsWith('.js')) continue;
        const contracts = directSocketContracts(fs.readFileSync(path.join(JS_DIRECTORY, file), 'utf8'));
        for (const type of ['emit', 'on', 'once']) {
            for (const event of contracts[type]) combined[type].add(event);
        }
    }
    return combined;
}

test('the inventory parses normal and optional emit on and once contracts', () => {
    const contracts = directSocketContracts(`
        socket.emit('socket_emit');
        socket.on('socket_on');
        socket.once('socket_once');
        socket?.emit('optional_socket_emit');
        socket?.on('optional_socket_on');
        socket?.once('optional_socket_once');
        window.socket.emit('window_emit');
        window.socket.on('window_on');
        window.socket.once('window_once');
        window.socket?.emit('optional_window_emit');
        window.socket?.on('optional_window_on');
        window.socket?.once('optional_window_once');
        this.socket.emit('this_emit');
        this.socket.on('this_on');
        this.socket.once('this_once');
        this.socket?.emit('optional_this_emit');
        this.socket?.on('optional_this_on');
        this.socket?.once('optional_this_once');
    `);

    assert.deepEqual([...contracts.emit].sort(), [
        'optional_socket_emit',
        'optional_this_emit',
        'optional_window_emit',
        'socket_emit',
        'this_emit',
        'window_emit',
    ]);
    assert.deepEqual([...contracts.on].sort(), [
        'optional_socket_on',
        'optional_this_on',
        'optional_window_on',
        'socket_on',
        'this_on',
        'window_on',
    ]);
    assert.deepEqual([...contracts.once].sort(), [
        'optional_socket_once',
        'optional_this_once',
        'optional_window_once',
        'socket_once',
        'this_once',
        'window_once',
    ]);
});

test('the own JavaScript inventory excludes stale client contracts', () => {
    const contracts = ownJavascriptContracts();
    const staleContracts = ['detect_os', 'os_detection_started', 'get_sessions'];

    for (const event of staleContracts) {
        assert.equal(
            contracts.emit.has(event) || contracts.on.has(event) || contracts.once.has(event),
            false,
            event,
        );
    }
});

test('a stale one-time listener is not treated as absent', () => {
    const contracts = directSocketContracts(
        "this.socket.once('os_detection_started', () => {});",
    );
    const isAbsent = event => (
        !contracts.emit.has(event) && !contracts.on.has(event) && !contracts.once.has(event)
    );

    assert.equal(isAbsent('os_detection_started'), false);
});

test('profile and command-set contracts keep their direct and dynamic acknowledgements', () => {
    const contracts = ownJavascriptContracts();
    const commandSetManager = fs.readFileSync(
        path.join(JS_DIRECTORY, 'command-set-manager.js'), 'utf8',
    );

    for (const event of ['list_profiles', 'save_profile', 'delete_profile']) {
        assert.equal(contracts.emit.has(event), true, event);
    }
    for (const event of ['profiles_list', 'profile_saved', 'profile_deleted']) {
        assert.equal(contracts.on.has(event) || contracts.once.has(event), true, event);
    }
    assert.equal(contracts.once.has('profiles_list'), true);
    assert.equal(contracts.emit.has('list_command_sets'), true);
    assert.equal(contracts.on.has('command_sets_list'), true);
    assert.ok(commandSetManager.includes(
        "const event = this.convertingProfileId ? 'convert_legacy_command_set' : 'save_command_set';",
    ));
    assert.ok(commandSetManager.includes('this.emitWithAck(event, payload, acknowledgement => {'));
    for (const event of ['duplicate_command_set', 'delete_command_set']) {
        assert.ok(commandSetManager.includes(`this.emitWithAck('${event}'`), event);
    }
});

test('quick_disconnect remains covered by its Socket.IO integration contract', () => {
    const integrationTest = fs.readFileSync(
        path.join(ROOT, 'tests', 'integration', 'test_paramiko5_socketio.py'), 'utf8',
    );

    assert.ok(integrationTest.includes("socket_client.emit('quick_disconnect'"));
    assert.ok(integrationTest.includes("'quick_disconnect_success'"));
});

test('transfer control contracts are represented by the browser client', () => {
    const contracts = ownJavascriptContracts();

    assert.equal(contracts.emit.has('cancel_transfer'), true);
    assert.equal(contracts.emit.has('prepare_transfer'), true);
});

test('the profile launcher preserves command-set post-connect payloads', () => {
    const manager = require('../../static/js/connection-command-manager.js');
    manager.mode = 'command_set';
    manager.selectedCommandSetId = 'bootstrap';

    assert.deepEqual(manager.getPayload(), {
        startup_mode: 'command_set',
        command_set_id: 'bootstrap',
    });
});
