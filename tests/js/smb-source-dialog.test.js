const assert = require('node:assert/strict');
const test = require('node:test');

global.window = {};
require('../../static/js/smb-source-dialog.js');

const SMBSourceDialog = global.window.SMBSourceDialog;

function field(value = '') {
    return {
        value,
        disabled: false,
        focused: false,
        focus() { this.focused = true; },
        addEventListener() {},
    };
}

function harness({ enabled = true, socketConnected = true } = {}) {
    const emitted = [];
    const connected = [];
    const closed = [];
    const handlers = {};
    const elements = {
        host: field(),
        share: field(),
        domain: field(),
        username: field(),
        password: field(),
        name: field(),
        saved: field(),
        save: field(),
        deleteSaved: field(),
        passwordToggle: field(),
        passwordIcon: { textContent: 'visibility' },
        submit: field(),
        status: { textContent: '', dataset: {} },
    };
    let requestNumber = 0;
    const volatileEmitted = [];
    const socket = {
        connected: socketConnected,
        emit(name, payload) { emitted.push([name, payload]); },
        on(name, handler) { handlers[name] = handler; },
        volatile: {
            emit(name, payload) { volatileEmitted.push([name, payload]); },
        },
    };
    const dialog = new SMBSourceDialog({
        enabled,
        elements,
        socket,
        requestIdFactory() {
            requestNumber += 1;
            return `smb-ui-${requestNumber}`;
        },
        openModal() {},
        closeModal() { closed.push(true); },
        onConnected(result) { connected.push(result); },
        t(_key, fallback) { return fallback; },
    });
    return {
        dialog, elements, emitted, volatileEmitted, connected, closed, handlers,
    };
}

function validValues() {
    return {
        host: 'nas.example',
        share: 'Docs',
        domain: 'DOMAIN',
        username: 'alice',
        password: 'Secret-Sentinel-42!',
    };
}

test('submit clears password and emits exactly one correlated request', () => {
    const { dialog, elements, emitted, volatileEmitted } = harness();
    dialog.open({ pane: 'right' });
    dialog.setValues(validValues());

    assert.equal(dialog.submit(), true);
    assert.equal(dialog.submit(), false);
    assert.equal(elements.password.value, '');
    assert.deepEqual(emitted, []);
    assert.deepEqual(volatileEmitted, [[
        'smb_quick_connect',
        {
            request_id: 'smb-ui-1',
            host: 'nas.example',
            share: 'Docs',
            domain: 'DOMAIN',
            username: 'alice',
            password: 'Secret-Sentinel-42!',
        },
    ]]);
});

test('offline submit clears the password and never buffers credentials', () => {
    const { dialog, elements, emitted, volatileEmitted } = harness({
        socketConnected: false,
    });
    dialog.open({ pane: 'right' });
    dialog.setValues(validValues());

    assert.equal(dialog.submit(), false);
    assert.equal(elements.password.value, '');
    assert.deepEqual(emitted, []);
    assert.deepEqual(volatileEmitted, []);
    assert.equal(dialog.pending, null);
});

test('disabled feature and invalid fields emit no network event', () => {
    const disabled = harness({ enabled: false });
    disabled.dialog.setValues(validValues());
    assert.equal(disabled.dialog.submit(), false);
    assert.deepEqual(disabled.emitted, []);

    const invalid = harness();
    invalid.dialog.setValues({ ...validValues(), share: '' });
    assert.equal(invalid.dialog.submit(), false);
    assert.deepEqual(invalid.emitted, []);
    assert.equal(invalid.elements.share.focused, true);
});

test('close cancels the exact attempt, clears password and returns focus', () => {
    const { dialog, elements, volatileEmitted, closed } = harness();
    const returnFocus = field();
    dialog.open({ pane: 'left', returnFocus });
    dialog.setValues(validValues());
    dialog.submit();

    dialog.close({ cancelAttempt: true });

    assert.deepEqual(volatileEmitted[1], [
        'smb_quick_connect_cancel',
        { request_id: 'smb-ui-1' },
    ]);
    assert.equal(elements.password.value, '');
    assert.equal(returnFocus.focused, true);
    assert.equal(closed.length, 1);
});

test('stale responses are ignored and success trusts only server descriptor', () => {
    const { dialog, volatileEmitted, connected } = harness();
    dialog.open({ pane: 'right' });
    dialog.setValues(validValues());
    dialog.submit();

    const descriptor = {
        source_id: 'smb-quick:server-issued',
        kind: 'smb',
        label: 'Docs on nas.example',
        endpoint: 'nas.example/Docs',
        protocol: 'SMB 3.1.1',
        capabilities: ['list'],
        ephemeral: true,
        security: { encrypted: true },
    };
    assert.equal(dialog.handleSuccess({
        request_id: 'stale-request', file_source: descriptor,
    }), false);
    assert.deepEqual(connected, []);
    assert.equal(dialog.handleSuccess({
        request_id: volatileEmitted[0][1].request_id, file_source: descriptor,
    }), true);
    assert.deepEqual(connected, [{ pane: 'right', descriptor }]);
});

test('authentication failure focuses the empty password field', () => {
    const { dialog, elements } = harness();
    dialog.open({ pane: 'left' });
    dialog.setValues(validValues());
    dialog.submit();

    assert.equal(dialog.handleError({
        request_id: 'smb-ui-1', code: 'AUTHENTICATION_REQUIRED',
    }), true);
    assert.equal(elements.password.value, '');
    assert.equal(elements.password.focused, true);
    assert.equal(elements.submit.disabled, false);
});

test('selecting a saved share prefills non-secret fields and focuses password', () => {
    const { dialog, elements } = harness();
    dialog.setSavedShares([{
        id: 'share-1',
        name: 'Team files',
        host: 'nas.example',
        share: 'Docs',
        domain: 'LAB',
        username: 'alice',
    }]);

    assert.equal(dialog.selectSavedShare('share-1'), true);
    assert.equal(elements.name.value, 'Team files');
    assert.equal(elements.host.value, 'nas.example');
    assert.equal(elements.share.value, 'Docs');
    assert.equal(elements.domain.value, 'LAB');
    assert.equal(elements.username.value, 'alice');
    assert.equal(elements.password.value, '');
    assert.equal(elements.password.focused, true);
});

test('saving a share emits only the non-secret definition', () => {
    const { dialog, elements, emitted } = harness();
    dialog.open({ pane: 'left' });
    dialog.setValues(validValues());
    elements.name.value = 'Team files';

    assert.equal(dialog.saveDefinition(), true);
    assert.deepEqual(emitted.at(-1), [
        'save_smb_share',
        {
            request_id: 'smb-ui-1',
            name: 'Team files',
            host: 'nas.example',
            share: 'Docs',
            domain: 'DOMAIN',
            username: 'alice',
        },
    ]);
    assert.equal(JSON.stringify(emitted.at(-1)).includes('Secret-Sentinel'), false);
});

test('updating and deleting a saved share stay correlated by request and server ID', () => {
    const { dialog, elements, emitted, handlers } = harness();
    dialog.setSavedShares([{
        id: 'share-1',
        name: 'Team files',
        host: 'nas.example',
        share: 'Docs',
        domain: '',
        username: 'alice',
    }]);
    dialog.selectSavedShare('share-1');
    elements.host.value = 'files.example';

    assert.equal(dialog.saveDefinition(), true);
    assert.equal(emitted.at(-1)[1].request_id, 'smb-ui-1');
    assert.equal(emitted.at(-1)[1].id, 'share-1');
    handlers.smb_share_saved({
        request_id: 'smb-ui-1',
        share: {
            id: 'share-1',
            name: 'Team files',
            host: 'files.example',
            share: 'Docs',
            domain: '',
            username: 'alice',
        },
    });
    assert.equal(dialog.deleteSelectedDefinition(), true);
    assert.deepEqual(emitted.at(-1), [
        'delete_smb_share',
        { request_id: 'smb-ui-2', share_id: 'share-1' },
    ]);
});

test('a delayed save response cannot bind the current password to another endpoint', () => {
    const { dialog, elements, emitted, volatileEmitted, handlers } = harness();
    dialog.open({ pane: 'left' });
    dialog.setValues({
        host: 'a.example',
        share: 'Alpha',
        domain: '',
        username: 'alice',
        password: 'A-password',
    });
    elements.name.value = 'Server A';

    assert.equal(dialog.saveDefinition(), true);
    assert.equal(emitted.at(-1)[1].request_id, 'smb-ui-1');

    dialog.setValues({
        host: 'b.example',
        share: 'Beta',
        domain: '',
        username: 'bob',
        password: 'B-only-secret',
    });
    elements.name.value = 'Server B';
    handlers.smb_share_saved({
        request_id: 'smb-ui-1',
        share: {
            id: 'share-a',
            name: 'Server A',
            host: 'a.example',
            share: 'Alpha',
            domain: '',
            username: 'alice',
        },
    });

    assert.equal(elements.host.value, 'b.example');
    assert.equal(elements.share.value, 'Beta');
    assert.equal(elements.username.value, 'bob');
    assert.equal(elements.password.value, 'B-only-secret');
    assert.equal(dialog.submit(), true);
    assert.deepEqual(volatileEmitted.at(-1), [
        'smb_quick_connect',
        {
            request_id: 'smb-ui-2',
            host: 'b.example',
            share: 'Beta',
            domain: '',
            username: 'bob',
            password: 'B-only-secret',
        },
    ]);
});

test('dialog implementation never reads or writes browser storage', () => {
    const source = require('node:fs').readFileSync(
        require('node:path').join(__dirname, '../../static/js/smb-source-dialog.js'),
        'utf8',
    );
    assert.doesNotMatch(source, /localStorage|sessionStorage|indexedDB/i);
});
