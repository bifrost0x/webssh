const test = require('node:test');
const assert = require('node:assert/strict');
global.window = { TerminalFileBridge: require('../../static/js/terminal-file-bridge.js') };
global.document = { getElementById: () => null };
require('../../static/js/file-directory-requests.js');
require('../../static/js/sftp-file-manager.js');
const Manager = window.SFTPFileManager;

function fixture() {
    const element = () => ({
        className: '', children: [], disabled: false,
        classList: { contains: () => false, toggle() {} },
        append(...children) { children.forEach(child => { child.parentElement = this; this.children.push(child); }); },
        before(child) { child.parentElement = this.parentElement; },
        querySelector() { return this.children[1]?.children[0] || this; },
        setAttribute() {}, removeAttribute() {}, focus() {},
    });
    document.createElement = element;
    document.createTextNode = textContent => ({textContent});
    const parent = element();
    const buttons = {};
    const sheet = {
        querySelector: selector => buttons[selector] ||= Object.assign(element(), {parentElement: parent}),
        classList: { toggle() {}, add() {} }, removeAttribute() {}, setAttribute() {},
    };
    global.document.getElementById = () => sheet;
    const manager = Object.create(Manager.prototype);
    Object.assign(manager, {
        activePane: 'left',
        panes: { left: { selected: new Set([0]), files: [{ name: 'file' }], sourceId: 'sftp-session:one' } },
        availableSessions: [{ id: 'one', connected: true }],
        getPaneSourceId: state => state.sourceId,
        sourceCan: () => true, canTransferBetweenPanes: () => false,
        canOpenMovePickerForState: () => false,
    });
    return { manager, buttons };
}

test('mobile terminal-path action requires one selected entry and its connected SSH source', () => {
    const { manager, buttons } = fixture();
    const disabled = () => {
        manager.showActionSheet('left', 0);
        return buttons['[data-action="insert-terminal-path"]']?.disabled;
    };
    assert.equal(disabled(), false);
    manager.panes.left.selected.add(1);
    assert.equal(disabled(), true);
    manager.panes.left.selected = new Set([0]);
    for (const sourceId of ['smb:one', 'sftp-quick:one', 'sftp-session:other']) {
        manager.panes.left.sourceId = sourceId;
        assert.equal(disabled(), true);
    }
    manager.panes.left.sourceId = 'sftp-session:one';
    manager.availableSessions[0].connected = false;
    assert.equal(disabled(), true);
});

test('mobile action dismisses sheet before routing to the captured source pane', () => {
    const { manager } = fixture();
    const calls = [];
    manager.showActionSheet('left', 0);
    manager.activePane = 'right';
    manager.hideActionSheet = () => calls.push('hide');
    manager.handleContextAction = (...args) => calls.push(args);
    manager.handleActionSheetAction('insert-terminal-path');
    assert.deepEqual(calls, ['hide', ['insert-terminal-path', 'left', 0]]);
    manager.availableSessions[0].connected = false;
    manager.handleActionSheetAction('insert-terminal-path');
    assert.equal(calls.length, 3);
});

test('keyboard context-menu shortcut opens the mobile sheet for the focused file', () => {
    const { manager } = fixture();
    const handlers = {};
    const checkbox = {};
    const item = { dataset: { index: '0' }, querySelector: () => checkbox };
    document.getElementById = () => ({ addEventListener: (name, handler) => { handlers[name] = handler; } });
    manager.capitalize = value => value;
    manager.setActivePane = pane => { manager.activePane = pane; };
    manager.panes.right = manager.panes.left;
    manager.updateSelectionVisual = () => {};
    const opened = [];
    manager.showActionSheet = (...args) => opened.push(args);
    manager.setupLongPress();
    assert.equal(typeof handlers.keydown, 'function');
    let prevented = false;
    handlers.keydown({ key: 'F10', shiftKey: true, target: { closest: () => item }, preventDefault() { prevented = true; } });
    assert.equal(prevented, true);
    assert.deepEqual(opened, [['right', 0, { trigger: checkbox }]]);
});

test('embedded action sheet leaves the hidden standalone modal and returns before detaching', () => {
    const { manager } = fixture();
    const sheet = document.getElementById('fmActionSheet');
    const classNames = new Set();
    sheet.classList = { toggle() {}, add: name => classNames.add(name), remove: name => classNames.delete(name), contains: name => classNames.has(name) };
    const body = { appendChild(child) { child.parentElement = this; } };
    const content = { appendChild(child) { child.parentElement = this; }, insertBefore(child, reference) { assert.equal(reference.parentElement, this); child.parentElement = this; } };
    document.body = body;
    sheet.parentElement = content;
    manager.modalContent = content;
    manager.actionSheet = sheet;
    manager.displayMode = 'embedded';
    manager.showActionSheet('left', 0);
    assert.equal(sheet.parentElement, body);
    assert.equal(classNames.has('visible'), true);
    manager.modalBody = { classList: { remove() {} } };
    manager.closeMovePicker = manager.closeContextMenu = manager.resetPane = manager.restoreStandalonePaneState = () => {};
    manager.detachEmbedded();
    assert.equal(sheet.parentElement, content);
    assert.equal(classNames.has('visible'), false);
    assert.equal(manager.modalBody.parentElement, content);
});
