const test = require('node:test');
const assert = require('node:assert/strict');

const {createController} = require('../../static/js/primary-workspace-controller.js');

function classList() {
    const values = new Set();
    return {
        add(...names) { names.forEach(name => values.add(name)); },
        remove(...names) { names.forEach(name => values.delete(name)); },
        toggle(name, force) {
            const enabled = force === undefined ? !values.has(name) : Boolean(force);
            if (enabled) values.add(name);
            else values.delete(name);
            return enabled;
        },
        contains(name) { return values.has(name); },
    };
}

function element(id) {
    const attributes = new Map();
    const listeners = new Map();
    const children = [];
    const node = {
        id,
        hidden: false,
        dataset: {},
        classList: classList(),
        parentNode: null,
        nextSibling: null,
        children,
        addEventListener(name, listener) { listeners.set(name, listener); },
        dispatch(name) { listeners.get(name)?.({currentTarget: node}); },
        setAttribute(name, value) { attributes.set(name, String(value)); },
        removeAttribute(name) { attributes.delete(name); },
        getAttribute(name) { return attributes.get(name) ?? null; },
        appendChild(child) {
            child.parentNode?.removeChild?.(child);
            const previous = children.at(-1);
            if (previous) previous.nextSibling = child;
            children.push(child);
            child.parentNode = node;
            child.nextSibling = null;
            return child;
        },
        insertBefore(child, before) {
            child.parentNode?.removeChild?.(child);
            const index = children.indexOf(before);
            if (index < 0) return node.appendChild(child);
            children.splice(index, 0, child);
            child.parentNode = node;
            children.forEach((item, itemIndex) => {
                item.nextSibling = children[itemIndex + 1] || null;
            });
            return child;
        },
        removeChild(child) {
            const index = children.indexOf(child);
            if (index >= 0) children.splice(index, 1);
            child.parentNode = null;
            child.nextSibling = null;
            children.forEach((item, itemIndex) => {
                item.nextSibling = children[itemIndex + 1] || null;
            });
        },
    };
    return node;
}

function harness() {
    const ids = [
        'workspaceNavBtn',
        'fileTransferBtn',
        'manageProfilesBtn',
        'commandLibraryBtn',
        'primaryWorkspaceSurface',
        'workspaceStatusBar',
    ];
    const elements = Object.fromEntries(ids.map(id => [id, element(id)]));
    const sessionRail = element('sessionRail');
    const workspace = element('mainContent');
    const headerButtons = element('headerButtons');
    const body = element('body');
    body.dataset = {};
    body.appendChild(elements.primaryWorkspaceSurface);

    const events = [];
    const documentRef = {
        body,
        getElementById(id) { return elements[id] || null; },
        querySelector(selector) {
            if (selector === '.session-tabs-row') return sessionRail;
            if (selector === '.main-content') return workspace;
            if (selector === '.header-buttons') return headerButtons;
            return null;
        },
    };
    const windowRef = {
        Event: class Event { constructor(type) { this.type = type; } },
        CustomEvent: class CustomEvent {
            constructor(type, options = {}) { this.type = type; this.detail = options.detail; }
        },
        requestAnimationFrame(callback) { callback(); },
        dispatchEvent(event) { events.push(event); },
    };
    const controller = createController({window: windowRef, document: documentRef});
    return {controller, elements, sessionRail, workspace, body, windowRef, events};
}

test('top-level management views replace the Workspaces surface without changing its DOM', () => {
    const state = harness();
    const origin = element('origin');
    const hosts = element('profileManagementModal');
    const commands = element('commandWorkspaceModal');
    hosts.setAttribute('role', 'dialog');
    hosts.setAttribute('aria-modal', 'true');
    origin.appendChild(hosts);
    origin.appendChild(commands);

    state.controller.init();
    assert.equal(state.sessionRail.hidden, false);
    assert.equal(state.workspace.hidden, false);
    assert.equal(state.elements.primaryWorkspaceSurface.hidden, true);

    assert.equal(state.controller.open('hosts', hosts), true);
    assert.equal(state.sessionRail.hidden, true);
    assert.equal(state.workspace.hidden, true);
    assert.equal(state.elements.workspaceStatusBar.hidden, true);
    assert.equal(hosts.parentNode, state.elements.primaryWorkspaceSurface);
    assert.equal(hosts.hidden, false);
    assert.equal(hosts.getAttribute('role'), 'region');
    assert.equal(hosts.getAttribute('aria-modal'), null);
    assert.equal(state.elements.manageProfilesBtn.getAttribute('aria-current'), 'page');
    assert.equal(state.elements.workspaceNavBtn.getAttribute('aria-current'), null);

    state.controller.open('commands', commands);
    assert.equal(hosts.hidden, true);
    assert.equal(commands.hidden, false);
    assert.equal(state.controller.getActiveView(), 'commands');

    state.controller.showWorkspaces();
    assert.equal(commands.hidden, true);
    assert.equal(state.sessionRail.hidden, false);
    assert.equal(state.workspace.hidden, false);
    assert.equal(state.elements.workspaceStatusBar.hidden, false);
    assert.equal(state.elements.workspaceNavBtn.getAttribute('aria-current'), 'page');
    assert.equal(state.controller.getActiveView(), 'workspaces');
});

test('switching away from the full File Manager restores its embedded session target', () => {
    const state = harness();
    const files = element('sftpFileManager');
    const hosts = element('profileManagementModal');
    const closeCalls = [];
    state.windowRef.sftpFileManager = {
        displayMode: 'modal',
        close(options) { closeCalls.push(options); this.displayMode = 'closed'; },
    };

    state.controller.init();
    state.controller.open('files', files);
    state.controller.open('hosts', hosts);

    assert.deepEqual(closeCalls, [{restorePrimaryWorkspace: false}]);
    assert.equal(files.hidden, true);
    assert.equal(hosts.hidden, false);
    assert.equal(state.controller.getActiveView(), 'hosts');
});

test('a primary view can be released back to modal semantics for nested workflows', () => {
    const state = harness();
    const origin = element('origin');
    const commands = element('commandWorkspaceModal');
    commands.setAttribute('role', 'dialog');
    commands.setAttribute('aria-modal', 'true');
    commands.setAttribute('aria-labelledby', 'commandWorkspaceTitle');
    origin.appendChild(commands);

    state.controller.init();
    state.controller.open('commands', commands);
    assert.equal(state.controller.release(commands), true);

    assert.equal(commands.parentNode, origin);
    assert.equal(commands.getAttribute('role'), 'dialog');
    assert.equal(commands.getAttribute('aria-modal'), 'true');
    assert.equal(commands.getAttribute('aria-labelledby'), 'commandWorkspaceTitle');
    assert.equal(commands.classList.contains('primary-workspace-view'), false);
    assert.equal(state.controller.getActiveView(), 'workspaces');
});
