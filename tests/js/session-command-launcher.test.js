const assert = require('node:assert/strict');
const fs = require('node:fs');
const test = require('node:test');
const vm = require('node:vm');

const launcher = require('../../static/js/session-command-launcher.js');

const commands = [
    {
        id: 'cmd-1',
        name: 'Service status',
        command: 'systemctl status',
        parameters: 'webssh',
        description: 'Show the service state',
    },
    {
        id: 'cmd-multiline',
        name: 'Unsafe paste',
        command: 'echo one\necho two',
        parameters: '',
        description: 'Contains a line break',
    },
];

const commandSets = [
    {
        id: 'set-1',
        name: 'Release checks',
        description: 'Inspect the deployment',
        resolved_command: 'git status && systemctl status webssh',
        sudo_resolved_command: 'sudo git status && sudo systemctl status webssh',
    },
    {
        id: 'set-broken',
        name: 'Missing command',
        description: 'No longer resolves',
        resolution_error: 'Command no longer exists',
    },
];

test('parameter previews bind exact session and set snapshot before deliberate insertion', async () => {
    let session = { connected: true, name: 'Target A' };
    let active = 'a';
    let sets = [{ id: 'parameter-set', name: 'Path', parameters: [{ name: 'path' }], steps: [{ type: 'argv', argv: ['ls', '--', '{{path}}'] }] }];
    const sent = [];
    const controller = launcher.createSessionCommandController({
        getSession: () => session,
        getActiveSession: () => active,
        getCommandSets: () => sets,
        resolveParameters: async () => ({ success: true, resolved_command: "'ls' -- 'a b'" }),
        emitInput: (id, data) => sent.push([id, data]),
    });
    assert.equal((await controller.insert('a', 'set', 'parameter-set')).ok, false);
    const first = await controller.preview('a', 'parameter-set', { path: 'a b' });
    assert.equal(first.ok, true);
    assert.deepEqual(sent, []);
    active = 'b';
    assert.equal((await controller.insert('a', 'set', 'parameter-set', { preview: first.preview })).ok, false);
    active = 'a';
    session = { connected: true, name: 'Replacement transport' };
    assert.equal((await controller.insert('a', 'set', 'parameter-set', { preview: first.preview })).ok, false);
    const second = await controller.preview('a', 'parameter-set', { path: 'a b' });
    sets = [{ ...sets[0], name: 'Changed set' }];
    assert.equal((await controller.insert('a', 'set', 'parameter-set', { preview: second.preview })).ok, false);
    const reconnected = await controller.preview('a', 'parameter-set', { path: 'a b' });
    controller.invalidatePreviews();
    assert.equal((await controller.insert('a', 'set', 'parameter-set', { preview: reconnected.preview })).ok, false);
    const third = await controller.preview('a', 'parameter-set', { path: 'a b' });
    assert.equal((await controller.insert('a', 'set', 'parameter-set', { preview: third.preview })).ok, true);
    assert.deepEqual(sent, [['a', "'ls' -- 'a b'"]]);
    assert.equal((await controller.insert('a', 'set', 'parameter-set', { preview: third.preview })).ok, false);
});

test('late parameter previews cannot follow a changed target', async () => {
    const session = { connected: true };
    let active = 'a';
    let finish;
    const controller = launcher.createSessionCommandController({
        getSession: () => session,
        getActiveSession: () => active,
        getCommandSets: () => [{ id: 'p', parameters: [{ name: 'x' }] }],
        resolveParameters: () => new Promise(resolve => { finish = resolve; }),
    });
    const pending = controller.preview('a', 'p', { x: 'v' });
    active = 'b';
    finish({ success: true, resolved_command: 'echo v' });
    assert.equal((await pending).ok, false);
});

test('builds one searchable model with command sets before commands', async () => {
    const all = launcher.buildLauncherEntries(commands, commandSets, 'status');

    assert.deepEqual(all.map(item => [item.type, item.id]), [
        ['set', 'set-1'],
        ['command', 'cmd-1'],
    ]);
    assert.equal(all[0].insertText, commandSets[0].resolved_command);
    assert.equal(all[1].insertText, 'systemctl status webssh');
});

test('keeps unsafe or unresolved entries visible but unavailable', async () => {
    const entries = launcher.buildLauncherEntries(commands, commandSets, '');
    const multiline = entries.find(item => item.id === 'cmd-multiline');
    const unresolved = entries.find(item => item.id === 'set-broken');

    assert.equal(multiline.available, false);
    assert.equal(multiline.unavailableReason, 'multiline');
    assert.equal(unresolved.available, false);
    assert.equal(unresolved.unavailableReason, 'unresolved');
});

test('inserts exact text into the bound connected session without Enter', async () => {
    const emissions = [];
    const events = [];
    const controller = launcher.createSessionCommandController({
        getSession: sessionId => (
            sessionId === 'session-a' ? { connected: true, name: 'Production Edge' } : null
        ),
        getCommands: () => commands,
        getCommandSets: () => commandSets,
        emitInput: (sessionId, text) => emissions.push({ sessionId, text }),
        focusSession: sessionId => events.push(['focus', sessionId]),
        notify: (message, type) => events.push(['notify', message, type]),
        insertedMessage: sessionName => `Inserted into ${sessionName}`,
    });

    const result = await controller.insert('session-a', 'set', 'set-1');

    assert.equal(result.ok, true);
    assert.deepEqual(emissions, [{
        sessionId: 'session-a',
        text: 'git status && systemctl status webssh',
    }]);
    assert.equal(/[\r\n]/.test(emissions[0].text), false);
    assert.deepEqual(events, [
        ['focus', 'session-a'],
        ['notify', 'Inserted into Production Edge', 'success'],
    ]);
});

test('adds one sudo prefix to a single command when requested', async () => {
    const emissions = [];
    const controller = launcher.createSessionCommandController({
        getSession: () => ({ connected: true, name: 'Production Edge' }),
        getCommands: () => commands,
        getCommandSets: () => commandSets,
        emitInput: (sessionId, text) => emissions.push({ sessionId, text }),
    });

    const result = await controller.insert(
        'session-a', 'command', 'cmd-1', { useSudo: true }
    );

    assert.equal(result.ok, true);
    assert.deepEqual(emissions, [{
        sessionId: 'session-a',
        text: 'sudo systemctl status webssh',
    }]);
});

test('recognizes only an existing sudo command token as prefixed', async () => {
    const emissions = [];
    const controller = launcher.createSessionCommandController({
        getSession: () => ({ connected: true, name: 'Production Edge' }),
        getCommands: () => [
            {
                id: 'cmd-sudo',
                name: 'Restart WebSSH',
                command: 'sudo systemctl restart',
                parameters: 'webssh',
            },
            {
                id: 'cmd-sudoers',
                name: 'Check sudoers helper',
                command: 'sudoers-check',
                parameters: '',
            },
        ],
        getCommandSets: () => [],
        emitInput: (sessionId, text) => emissions.push({ sessionId, text }),
    });

    const result = await controller.insert(
        'session-a', 'command', 'cmd-sudo', { useSudo: true }
    );

    assert.equal(result.ok, true);
    assert.equal(emissions[0].text, 'sudo systemctl restart webssh');

    await controller.insert(
        'session-a', 'command', 'cmd-sudoers', { useSudo: true }
    );
    assert.equal(emissions[1].text, 'sudo sudoers-check');
});

test('uses the fully resolved sudo variant for a command set', async () => {
    const emissions = [];
    const controller = launcher.createSessionCommandController({
        getSession: () => ({ connected: true, name: 'Production Edge' }),
        getCommands: () => commands,
        getCommandSets: () => commandSets,
        emitInput: (sessionId, text) => emissions.push({ sessionId, text }),
    });

    const result = await controller.insert(
        'session-a', 'set', 'set-1', { useSudo: true }
    );

    assert.equal(result.ok, true);
    assert.equal(
        emissions[0].text,
        'sudo git status && sudo systemctl status webssh'
    );
});

test('refuses stale, disconnected, and multiline targets', async () => {
    const emissions = [];
    const controller = launcher.createSessionCommandController({
        getSession: sessionId => (
            sessionId === 'offline' ? { connected: false, name: 'Offline' } : null
        ),
        getCommands: () => commands,
        getCommandSets: () => commandSets,
        emitInput: (sessionId, text) => emissions.push({ sessionId, text }),
    });

    assert.equal((await controller.insert('missing', 'command', 'cmd-1')).ok, false);
    assert.equal((await controller.insert('offline', 'command', 'cmd-1')).ok, false);
    assert.equal((await controller.insert('offline', 'command', 'cmd-multiline')).ok, false);
    assert.deepEqual(emissions, []);
});

test('mounts with the real top-level const manager pattern', async () => {
    class FakeElement {
        constructor(tagName) {
            this.tagName = tagName;
            this.children = [];
            this.dataset = {};
            this.attributes = {};
            this.className = '';
            this.listeners = {};
            this.disabled = false;
            this.hidden = false;
            this.classList = {
                add: (...names) => {
                    const classes = new Set(this.className.split(/\s+/).filter(Boolean));
                    names.forEach(name => classes.add(name));
                    this.className = [...classes].join(' ');
                },
                remove: (...names) => {
                    const classes = new Set(this.className.split(/\s+/).filter(Boolean));
                    names.forEach(name => classes.delete(name));
                    this.className = [...classes].join(' ');
                },
                toggle: (name, force) => {
                    const classes = new Set(this.className.split(/\s+/).filter(Boolean));
                    const enabled = force === undefined ? !classes.has(name) : Boolean(force);
                    if (enabled) classes.add(name);
                    else classes.delete(name);
                    this.className = [...classes].join(' ');
                    return enabled;
                },
                contains: name => this.className.split(/\s+/).includes(name),
            };
        }

        addEventListener(type, handler) {
            this.listeners[type] = handler;
        }

        append(...children) {
            children.forEach(child => this.appendChild(child));
        }

        appendChild(child) {
            child.parentElement = this;
            this.children.push(child);
            return child;
        }

        replaceChildren(...children) {
            this.children = [];
            this.append(...children);
        }

        querySelector(selector) {
            const matches = element => {
                if (selector === 'input') return element.tagName === 'input';
                if (selector.startsWith('.')) {
                    return element.className.split(/\s+/).includes(selector.slice(1));
                }
                return false;
            };
            const visit = element => {
                for (const child of element.children) {
                    if (matches(child)) return child;
                    const nested = visit(child);
                    if (nested) return nested;
                }
                return null;
            };
            return visit(this);
        }

        findByText(text) {
            if (this.textContent === text) return this;
            for (const child of this.children) {
                const match = child.findByText(text);
                if (match) return match;
            }
            return null;
        }

        focus() {}

        setSelectionRange() {}

        remove() {
            if (!this.parentElement) return;
            this.parentElement.children = this.parentElement.children.filter(
                child => child !== this
            );
        }

        setAttribute(name, value) {
            this.attributes[name] = String(value);
        }
    }

    const trigger = new FakeElement('button');
    const panel = new FakeElement('aside');
    const mount = new FakeElement('div');
    const workspace = new FakeElement('main');
    panel.hidden = true;
    panel.appendChild(mount);
    const elements = {
        contextCommandsTab: trigger,
        sessionCommandsPanel: panel,
        sessionCommandsMount: mount,
        workspace,
    };
    const documentListeners = {};
    const document = {
        addEventListener(type, handler) { documentListeners[type] = handler; },
        dispatchEvent(event) { documentListeners[event.type]?.(event); },
        createElement: tagName => new FakeElement(tagName),
        getElementById: id => elements[id] || null,
        querySelector: () => null,
        querySelectorAll: () => [],
    };
    const context = vm.createContext({
        document,
        addEventListener() {},
        setTimeout: callback => callback(),
        Event: class Event { constructor(type) { this.type = type; } },
        CustomEvent: class CustomEvent {
            constructor(type, options = {}) {
                this.type = type;
                this.detail = options.detail;
            }
        },
    });
    context.window = context;
    vm.runInContext(`
        let launcherOpen = false;
        let targetName = 'Production Edge';
        window.renameTarget = name => { targetName = name; };
        const SessionManager = {
            paneAssignments: ['real-session'],
            getActivePaneIndex: () => 0,
            sessions: { 'real-session': { connected: true, displayName: 'Production Edge' } },
            switchSession() { launcherOpen = false; },
            showConnectionLauncher() { window.connectionRequests = (window.connectionRequests || 0) + 1; },
            getActiveSession: () => launcherOpen ? null : 'real-session',
            getSession: id => id === 'real-session'
                ? { connected: true, displayName: targetName }
                : null,
        };
        window.setLauncherOpen = open => { launcherOpen = open; };
        const CommandLibrary = {
            commands: [{
                id: 'status',
                name: 'Status',
                command: 'systemctl status webssh',
                parameters: '',
                description: 'Service status',
            }],
        };
        const TerminalManager = { terminals: {} };
        window.CommandSetManager = {
            commandSets: [],
            managementOpens: 0,
            openManagement() { this.managementOpens += 1; },
        };
        window.socket = {
            emissions: [],
            on() {},
            emit(event, payload) { this.emissions.push([event, payload]); },
        };
        window.workspaceLayoutController = {
            getState: () => ({ activeContext: null }),
        };
    `, context);
    const source = fs.readFileSync(
        'static/js/session-command-launcher.js',
        'utf8'
    );

    vm.runInContext(source, context);
    context.SessionCommandLauncher.init();

    assert.equal(trigger.disabled, false);
    assert.equal(mount.children.length, 0);
    const entries = context.SessionCommandLauncher.controller.entries();
    assert.equal(entries.length, 1);
    assert.equal(entries[0].id, 'status');

    document.dispatchEvent(new context.CustomEvent('workspace-context-change', {
        detail: { activeContext: 'commands' },
    }));
    assert.equal(panel.hidden, false);
    assert.equal(context.SessionCommandLauncher.popup.querySelector('.session-command-target-select'), null);
    assert.equal(context.SessionCommandLauncher.popup.findByText('Insert Commands'), null);
    const libraryTab = context.SessionCommandLauncher.popup.findByText('Library');
    assert.equal(libraryTab.attributes.role, 'tab');
    libraryTab.listeners.click();
    assert.ok(context.SessionCommandLauncher.popup.findByText('Status'));
    const sudoInput = context.SessionCommandLauncher.popup.querySelector(
        '.session-command-sudo-input'
    );
    assert.ok(sudoInput);
    assert.equal(sudoInput.checked, false);

    sudoInput.checked = true;
    sudoInput.listeners.change({ target: sudoInput });
    assert.ok(
        context.SessionCommandLauncher.popup.findByText(
            'sudo systemctl status webssh'
        )
    );
    const insert = context.SessionCommandLauncher.popup.findByText('Insert');
    const notices = [];
    context.showNotification = (...args) => notices.push(args);
    const originalInsert = context.SessionCommandLauncher.controller.insert;
    let finishInsert;
    let insertCalls = 0;
    context.SessionCommandLauncher.controller.insert = () => {
        insertCalls++;
        return new Promise(resolve => { finishInsert = resolve; });
    };
    const pendingInsert = insert.listeners.click();
    assert.equal(insert.disabled, true);
    await insert.listeners.click();
    assert.equal(insertCalls, 1);
    assert.equal(notices.length, 0);
    finishInsert({ ok: true });
    await pendingInsert;
    assert.equal(insert.disabled, false);
    assert.equal(notices.length, 0);
    context.SessionCommandLauncher.controller.insert = originalInsert;
    await insert.listeners.click();

    assert.equal(context.socket.emissions.length, 1);
    assert.equal(context.socket.emissions[0][0], 'ssh_input');
    assert.equal(
        context.socket.emissions[0][1].data,
        'sudo systemctl status webssh'
    );

    context.setLauncherOpen(true);
    context.SessionCommandLauncher.sync();
    context.SessionCommandLauncher.render();
    const blockedInsert = context.SessionCommandLauncher.popup.findByText('Insert');
    assert.equal(blockedInsert.disabled, true);
    await blockedInsert.listeners.click();
    assert.equal(context.socket.emissions.length, 1);

    assert.equal(panel.hidden, false);
    assert.ok(context.SessionCommandLauncher.popup);

    assert.equal(context.SessionCommandLauncher.popup.findByText('Open connections'), null);
    context.setLauncherOpen(false);
    context.SessionCommandLauncher.sync();
    assert.equal(context.SessionCommandLauncher.sessionId, 'real-session');
    assert.equal(context.socket.emissions.length, 1);

    const manage = context.SessionCommandLauncher.popup.findByText('Manage Commands');
    manage.listeners.click();
    assert.equal(context.CommandSetManager.managementOpens, 1);
    assert.equal(panel.hidden, false);
    assert.ok(context.SessionCommandLauncher.popup);
    const failureInsert = context.SessionCommandLauncher.popup.findByText('Insert');
    context.SessionCommandLauncher.controller.insert = () => new Promise(resolve => {
        finishInsert = resolve;
    });
    const noticeCount = notices.length;
    const pendingFailure = failureInsert.listeners.click();
    assert.equal(notices.length, noticeCount);
    finishInsert({ ok: false });
    await pendingFailure;
    assert.equal(notices.length, noticeCount + 1);
    assert.equal(notices.at(-1)[1], 'error');
});

test('command insertion waits for sending and never reports success on rejection', async () => {
    let finish;
    const notices = [];
    const controller = launcher.createSessionCommandController({
        getSession: () => ({ connected: true }), getCommands: () => commands,
        emitInput: () => new Promise(resolve => { finish = resolve; }),
        notify: (...args) => notices.push(args),
    });
    const pending = controller.insert('one', 'command', 'cmd-1');
    assert.deepEqual(notices, []);
    finish(false);
    assert.equal((await pending).ok, false);
    assert.deepEqual(notices, []);
    const success = controller.insert('one', 'command', 'cmd-1');
    finish(true);
    assert.equal((await success).ok, true);
    assert.equal(notices.length, 1);
});


test('parameter overrides change only the inserted text and respect sudo and empty values', async () => {
    const sent = [];
    const controller = launcher.createSessionCommandController({
        getSession: () => ({connected: true}), getCommands: () => commands,
        emitInput: (id, text) => sent.push([id, text]),
    });
    assert.equal((await controller.insert('active', 'command', 'cmd-1', {parameters: 'nginx --no-pager', useSudo: true})).ok, true);
    assert.deepEqual(sent[0], ['active', 'sudo systemctl status nginx --no-pager']);
    await controller.insert('active', 'command', 'cmd-1', {parameters: ''});
    assert.equal(sent[1][1], 'systemctl status');
    assert.equal(commands[0].parameters, 'webssh');
    assert.equal((await controller.insert('active', 'command', 'cmd-1', {parameters: 'nginx\nreboot'})).ok, false);
    assert.equal((await controller.insert('active', 'command', 'cmd-multiline', {parameters: ''})).ok, false);
    assert.equal(sent.length, 2);
});
