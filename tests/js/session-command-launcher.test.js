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

test('builds one searchable model with command sets before commands', () => {
    const all = launcher.buildLauncherEntries(commands, commandSets, 'status');

    assert.deepEqual(all.map(item => [item.type, item.id]), [
        ['set', 'set-1'],
        ['command', 'cmd-1'],
    ]);
    assert.equal(all[0].insertText, commandSets[0].resolved_command);
    assert.equal(all[1].insertText, 'systemctl status webssh');
});

test('keeps unsafe or unresolved entries visible but unavailable', () => {
    const entries = launcher.buildLauncherEntries(commands, commandSets, '');
    const multiline = entries.find(item => item.id === 'cmd-multiline');
    const unresolved = entries.find(item => item.id === 'set-broken');

    assert.equal(multiline.available, false);
    assert.equal(multiline.unavailableReason, 'multiline');
    assert.equal(unresolved.available, false);
    assert.equal(unresolved.unavailableReason, 'unresolved');
});

test('inserts exact text into the bound connected session without Enter', () => {
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

    const result = controller.insert('session-a', 'set', 'set-1');

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

test('adds one sudo prefix to a single command when requested', () => {
    const emissions = [];
    const controller = launcher.createSessionCommandController({
        getSession: () => ({ connected: true, name: 'Production Edge' }),
        getCommands: () => commands,
        getCommandSets: () => commandSets,
        emitInput: (sessionId, text) => emissions.push({ sessionId, text }),
    });

    const result = controller.insert(
        'session-a', 'command', 'cmd-1', { useSudo: true }
    );

    assert.equal(result.ok, true);
    assert.deepEqual(emissions, [{
        sessionId: 'session-a',
        text: 'sudo systemctl status webssh',
    }]);
});

test('recognizes only an existing sudo command token as prefixed', () => {
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

    const result = controller.insert(
        'session-a', 'command', 'cmd-sudo', { useSudo: true }
    );

    assert.equal(result.ok, true);
    assert.equal(emissions[0].text, 'sudo systemctl restart webssh');

    controller.insert(
        'session-a', 'command', 'cmd-sudoers', { useSudo: true }
    );
    assert.equal(emissions[1].text, 'sudo sudoers-check');
});

test('uses the fully resolved sudo variant for a command set', () => {
    const emissions = [];
    const controller = launcher.createSessionCommandController({
        getSession: () => ({ connected: true, name: 'Production Edge' }),
        getCommands: () => commands,
        getCommandSets: () => commandSets,
        emitInput: (sessionId, text) => emissions.push({ sessionId, text }),
    });

    const result = controller.insert(
        'session-a', 'set', 'set-1', { useSudo: true }
    );

    assert.equal(result.ok, true);
    assert.equal(
        emissions[0].text,
        'sudo git status && sudo systemctl status webssh'
    );
});

test('refuses stale, disconnected, and multiline targets', () => {
    const emissions = [];
    const controller = launcher.createSessionCommandController({
        getSession: sessionId => (
            sessionId === 'offline' ? { connected: false, name: 'Offline' } : null
        ),
        getCommands: () => commands,
        getCommandSets: () => commandSets,
        emitInput: (sessionId, text) => emissions.push({ sessionId, text }),
    });

    assert.equal(controller.insert('missing', 'command', 'cmd-1').ok, false);
    assert.equal(controller.insert('offline', 'command', 'cmd-1').ok, false);
    assert.equal(controller.insert('offline', 'command', 'cmd-multiline').ok, false);
    assert.deepEqual(emissions, []);
});

test('mounts with the real top-level const manager pattern', () => {
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
        const SessionManager = {
            paneAssignments: ['real-session'],
            getActivePaneIndex: () => 0,
            getSession: id => id === 'real-session'
                ? { connected: true, displayName: 'Production Edge' }
                : null,
        };
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
    insert.listeners.click();

    assert.equal(context.socket.emissions.length, 1);
    assert.equal(context.socket.emissions[0][0], 'ssh_input');
    assert.equal(
        context.socket.emissions[0][1].data,
        'sudo systemctl status webssh'
    );
    assert.equal(panel.hidden, false);
    assert.ok(context.SessionCommandLauncher.popup);

    const manage = context.SessionCommandLauncher.popup.findByText('Manage Commands');
    manage.listeners.click();
    assert.equal(context.CommandSetManager.managementOpens, 1);
    assert.equal(panel.hidden, false);
    assert.ok(context.SessionCommandLauncher.popup);
});
