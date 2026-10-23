const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');
const vm = require('node:vm');

function harness() {
    const listeners = new Map();
    const requests = [];
    const notifications = [];
    const source = {id: 'original', name: 'Original', steps: [{type: 'inline', command: 'printf original'}]};
    const copy = {...source, id: 'copy', name: 'Original Copy'};
    let serverSets = [source];
    let acknowledge;
    let menuOpen = false;
    let renders = 0;
    const window = {
        addEventListener() {},
        showNotification: (...args) => notifications.push(args),
        socket: {
            on: (event, handler) => listeners.set(event, handler),
            emit(event, payload, callback) {
                requests.push(event);
                if (event === 'duplicate_command_set') acknowledge = callback;
                if (event === 'list_command_sets') {
                    listeners.get('command_sets_list')({success: true, command_sets: serverSets});
                }
            },
        },
    };
    vm.runInNewContext(fs.readFileSync(path.join(__dirname, '../../static/js/command-set-manager.js'), 'utf8'), {
        window,
        document: {getElementById: () => null, querySelectorAll: () => []},
    });
    const manager = window.CommandSetManager;
    manager.renderSelect = () => {};
    manager.renderPreview = () => {};
    // Rebuilding the real management list replaces its closed <details> nodes.
    manager.renderManagementList = () => { menuOpen = false; renders++; };
    manager.init();
    requests.length = 0;
    renders = 0;
    return {
        manager, source, copy, requests, notifications,
        publishDuplicate() {
            serverSets = [source, copy];
            listeners.get('command_sets_list')({success: true, command_sets: serverSets});
        },
        acknowledge: result => acknowledge(result),
        openMenu: () => { menuOpen = true; },
        menuOpen: () => menuOpen,
        renders: () => renders,
    };
}

test('duplicate acknowledgement preserves the authoritative pushed list and already opened actions', () => {
    const state = harness();
    state.manager.duplicate(state.source.id);
    // The server sends its updated list before the duplicate acknowledgement.
    state.publishDuplicate();
    assert.equal(state.manager.getById(state.copy.id), state.copy);
    state.openMenu();
    state.acknowledge({success: true, command_set: state.copy});
    assert.equal(state.menuOpen(), true, 'the ACK must not trigger a second list replacement');
    assert.equal(state.renders(), 1);
    assert.deepEqual(state.requests, ['duplicate_command_set']);
    assert.equal(state.manager.getById(state.copy.id), state.copy);
});

test('a rejected duplicate acknowledgement still reports its error without reloading the list', () => {
    const state = harness();
    state.manager.duplicate(state.source.id);
    state.acknowledge({success: false, error: 'Duplicate rejected'});
    assert.deepEqual(state.notifications, [['Duplicate rejected', 'error']]);
    assert.deepEqual(state.requests, ['duplicate_command_set']);
    assert.equal(state.manager.getById(state.source.id), state.source);
    assert.equal(state.manager.getById(state.copy.id), null);
});

function editorHarness() {
    class Element {
        constructor() {
            this.children = []; this.dataset = {}; this.value = ''; this.checked = false;
            this.classList = {add() {}, remove() {}, contains: () => false, toggle() {}};
        }
        append(...items) { this.children.push(...items); }
        appendChild(item) { this.append(item); return item; }
        replaceChildren(...items) { this.children = items; this.text = ''; }
        setAttribute() {}
        querySelectorAll() { return []; }
        contains() { return false; }
        focus() {}
        addEventListener() {}
        get textContent() { return this.text || this.children.map(child => child.textContent || '').join(''); }
        set textContent(value) { this.text = value; this.children = []; }
    }
    const elements = new Map();
    const timers = new Map();
    let timerId = 0;
    ['commandSetNameInput', 'commandSetDescriptionInput', 'commandSetParameterNames',
        'commandSetUseSudoInput', 'commandSetEditorTitle', 'commandSetManagementList',
        'commandSetSteps', 'commandSetDraftPreview', 'commandSetDraftCount',
        'commandSetEditorView', 'commandSetManagementView', 'commandSetUsageFilter'].forEach(id => elements.set(id, new Element()));
    const requests = [];
    let closed = 0;
    const window = {
        CommandWorkspace: {open() {}, close() { closed++; }},
        CommandSetUtils: require('../../static/js/command-set-utils.js'),
        socket: {emit: (event, payload, ack) => requests.push({event, payload, ack})},
    };
    vm.runInNewContext(fs.readFileSync(path.join(__dirname, '../../static/js/command-set-manager.js'), 'utf8'), {
        window, document: {getElementById: id => elements.get(id), createElement: () => new Element(),
            createTextNode: text => ({textContent: text}), querySelectorAll: () => [], activeElement: null},
        setTimeout: (callback, delay) => { timers.set(++timerId, {callback, delay}); return timerId; },
        clearTimeout: id => timers.delete(id),
    });
    const manager = window.CommandSetManager;
    manager.renderSelect = () => {};
    manager.renderPreview = () => {};
    manager.renderLibraryResults = () => {};
    return {manager, elements, window, requests, timers, closed: () => closed};
}

test('set cards show exactly one count with literal description and command preview', () => {
    const {manager, elements} = editorHarness();
    manager.commandSets = [{id: 'a', name: '<name>', description: '', steps: [{type: 'inline', command: '<script>'}]}];
    manager.renderManagementList();
    const card = elements.get('commandSetManagementList').children[0];
    assert.equal(card.textContent.split('1 step').length - 1, 1);
    assert.ok(card.textContent.includes('<script>'));
    assert.ok(card.textContent.includes('Command set'));
});

test('saving from management keeps management open and ignores duplicate submission', () => {
    const {manager, elements, requests, closed} = editorHarness();
    manager.openBuilder();
    elements.get('commandSetNameInput').value = 'New';
    manager.draftSteps.push({type: 'inline', command: 'pwd'});
    manager.save(); manager.save();
    assert.equal(requests.filter(request => request.event === 'save_command_set').length, 1);
    requests[0].ack({success: true, command_set: {id: 'new', name: 'New', steps: [{type: 'inline', command: 'pwd'}]}});
    assert.equal(closed(), 0);
    assert.equal(manager.hasUnsavedChanges(), false);
});

test('dirty draft tracks invalid argument text and blocks navigation until discard is accepted', async () => {
    const {manager, elements} = editorHarness();
    manager.openBuilder();
    assert.equal(manager.hasUnsavedChanges(), false);
    elements.get('commandSetNameInput').value = 'Draft';
    assert.equal(manager.hasUnsavedChanges(), true);
    manager.requestConfirmation = async () => false;
    assert.equal(await manager.confirmDiscard(), false);
    assert.equal(elements.get('commandSetNameInput').value, 'Draft');
    manager.requestConfirmation = async () => true;
    assert.equal(await manager.confirmDiscard(), true);
    assert.equal(manager.hasUnsavedChanges(), false);
});

test('late save acknowledgement cannot replace or close a reopened draft', () => {
    const {manager, elements, requests, closed} = editorHarness();
    manager.openBuilder();
    elements.get('commandSetNameInput').value = 'First';
    manager.draftSteps.push({type: 'inline', command: 'pwd'});
    manager.save();
    manager.draftActive = false; // The previous editor was deliberately discarded before reopening.
    manager.openBuilder();
    elements.get('commandSetNameInput').value = 'Second';
    requests[0].ack({success: true, command_set: {id: 'first', name: 'First', steps: [{type: 'inline', command: 'pwd'}]}});
    assert.equal(elements.get('commandSetNameInput').value, 'Second');
    assert.equal(manager.hasUnsavedChanges(), true);
    assert.equal(closed(), 0);
});

test('draft preview follows reordered steps and invalid JSON is preserved', () => {
    const {manager, elements} = editorHarness();
    manager.openBuilder();
    manager.draftSteps = [{type: 'inline', command: 'first'}, {type: 'inline', command: 'second'}];
    manager.moveStep(1, 0);
    assert.equal(elements.get('commandSetDraftCount').textContent, '2 steps');
    assert.match(elements.get('commandSetDraftPreview').textContent, /second[\s\S]*first/);
    manager.draftSteps = [{type: 'argv', argv: ['ls']}];
    manager.handleStepInput({target: {dataset: {stepField: 'argv', stepIndex: '0'}, value: '[broken'}});
    manager.renderSteps();
    assert.equal(manager.draftSteps[0].argvText, '[broken');
    assert.equal(manager.draftSteps[0].argvError, true);
});

test('save rejection keeps draft and releases pending state for retry', () => {
    const {manager, elements, requests} = editorHarness();
    manager.openBuilder();
    elements.get('commandSetNameInput').value = 'Retained';
    manager.save();
    requests[0].ack({success: false, error: 'No'});
    assert.equal(manager.hasUnsavedChanges(), true);
    assert.equal(elements.get('commandSetNameInput').value, 'Retained');
    manager.save();
    assert.equal(requests.length, 2);
});

test('editing while save is pending preserves newer input after acknowledgement', () => {
    const {manager, elements, requests} = editorHarness();
    manager.openBuilder();
    elements.get('commandSetNameInput').value = 'Saved';
    manager.save();
    elements.get('commandSetNameInput').value = 'Still editing';
    requests[0].ack({success: true, command_set: {id: 'saved', name: 'Saved', steps: []}});
    assert.equal(manager.hasUnsavedChanges(), true);
    assert.equal(manager.editingId, 'saved');
});

test('grouped argument editing preserves each complete argument without shell splitting', () => {
    const {manager} = editorHarness();
    manager.openBuilder();
    manager.draftSteps = [{type: 'argv', argv: ['printf', '%s', '{{value}}']}];
    manager.handleStepInput({target: {dataset: {stepField: 'argument', stepIndex: '0', argumentIndex: '1'}, value: 'a b; $(literal)'}});
    assert.equal(manager.draftSteps[0].argv[1], 'a b; $(literal)');
    assert.deepEqual(JSON.parse(manager.draftSteps[0].argvText), ['printf', 'a b; $(literal)', '{{value}}']);
});

test('editing argument draft never mutates the saved command set', () => {
    const {manager} = editorHarness();
    manager.commandSets = [{id: 'stored', name: 'Stored', steps: [{type: 'argv', argv: ['printf', 'original']}]}];
    manager.openBuilder('stored');
    manager.handleStepInput({target: {dataset: {stepField: 'argument', stepIndex: '0', argumentIndex: '1'}, value: 'draft'}});
    assert.equal(manager.commandSets[0].steps[0].argv[1], 'original');
});

test('opening another set retains dirty editor when discard is cancelled', async () => {
    const {manager, elements} = editorHarness();
    manager.openBuilder();
    elements.get('commandSetNameInput').value = 'Keep this';
    manager.requestConfirmation = async () => false;
    await manager.openBuilder('another');
    assert.equal(elements.get('commandSetNameInput').value, 'Keep this');
    assert.equal(manager.hasUnsavedChanges(), true);
});

test('usage filter combines startup eligibility with text search and refreshes new sets', () => {
    const {manager, elements} = editorHarness();
    manager.commandSets = [
        {id: 'startup', name: 'Startup common', steps: []},
        {id: 'interactive', name: 'Interactive common', parameters: [{name: 'path'}], steps: []},
    ];
    manager.managementUsageFilter = 'startup';
    manager.renderManagementList();
    assert.match(elements.get('commandSetManagementList').textContent, /Startup common/);
    assert.doesNotMatch(elements.get('commandSetManagementList').textContent, /Interactive common/);
    manager.managementUsageFilter = 'interactive';
    manager.renderManagementList();
    assert.match(elements.get('commandSetManagementList').textContent, /Interactive common/);
    assert.doesNotMatch(elements.get('commandSetManagementList').textContent, /Startup common/);
    manager.managementSearchQuery = 'missing';
    manager.renderManagementList();
    assert.equal(elements.get('commandSetManagementList').textContent, 'No command sets match this search.');
    manager.setCommandSets([{id: 'fresh', name: 'Missing fresh', parameters: [{name: 'path'}], steps: []}]);
    assert.match(elements.get('commandSetManagementList').textContent, /Missing fresh/);
    manager.managementUsageFilter = 'all';
    manager.managementSearchQuery = '';
    manager.setCommandSets([{id: 'startup', name: 'No parameters', parameters: [], steps: []}]);
    assert.match(elements.get('commandSetManagementList').textContent, /No parameters/);
});

test('lost save acknowledgement times out and preserves draft without automatically resubmitting', async () => {
    const {manager, elements, requests, timers} = editorHarness();
    manager.openBuilder();
    elements.get('commandSetNameInput').value = 'Uncertain';
    manager.save();
    const timer = Array.from(timers.values()).find(item => item.delay === 10000);
    assert.ok(timer, 'save must have a bounded 10 second timeout');
    timer.callback();
    assert.equal(manager.pendingSave, false);
    assert.equal(manager.saveOutcomeUnknown, true);
    assert.equal(manager.hasUnsavedChanges(), true);
    assert.equal(requests.filter(item => item.event === 'save_command_set').length, 1);
    assert.ok(requests.some(item => item.event === 'list_command_sets'));
    manager.requestConfirmation = async () => false;
    await manager.save();
    assert.equal(requests.filter(item => item.event === 'save_command_set').length, 1);
});

test('retry after uncertain save needs explicit confirmation and ignores old acknowledgement', async () => {
    const {manager, elements, requests, timers} = editorHarness();
    manager.openBuilder();
    elements.get('commandSetNameInput').value = 'Uncertain';
    manager.save();
    const first = requests[0];
    Array.from(timers.values()).find(item => item.delay === 10000).callback();
    let confirmed = 0;
    manager.requestConfirmation = async () => { confirmed++; return true; };
    await manager.save();
    assert.equal(confirmed, 1);
    assert.equal(requests.filter(item => item.event === 'save_command_set').length, 2);
    first.ack({success: true, command_set: {id: 'old', name: 'Old', steps: []}});
    assert.equal(manager.pendingSave, true);
    assert.equal(manager.hasUnsavedChanges(), true);
    assert.equal(manager.getById('old'), null);
    const retry = requests.filter(item => item.event === 'save_command_set')[1];
    retry.ack({success: false, error: 'Denied'});
    assert.equal(manager.pendingSave, false);
    assert.equal(manager.hasUnsavedChanges(), true);
});

test('grouped input synchronizes raw JSON and raw changes refresh grouped fields and preview', () => {
    const {manager, elements} = editorHarness();
    manager.openBuilder();
    manager.draftSteps = [{type: 'argv', argv: ['printf', 'old']}];
    const raw = {value: '["printf","old"]'};
    const input = {dataset: {stepField: 'argument', stepIndex: '0', argumentIndex: '1'}, value: 'new value',
        querySelector: () => null,
        closest(selector) { return selector === '.command-set-step' ? {querySelector: () => raw} : this; }};
    manager.handleStepInput({type: 'input', target: input});
    assert.equal(raw.value, '["printf","new value"]');
    assert.match(elements.get('commandSetDraftPreview').textContent, /new value/);
    manager.handleStepInput({type: 'change', target: {dataset: {stepField: 'argv', stepIndex: '0'}, value: '["printf","from raw"]'}});
    const descendants = element => [element, ...(element.children || []).flatMap(descendants)];
    const grouped = descendants(elements.get('commandSetSteps')).filter(element => element.dataset?.stepField === 'argument');
    assert.deepEqual(grouped.map(element => element.value), ['printf', 'from raw']);
    assert.match(elements.get('commandSetDraftPreview').textContent, /from raw/);
});

test('argument steps are labelled as arguments instead of free text', () => {
    const {manager,elements} = editorHarness();
    manager.draftSteps = [{type:'argv',argv:['ls','--','{{path}}']}];
    manager.renderSteps();
    const header = elements.get('commandSetSteps').children[0].children[0];
    assert.ok(header.textContent.includes('Arguments'));
    assert.equal(header.textContent.includes('Free text'),false);
});
