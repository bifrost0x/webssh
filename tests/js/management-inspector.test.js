const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');

function element(tag = 'div') {
    const classes = new Set();
    return {tag, children: [], dataset: {}, attributes: {},
        classList: {add: value => classes.add(value), remove: value => classes.delete(value),
            contains: value => classes.has(value), toggle(value, active) {if (active) classes.add(value); else classes.delete(value);}},
        append(...children) {for (const child of children) {child.parent = this; this.children.push(child);}},
        replaceChildren(...children) {this.children = []; this.append(...children);},
        setAttribute(key, value) {this.attributes[key] = value;},
        remove() {this.parent.children = this.parent.children.filter(child => child !== this);},
        focus() {this.focused = true;},
        querySelectorAll() {return [];},
    };
}

function libraryState() {
    const panel = element();
    const list = element();
    const find = (root, id) => root.id === id ? root : root.children.map(child => find(child, id)).find(Boolean);
    const document = {createElement: element, getElementById(id) {
        if (id === 'commandLibraryPanel') return panel;
        if (id === 'commandsList') return list;
        return find(panel, id);
    }};
    const window = {CommandWorkspace: {favoriteButton: () => element('favorite')}};
    vm.runInNewContext(fs.readFileSync('static/js/command-library.js', 'utf8'), {window, document});
    const library = window.CommandLibrary;
    library.commands = [
        {id: 'system', name: '<img onerror=bad>', command: 'df', parameters: '-h', description: 'Disk usage', os: ['linux'], isSystem: true},
        {id: 'personal', name: 'Mine', command: 'echo', parameters: 'safe', description: 'Personal command', os: ['all']},
    ];
    return {library, panel, document, window};
}

test('system details preserve literal remote text and offer own-copy without execution', () => {
    const {library, panel, document} = libraryState();
    const copied = [];
    library.copyCommand = id => copied.push(id);
    library.selectCommand('system');
    const details = document.getElementById('commandLibraryDetails');
    assert.ok(panel.classList.contains('has-command-details'));
    assert.equal(details.children[0].children[0].textContent, '<img onerror=bad>');
    assert.equal(details.children[1].textContent, 'System · fixed template');
    assert.equal(details.children.filter(child => child.className === 'command-detail-field')[0].children[1].textContent, 'df');
    assert.equal(details.children.filter(child => child.className === 'command-detail-field')[1].children[1].textContent, '-h');
    const actions = details.children.find(child => child.className === 'management-inspector-actions');
    assert.deepEqual(actions.children.map(child => child.textContent).filter(Boolean), ['Add to my commands']);
    actions.children[0].onclick();
    assert.deepEqual(copied, ['system']);
    details.children[0].children[1].onclick();
    assert.equal(document.getElementById('commandLibraryDetails'), undefined);
    assert.equal(library.selectedCommandId, null);
});

test('personal command details retain edit and delete actions and a catalog refresh updates selection', () => {
    const {library, document} = libraryState();
    const calls = [];
    library.editCommand = id => calls.push(['edit', id]);
    library.deleteCommand = id => calls.push(['delete', id]);
    library.selectCommand('personal');
    let details = document.getElementById('commandLibraryDetails');
    assert.equal(details.children[1].textContent, 'Personal');
    const actions = details.children.find(child => child.className === 'management-inspector-actions');
    actions.children[0].onclick();
    actions.children[1].onclick();
    assert.deepEqual(calls, [['edit', 'personal'], ['delete', 'personal']]);
    library.commands[1].description = 'Updated safely';
    library.renderCommandDetails();
    details = document.getElementById('commandLibraryDetails');
    assert.equal(details.children.filter(child => child.className === 'command-detail-field')[2].children[1].textContent, 'echo safe');
    assert.equal(details.children.filter(child => child.className === 'command-detail-field')[3].children[1].textContent, 'Updated safely');
});

test('the compact catalog loads subsequent chunks from its scrolling wrapper', () => {
    const {library, document} = libraryState();
    const list = document.getElementById('commandsList');
    const wrapper = {scrollTop: 0, clientHeight: 200, scrollHeight: 1200};
    list.closest = selector => selector === '.commands-table-wrapper' ? wrapper : null;
    library.filteredCommands = library.commands;
    let chunks = 0;
    library.renderNextChunk = () => {chunks++;};
    library.renderCommandsList();
    assert.equal(chunks, 1);
    wrapper.onscroll();
    assert.equal(chunks, 1);
    wrapper.scrollTop = 1000;
    wrapper.onscroll();
    assert.equal(chunks, 2);
});

test('selecting the currently edited host preserves its unsaved draft', () => {
    const modal = element();
    modal.classList.add('has-profile-editor');
    const input = element('input');
    input.value = 'Unsaved destination';
    const window = {};
    const document = {getElementById: id => id === 'profileManagementModal' ? modal : input};
    vm.runInNewContext(fs.readFileSync('static/js/profile-manager.js', 'utf8'), {window, document});
    window.ProfileManager.editingProfileId = 'one';
    window.ProfileManager.openEditor('one');
    assert.equal(input.value, 'Unsaved destination');
    assert.equal(input.focused, true);
});

test('switching host waits for discard confirmation and preserves later edits', async () => {
    const modal = element();
    modal.classList.add('has-profile-editor');
    const form = {elements: [{id: 'profileEditorHost', value: 'changed'}]};
    let resolve;
    const window = {CommandSetManager: {confirmDialog: () => new Promise(done => {resolve = done;})}};
    const document = {getElementById: id => id === 'profileManagementModal' ? modal : form};
    vm.runInNewContext(fs.readFileSync('static/js/profile-manager.js', 'utf8'), {window, document});
    const manager = window.ProfileManager;
    manager.editorBaseline = 'previous';
    manager.editingProfileId = 'one';
    manager.openEditor('two');
    assert.equal(manager.editingProfileId, 'one');
    form.elements[0].value = 'newer edit';
    resolve(true);
    await Promise.resolve();
    assert.equal(manager.editingProfileId, 'one');
    assert.equal(form.elements[0].value, 'newer edit');
});


test('command row selection respects nested controls and code text selection', () => {
    const {library, window} = libraryState();
    const row = {dataset: {commandId: 'personal'}};
    const calls = [];
    library.selectCommand = id => calls.push(id);
    const container = {contains: node => node === row};
    library.attachCommandListeners(container);
    let interactive = false;
    const target = {closest(selector) {
        if (selector === 'button[data-cmd-id]') return null;
        if (selector === '.command-row[data-command-id]') return row;
        return interactive ? {} : null;
    }};
    container.onclick({target});
    assert.deepEqual(calls, ['personal']);
    interactive = true;
    container.onclick({target});
    assert.equal(calls.length, 1);
    interactive = false;
    window.getSelection = () => ({type: 'Range', containsNode: node => node === row});
    container.onclick({target});
    assert.equal(calls.length, 1);
    window.getSelection = () => ({type: 'Range', containsNode: () => false});
    container.onclick({target});
    assert.deepEqual(calls, ['personal', 'personal']);
});
