const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');

const root = path.join(__dirname, '../..');
const systemCommands = JSON.parse(fs.readFileSync(path.join(root, 'app/resources/commands/system_commands.json'), 'utf8'));

function load({language = 'de', table = null} = {}) {
    const requests = [];
    const window = {
        i18n: {t: key => key, getLanguage: () => language},
        addEventListener() {},
        CommandSetManager: {onCommandsChanged() {}},
        ConnectionCommandManager: {onDataChanged() {}},
    };
    const stub = () => ({innerHTML: '', textContent: '', hidden: false, dataset: {}, classList: {toggle() {}, add() {}, remove() {}, contains: () => false}, setAttribute() {}, appendChild() {}, querySelector: () => null, querySelectorAll: () => [], addEventListener() {}});
    const document = {querySelector: () => ({content: '/root'}), getElementById: stub, querySelectorAll: () => [], createElement: stub};
    const fetch = async (url, options) => {
        requests.push({url, options});
        return {ok: Boolean(table), json: async () => table};
    };
    vm.runInNewContext(fs.readFileSync(path.join(root, 'static/js/command-library.js'), 'utf8'), {window, document, fetch, i18n: window.i18n});
    const library = window.CommandLibrary;
    library.renderCommandsList = () => {};
    return {library, requests, setLanguage: value => { language = value; }};
}

const system = {id: 'sys-001', name: 'Update Package Lists', description: 'Update APT package repository lists', command: 'apt update', parameters: '', category: 'system', os: ['linux'], isSystem: true};
const personal = {id: 'own-1', name: 'Mine', description: 'Kept as written', command: 'ls', parameters: '', category: 'custom', os: ['linux'], isSystem: false};

test('built-in commands show the translated name and stay findable by their English text', async () => {
    const {library, requests} = load({table: {'sys-001': {name: 'Paketlisten aktualisieren', description: 'APT-Paketlisten aktualisieren'}}});
    library.setCommands([system, personal]);
    await library.applyLanguage();
    assert.equal(requests[0].url, '/root/static/i18n/commands/de.json');
    const [translated, own] = library.commands;
    assert.equal(translated.name, 'Paketlisten aktualisieren');
    assert.equal(translated.command, 'apt update');
    assert.equal(own.name, 'Mine');
    library.searchCommands('package lists');
    assert.deepEqual(library.filteredCommands.map(item => item.id), ['sys-001']);
});

test('English and missing tables keep the original commands', async () => {
    const english = load({language: 'en'});
    english.library.setCommands([system]);
    await english.library.applyLanguage();
    assert.equal(english.requests.length, 0);
    assert.equal(english.library.commands[0].name, 'Update Package Lists');

    const missing = load({language: 'fr', table: null});
    missing.library.setCommands([system]);
    await missing.library.applyLanguage();
    assert.equal(missing.library.commands[0].name, 'Update Package Lists');
});

test('a table for a language that is no longer active is not applied', async () => {
    const {library, setLanguage} = load({table: {'sys-001': {name: 'Paketlisten aktualisieren', description: 'x'}}});
    library.sourceCommands = [system];
    const pending = library.applyLanguage();
    setLanguage('en');
    await pending;
    assert.equal(library.commands.length, 0);
});

test('every shipped table covers every built-in command with a name and description', () => {
    const ids = systemCommands.map(command => command.id);
    for (const language of ['vi', 'de', 'fr', 'es', 'zh']) {
        const table = JSON.parse(fs.readFileSync(path.join(root, `static/i18n/commands/${language}.json`), 'utf8'));
        assert.deepEqual(Object.keys(table), ids, language);
        for (const [id, entry] of Object.entries(table)) {
            assert.deepEqual(Object.keys(entry).sort(), ['description', 'name'], `${language} ${id}`);
            assert.ok(entry.name.trim() && entry.description.trim(), `${language} ${id}`);
        }
    }
});
