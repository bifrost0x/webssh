// Every English translation key must be referenced by the product: as a
// literal (JavaScript, templates, Python, JSON resources) or through one of
// the dynamic prefixes below, whose keys are assembled at runtime.
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const {localeTable} = require('./i18n-locales.js');

const root = path.join(__dirname, '../..');

// Prefix -> where the rest of the key comes from.
const DYNAMIC_PREFIXES = {
    'automation.': 'automation.js tr() and session-diagnostics.js at()',
    'background.': 'theme-background.js `background.${name}`',
    'commandSets.downStep': 'command-set-manager.js `commandSets.${action}Step`',
    'commandSets.stepType': 'command-set-manager.js `commandSets.stepType${type}`',
    'commandSets.upStep': 'command-set-manager.js `commandSets.${action}Step`',
    'connection.': 'profile-launcher-utils.js `connection.${key}` launch labels',
    'exchange.': 'profile-exchange.js `exchange.${item.status}`',
    'fm.jobState.': 'permission-job-dialog.js `fm.jobState.${state}`',
    'fm.permission.': 'file-mutation-dialog.js and permission-job-dialog.js `fm.permission.${key}`',
    'fm.workspace.move': 'sftp-file-manager.js `fm.workspace.move${direction}`',
    'fm.workspace.transfer': 'sftp-file-manager.js `fm.workspace.transfer${direction}`',
    'hostContext.': 'host-context.js `hostContext.${key}`',
    'notes.': 'app.js `notes.${state}`',
    'operations.': 'admin.js operation titles, kinds, directions and results',
    'overview.ui.': 'overview-route-map.js derives the key from the English label',
    'overviewWorkspace.': 'overview-workspace.js tw()',
    'palette.': 'app.js `palette.${kind}s`',
    'platform.': 'host-platform.js `platform.${source}`',
    'serverOps.': 'server-operations.js `serverOps.${code}`',
    'sessionCommands.search': 'session-command-launcher.js `sessionCommands.search${section}`',
    'sshErrors.': 'ssh-error-ui.js `sshErrors.${key}`',
    'terminalAppearance.': 'terminal_appearance.html renders font and colour keys in Jinja loops',
    'tour.step': 'onboarding.js `tour.step${index}Title`',
    'transfer.error.': 'sftp-file-manager.js `transfer.error.${code}`',
    'transfer.limit.kind.': 'sftp-file-manager.js `transfer.limit.kind.${kind}`',
    'workspace.directorySync.': 'session-workspace-ui.js `workspace.directorySync.${key}`',
    'workspaceContext.': 'workspace-layout-controller.js `workspaceContext.${name}Unavailable`',
};

function productFiles() {
    const files = [];
    const walk = (directory, accept) => {
        for (const entry of fs.readdirSync(directory, {withFileTypes: true})) {
            const full = path.join(directory, entry.name);
            if (entry.isDirectory()) {
                if (!['vendor', 'i18n', '__pycache__', 'node_modules'].includes(entry.name)) walk(full, accept);
            } else if (accept(entry.name)) files.push(full);
        }
    };
    walk(path.join(root, 'static/js'), name => name.endsWith('.js') && name !== 'i18n-auth.js');
    walk(path.join(root, 'templates'), name => name.endsWith('.html'));
    walk(path.join(root, 'app'), name => /\.(py|json)$/.test(name));
    return files;
}

function referencedTokens() {
    const tokens = new Set();
    for (const file of productFiles()) {
        const source = fs.readFileSync(file, 'utf8');
        for (const [token] of source.matchAll(/[A-Za-z][\w-]*(?:\.[\w-]+)+/g)) tokens.add(token);
        // Keys without a namespace are only counted as quoted words.
        for (const [, word] of source.matchAll(/['"`]([A-Za-z][\w-]*)['"`]/g)) tokens.add(word);
    }
    return tokens;
}

test('every English translation key is used by the product', () => {
    const tokens = referencedTokens();
    const english = Object.keys(localeTable().en);
    const prefixes = Object.keys(DYNAMIC_PREFIXES);
    const unused = english.filter(key => !tokens.has(key) && !prefixes.some(prefix => key.startsWith(prefix)));
    assert.deepEqual(unused, [], 'Remove these keys from every static/js/i18n/<lang>.js file, or reference them');
});

test('every dynamic prefix still covers keys that are not referenced literally', () => {
    const tokens = referencedTokens();
    const english = Object.keys(localeTable().en);
    for (const prefix of Object.keys(DYNAMIC_PREFIXES)) {
        const covered = english.filter(key => key.startsWith(prefix) && !tokens.has(key));
        assert.ok(covered.length > 0, `${prefix} no longer covers any key; drop it from the list`);
    }
});
