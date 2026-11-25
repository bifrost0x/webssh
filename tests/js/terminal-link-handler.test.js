const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

global.window = {
    addEventListener() {},
    visualViewport: null,
};
global.document = {};
global.navigator = {};

require('../../static/js/terminal-manager.js');
const TerminalManager = global.window.TerminalManager;

function withBrowser({ confirmResult = true, language = null } = {}, run) {
    const opened = [];
    const prompts = [];
    window.confirm = message => {
        prompts.push(message);
        return confirmResult;
    };
    window.open = (...args) => {
        opened.push(args);
        return null;
    };
    window.i18n = language;
    try {
        run({ opened, prompts });
    } finally {
        delete window.confirm;
        delete window.open;
        delete window.i18n;
    }
}

test('terminal hyperlinks open only http and https targets without credentials', () => {
    for (const uri of [
        'javascript:alert(1)',
        'data:text/html,<script>alert(1)</script>',
        'file:///etc/passwd',
        'ssh://host.example',
        'vbscript:msgbox',
        'https://user:secret@host.example/',
        'http://user@host.example/',
        'not a url',
        '',
    ]) {
        withBrowser({}, ({ opened, prompts }) => {
            assert.equal(TerminalManager.activateTerminalLink(new Event('click'), uri), false, uri);
            assert.deepEqual(opened, [], uri);
            assert.deepEqual(prompts, [], uri);
        });
    }
});

test('terminal hyperlinks are confirmed and opened without opener or referrer', () => {
    withBrowser({}, ({ opened, prompts }) => {
        assert.equal(TerminalManager.activateTerminalLink(new Event('click'), 'https://docs.example/a?b=1'), true);
        assert.equal(prompts.length, 1);
        assert.match(prompts[0], /https:\/\/docs\.example\/a\?b=1/);
        assert.match(prompts[0], /could potentially be dangerous/);
        assert.deepEqual(opened, [['https://docs.example/a?b=1', '_blank', 'noopener,noreferrer']]);
    });
});

test('declining the confirmation opens nothing', () => {
    withBrowser({ confirmResult: false }, ({ opened, prompts }) => {
        assert.equal(TerminalManager.activateTerminalLink(new Event('click'), 'http://host.example/'), false);
        assert.equal(prompts.length, 1);
        assert.deepEqual(opened, []);
    });
});

test('the confirmation is translated and shows the normalized address verbatim', () => {
    const language = { t: key => (key === 'terminal.openLinkConfirm' ? 'Öffnen: {url}?' : key) };
    withBrowser({ language }, ({ prompts }) => {
        TerminalManager.activateTerminalLink(new Event('click'), 'https://HOST.example/$&');
        assert.deepEqual(prompts, ['Öffnen: https://host.example/$&?']);
    });
});

test('the address stands on its own line in the fallback and every locale', () => {
    withBrowser({}, ({ prompts }) => {
        const address = 'https://host.example/path';
        TerminalManager.activateTerminalLink(new Event('click'), address);
        // One whole line equals the address; nothing else shares that line.
        assert.deepEqual(prompts[0].split('\n').filter(line => line === address), [address], prompts[0]);
    });
    const { LOCALES, localeTable } = require('./i18n-locales.js');
    const table = localeTable();
    for (const language of LOCALES) {
        const template = table[language]['terminal.openLinkConfirm'];
        assert.ok(template.split('\n').includes('{url}'), `${language}: ${template}`);
    }
});

test('the host is named on its own line before a long address', () => {
    const host = `${'a'.repeat(40)}.${'b'.repeat(40)}.${'c'.repeat(40)}.attacker.example:8443`;
    const address = `https://${host}/login?next=${'x'.repeat(200)}`;
    withBrowser({}, ({ prompts }) => {
        TerminalManager.activateTerminalLink(new Event('click'), address);
        const lines = prompts[0].split('\n');
        const hostLine = lines.indexOf(`Host: ${host}`);
        assert.ok(hostLine > 0, prompts[0]);
        assert.ok(hostLine < lines.indexOf(address), prompts[0]);
    });
    const { LOCALES, localeTable } = require('./i18n-locales.js');
    const table = localeTable();
    for (const language of LOCALES) {
        const template = table[language]['terminal.openLinkConfirm'];
        const lines = template.split('\n');
        const hostLine = lines.findIndex(line => line.endsWith('{host}') && line !== '{host}');
        assert.ok(hostLine >= 0 && hostLine < lines.indexOf('{url}'), `${language}: ${template}`);
        withBrowser({ language: { t: () => template } }, ({ prompts }) => {
            TerminalManager.activateTerminalLink(new Event('click'), address);
            const rendered = prompts[0].split('\n');
            assert.ok(rendered[hostLine].endsWith(host), `${language}: ${prompts[0]}`);
            assert.equal(rendered[hostLine + 1], address);
        });
    }
});

test('an internationalized host is shown in its ASCII form', () => {
    withBrowser({}, ({ prompts }) => {
        TerminalManager.activateTerminalLink(new Event('click'), 'https://pаypal.example/');
        assert.match(prompts[0], /^Host: xn--/m);
    });
});

test('every terminal is created with the restricted link handler', () => {
    const source = fs.readFileSync(path.join(__dirname, '../../static/js/terminal-manager.js'), 'utf8');
    assert.match(source, /\.\.\.this\.getAppearance\(\)\.options,\s*linkHandler: this\.createLinkHandler\(\),/);
    const handler = TerminalManager.createLinkHandler();
    assert.equal(handler.allowNonHttpProtocols, undefined);
    withBrowser({}, ({ opened }) => {
        handler.activate(new Event('click'), 'javascript:alert(1)');
        handler.activate(new Event('click'), 'https://host.example/');
        assert.deepEqual(opened, [['https://host.example/', '_blank', 'noopener,noreferrer']]);
    });
});
