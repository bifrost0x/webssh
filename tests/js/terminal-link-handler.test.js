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
