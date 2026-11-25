const test = require('node:test');
const assert = require('node:assert/strict');
const { loadEscapeHtml } = require('./support/escape-html');

global.window = { escapeHtml: loadEscapeHtml() };
global.document = {};
require('../../static/js/file-directory-requests.js');
require('../../static/js/sftp-file-manager.js');
const Manager = window.SFTPFileManager;

function renderedModal() {
    const manager = Object.create(Manager.prototype);
    let modal = null;
    const element = { hidden: false };
    global.document = {
        createElement: () => {
            modal = { setAttribute() {}, querySelector: () => element };
            return modal;
        },
        body: { dataset: {}, appendChild() {} },
    };
    manager.createQuickConnectModal = () => {};
    manager.setupEventListeners = () => {};
    manager.createModal();
    return modal.innerHTML;
}

function paneMarkup(html, side) {
    const id = side === 'left' ? 'fmLeftPane' : 'fmRightPane';
    const start = html.lastIndexOf('<div', html.indexOf(`id="${id}"`));
    const end = side === 'left'
        ? html.indexOf('<div class="fm-transfer-rail"', start)
        : html.lastIndexOf('</div>', html.indexOf('<!-- Transfer Queue -->', start));
    return html.slice(start, end).trimEnd();
}

const attributes = (markup, name) => [...markup.matchAll(new RegExp(` ${name}="([^"]*)"`, 'g'))].map(match => match[1]);

const leftIds = [
    'fmLeftPane', 'fmLeftTabs', 'fmLeftSource', 'fmLeftSessions', 'fmLeftIdentity', 'fmLeftUp', 'fmLeftHome',
    'fmLeftBreadcrumb', 'fmLeftPath', 'fmLeftRefresh', 'fmLeftList', 'fmLeftBadge', 'fmLeftCount', 'fmLeftSelected',
];

test('both file manager panes render the same structure with side-specific ids', () => {
    const html = renderedModal();
    const left = paneMarkup(html, 'left');
    const right = paneMarkup(html, 'right');

    assert.match(left, /^<div class="fm-pane active" id="fmLeftPane" data-pane="left">/);
    assert.match(right, /^<div class="fm-pane" id="fmRightPane" data-pane="right">/);
    assert.deepEqual(attributes(left, 'id'), leftIds);
    assert.deepEqual(attributes(right, 'id'), leftIds.map(id => id.replace('Left', 'Right')));
    for (const [markup, side] of [[left, 'left'], [right, 'right']]) {
        assert.deepEqual(attributes(markup, 'data-pane'), [side]);
        assert.deepEqual(attributes(markup, 'data-source-target'), [side]);
        assert.deepEqual(attributes(markup, 'data-pane-toolbar'), [side]);
        assert.deepEqual(attributes(markup, 'data-pane-select-all'), [side]);
        assert.ok(markup.includes(`aria-label="${side === 'left' ? 'Left' : 'Right'} side sources" data-i18n-aria-label="fm.workspace.${side}Sources"`));
    }
    assert.deepEqual(attributes(right, 'class'), attributes(left, 'class').map(name => name === 'fm-pane active' ? 'fm-pane' : name));
    assert.equal(
        right,
        left
            .replace('class="fm-pane active"', 'class="fm-pane"')
            .replaceAll('fmLeft', 'fmRight')
            .replaceAll('"left"', '"right"')
            .replace('Left side sources', 'Right side sources')
            .replace('fm.workspace.leftSources', 'fm.workspace.rightSources'),
    );
    assert.equal(html.match(/class="fm-pane( active)?"/g).length, 2);
    assert.ok(html.indexOf('<!-- Left Pane -->') < html.indexOf('id="fmLeftPane"'));
    assert.ok(html.indexOf('<!-- Right Pane -->') < html.indexOf('id="fmRightPane"'));
});

test('pane markup rejects sides other than left and right', () => {
    const manager = Object.create(Manager.prototype);
    for (const side of ['center', '"><img src=x>', undefined, 'Left']) {
        assert.throws(() => manager.paneMarkup(side, false), /Unknown pane side/);
    }
});
