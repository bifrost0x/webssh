const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');
const vm = require('node:vm');

// Permissive stand-in for a DOM node: unknown members are callable no-ops
// returning another node, assigned properties are remembered.
function fakeNode(registry, tag) {
    const stored = new Map([['tagName', tag], ['isConnected', true]]);
    const listeners = new Map();
    const node = new Proxy(function () {}, {
        apply: () => fakeNode(registry, 'x'),
        get(_target, key) {
            if (key === Symbol.iterator) return function* () {};
            if (key === Symbol.toPrimitive) return () => '';
            if (key === 'listeners') return listeners;
            if (key === 'then') return undefined;
            if (stored.has(key)) return stored.get(key);
            if (key === 'addEventListener') {
                return (type, handler) => listeners.set(type, handler);
            }
            if (key === 'children') return [];
            if (key === 'textContent') return undefined;
            return fakeNode(registry, 'x');
        },
        set(_target, key, value) {
            stored.set(key, value);
            return true;
        },
    });
    registry.push(node);
    return node;
}

function htmlGatewayResponse() {
    return {
        ok: false,
        status: 502,
        headers: { get: () => 'text/html' },
        async json() {
            throw new SyntaxError("Unexpected token '<', \"<html>\" is not valid JSON");
        },
    };
}

function loadModule(file, extra = {}) {
    const nodes = [];
    const documentListeners = new Map();
    const context = {
        console,
        CustomEvent: class { constructor(type, init) { this.type = type; this.detail = init?.detail; } },
        fetch: async () => htmlGatewayResponse(),
        window: {
            i18n: { t: key => key },
            dispatchEvent() {},
            addEventListener() {},
            removeEventListener() {},
            matchMedia: () => ({ matches: false, addEventListener() {} }),
            ModalManager: { open() {}, close() {} },
            ...extra.window,
        },
        document: {
            querySelector: () => null,
            createElement: tag => fakeNode(nodes, tag),
            createTextNode: () => fakeNode(nodes, '#text'),
            body: fakeNode(nodes, 'body'),
            addEventListener: (type, handler) => documentListeners.set(type, handler),
            removeEventListener() {},
            getElementById: id => extra.elements?.[id] || null,
        },
        ...extra.globals,
    };
    context.window.window = context.window;
    vm.runInNewContext(
        fs.readFileSync(path.join(__dirname, '../../static/js', file), 'utf8'),
        context,
    );
    return { context, nodes, documentListeners };
}

const flush = () => new Promise(resolve => setImmediate(resolve));

test('profile exchange preview shows the module failure text for a non-JSON error', async () => {
    const importButton = fakeNode([], 'button');
    const exportButton = fakeNode([], 'button');
    const { nodes, documentListeners } = loadModule('profile-exchange.js', {
        elements: { importProfilesBtn: importButton, exportProfilesBtn: exportButton },
    });
    documentListeners.get('DOMContentLoaded')();
    importButton.listeners.get('click')();

    const preview = nodes.find(node => node.textContent === 'exchange.preview');
    assert.ok(preview);
    await preview.listeners.get('click')();
    await flush();

    const texts = nodes.map(node => node.textContent).filter(value => typeof value === 'string');
    assert.ok(texts.includes('exchange.failed'), texts.join('|'));
    assert.equal(texts.some(value => /Unexpected token/.test(value)), false);
});

test('server operations report the generic failure for a non-JSON error response', async () => {
    const manager = { sessions: { s1: { connected: true, host: 'h', username: 'u', port: 22 } } };
    const { context, nodes } = loadModule('server-operations.js', {
        window: { SessionManager: manager },
    });
    context.window.ServerOperations.open('s1', 'system');
    await flush();
    await flush();

    const texts = nodes.map(node => node.textContent).filter(value => typeof value === 'string');
    assert.ok(texts.includes('Operation failed.'), texts.join('|'));
    assert.equal(texts.some(value => /Unexpected token/.test(value)), false);
});
