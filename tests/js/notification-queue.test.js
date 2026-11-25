const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');

const source = fs.readFileSync(path.join(__dirname, '../../static/js/app.js'), 'utf8');

class FakeElement {
    constructor(tag) {
        this.tagName = tag.toUpperCase();
        this.children = [];
        this.parent = null;
        this.dataset = {};
        this.attributes = {};
        this.textContent = '';
        this.className = '';
        const classes = new Set();
        this.classList = {
            add: name => classes.add(name),
            contains: name => classes.has(name) || this.className.split(' ').includes(name),
        };
    }
    setAttribute(name, value) { this.attributes[name] = String(value); }
    appendChild(child) {
        child.parent = this;
        this.children.push(child);
        return child;
    }
    remove() {
        if (!this.parent) return;
        this.parent.children = this.parent.children.filter(item => item !== this);
        this.parent = null;
    }
    addEventListener() {}
    contains(node) {
        return node === this || this.children.some(child => child.contains(node));
    }
    querySelector() { return null; }
    querySelectorAll() { return []; }
}

function loadNotifications({ narrow = false } = {}) {
    const start = source.indexOf('    const MAX_TIMED_NOTIFICATIONS = 4;');
    const end = source.indexOf('    let socketProtocolReloadNoticeVisible');
    assert.ok(start > 0 && end > start);
    const container = new FakeElement('div');
    const timers = [];
    const context = {
        window: { matchMedia: () => ({ matches: narrow }) },
        document: {
            activeElement: null,
            getElementById: () => container,
            createElement: tag => new FakeElement(tag),
        },
        setTimeout(fn, delay) {
            timers.push({ fn, delay });
            return timers.length;
        },
        clearTimeout() {},
        Date,
    };
    vm.runInNewContext(source.slice(start, end), context);
    const visible = () => container.children
        .filter(item => !item.classList.contains('fade-out'))
        .map(item => item.children[0].textContent);
    return { show: context.window.showNotification, visible };
}

test('a success toast waits while errors fill the stack and appears once one closes', () => {
    const { show, visible } = loadNotifications();
    const dismissErrors = [1, 2, 3, 4].map(index => show(`Upload failed ${index}`, 'error'));
    show('Saved', 'success');
    assert.deepEqual(visible(), ['Upload failed 1', 'Upload failed 2', 'Upload failed 3', 'Upload failed 4']);

    dismissErrors[0]();
    assert.deepEqual(visible(), ['Upload failed 2', 'Upload failed 3', 'Upload failed 4', 'Saved']);
});

test('a new error does not release a queued success into its own slot', () => {
    const { show, visible } = loadNotifications({ narrow: true });
    show('Error 1', 'error');
    show('Error 2', 'error');
    show('Copied', 'success');
    show('Error 3', 'error');
    assert.deepEqual(visible(), ['Error 2', 'Error 3']);
});

test('dismissing a queued toast removes it and runs onDismiss once', () => {
    const { show, visible } = loadNotifications({ narrow: true });
    const dismissFirst = show('Error 1', 'error');
    show('Error 2', 'error');
    let dismissed = 0;
    const dismissPrompt = show({
        message: 'Copy remote text?',
        type: 'info',
        onDismiss: () => { dismissed += 1; },
    });
    dismissPrompt();
    dismissPrompt();
    assert.equal(dismissed, 1);
    dismissFirst();
    assert.deepEqual(visible(), ['Error 2']);
});

test('the wait queue is bounded and reports dropped toasts through onDismiss', () => {
    const { show } = loadNotifications({ narrow: true });
    show('Error 1', 'error');
    show('Error 2', 'error');
    const dropped = [];
    for (let index = 1; index <= 9; index += 1) {
        show({ message: `Info ${index}`, type: 'info', onDismiss: () => dropped.push(index) });
    }
    assert.deepEqual(dropped, [1]);
});
