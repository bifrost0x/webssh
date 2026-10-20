const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
function setup() {
    const listeners = {}, sent = [], nodes = {};
    for (const id of ['sshHostKeyModal', 'sshHostKeyTarget', 'sshHostKeyFingerprint', 'sshHostKeyCancel', 'sshHostKeyAccept']) {
        nodes[id] = {textContent: '', addEventListener(name, fn) { this[name] = fn; }};
    }
    const window = {ModalManager: {open() {}, close() {}}};
    vm.runInNewContext(fs.readFileSync('static/js/ssh-host-trust.js', 'utf8'), {window, document: {getElementById: id => nodes[id]}});
    window.SSHHostTrust.init({on: (name, fn) => listeners[name] = fn, emit: (...args) => sent.push(args)}, id => id === 'current');
    return {listeners, sent, nodes};
}
test('unknown or stale requests cannot show a trust prompt', () => {
    const {listeners, sent} = setup();
    listeners.ssh_host_key({prompt_id: 'p', client_request_id: 'old', fingerprint: 'SHA256:key'});
    assert.equal(sent[0][1].accepted, false);
});
test('acceptance binds the displayed exact prompt and request', () => {
    const {listeners, sent, nodes} = setup();
    listeners.ssh_host_key({prompt_id: 'p', client_request_id: 'current', fingerprint: 'SHA256:key', host: '<host>', port: 22, key_type: 'ssh-ed25519'});
    assert.match(nodes.sshHostKeyTarget.textContent, /<host>:22/);
    assert.equal(nodes.sshHostKeyFingerprint.textContent, 'ssh-ed25519\nSHA256:key');
    nodes.sshHostKeyAccept.click();
    assert.equal(sent[0][1].prompt_id, 'p');
    assert.equal(sent[0][1].client_request_id, 'current');
    assert.equal(sent[0][1].accepted, true);
});
test('disconnect clears pending approval', () => {
    const {listeners, sent, nodes} = setup();
    listeners.ssh_host_key({prompt_id: 'p', client_request_id: 'current', fingerprint: 'SHA256:key'});
    listeners.disconnect();
    nodes.sshHostKeyAccept.click();
    assert.equal(sent.length, 0);
});

test('backdrop dismissal rejects the prompt and allows the next connection decision', () => {
    const {listeners, sent, nodes} = setup();
    listeners.ssh_host_key({prompt_id: 'first', client_request_id: 'current', fingerprint: 'SHA256:first'});
    let stopped = false;
    nodes.sshHostKeyModal.click({target: nodes.sshHostKeyModal, stopPropagation() { stopped = true; }});
    assert.equal(stopped, true);
    assert.equal(sent[0][1].accepted, false);
    listeners.ssh_host_key({prompt_id: 'second', client_request_id: 'current', fingerprint: 'SHA256:second'});
    nodes.sshHostKeyAccept.click();
    assert.equal(sent[1][1].prompt_id, 'second');
    assert.equal(sent[1][1].accepted, true);
});
