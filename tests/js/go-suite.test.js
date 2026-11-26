const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');
const {plan} = require('../e2e/run-go-suite.js');

const suite = JSON.parse(fs.readFileSync(path.join(__dirname, '../e2e/go-suite.json'), 'utf8'));
const exists = file => fs.existsSync(path.join(__dirname, '../e2e', file));

test('go-suite.json is valid: every exclusion names a reason and what unlocks it', () => {
    const all = plan(suite, new Set(Object.keys(suite.requires)), exists);
    assert.equal(all.all.length, suite.specs.length);
    assert.equal(all.parallel.length + all.serial.length, all.all.length);
    assert.ok(all.serial.length > 0);
    const none = plan(suite, new Set(), exists);
    assert.ok(none.excluded.includes('shows mixed MFA methods one at a time'));
    assert.ok(!none.all.some(file => file.endsWith('webauthn.spec.js')));
});

test('the runner refuses malformed entries', () => {
    const base = {requires: {passkeys: 'x'}, specs: []};
    const bad = [
        {file: 'mfa.spec.js', exclude: [{title: 't', reason: 'r'}]},
        {file: 'mfa.spec.js', exclude: [{title: 't', reason: 'r', package: 'XX9'}]},
        {file: 'mfa.spec.js', exclude: [{title: 't', package: 'ID1'}]},
        {file: 'mfa.spec.js', serial: 'e2e_user', exclude: []},
        {file: 'mfa.spec.js', requires: 'nothing', exclude: []},
        {file: 'missing.spec.js', exclude: []},
    ];
    for (const spec of bad) {
        assert.throws(() => plan({...base, specs: [spec]}, new Set(), exists), undefined, JSON.stringify(spec));
    }
    assert.throws(() => plan({...base, specs: [{file: 'mfa.spec.js', exclude: []}, {file: 'mfa.spec.js', exclude: []}]}, new Set(), exists));
    assert.throws(() => plan(base, new Set(['unknown']), exists));
    const ok = plan({...base, specs: [{file: 'mfa.spec.js', exclude: [{title: 't', reason: 'r', package: 'ID1'}]}]}, new Set(), exists);
    assert.deepEqual(ok.excluded, ['t']);
});
