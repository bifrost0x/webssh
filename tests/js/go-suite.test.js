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
        {file: 'mfa.spec.js', exclude: [{title: 't', reason: 'r', decision: 'later'}]},
        {file: 'mfa.spec.js', exclude: [{title: 't', reason: 'r', decision: 'ADR 0005', package: 'FE1'}]},
    ];
    for (const spec of bad) {
        assert.throws(() => plan({...base, specs: [spec]}, new Set(), exists), undefined, JSON.stringify(spec));
    }
    assert.throws(() => plan({...base, specs: [{file: 'mfa.spec.js', exclude: []}, {file: 'mfa.spec.js', exclude: []}]}, new Set(), exists));
    assert.throws(() => plan(base, new Set(['unknown']), exists));
    const ok = plan({...base, specs: [{file: 'mfa.spec.js', exclude: [{title: 't', reason: 'r', package: 'ID1'}]}]}, new Set(), exists);
    assert.deepEqual(ok.excluded, ['t']);
    const decided = plan({...base, specs: [{file: 'mfa.spec.js', exclude: [
        {title: 'a', reason: 'r', decision: 'ADR 0005'}, {title: 'b', reason: 'r', decision: 'D-13'}]}]}, new Set(), exists);
    assert.deepEqual(decided.excluded, ['a', 'b']);
});

// After the last M2 package nothing waits for a package any more: what is
// left out is either a capability of the build or a decision.
test('no excluded test waits for FE1', () => {
    for (const spec of suite.specs) {
        for (const entry of spec.exclude) assert.notEqual(entry.package, 'FE1', `${spec.file}: ${entry.title}`);
    }
});

// Every spec of the main suite runs against Go; a test that does not is
// excluded by name with its reason, never by leaving its file out.
test('go-suite.json lists every spec of the main suite', () => {
    const listed = new Set(suite.specs.map(spec => spec.file));
    const missing = fs.readdirSync(path.join(__dirname, '../e2e')).filter(file => file.endsWith('.spec.js') && !listed.has(file));
    assert.deepEqual(missing, []);
});
