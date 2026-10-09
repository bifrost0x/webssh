const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
const path = require('node:path');
for (const file of ['auth.js', 'webauthn.js']) {
    const source = fs.readFileSync(path.join(__dirname, '../../static/js', file), 'utf8');
    const statements = source.match(/window\.location\.assign\([^;]*continuation[^;]*;/g);
    for (const [index, statement] of statements.entries()) {
        for (const root of ['', '/webssh', '/tools/webssh']) {
            test(`${file} continuation ${index} retains public path at ${root || '/'}`, () => {
                let assigned;
                const continuation = root + '/admin?tab=users';
                vm.runInNewContext(statement, {
                    root, data: {continuation}, result: {continuation},
                    window: {location: {assign(value) { assigned = value; }}},
                });
                assert.equal(assigned, continuation);
            });
        }
    }
}
