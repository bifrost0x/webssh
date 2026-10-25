const {test} = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const {spawnSync} = require('node:child_process');

for (const endings of ['LF', 'CRLF']) {
    test(`authentication bundle check accepts ${endings} checkouts without changing files`, () => {
        const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'webssh-i18n-'));
        try {
            for (const name of ['templates', 'static/js']) {
                fs.cpSync(path.resolve(name), path.join(directory, name), {recursive: true});
            }
            fs.mkdirSync(path.join(directory, 'scripts'));
            const script = path.join(directory, 'scripts/build-auth-i18n.js');
            fs.copyFileSync(path.resolve('scripts/build-auth-i18n.js'), script);
            const inputs = ['static/js/i18n.js', 'static/js/i18n-auth.js'];
            const snapshots = inputs.map(name => {
                const filename = path.join(directory, name);
                let text = fs.readFileSync(filename, 'utf8').replace(/\r\n/g, '\n');
                if (endings === 'CRLF') text = text.replace(/\n/g, '\r\n');
                fs.writeFileSync(filename, text);
                return fs.readFileSync(filename);
            });
            const result = spawnSync(process.execPath, [script, '--check'], {cwd: directory, encoding: 'utf8'});
            assert.equal(result.status, 0, result.stderr);
            inputs.forEach((name, index) => assert.deepEqual(fs.readFileSync(path.join(directory, name)), snapshots[index]));
        } finally {
            fs.rmSync(directory, {recursive: true, force: true});
        }
    });
}
