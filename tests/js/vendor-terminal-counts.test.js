const assert = require('node:assert/strict');
const test = require('node:test');
const path = require('node:path');
const {spawnSync} = require('node:child_process');

const vendor = path.resolve(__dirname, '../../static/vendor/xterm/xterm.js');
function render(input) {
    const script = `const {Terminal}=require(process.argv[1]);
        const term=new Terminal({cols:10,rows:4,scrollback:10,allowProposedApi:true});
        term.write(JSON.parse(process.argv[2]),()=>{
            const buffer=term.buffer.active;
            console.log(JSON.stringify({x:buffer.cursorX,y:buffer.cursorY,
                lines:Array.from({length:buffer.length},(_,i)=>buffer.getLine(i).translateToString(true))}));
            term.dispose();
        });`;
    const result = spawnSync(process.execPath, ['-e', script, vendor, JSON.stringify(input)], {
        encoding: 'utf8', timeout: 5000, maxBuffer: 1024 * 1024,
    });
    assert.ifError(result.error);
    assert.equal(result.status, 0, result.stderr);
    return JSON.parse(result.stdout);
}

for (const [name, control] of Object.entries({
    'scroll-up': 'S', 'scroll-down': 'T', 'insert-lines': 'L',
    'delete-lines': 'M', 'forward-tabs': 'I', 'backward-tabs': 'Z',
})) {
    test(`terminal ${name} saturates at geometry without blocking on a huge count`, () => {
        const prefix = 'one\r\ntwo\r\nthree\r\nfour\x1b[2;3H';
        assert.deepEqual(render(prefix + `\x1b[2147483647${control}`), render(prefix + `\x1b[20${control}`));
    });
}

test('terminal repetition bounds expansion from a tiny control sequence', () => {
    const result = render('A\x1b[2147483647b');
    assert.ok(result.lines.length <= 14);
    assert.ok(result.lines.every(line => /^A*$/.test(line)));
});

test('terminal ordinary repetition and combining characters retain their text', () => {
    assert.equal(render('A\x1b[3b').lines[0], 'AAAA');
    assert.equal(render('e\u0301\x1b[2b').lines[0], 'e\u0301e\u0301e\u0301');
});

test('terminal repetition shares a bounded expansion budget across one input chunk', () => {
    const result = render('A\x1b[2147483647b'.repeat(1000) + '\r\nDONE');
    assert.ok(result.lines.includes('DONE'));
});
