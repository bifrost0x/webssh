const test = require('node:test');
const assert = require('node:assert/strict');
const guidance = require('../../static/js/automation-guidance');

test('unattended upgrade hints distinguish explicit confirmation and ordinary commands', () => {
    assert.deepEqual(guidance.stepHints({command:'sudo apt upgrade', timeout:30, sudo:true}), ['guidance.confirmation','guidance.packageTimeout','guidance.doubleSudo']);
    assert.deepEqual(guidance.stepHints({command:'sudo apt upgrade -y', timeout:300}), []);
    assert.deepEqual(guidance.stepHints({command:'apt-get --quiet upgrade --assume-yes', timeout:300}), []);
    assert.deepEqual(guidance.stepHints({command:'sudo apt update', timeout:30}), []);
});
test('only a matching failed confirmation result gets a specific explanation', () => {
    for (const stdout of ['Fortfahren? [J/n] Abbruch.','Do you want to continue? [Y/n] Abort.']) {
        assert.equal(guidance.resultHint({status:'failed',reason:'nonzero_exit',stdout}), 'guidance.confirmationAborted');
    }
    assert.equal(guidance.resultHint({status:'failed',reason:'nonzero_exit',stderr:'WARNING: apt does not have a stable CLI interface.'}), null);
    assert.equal(guidance.resultHint({status:'unknown',reason:'timeout',stdout:'Fortfahren? [J/n] Abbruch.'}), null);
});
