const test = require('node:test');
const assert = require('node:assert/strict');

global.document = { addEventListener() {} };
const { createRetryCountdown } = require('../../static/js/auth.js');
delete global.document;

function clock() {
    let now = 0;
    const timers = [];
    return {
        now: () => now,
        schedule(callback, delay) {
            timers.push({ at: now + delay, callback });
            return timers.length;
        },
        cancel() {},
        advance(ms) {
            const end = now + ms;
            for (;;) {
                timers.sort((a, b) => a.at - b.at);
                const next = timers[0];
                if (!next || next.at > end) break;
                timers.shift();
                now = next.at;
                next.callback();
            }
            now = end;
        },
    };
}

test('the verify button counts down the retry delay and then returns to its label', () => {
    const time = clock();
    const button = { textContent: 'Verify code' };
    const ticks = [];
    let done = 0;
    const countdown = createRetryCountdown({
        button,
        label: seconds => `Verify code in ${seconds} s`,
        restoreLabel: () => 'Verify code',
        onTick: seconds => ticks.push(seconds),
        onDone: () => { done += 1; },
        now: time.now,
        schedule: time.schedule,
        cancel: time.cancel,
    });
    assert.equal(countdown.start(3), true);
    assert.equal(button.textContent, 'Verify code in 3 s');
    assert.equal(countdown.active(), true);
    time.advance(1000);
    assert.equal(button.textContent, 'Verify code in 2 s');
    time.advance(1999);
    assert.equal(button.textContent, 'Verify code in 1 s');
    assert.equal(done, 0);
    time.advance(1);
    assert.equal(button.textContent, 'Verify code');
    assert.equal(done, 1);
    assert.equal(countdown.active(), false);
    assert.deepEqual(ticks, [3, 2, 1]);
});

test('missing or invalid retry delays do not start a countdown', () => {
    const button = { textContent: 'Verify code' };
    const countdown = createRetryCountdown({ button, label: () => 'x', schedule: () => 0, cancel() {} });
    for (const value of [undefined, null, 0, -5, 'soon', Number.NaN]) assert.equal(countdown.start(value), false);
    assert.equal(button.textContent, 'Verify code');
});
