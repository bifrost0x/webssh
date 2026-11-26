const test = require('node:test');
const assert = require('node:assert/strict');

const { withStepUpRetry } = require('../../static/js/security-ui.js');

function stepUpRequired() {
    const error = new Error('Confirm your identity to continue.');
    error.status = 403;
    error.code = 'step_up_required';
    return error;
}

test('a route without step-up runs once and never prompts', async () => {
    const calls = [];
    let prompted = false;
    const result = await withStepUpRetry(async headers => {
        calls.push(headers);
        return { ok: true };
    }, async () => { prompted = true; return { 'X-WebSSH-Step-Up': 'g' }; });
    assert.deepEqual(result, { ok: true });
    assert.deepEqual(calls, [{}]);
    assert.equal(prompted, false);
});

test('step_up_required retries once with the grant header', async () => {
    const calls = [];
    const result = await withStepUpRetry(async headers => {
        calls.push(headers);
        if (!headers['X-WebSSH-Step-Up']) { throw stepUpRequired(); }
        return { ok: true };
    }, async () => ({ 'X-WebSSH-Step-Up': 'grant-1' }));
    assert.deepEqual(result, { ok: true });
    assert.deepEqual(calls, [{}, { 'X-WebSSH-Step-Up': 'grant-1' }]);
});

test('a cancelled prompt resolves to null without a second request', async () => {
    let calls = 0;
    const result = await withStepUpRetry(async () => {
        calls += 1;
        throw stepUpRequired();
    }, async () => null);
    assert.equal(result, null);
    assert.equal(calls, 1);
});

test('other failures and a refused retry reach the caller', async () => {
    const conflict = Object.assign(new Error('changed'), { status: 412, code: 'precondition_failed' });
    await assert.rejects(withStepUpRetry(async () => { throw conflict; }, async () => {
        throw new Error('must not prompt');
    }), conflict);
    await assert.rejects(withStepUpRetry(async () => { throw stepUpRequired(); }, async () => ({ 'X-WebSSH-Step-Up': 'stale' })),
        error => error.code === 'step_up_required');
});
