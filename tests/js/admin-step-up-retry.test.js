const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');

const source = fs.readFileSync(path.join(__dirname, '../../static/js/admin.js'), 'utf8');

function loadStepUpAnswers() {
    const start = source.indexOf('    function stepUpRetryMessage(');
    const end = source.indexOf('    // ``verify`` sends the entered value');
    assert.ok(start > 0 && end > start);
    const context = { t: (_key, fallback) => fallback };
    vm.runInNewContext(
        `${source.slice(start, end)}\nthis.retry = stepUpRetryMessage; this.failure = stepUpFailure;`,
        context,
    );
    return context;
}

function apiError(status, code, message = 'Step-up authentication failed') {
    return Object.assign(new Error(message), { status, code });
}

test('only a wrong value or throttling keeps the step-up dialog open', () => {
    const { retry } = loadStepUpAnswers();
    assert.equal(
        retry(apiError(403, 'invalid_value')),
        'Authentication failed. Check the value and try again.',
    );
    assert.equal(retry(apiError(429, 'rate_limited', 'Too many attempts. Try again in 30 s.')),
        'Too many attempts. Try again in 30 s.');
    assert.match(retry(apiError(429, 'step_up_failed')), /Wait a moment/);
    assert.equal(retry(apiError(403, 'step_up_failed')), null);
    assert.equal(retry(apiError(403, undefined)), null);
    assert.equal(retry(apiError(401, 'invalid_value')), null);
});

test('refusals a new value cannot fix end with a fixed explanation', () => {
    const { failure } = loadStepUpAnswers();
    for (const status of [401, 403]) {
        const result = failure(apiError(status, 'step_up_failed'));
        assert.match(result.message, /not available for this account/);
        assert.equal(result.status, status);
        assert.equal(result.code, 'step_up_failed');
    }
    const network = new Error('Network down');
    assert.equal(failure(network), network);
    const server = apiError(500, undefined, 'Request failed (500)');
    assert.equal(failure(server), server);
});
