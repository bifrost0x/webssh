const test = require('node:test');
const assert = require('node:assert/strict');
const ui = require('../../static/js/account-controls.js');

test('disable preview describes affected admins, configured paths and uncertainty', () => {
    const lines = ui.featureImpactLines({affected_accounts:4, affected_admins:2, locked_affected_accounts:1,
        remaining_primary:{password:3}, remaining_factors:{totp:1}, accounts_without_primary:1,
        admins_without_primary:1, mfa_required_without_local_factor:2, admins_without_local_factor:1});
    const text = lines.join('\n');
    assert.match(text, /4.*2/);
    assert.match(text, /Password: 3/);
    assert.match(text, /configured.*not tested/i);
    assert.match(text, /identity provider.*MFA/i);
});

test('deletion confirmation names the account and retained quarantine files', () => {
    const text = ui.deletionConfirmation('selected_account');
    assert.match(text, /selected_account/);
    assert.match(text, /access.*revoked/i);
    assert.match(text, /files.*quarantine/i);
    assert.doesNotMatch(text, /permanently/);
});

test('a throttled login update shows the wait time instead of the generic failure', () => {
    const previous = globalThis.WebSSHSecurityUI;
    globalThis.WebSSHSecurityUI = require('../../static/js/security-ui.js');
    try {
        assert.equal(
            ui.requestErrorMessage(429, {code:'rate_limited', retry_after:30}),
            'Too many attempts. Try again in 30 s.',
        );
        assert.equal(
            ui.requestErrorMessage(429, {error:'Rate limit exceeded'}),
            'Too many requests. Wait a moment and try again.',
        );
        assert.equal(
            ui.requestErrorMessage(500, null),
            'Could not update logins. Refresh and try again.',
        );
        const german = {'accountControls.throttled': 'Zu viele Anfragen.'};
        assert.equal(ui.requestErrorMessage(429, null, (key, fallback) => german[key] || fallback), 'Zu viele Anfragen.');
    } finally {
        globalThis.WebSSHSecurityUI = previous;
    }
});

test('account controls provide the same complete keys and placeholders in six locales', () => {
    const fs = require('node:fs');
    const vm = require('node:vm');
    const dictionaries = {};
    vm.runInNewContext(fs.readFileSync(require.resolve('../../static/js/account-controls-i18n.js'), 'utf8'), {
        window:{i18n:{addTranslations:(language, values) => { dictionaries[language] = values; }}},
    });
    assert.deepEqual(Object.keys(dictionaries).sort(), ['de', 'en', 'es', 'fr', 'vi', 'zh']);
    for (const values of Object.values(dictionaries)) {
        assert.deepEqual(Object.keys(values).sort(), Object.keys(dictionaries.en).sort());
        for (const [key, value] of Object.entries(values)) {
            assert.ok(value.length);
            assert.deepEqual((value.match(/\{\w+\}/g) || []).sort(), (dictionaries.en[key].match(/\{\w+\}/g) || []).sort());
        }
    }
});
