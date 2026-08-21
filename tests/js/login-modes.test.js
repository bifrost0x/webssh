const test = require('node:test');
const assert = require('node:assert/strict');

global.document = { addEventListener() {} };
const {
    createAuthMethodSwitcherController,
    createAuthenticationSourceController,
    createLanguageSelectorController,
    createPasskeyOperationRunner,
    normalizeTotpCode
} = require('../../static/js/auth.js');
delete global.document;

test('TOTP codes accept six ASCII digits and ignore spaces only', () => {
    assert.equal(normalizeTotpCode(' 123 456 '), '123456');
    assert.equal(normalizeTotpCode('12345'), null);
    assert.equal(normalizeTotpCode('１２３４５６'), null);
});

function element({ hidden = false, value = '' } = {}) {
    const classes = new Set(hidden ? ['hidden'] : []);
    return {
        value,
        focused: false,
        attributes: new Map(),
        classList: {
            contains(name) { return classes.has(name); },
            toggle(name, force) {
                if (force) { classes.add(name); } else { classes.delete(name); }
            }
        },
        focus() { this.focused = true; },
        setAttribute(name, nextValue) { this.attributes.set(name, nextValue); }
    };
}

test('selecting LDAP shows its form and clears the local password', () => {
    const sourceSelect = element({ value: 'local' });
    const localForm = element();
    const ldapForm = element({ hidden: true });
    const localPassword = element({ value: 'local-secret' });
    const ldapPassword = element();
    const ldapUsername = element();
    const localUsername = element();
    const controller = createAuthenticationSourceController({
        sourceSelect,
        localForm,
        ldapForm,
        localPassword,
        ldapPassword,
        ldapUsername,
        localUsername
    });

    controller.select('ldap');

    assert.equal(sourceSelect.value, 'ldap');
    assert.equal(localForm.classList.contains('hidden'), true);
    assert.equal(ldapForm.classList.contains('hidden'), false);
    assert.equal(localPassword.value, '');
    assert.equal(ldapUsername.focused, true);
});

test('selecting local shows its form and clears the LDAP password', () => {
    const sourceSelect = element({ value: 'ldap' });
    const localForm = element({ hidden: true });
    const ldapForm = element();
    const localPassword = element();
    const ldapPassword = element({ value: 'directory-secret' });
    const ldapUsername = element();
    const localUsername = element();
    const controller = createAuthenticationSourceController({
        sourceSelect,
        localForm,
        ldapForm,
        localPassword,
        ldapPassword,
        ldapUsername,
        localUsername
    });

    controller.select('local');

    assert.equal(sourceSelect.value, 'local');
    assert.equal(localForm.classList.contains('hidden'), false);
    assert.equal(ldapForm.classList.contains('hidden'), true);
    assert.equal(ldapPassword.value, '');
    assert.equal(localUsername.focused, true);
});

test('passkey SecurityError becomes an inline configured-origin action without alert', async () => {
    let alertCalls = 0;
    const notices = [];
    global.window = {
        alert() { alertCalls += 1; },
    };
    const runPasskeyOperation = createPasskeyOperationRunner({
        configuredOrigin: 'http://localhost:5050',
        notify(presentation) { notices.push(presentation); },
        translate(_key, fallback) { return fallback; },
    });

    const result = await runPasskeyOperation(async () => {
        const error = new Error('The operation is insecure.');
        error.name = 'SecurityError';
        throw error;
    });

    assert.equal(result, false);
    assert.equal(alertCalls, 0);
    assert.deepEqual(notices, [{
        message: 'Passkeys are configured for http://localhost:5050. Open that address and try again.',
        type: 'error',
        action: {
            label: 'Open configured WebSSH address',
            url: 'http://localhost:5050',
        },
    }]);
    delete global.window;
});

test('authentication method switcher exposes exactly one credentials panel', () => {
    const tabs = ['password', 'passkey', 'oidc'].map(mode => ({
        dataset: { authMode: mode },
        attributes: new Map(),
        setAttribute(name, value) { this.attributes.set(name, String(value)); },
    }));
    const panels = ['password', 'passkey', 'oidc'].map(mode => ({
        dataset: { authModePanel: mode },
        classList: element({ hidden: mode !== 'password' }).classList,
        attributes: new Map(),
        setAttribute(name, value) { this.attributes.set(name, String(value)); },
    }));
    const controller = createAuthMethodSwitcherController({ tabs, panels });

    assert.equal(controller.select('passkey'), true);
    assert.equal(tabs[1].attributes.get('aria-selected'), 'true');
    assert.equal(tabs[0].attributes.get('aria-selected'), 'false');
    assert.equal(panels[1].classList.contains('hidden'), false);
    assert.equal(panels[0].classList.contains('hidden'), true);
    assert.equal(controller.select('missing'), false);
});

test('language menu keeps visual state and aria-expanded synchronized', () => {
    const button = element();
    const dropdown = element();
    const controller = createLanguageSelectorController({ button, dropdown });

    assert.equal(controller.toggle(), true);
    assert.equal(dropdown.classList.contains('show'), true);
    assert.equal(button.attributes.get('aria-expanded'), 'true');

    controller.close();
    assert.equal(dropdown.classList.contains('show'), false);
    assert.equal(button.attributes.get('aria-expanded'), 'false');
});
