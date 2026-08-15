const test = require('node:test');
const assert = require('node:assert/strict');

global.document = { addEventListener() {} };
const { createAuthenticationSourceController } = require('../../static/js/auth.js');
delete global.document;

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
