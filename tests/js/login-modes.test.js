const test = require('node:test');
const assert = require('node:assert/strict');

global.document = { addEventListener() {} };
const { createLoginModeController } = require('../../static/js/auth.js');
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

test('LDAP mode hides every standard sign-in option and clears local password', () => {
    const defaultPanel = element();
    const ldapPanel = element({ hidden: true });
    const trigger = element();
    const localPassword = element({ value: 'local-secret' });
    const ldapPassword = element();
    const ldapUsername = element();
    const localUsername = element();
    const controller = createLoginModeController({
        defaultPanel,
        ldapPanel,
        trigger,
        localPassword,
        ldapPassword,
        ldapUsername,
        localUsername
    });

    controller.showLdap();

    assert.equal(defaultPanel.classList.contains('hidden'), true);
    assert.equal(ldapPanel.classList.contains('hidden'), false);
    assert.equal(trigger.attributes.get('aria-expanded'), 'true');
    assert.equal(localPassword.value, '');
    assert.equal(ldapUsername.focused, true);
});

test('back navigation restores standard sign-in and clears LDAP password', () => {
    const defaultPanel = element({ hidden: true });
    const ldapPanel = element();
    const trigger = element();
    const localPassword = element();
    const ldapPassword = element({ value: 'directory-secret' });
    const ldapUsername = element();
    const localUsername = element();
    const controller = createLoginModeController({
        defaultPanel,
        ldapPanel,
        trigger,
        localPassword,
        ldapPassword,
        ldapUsername,
        localUsername
    });

    controller.showDefault();

    assert.equal(defaultPanel.classList.contains('hidden'), false);
    assert.equal(ldapPanel.classList.contains('hidden'), true);
    assert.equal(trigger.attributes.get('aria-expanded'), 'false');
    assert.equal(ldapPassword.value, '');
    assert.equal(localUsername.focused, true);
});
