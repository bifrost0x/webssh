(function (root, factory) {
    const api = factory();
    if (typeof module === 'object' && module.exports) {
        module.exports = api;
    }
    if (root) {
        root.SSHErrorUI = api;
    }
}(typeof window !== 'undefined' ? window : globalThis, function () {
    'use strict';

    function translated(translate, key, fallback, replacements = {}) {
        const candidate = typeof translate === 'function' ? translate(key) : null;
        const source = candidate && candidate !== key ? candidate : fallback;
        return Object.entries(replacements).reduce(
            (value, [name, replacement]) => value.replaceAll(`{${name}}`, String(replacement)),
            source,
        );
    }

    function safeAppRoot(value) {
        const candidate = String(value || '').replace(/\/$/, '');
        return candidate === '' || (/^\/[A-Za-z0-9/_-]*$/.test(candidate))
            ? candidate
            : '';
    }

    function describeSSHError(data, translate, appRoot = '') {
        if (data?.code === 'host_key_changed') {
            return {
                message: translated(
                    translate,
                    'sshErrors.hostKeyChanged',
                    'The server presented a different SSH host key. WebSSH blocked the connection. Verify the change before removing the stored trust entry.',
                ),
                type: 'error',
                duration: 12000,
                action: {
                    label: translated(
                        translate,
                        'sshErrors.reviewTrust',
                        'Review SSH host trust',
                    ),
                    url: `${safeAppRoot(appRoot)}/security#ssh-host-trust`,
                },
            };
        }
        const safeMessage = String(data?.error || 'Connection failed');
        return {
            message: translated(
                translate,
                'sshErrors.generic',
                `SSH error: ${safeMessage}`,
                { message: safeMessage },
            ),
            type: 'error',
            duration: undefined,
        };
    }

    return Object.freeze({ describeSSHError, safeAppRoot });
}));
