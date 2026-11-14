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
        const socksErrors = {
            socks_proxy_failure: ['socksProxyFailure', 'The SOCKS5 proxy reported a general failure.'],
            socks_not_allowed: ['socksNotAllowed', 'The SOCKS5 proxy does not allow this connection.'],
            socks_network_unreachable: ['socksNetworkUnreachable', 'The SOCKS5 proxy cannot reach the target network.'],
            socks_host_unreachable: ['socksHostUnreachable', 'The SOCKS5 proxy cannot reach the target host.'],
            socks_connection_refused: ['socksConnectionRefused', 'The target refused the connection through the SOCKS5 proxy.'],
            socks_ttl_expired: ['socksTtlExpired', 'The connection through the SOCKS5 proxy timed out.'],
            socks_unsupported: ['socksUnsupported', 'The SOCKS5 proxy does not support this request.'],
            socks_protocol_error: ['socksProtocolError', 'The SOCKS5 proxy sent an invalid response.'],
            socks_proxy_unreachable: ['socksProxyUnreachable', 'The SOCKS5 proxy could not be reached.'],
            socks_timeout: ['socksTimeout', 'The SOCKS5 proxy did not respond in time.'],
            socks_auth_required: ['socksAuthRequired', 'The SOCKS5 proxy requires a username and password.'],
            socks_auth_rejected: ['socksAuthRejected', 'The SOCKS5 proxy does not accept username and password login.'],
            socks_auth_failed: ['socksAuthFailed', 'SOCKS5 proxy login failed. Check the username and password.'],
        };
        if (Object.hasOwn(socksErrors, data?.code)) {
            const [key, fallback] = socksErrors[data.code];
            return {message: translated(translate, `sshErrors.${key}`, fallback), type: 'error', duration: 12000,
                action: {label: translated(translate, 'sshErrors.socksReview', 'Review SOCKS5 proxy'), asset: 'socks-proxies'}};
        }
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
