(function() {
    'use strict';

    function t(key, fallback) {
        const translated = typeof window !== 'undefined'
            ? window.i18n?.t?.(key)
            : null;
        return translated && translated !== key ? translated : (fallback || key);
    }

    function createAuthenticationSourceController(elements) {
        const {
            sourceSelect,
            localForm,
            ldapForm,
            localPassword,
            ldapPassword,
            ldapUsername,
            localUsername
        } = elements;

        function applySource(source, { clearPassword = true, focus = true } = {}) {
            const ldapActive = source === 'ldap';
            sourceSelect.value = ldapActive ? 'ldap' : 'local';
            localForm.classList.toggle('hidden', ldapActive);
            ldapForm.classList.toggle('hidden', !ldapActive);

            if (clearPassword) {
                const passwordToClear = ldapActive ? localPassword : ldapPassword;
                if (passwordToClear) {
                    passwordToClear.value = '';
                }
            }
            if (focus) {
                const fieldToFocus = ldapActive ? ldapUsername : localUsername;
                fieldToFocus?.focus();
            }
        }

        return {
            select(source) {
                applySource(source);
            },
            sync() {
                applySource(sourceSelect.value, {
                    clearPassword: false,
                    focus: false
                });
            }
        };
    }

    function setupAuthenticationSources() {
        const sourceSelect = document.getElementById('authenticationSource');
        const localForm = document.getElementById('localLoginForm');
        const ldapForm = document.getElementById('ldapLoginForm');
        if (!sourceSelect || !localForm || !ldapForm) {
            return;
        }

        const controller = createAuthenticationSourceController({
            sourceSelect,
            localForm,
            ldapForm,
            localPassword: document.getElementById('password'),
            ldapPassword: document.getElementById('ldapPassword'),
            ldapUsername: document.getElementById('ldapUsername'),
            localUsername: document.getElementById('username')
        });
        sourceSelect.addEventListener('change', () => {
            controller.select(sourceSelect.value);
        });
        controller.sync();
    }

    function setFieldState(input, hintEl, message, isValid) {
        if (!input || !hintEl) {
            return;
        }
        input.classList.toggle('is-valid', Boolean(isValid));
        input.classList.toggle('is-invalid', isValid === false);
        hintEl.textContent = message || '';
        hintEl.classList.toggle('hint-error', isValid === false);
        hintEl.classList.toggle('hint-success', isValid === true);
    }

    function setupPasswordToggles() {
        document.querySelectorAll('.password-toggle').forEach(button => {
            button.addEventListener('click', () => {
                const targetId = button.dataset.target;
                const input = document.getElementById(targetId);
                if (!input) {
                    return;
                }
                const isHidden = input.getAttribute('type') === 'password';
                input.setAttribute('type', isHidden ? 'text' : 'password');
                button.classList.toggle('active', isHidden);
            });
        });
    }

    function setupRegisterValidation() {
        const username = document.getElementById('username');
        const password = document.getElementById('password');
        const confirm = document.getElementById('confirm_password');
        const usernameHint = document.getElementById('registerUsernameHint');
        const passwordHint = document.getElementById('registerPasswordHint');
        const confirmHint = document.getElementById('registerConfirmHint');

        if (!username || !password || !confirm) {
            return;
        }

        username.addEventListener('input', () => {
            const value = username.value.trim();
            const isValid = /^[a-zA-Z0-9_]{3,32}$/.test(value);
            setFieldState(
                username,
                usernameHint,
                value
                    ? (isValid
                        ? t('auth.validUsername', 'Valid username')
                        : t('auth.usernameRulesShort', '3-32 chars, letters/numbers/_'))
                    : t('auth.usernameRequired', 'Username required'),
                value ? isValid : false
            );
        });

        password.addEventListener('input', () => {
            const value = password.value;
            const isValid = value.length >= 8;
            setFieldState(
                password,
                passwordHint,
                isValid
                    ? t('auth.passwordStrongEnough', 'Strong enough')
                    : t('auth.passwordHint', 'Minimum 8 characters'),
                isValid
            );
        });

        const checkMatch = () => {
            const match = confirm.value && confirm.value === password.value;
            setFieldState(
                confirm,
                confirmHint,
                match
                    ? t('auth.passwordsMatch', 'Passwords match')
                    : t('auth.passwordsNoMatch', 'Passwords do not match'),
                match
            );
        };

        confirm.addEventListener('input', checkMatch);
        password.addEventListener('input', checkMatch);
        document.getElementById('registerForm')?.addEventListener('submit', event => {
            const validUsername = /^[a-zA-Z0-9_]{3,32}$/.test(username.value.trim());
            const validPassword = password.value.length >= 8;
            const matchingPassword = Boolean(
                confirm.value && confirm.value === password.value
            );
            if (validUsername && validPassword && matchingPassword) return;
            event.preventDefault();
            if (!validUsername) username.focus();
            else if (!validPassword) password.focus();
            else confirm.focus();
        });
    }

    function setupChangePasswordValidation() {
        const current = document.getElementById('current_password');
        const next = document.getElementById('new_password');
        const confirm = document.getElementById('confirm_password');
        const currentHint = document.getElementById('currentPasswordHint');
        const nextHint = document.getElementById('newPasswordHint');
        const confirmHint = document.getElementById('confirmPasswordHint');

        if (!current || !next || !confirm) {
            return;
        }

        current.addEventListener('input', () => {
            const value = current.value;
            setFieldState(
                current,
                currentHint,
                value
                    ? t('auth.validationLooksGood', 'Looks good')
                    : t('auth.currentPasswordRequired', 'Current password required'),
                Boolean(value)
            );
        });

        next.addEventListener('input', () => {
            const value = next.value;
            const isValid = value.length >= 8;
            setFieldState(
                next,
                nextHint,
                isValid
                    ? t('auth.passwordStrongEnough', 'Strong enough')
                    : t('auth.passwordHint', 'Minimum 8 characters'),
                isValid
            );
        });

        const checkMatch = () => {
            const match = confirm.value && confirm.value === next.value;
            setFieldState(
                confirm,
                confirmHint,
                match
                    ? t('auth.passwordsMatch', 'Passwords match')
                    : t('auth.passwordsNoMatch', 'Passwords do not match'),
                match
            );
        };

        confirm.addEventListener('input', checkMatch);
        next.addEventListener('input', checkMatch);
        document.getElementById('changePasswordForm')?.addEventListener('submit', event => {
            if (
                current.value
                && next.value.length >= 8
                && confirm.value === next.value
            ) return;
            event.preventDefault();
            if (!current.value) current.focus();
            else if (next.value.length < 8) next.focus();
            else confirm.focus();
        });
    }

    function createAuthMethodSwitcherController({ tabs, panels }) {
        const tabList = Array.from(tabs || []);
        const panelList = Array.from(panels || []);
        const available = new Set(
            tabList.map(tab => tab.dataset?.authMode).filter(Boolean)
        );

        function select(mode, { focus = false } = {}) {
            if (!available.has(mode)) return false;
            tabList.forEach(tab => {
                const selected = tab.dataset.authMode === mode;
                tab.setAttribute('aria-selected', String(selected));
                tab.setAttribute('tabindex', selected ? '0' : '-1');
            });
            panelList.forEach(panel => {
                const selected = panel.dataset?.authModePanel === mode;
                panel.classList.toggle('hidden', !selected);
                panel.setAttribute('aria-hidden', String(!selected));
                if (selected && focus) {
                    panel.querySelector?.('input:not([type="hidden"]), button, a')?.focus?.();
                }
            });
            return true;
        }

        return { select };
    }

    function setupAuthMethodSwitcher() {
        const tabs = document.querySelectorAll('[data-auth-mode]');
        const panels = document.querySelectorAll('[data-auth-mode-panel]');
        if (!tabs.length || !panels.length) return;
        const controller = createAuthMethodSwitcherController({ tabs, panels });
        tabs.forEach(tab => {
            tab.addEventListener('click', () => controller.select(
                tab.dataset.authMode,
                { focus: true },
            ));
        });
        const selected = Array.from(tabs).find(
            tab => tab.getAttribute('aria-selected') === 'true'
        ) || tabs[0];
        controller.select(selected.dataset.authMode);
    }

    function safeConfiguredWebAuthnOrigin(value) {
        try {
            const parsed = new URL(String(value || ''));
            const localHttp = parsed.protocol === 'http:'
                && parsed.hostname === 'localhost';
            if (parsed.protocol !== 'https:' && !localHttp) return null;
            return parsed.origin;
        } catch {
            return null;
        }
    }

    function describePasskeyError(error, configuredOrigin, translate) {
        const t = typeof translate === 'function'
            ? translate
            : (_key, fallback) => fallback;
        const safeOrigin = safeConfiguredWebAuthnOrigin(configuredOrigin);
        const errorName = String(error?.name || '');
        if (errorName === 'SecurityError') {
            if (safeOrigin) {
                return {
                    message: t(
                        'auth.passkeyOriginMismatch',
                        `Passkeys are configured for ${safeOrigin}. Open that address and try again.`,
                    ).replace('{origin}', safeOrigin),
                    type: 'error',
                    action: {
                        label: t(
                            'auth.openConfiguredAddress',
                            'Open configured WebSSH address',
                        ),
                        url: safeOrigin,
                    },
                };
            }
            return {
                message: t(
                    'auth.passkeySecurityError',
                    'Passkey sign-in is unavailable at this address. Open the configured WebSSH address and try again.',
                ),
                type: 'error',
            };
        }
        if (errorName === 'NotAllowedError') {
            return {
                message: t(
                    'auth.passkeyNotAllowed',
                    'Passkey sign-in was cancelled or no matching passkey was available.',
                ),
                type: 'error',
            };
        }
        if (errorName === 'NotSupportedError') {
            return {
                message: t(
                    'auth.passkeyUnsupported',
                    'This browser cannot use Passkeys for this WebSSH instance.',
                ),
                type: 'error',
            };
        }
        return {
            message: t(
                'auth.passkeyFailed',
                'Passkey sign-in could not be completed. Try again or use another sign-in method.',
            ),
            type: 'error',
        };
    }

    function createPasskeyOperationRunner(options = {}) {
        const notify = options.notify || (() => {});
        return async operation => {
            try {
                return await operation();
            } catch (error) {
                notify(describePasskeyError(
                    error,
                    options.configuredOrigin,
                    options.translate,
                ));
                return false;
            }
        };
    }

    function normalizeTotpCode(value) {
        const normalized = String(value || '').replace(/\s+/g, '');
        return /^[0-9]{6}$/.test(normalized) ? normalized : null;
    }

    function setupTotpMfa() {
        const button = document.getElementById('submitTotpMfa');
        const input = document.getElementById('totpMfaCode');
        const error = document.getElementById('totpMfaError');
        if (!button || !input || !error) {
            return;
        }
        const root = (document.querySelector('meta[name="app-root"]')?.content || '')
            .replace(/\/$/, '');
        const csrf = document.querySelector('meta[name="csrf-token"]')?.content || '';
        const submit = async () => {
            const code = normalizeTotpCode(input.value);
            if (!code) {
                error.textContent = t(
                    'security.invalidTotpCode',
                    'Enter a valid six-digit code.'
                );
                error.classList.remove('hidden');
                return;
            }
            button.disabled = true;
            error.classList.add('hidden');
            try {
                const response = await fetch(root + '/api/totp/auth/verify', {
                    method: 'POST',
                    credentials: 'same-origin',
                    headers: {
                        'Accept': 'application/json',
                        'Content-Type': 'application/json',
                        'X-CSRFToken': csrf
                    },
                    body: JSON.stringify({ code })
                });
                const data = await response.json().catch(() => ({}));
                if (!response.ok) {
                    throw new Error(data.error || t(
                        'auth.codeVerificationFailed',
                        'The code could not be verified.'
                    ));
                }
                window.location.assign(root + (data.continuation || '/'));
            } catch (requestError) {
                error.textContent = requestError.message;
                error.classList.remove('hidden');
                input.select();
            } finally {
                button.disabled = false;
            }
        };
        button.addEventListener('click', submit);
        input.addEventListener('keydown', event => {
            if (event.key === 'Enter') {
                event.preventDefault();
                submit();
            }
        });
    }

    function createLanguageSelectorController({ button, dropdown }) {
        function setOpen(open) {
            const next = Boolean(open);
            dropdown?.classList.toggle('show', next);
            button?.setAttribute('aria-expanded', String(next));
            return next;
        }

        return {
            close() { return setOpen(false); },
            open() { return setOpen(true); },
            toggle() {
                return setOpen(!dropdown?.classList.contains('show'));
            }
        };
    }

    function setupLanguageSelector() {
        const button = document.getElementById('langBtn');
        const dropdown = document.getElementById('langDropdown');
        const code = document.getElementById('currentLangFlag');
        const name = document.getElementById('currentLangName');
        if (!button || !dropdown || !window.i18n?.getLanguages) return;

        const controller = createLanguageSelectorController({ button, dropdown });
        const languages = i18n.getLanguages();
        const updateCurrent = language => {
            if (!language) return;
            if (code) code.textContent = language.code.toUpperCase();
            if (name) name.textContent = language.name;
            dropdown.querySelectorAll('[data-language-code]').forEach(option => {
                const selected = option.dataset.languageCode === language.code;
                option.setAttribute('aria-checked', String(selected));
                option.classList.toggle('active', selected);
            });
        };

        dropdown.textContent = '';
        dropdown.setAttribute('role', 'menu');
        languages.forEach(language => {
            const option = document.createElement('button');
            option.type = 'button';
            option.className = 'lang-option';
            option.dataset.languageCode = language.code;
            option.setAttribute('role', 'menuitemradio');
            option.textContent = `${language.code.toUpperCase()}  ${language.name}`;
            option.addEventListener('click', () => {
                i18n.setLanguage(language.code);
                updateCurrent(language);
                controller.close();
                button.focus();
            });
            dropdown.appendChild(option);
        });

        updateCurrent(languages.find(language => (
            language.code === i18n.getLanguage()
        )) || languages[0]);
        button.addEventListener('click', () => controller.toggle());
        document.addEventListener('click', event => {
            if (!event.target.closest('.language-selector')) controller.close();
        });
        document.addEventListener('keydown', event => {
            if (event.key !== 'Escape') return;
            controller.close();
            button.focus();
        });
    }

    function setupRecoveryMfa() {
        const button = document.getElementById('submitRecoveryMfa');
        const input = document.getElementById('recoveryMfaCode');
        const error = document.getElementById('recoveryMfaError');
        if (!button || !input || !error) {
            return;
        }
        const root = (document.querySelector('meta[name="app-root"]')?.content || '')
            .replace(/\/$/, '');
        const csrf = document.querySelector('meta[name="csrf-token"]')?.content || '';
        const submit = async () => {
            const code = input.value.trim();
            if (!code) {
                error.textContent = t(
                    'auth.recoveryCodeRequired',
                    'Enter a recovery code.'
                );
                error.classList.remove('hidden');
                return;
            }
            button.disabled = true;
            error.classList.add('hidden');
            try {
                const response = await fetch(root + '/api/auth/recovery', {
                    method: 'POST',
                    credentials: 'same-origin',
                    headers: {
                        'Accept': 'application/json',
                        'Content-Type': 'application/json',
                        'X-CSRFToken': csrf
                    },
                    body: JSON.stringify({ code })
                });
                const data = await response.json().catch(() => ({}));
                if (!response.ok) {
                    throw new Error(data.error || t(
                        'auth.recoveryAuthenticationFailed',
                        'Recovery authentication failed.'
                    ));
                }
                window.location.assign(root + (data.continuation || '/security'));
            } catch (requestError) {
                error.textContent = requestError.message;
                error.classList.remove('hidden');
                input.select();
            } finally {
                button.disabled = false;
            }
        };
        button.addEventListener('click', submit);
        input.addEventListener('keydown', event => {
            if (event.key === 'Enter') {
                event.preventDefault();
                submit();
            }
        });
    }

    document.addEventListener('DOMContentLoaded', () => {
        setupLanguageSelector();
        setupAuthMethodSwitcher();
        setupAuthenticationSources();
        setupPasswordToggles();
        setupRegisterValidation();
        setupChangePasswordValidation();
        setupTotpMfa();
        setupRecoveryMfa();
    });

    if (typeof window !== 'undefined') {
        window.WebSSHAuthUI = Object.freeze({
            createPasskeyOperationRunner,
            describePasskeyError,
            safeConfiguredWebAuthnOrigin,
        });
    }

    if (typeof module === 'object' && module.exports) {
        module.exports = {
            createAuthMethodSwitcherController,
            createAuthenticationSourceController,
            createLanguageSelectorController,
            createPasskeyOperationRunner,
            describePasskeyError,
            safeConfiguredWebAuthnOrigin,
            normalizeTotpCode
        };
    }
})();
