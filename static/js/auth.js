(function() {
    'use strict';

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

    function setupLoginValidation() {
        const username = document.getElementById('username');
        const password = document.getElementById('password');
        const usernameHint = document.getElementById('loginUsernameHint');
        const passwordHint = document.getElementById('loginPasswordHint');

        if (!username || !password) {
            return;
        }

        username.addEventListener('input', () => {
            const value = username.value.trim();
            setFieldState(username, usernameHint, value ? '✓ Looks good' : 'Username required', Boolean(value));
        });

        password.addEventListener('input', () => {
            const value = password.value;
            setFieldState(password, passwordHint, value ? '✓ Ready' : 'Password required', Boolean(value));
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
                value ? (isValid ? '✓ Valid username' : '3-32 chars, letters/numbers/_') : 'Username required',
                value ? isValid : false
            );
        });

        password.addEventListener('input', () => {
            const value = password.value;
            const isValid = value.length >= 8;
            setFieldState(password, passwordHint, isValid ? '✓ Strong enough' : 'Minimum 8 characters', isValid);
        });

        const checkMatch = () => {
            const match = confirm.value && confirm.value === password.value;
            setFieldState(confirm, confirmHint, match ? '✓ Passwords match' : 'Passwords do not match', match);
        };

        confirm.addEventListener('input', checkMatch);
        password.addEventListener('input', checkMatch);
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
            setFieldState(current, currentHint, value ? '✓ Looks good' : 'Current password required', Boolean(value));
        });

        next.addEventListener('input', () => {
            const value = next.value;
            const isValid = value.length >= 8;
            setFieldState(next, nextHint, isValid ? '✓ Strong enough' : 'Minimum 8 characters', isValid);
        });

        const checkMatch = () => {
            const match = confirm.value && confirm.value === next.value;
            setFieldState(confirm, confirmHint, match ? '✓ Passwords match' : 'Passwords do not match', match);
        };

        confirm.addEventListener('input', checkMatch);
        next.addEventListener('input', checkMatch);
    }

    document.addEventListener('DOMContentLoaded', () => {
        setupPasswordToggles();
        setupLoginValidation();
        setupRegisterValidation();
        setupChangePasswordValidation();
    });
})();
