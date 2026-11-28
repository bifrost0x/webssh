(function(root, factory) {
    const api = factory();
    if (typeof module === 'object' && module.exports) module.exports = api;
    if (root) root.ConnectionValidation = api;
}(typeof window !== 'undefined' ? window : null, function() {
    'use strict';
    function isValidHost(host) {
        let value = String(host || '').trim();
        if (value.startsWith('[') && value.endsWith(']')) value = value.slice(1, -1);
        value = value.replace(/\.+$/, '');
        if (!value) return false;
        if (value.includes(':')) {
            // Use the browser's IPv6 parser instead of an incomplete IPv6 regex.
            const [address, zone, ...extra] = value.split('%');
            if (extra.length || (zone !== undefined && (!zone || /\s/.test(zone)))) return false;
            try {
                return new URL(`http://[${address}]/`).hostname.startsWith('[');
            } catch { return false; }
        }
        if (/[^\x00-\x7f]/.test(value)) {
            if (/[\s/@:#?\\]/.test(value)) return false;
            try { value = new URL(`http://${value}/`).hostname; } catch { return false; }
        }
        return value.length <= 253 && value.split('.').every(label => (
            /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/i.test(label)
        ));
    }
    function isGateway(value) {
        if (typeof document === 'undefined'
                || document.querySelector('meta[name="ssh-gateway-enabled"]')?.content !== 'true') return false;
        if (typeof value !== 'string' || !value.includes(':') || value.includes('#')
                || value.startsWith('ticket-') || /[\p{Cc}\p{Cf}\p{Cs}\p{Zl}\p{Zp}]/u.test(value)
                || new TextEncoder().encode(value).length > 128) return false;
        const split = value.indexOf(':');
        return [value.slice(0, split), value.slice(split + 1)]
            .every(part => part.length > 0 && part === part.trim());
    }
    function isValidUsername(value, allowGateway = false) {
        if (allowGateway && typeof value === 'string' && value.includes(':')) return isGateway(value);
        return /^[a-zA-Z0-9_.-]{1,32}$/.test(String(value || '').trim());
    }
    function isValidPort(value) {
        return /^\d+$/.test(String(value)) && Number(value) >= 1 && Number(value) <= 65535;
    }
    // Shows message under a form field (role=alert, aria-invalid) and moves
    // the focus there; an empty message clears it. Typing in the field
    // clears it, too. Used for a name another saved record already has.
    let fieldCount = 0;
    function fieldError(input, message) {
        if (!input || typeof document === 'undefined') return;
        if (!input.id) input.id = `formField${++fieldCount}`;
        let hint = document.getElementById(`${input.id}Error`);
        if (!message) {
            if (hint) {
                hint.hidden = true;
                input.removeAttribute('aria-invalid');
                input.classList.remove('has-form-error');
            }
            return;
        }
        if (!hint) {
            hint = document.createElement('p');
            hint.id = `${input.id}Error`;
            hint.className = 'form-error';
            hint.setAttribute('role', 'alert');
            input.after(hint);
            input.setAttribute('aria-describedby', [input.getAttribute('aria-describedby'), hint.id].filter(Boolean).join(' '));
            input.addEventListener('input', () => fieldError(input, ''));
        }
        hint.textContent = message;
        hint.hidden = false;
        input.setAttribute('aria-invalid', 'true');
        input.classList.add('has-form-error');
        input.focus();
    }
    return {isValidHost, isValidUsername, isValidPort, isGateway, fieldError};
}));
