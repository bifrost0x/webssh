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
    function isValidUsername(value) {
        return /^[a-zA-Z0-9_.-]{1,32}$/.test(String(value || '').trim());
    }
    function isValidPort(value) {
        return /^\d+$/.test(String(value)) && Number(value) >= 1 && Number(value) <= 65535;
    }
    return {isValidHost, isValidUsername, isValidPort};
}));
