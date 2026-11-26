/* Preview notice of the Go server: says that this build is a preview and
 * names the features the user reached that it does not provide yet. The
 * realtime shim reports them with the webssh:preview-unavailable event.
 */
(function (root, factory) {
    const api = factory(root);
    if (typeof module === 'object' && module.exports) module.exports = api;
    if (root) root.WebSSHPreviewNotice = api;
})(typeof window !== 'undefined' ? window : globalThis, function (root) {
    'use strict';

    const STORAGE_KEY = 'webssh:preview-notice-dismissed';
    const LABELS = Object.freeze({
        files: 'previewNotice.feature.files',
        smb: 'previewNotice.feature.smb',
        commands: 'previewNotice.feature.commands',
        commandSets: 'previewNotice.feature.commandSets',
        insights: 'previewNotice.feature.insights',
        terminalTools: 'previewNotice.feature.terminalTools',
        automation: 'previewNotice.feature.automation',
        credentials: 'previewNotice.feature.credentials',
        discovery: 'previewNotice.feature.discovery',
        herdr: 'previewNotice.feature.herdr',
        gateway: 'previewNotice.feature.gateway',
        tailscale: 'previewNotice.feature.tailscale',
        serverOps: 'previewNotice.feature.serverOps',
        other: 'previewNotice.feature.other',
    });
    // Areas of the sign-in page (#websshPreview); their accounts cannot
    // sign in to the preview. The page has no i18n.js, so the text comes
    // in every language of the product here.
    const SIGN_IN_AREAS = ['ldap', 'oidc', 'github'];
    const SIGN_IN_TEXT = Object.freeze({
        en: 'This is a preview of the new server. Accounts from LDAP, OIDC or GitHub cannot sign in yet.',
        de: 'Dies ist eine Vorschau des neuen Servers. Konten aus LDAP, OIDC oder GitHub können sich noch nicht anmelden.',
        fr: 'Ceci est un aperçu du nouveau serveur. Les comptes LDAP, OIDC ou GitHub ne peuvent pas encore se connecter.',
        es: 'Esta es una versión preliminar del nuevo servidor. Las cuentas de LDAP, OIDC o GitHub aún no pueden iniciar sesión.',
        vi: 'Đây là bản xem trước của máy chủ mới. Tài khoản LDAP, OIDC hoặc GitHub chưa thể đăng nhập.',
        zh: '这是新服务器的预览版。LDAP、OIDC 或 GitHub 账户暂时无法登录。',
    });
    const FEATURES = Object.keys(LABELS);
    const FALLBACK = {
        'previewNotice.title': 'Preview',
        'previewNotice.text': 'This is a preview of the new server. Some features are not available yet.',
        'previewNotice.unavailable': 'Not available in this preview yet: {features}',
        'previewNotice.dismiss': 'Dismiss preview notice',
        'previewNotice.feature.files': 'Files',
        'previewNotice.feature.smb': 'SMB shares',
        'previewNotice.feature.commands': 'Command library',
        'previewNotice.feature.commandSets': 'Command sets',
        'previewNotice.feature.insights': 'Session insights',
        'previewNotice.feature.terminalTools': 'Terminal tools',
        'previewNotice.feature.automation': 'Automation',
        'previewNotice.feature.credentials': 'Saved passwords',
        'previewNotice.feature.discovery': 'Host discovery',
        'previewNotice.feature.herdr': 'Herdr',
        'previewNotice.feature.gateway': 'SSH gateway',
        'previewNotice.feature.tailscale': 'Tailscale SSH',
        'previewNotice.feature.serverOps': 'Server operations',
        'previewNotice.feature.other': 'Other functions',
    };

    // The server's description of the preview (#websshPreview), or null.
    function pageConfig(doc) {
        try {
            const config = JSON.parse(doc.getElementById?.('websshPreview')?.textContent || 'null');
            return config && typeof config === 'object' && Array.isArray(config.unavailable) ? config : null;
        } catch {
            return null;
        }
    }

    function language(doc, win) {
        const value = win.i18n?.currentLanguage || doc.documentElement?.lang || win.navigator?.language || 'en';
        return String(value).slice(0, 2).toLowerCase();
    }

    function create(options = {}) {
        const doc = options.document || root.document;
        const win = options.window || root;
        let storage = options.storage;
        if (storage === undefined) {
            try { storage = win.sessionStorage; } catch { storage = null; }
        }
        const reached = new Set();
        const config = options.config === undefined ? pageConfig(doc) : options.config;
        const signIn = Boolean(config?.unavailable?.some(area => SIGN_IN_AREAS.includes(area)));
        let dismissed = [];
        try {
            dismissed = JSON.parse(storage?.getItem(STORAGE_KEY) || '[]');
        } catch {
            dismissed = [];
        }
        if (!Array.isArray(dismissed)) dismissed = [];

        const t = key => {
            const text = win.i18n?.t?.(key);
            return text && text !== key ? text : (FALLBACK[key] || key);
        };

        const element = doc.createElement('div');
        element.id = 'previewNotice';
        element.className = 'preview-notice';
        element.setAttribute('role', 'status');
        const title = doc.createElement('strong');
        title.className = 'preview-notice-title';
        const text = doc.createElement('span');
        text.className = 'preview-notice-text';
        const details = doc.createElement('span');
        details.className = 'preview-notice-details';
        const dismiss = doc.createElement('button');
        dismiss.type = 'button';
        dismiss.className = 'preview-notice-dismiss';
        dismiss.textContent = '×';
        element.append(title, text, details, dismiss);

        function features() {
            return FEATURES.filter(feature => reached.has(feature));
        }

        function render() {
            title.textContent = t('previewNotice.title');
            text.textContent = signIn
                ? (SIGN_IN_TEXT[language(doc, win)] || SIGN_IN_TEXT.en)
                : t('previewNotice.text');
            const names = features().map(feature => t(LABELS[feature]));
            details.textContent = names.length
                ? t('previewNotice.unavailable').replace('{features}', names.join(', '))
                : '';
            details.hidden = names.length === 0;
            const label = t('previewNotice.dismiss');
            dismiss.setAttribute('aria-label', label);
            dismiss.title = label;
            // Hidden while everything shown so far was dismissed.
            const current = ['notice', ...features()];
            element.hidden = current.every(entry => dismissed.includes(entry));
        }

        dismiss.addEventListener('click', () => {
            dismissed = ['notice', ...features()];
            try {
                storage?.setItem(STORAGE_KEY, JSON.stringify(dismissed));
            } catch {
                // Restricted storage only means the notice returns on reload.
            }
            render();
        });

        function report(feature) {
            const name = FEATURES.includes(feature) ? feature : 'other';
            if (reached.has(name)) return;
            reached.add(name);
            render();
        }

        // The areas the server named are listed from the start.
        for (const area of config?.unavailable || []) {
            if (FEATURES.includes(area) && area !== 'other') reached.add(area);
        }
        win.addEventListener('webssh:preview-unavailable', event => report(event.detail?.feature));
        win.addEventListener('languageChanged', render);
        render();

        const mount = () => doc.body.prepend(element);
        if (doc.body) mount();
        else doc.addEventListener('DOMContentLoaded', mount, {once: true});

        return {element, report, render};
    }

    return Object.freeze({create, STORAGE_KEY, FEATURES});
});

if (typeof window !== 'undefined' && window.document) {
    window.previewNotice = window.WebSSHPreviewNotice.create();
}
