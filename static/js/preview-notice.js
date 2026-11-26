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
        other: 'previewNotice.feature.other',
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
        'previewNotice.feature.other': 'Other functions',
    };

    function create(options = {}) {
        const doc = options.document || root.document;
        const win = options.window || root;
        let storage = options.storage;
        if (storage === undefined) {
            try { storage = win.sessionStorage; } catch { storage = null; }
        }
        const reached = new Set();
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
            text.textContent = t('previewNotice.text');
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
