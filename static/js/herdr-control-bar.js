/*
 * Herdr control bar: buttons that send Herdr's prefix (Ctrl+B) and one key to
 * the active Herdr session, for actions a browser makes hard to type. Every
 * button sends a fixed byte sequence through the normal terminal input path;
 * nothing the user types and no new server event is involved.
 */
(function (root, factory) {
    const api = factory();
    if (typeof module === 'object' && module.exports) {
        module.exports = api;
    }
    if (root) {
        root.HerdrControlBar = api;
    }
}(typeof globalThis !== 'undefined' ? globalThis : this, function () {
    'use strict';

    const PREFIX = '\x02';
    const ACTIONS = Object.freeze([
        {id: 'prefix', bytes: PREFIX, label: 'Ctrl+B', labelKey: 'herdr.barPrefix', title: 'Send Ctrl+B', hint: 'Ctrl+B'},
        {id: 'splitRight', key: 'v', icon: 'vertical_split', labelKey: 'herdr.barSplitRight', title: 'Split right', hint: 'v'},
        {id: 'splitDown', key: '-', icon: 'horizontal_split', labelKey: 'herdr.barSplitDown', title: 'Split down', hint: '-'},
        {id: 'zoom', key: 'z', icon: 'fullscreen', labelKey: 'herdr.barZoom', title: 'Zoom pane', hint: 'z'},
        {id: 'previousPane', key: '\x1b[Z', icon: 'arrow_back', labelKey: 'herdr.barPreviousPane', title: 'Previous pane', hint: 'Shift+Tab'},
        {id: 'nextPane', key: '\t', icon: 'arrow_forward', labelKey: 'herdr.barNextPane', title: 'Next pane', hint: 'Tab'},
        {id: 'newTab', key: 'c', icon: 'tab', labelKey: 'herdr.barNewTab', title: 'New tab', hint: 'c'},
        {id: 'previousTab', key: 'p', icon: 'navigate_before', labelKey: 'herdr.barPreviousTab', title: 'Previous tab', hint: 'p'},
        {id: 'nextTab', key: 'n', icon: 'navigate_next', labelKey: 'herdr.barNextTab', title: 'Next tab', hint: 'n'},
        {id: 'workspaces', key: 'w', icon: 'dashboard', labelKey: 'herdr.barWorkspaces', title: 'Workspaces', hint: 'w'},
        {id: 'sidebar', key: 'b', icon: 'view_sidebar', labelKey: 'herdr.barSidebar', title: 'Toggle sidebar', hint: 'b'},
        {id: 'renamePane', key: 'P', icon: 'drive_file_rename_outline', labelKey: 'herdr.barRenamePane', title: 'Rename pane', hint: 'Shift+P'},
        {id: 'help', key: '?', icon: 'help_outline', labelKey: 'herdr.barHelp', title: 'Herdr help', hint: '?'},
        {id: 'settings', key: 's', icon: 'settings', labelKey: 'herdr.barSettings', title: 'Herdr settings', hint: 's'},
        {id: 'closePane', key: 'x', icon: 'close', labelKey: 'herdr.barClosePane', title: 'Close pane', hint: 'x', confirm: true},
    ].map(action => Object.freeze(action)));
    const BY_ID = new Map(ACTIONS.map(action => [action.id, action]));

    /** The exact bytes an action sends, or null for an unknown action. */
    function bytesFor(id) {
        const action = BY_ID.get(id);
        if (!action) return null;
        return action.bytes || PREFIX + action.key;
    }

    /** The key shown next to an action, as typed after the prefix. */
    function shortcutFor(action) {
        return action.id === 'prefix' ? action.hint : `Ctrl+B ${action.hint}`;
    }

    function create(options = {}) {
        const bar = options.bar || null;
        const toggleButton = options.toggleButton || null;
        const doc = options.document || bar?.ownerDocument || null;
        const activeSession = options.activeSession || (() => null);
        const send = options.send || (() => false);
        const focusTerminal = options.focusTerminal || (() => {});
        const confirm = options.confirm || (() => Promise.resolve(false));
        const onLayoutChange = options.onLayoutChange || (() => {});
        const storage = options.storage || null;
        const storageKey = options.storageKey || 'webssh.herdrControlBar';
        const translate = options.translate || (() => '');
        let shown = readPreference();
        let visible = false;
        let built = false;

        function t(key, fallback) {
            const text = translate(key);
            return text && text !== key ? text : fallback;
        }

        function readPreference() {
            try {
                return storage?.getItem(storageKey) !== 'off';
            } catch {
                return true;
            }
        }

        function writePreference() {
            try {
                storage?.setItem(storageKey, shown ? 'on' : 'off');
            } catch {
                // The choice still applies to this page without storage.
            }
        }

        /** The active session when it runs Herdr, otherwise null. */
        function herdrSession() {
            const session = activeSession();
            if (!session || typeof session.id !== 'string' || !session.id) return null;
            if (session.connected === false || session.useHerdr !== true || session.useTmux === true) return null;
            return session;
        }

        function build() {
            if (built || !bar || !doc) return;
            built = true;
            bar.setAttribute('role', 'toolbar');
            for (const action of ACTIONS) {
                const button = doc.createElement('button');
                button.type = 'button';
                button.className = 'tab-row-icon-btn herdr-control-btn';
                button.dataset.herdrAction = action.id;
                if (action.icon) {
                    const icon = doc.createElement('span');
                    icon.className = 'material-icons';
                    icon.setAttribute('aria-hidden', 'true');
                    icon.textContent = action.icon;
                    button.appendChild(icon);
                } else {
                    const label = doc.createElement('span');
                    label.className = 'herdr-control-key';
                    label.textContent = action.label;
                    button.appendChild(label);
                }
                // Keep the terminal focused while the pointer presses the button.
                button.addEventListener('mousedown', event => event.preventDefault());
                button.addEventListener('click', () => { run(action.id); });
                bar.appendChild(button);
            }
            toggleButton?.addEventListener('click', toggle);
        }

        function render() {
            build();
            if (bar) {
                bar.setAttribute('aria-label', t('herdr.barLabel', 'Herdr controls'));
                for (const button of bar.querySelectorAll('[data-herdr-action]')) {
                    const action = BY_ID.get(button.dataset.herdrAction);
                    const name = t(action.labelKey, action.title);
                    button.title = `${name} (${shortcutFor(action)})`;
                    button.setAttribute('aria-label', name);
                }
            }
            const session = herdrSession();
            const nowVisible = Boolean(session) && shown;
            if (toggleButton) {
                toggleButton.hidden = !session;
                toggleButton.setAttribute('aria-pressed', String(shown));
                toggleButton.classList.toggle('active', shown);
                const name = t('herdr.barToggle', 'Herdr controls');
                toggleButton.title = name;
                toggleButton.setAttribute('aria-label', name);
            }
            if (bar) bar.hidden = !nowVisible;
            if (nowVisible !== visible) {
                visible = nowVisible;
                onLayoutChange();
            }
        }

        async function run(id) {
            const action = BY_ID.get(id);
            const session = herdrSession();
            if (!action || !session) return false;
            if (action.confirm) {
                const accepted = await confirm({
                    title: t('herdr.barClosePaneTitle', 'Close Herdr pane'),
                    message: t('herdr.barClosePaneConfirm',
                        'Close the focused Herdr pane? Programs running in it are ended.'),
                    confirmLabel: t('herdr.barClosePane', 'Close pane'),
                });
                // The dialog may have taken long; act only on the same Herdr session.
                if (accepted !== true || herdrSession()?.id !== session.id) {
                    focusTerminal(session.id);
                    return false;
                }
            }
            const sent = await send(session.id, bytesFor(id));
            focusTerminal(session.id);
            return sent !== false;
        }

        function toggle() {
            shown = !shown;
            writePreference();
            render();
            const session = herdrSession();
            if (session) focusTerminal(session.id);
        }

        return {
            render,
            run,
            toggle,
            available: () => Boolean(herdrSession()),
            get shown() { return shown; },
        };
    }

    function install(win) {
        const doc = win.document;
        const bar = doc.getElementById('herdrControlBar');
        const toggleButton = doc.getElementById('herdrBarToggleBtn');
        if (!bar || !toggleButton) return null;
        // SessionManager is a page-wide const of session-manager.js, not a window property.
        const sessions = () => (typeof SessionManager !== 'undefined' ? SessionManager : win.SessionManager || null);
        const controller = create({
            bar,
            toggleButton,
            document: doc,
            storage: win.localStorage,
            storageKey: `webssh.herdrControlBar.${doc.body?.dataset.connectionHistoryScope || 'local'}`,
            translate: key => win.i18n?.t(key),
            activeSession: () => {
                const manager = sessions();
                const id = manager?.getActiveSession?.();
                const session = id ? manager.sessions?.[id] : null;
                return session ? {...session, id} : null;
            },
            send: (sessionId, data) => (win.SSHInput ? win.SSHInput.send(sessionId, data) : false),
            focusTerminal: sessionId => {
                const manager = win.TerminalManager;
                const key = manager?.sessionTerminals?.[sessionId]?.[0] || sessionId;
                manager?.terminals?.[key]?.focus();
            },
            confirm: request => (win.CommandSetManager?.confirmDialog
                ? win.CommandSetManager.confirmDialog({...request, danger: true})
                : Promise.resolve(win.confirm(request.message))),
            onLayoutChange: () => win.requestAnimationFrame(() => win.TerminalManager?.fitAllTerminals?.()),
        });
        win.addEventListener('session-workspace-change', controller.render);
        win.addEventListener('languageChanged', controller.render);
        controller.render();
        return controller;
    }

    if (typeof window !== 'undefined' && typeof document !== 'undefined' && document.addEventListener) {
        const start = () => { window.herdrControlBar = install(window); };
        if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', start);
        else start();
    }

    return {ACTIONS, PREFIX, bytesFor, create, install};
}));
