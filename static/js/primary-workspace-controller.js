/* Top-level application views that share the space below the global header. */
(function(root, factory) {
    const api = factory();
    if (typeof module !== 'undefined' && module.exports) module.exports = api;
    if (root) root.PrimaryWorkspaceController = api;
})(typeof window !== 'undefined' ? window : globalThis, function() {
    'use strict';

    const VIEW_NAV_IDS = Object.freeze({
        workspaces: 'workspaceNavBtn',
        files: 'fileTransferBtn',
        hosts: 'manageProfilesBtn',
        commands: 'commandLibraryBtn',
    });

    function createController(options = {}) {
        const browserWindow = options.window || window;
        const browserDocument = options.document || document;
        const origins = new WeakMap();
        let activeView = 'workspaces';
        let activeElement = null;
        let initialized = false;

        const getSurface = () => browserDocument.getElementById('primaryWorkspaceSurface');
        const getSessionRail = () => browserDocument.querySelector('.session-tabs-row');
        const getWorkspace = () => browserDocument.querySelector('.main-content');
        const getStatusBar = () => browserDocument.getElementById('workspaceStatusBar');

        function rememberOrigin(element) {
            if (!element || origins.has(element)) return;
            origins.set(element, {
                parent: element.parentNode,
                nextSibling: element.nextSibling,
                role: element.getAttribute('role'),
                ariaModal: element.getAttribute('aria-modal'),
                labelledBy: element.getAttribute('aria-labelledby'),
            });
        }

        function restoreAttribute(element, name, value) {
            if (value === null || value === undefined) element.removeAttribute(name);
            else element.setAttribute(name, value);
        }

        function restoreOrigin(element) {
            const origin = origins.get(element);
            if (!origin?.parent) {
                browserDocument.body.appendChild(element);
                return;
            }
            if (origin.nextSibling?.parentNode === origin.parent) {
                origin.parent.insertBefore(element, origin.nextSibling);
            } else {
                origin.parent.appendChild(element);
            }
        }

        function setNavigation(view) {
            Object.entries(VIEW_NAV_IDS).forEach(([name, id]) => {
                const button = browserDocument.getElementById(id);
                if (!button) return;
                const selected = name === view;
                button.classList.toggle('active', selected);
                if (selected) button.setAttribute('aria-current', 'page');
                else button.removeAttribute('aria-current');
            });
            browserDocument.querySelector('.header-buttons')?.classList.remove('is-open');
        }

        function hideElement(element) {
            if (!element) return;
            element.hidden = true;
            element.classList.remove('show');
            element.setAttribute('aria-hidden', 'true');
        }

        function showWorkspaceChrome(visible) {
            const sessionRail = getSessionRail();
            const workspace = getWorkspace();
            const statusBar = getStatusBar();
            if (sessionRail) sessionRail.hidden = !visible;
            if (workspace) workspace.hidden = !visible;
            if (statusBar) statusBar.hidden = !visible;
            const surface = getSurface();
            if (surface) surface.hidden = visible;
        }

        function deactivateFileManager(nextView) {
            if (activeView !== 'files' || nextView === 'files') return;
            const fileManager = browserWindow.sftpFileManager;
            if (fileManager?.displayMode === 'modal') {
                fileManager.close({restorePrimaryWorkspace: false});
            }
        }

        function scheduleWorkspaceFit() {
            const refresh = () => {
                browserWindow.dispatchEvent?.(new browserWindow.Event('resize'));
                browserWindow.workspaceLayoutController?.refresh?.();
                browserWindow.TerminalManager?.fitAll?.();
            };
            browserWindow.requestAnimationFrame?.(() => {
                browserWindow.requestAnimationFrame?.(refresh);
            });
        }

        function showWorkspaces(options = {}) {
            if (!options.skipFileManagerClose) deactivateFileManager('workspaces');
            hideElement(activeElement);
            activeElement = null;
            activeView = 'workspaces';
            browserDocument.body.dataset.primaryWorkspace = 'workspaces';
            showWorkspaceChrome(true);
            setNavigation('workspaces');
            scheduleWorkspaceFit();
            browserWindow.dispatchEvent?.(new browserWindow.CustomEvent(
                'primary-workspace-change',
                {detail: {view: 'workspaces'}},
            ));
            return true;
        }

        function open(view, element) {
            if (!['files', 'hosts', 'commands'].includes(view) || !element) return false;
            const surface = getSurface();
            if (!surface) return false;

            deactivateFileManager(view);
            if (activeElement && activeElement !== element) hideElement(activeElement);

            rememberOrigin(element);
            if (browserWindow.ModalManager?.activeModal === element) {
                browserWindow.ModalManager.activeModal = null;
            }
            surface.appendChild(element);
            element.classList.add('primary-workspace-view', `primary-workspace-view-${view}`);
            element.dataset.primaryWorkspaceView = view;
            element.setAttribute('role', 'region');
            element.removeAttribute('aria-modal');
            element.hidden = false;
            element.classList.add('show');
            element.setAttribute('aria-hidden', 'false');

            activeView = view;
            activeElement = element;
            browserDocument.body.dataset.primaryWorkspace = view;
            showWorkspaceChrome(false);
            surface.hidden = false;
            setNavigation(view);
            browserWindow.dispatchEvent?.(new browserWindow.CustomEvent(
                'primary-workspace-change',
                {detail: {view}},
            ));
            return true;
        }

        function release(element) {
            if (!element?.classList.contains('primary-workspace-view')) return false;
            if (activeElement === element) showWorkspaces();
            const origin = origins.get(element) || {};
            element.classList.remove(
                'primary-workspace-view',
                'primary-workspace-view-files',
                'primary-workspace-view-hosts',
                'primary-workspace-view-commands',
            );
            delete element.dataset.primaryWorkspaceView;
            element.hidden = false;
            restoreAttribute(element, 'role', origin.role);
            restoreAttribute(element, 'aria-modal', origin.ariaModal);
            restoreAttribute(element, 'aria-labelledby', origin.labelledBy);
            restoreOrigin(element);
            return true;
        }

        function close(element) {
            if (!isElementActive(element)) return false;
            return showWorkspaces();
        }

        function isElementActive(element) {
            return Boolean(element && activeElement === element && activeView !== 'workspaces');
        }

        function init() {
            if (initialized) return controller;
            initialized = true;
            browserDocument.getElementById('workspaceNavBtn')?.addEventListener(
                'click',
                () => showWorkspaces(),
            );
            browserDocument.body.dataset.primaryWorkspace = 'workspaces';
            showWorkspaceChrome(true);
            setNavigation('workspaces');
            return controller;
        }

        const controller = {
            init,
            open,
            close,
            release,
            showWorkspaces,
            isElementActive,
            getActiveView: () => activeView,
        };
        return controller;
    }

    return {createController};
});
