(function (root, factory) {
    const api = factory(root);
    if (typeof module === 'object' && module.exports) module.exports = api;
    if (root.document) root.TerminalFileBridge = api;
}(typeof globalThis !== 'undefined' ? globalThis : this, function (root) {
    'use strict';
    // A backslash ends single quoting in fish, so such names are not inserted as
    // typed input; the shell is not known reliably enough to quote them safely.
    function validPath(path) {
        return typeof path === 'string' && path.startsWith('/') && path.length <= 4096
            && !/[\x00-\x1f\x7f-\x9f\\]/.test(path);
    }
    function quotePath(path) {
        return validPath(path) ? `'${path.replace(/'/g, `'"'"'`)}'` : null;
    }
    function sourceSession(sourceId) {
        return typeof sourceId === 'string' && sourceId.startsWith('sftp-session:')
            ? sourceId.slice('sftp-session:'.length) : null;
    }
    async function insertPath(deps, sourceId, path) {
        const id = sourceSession(sourceId);
        const quoted = quotePath(path);
        if (!id || !quoted || !deps.getSession(id)?.connected) return false;
        return await deps.send(id, quoted) === true;
    }
    function sessionManager() {
        return typeof SessionManager !== 'undefined' ? SessionManager : root.SessionManager;
    }
    function terminalManager() {
        return typeof TerminalManager !== 'undefined' ? TerminalManager : root.TerminalManager;
    }
    function t(key, fallback) {
        const value = root.i18n?.t(key);
        return value && value !== key ? value : fallback;
    }
    let pending = null;
    function openSelection(sessionId) {
        const selection = terminalManager()?.terminals?.[sessionId]?.getSelection?.() || '';
        open(sessionId, selection);
    }
    function open(sessionId, path = '', mode = 'open') {
        const manager = sessionManager();
        const session = manager?.getSession(sessionId);
        const modal = root.document.getElementById('terminalFileModal');
        if (!modal) return;
        pending = { sessionId, mode };
        root.document.getElementById('terminalFileTitle').textContent = mode === 'insert'
            ? t('terminalFiles.insertPath', 'Insert path into terminal') : t('terminalFiles.openFolder', 'Open folder in Files');
        root.document.getElementById('terminalFileTarget').textContent = session
            ? `${session.username || ''}@${session.host || ''}:${session.port || 22}` : '—';
        const input = root.document.getElementById('terminalFilePath');
        input.value = path;
        input.readOnly = mode === 'insert';
        root.document.getElementById('terminalFileHint').textContent = mode === 'insert'
            ? t('terminalFiles.insertHint', 'Review the path for this session. It is quoted for POSIX shells and inserted without pressing Enter.')
            : t('terminalFiles.pathHint', 'Use the absolute path shown by SFTP. Shell aliases, ~ and relative paths are not expanded; chroot paths may differ.');
        const preview = root.document.getElementById('terminalFilePreview');
        preview.hidden = mode !== 'insert';
        preview.textContent = quotePath(path) || '';
        const submit = root.document.getElementById('terminalFileSubmit');
        submit.textContent = mode === 'insert' ? t('terminalFiles.insertPath', 'Insert path into terminal') : t('terminalFiles.openFolder', 'Open folder in Files');
        submit.disabled = !session?.connected;
        root.document.getElementById('terminalFileError').textContent = session?.connected ? ''
            : t('terminalFiles.unavailable', 'The source session is no longer connected. Reconnect it before continuing.');
        root.document.getElementById('terminalFileConnect').hidden = Boolean(session?.connected);
        root.document.querySelector('label[for="terminalFilePath"]').textContent = mode === 'insert'
            ? t('terminalFiles.path', 'Absolute path') : t('terminalFiles.folderPath', 'Absolute folder path');
        root.mobileAppShell?.closeMoreMenu?.();
        root.requestAnimationFrame(() => root.ModalManager.open(modal));
    }
    async function openFolder(sessionId, path) {
        const manager = sessionManager();
        const session = manager?.getSession(sessionId);
        if (!validPath(path) || !session?.connected) return false;
        // Select this precise session, not whichever session became active while the dialog was open.
        root.primaryWorkspaceController?.showWorkspaces();
        manager.switchSession(sessionId);
        const layout = root.workspaceLayoutController;
        if (!layout?.openContext('files', 'user')) return false;
        const files = root.getSFTPFileManager?.();
        const mount = root.document.getElementById('sessionFilesMount');
        if (!files || !mount) return false;
        if (!files.isEmbeddedOpen() || files.getPaneSourceId('left') !== `sftp-session:${sessionId}`) {
            await files.openEmbedded(mount, sessionId, session);
        }
        if (!manager.getSession(sessionId)?.connected
            || files.getPaneSourceId('left') !== `sftp-session:${sessionId}`) return false;
        await files.navigatePaneTo('left', path);
        return true;
    }
    function init() {
        const doc = root.document;
        const modal = doc.getElementById('terminalFileModal');
        if (!modal) return;
        const close = () => { pending = null; root.ModalManager.close(modal); };
        doc.querySelectorAll('[data-close-terminal-file]').forEach(button => button.addEventListener('click', close));
        doc.getElementById('terminalFileConnect').addEventListener('click', () => {
            close();
            root.primaryWorkspaceController?.showWorkspaces();
            const manager = sessionManager();
            manager?.showConnectionLauncher(manager.getActivePaneIndex());
        });
        doc.getElementById('terminalFileForm').addEventListener('submit', async event => {
            event.preventDefault();
            const request = pending;
            if (!request || request.busy) return;
            const current = () => request === pending && modal.classList.contains('show');
            const path = doc.getElementById('terminalFilePath').value;
            const error = doc.getElementById('terminalFileError');
            if (!validPath(path)) {
                error.textContent = t('terminalFiles.invalidPath', 'Enter an absolute path without line breaks or control characters.');
                return;
            }
            const manager = sessionManager();
            if (!manager.getSession(request.sessionId)?.connected) {
                error.textContent = t('terminalFiles.unavailable', 'The source session is no longer connected. Reconnect it before continuing.');
                doc.getElementById('terminalFileConnect').hidden = false;
                return;
            }
            const submit = doc.getElementById('terminalFileSubmit');
            request.busy = true;
            submit.disabled = true;
            try {
                if (request.mode === 'insert') {
                    const sent = await insertPath({getSession: id => manager.getSession(id), send: (id, text) => root.SSHInput.send(id, text)}, `sftp-session:${request.sessionId}`, path);
                    if (!current()) return;
                    if (!sent) {
                        error.textContent = t('terminalFiles.unavailable', 'The source session is no longer connected. Reconnect it before continuing.');
                        return;
                    }
                    root.ModalManager.close(modal);
                    root.primaryWorkspaceController?.showWorkspaces();
                    manager.switchSession(request.sessionId);
                    if (root.matchMedia('(max-width: 767px)').matches) root.workspaceLayoutController?.closeContext('user');
                    terminalManager()?.terminals?.[request.sessionId]?.focus();
                    const session = manager.getSession(request.sessionId);
                    root.showNotification?.(t('terminalFiles.inserted', 'Path inserted into {session}. Review the command before pressing Enter.')
                        .replace('{session}', `${session.username || ''}@${session.host}`), 'success');
                } else {
                    const opened = await openFolder(request.sessionId, path);
                    if (!current()) return;
                    if (opened) root.ModalManager.close(modal);
                    else error.textContent = t('terminalFiles.openFailed', 'Files could not be opened for this session. Check the connection and SFTP availability.');
                }
            } catch {
                if (current()) error.textContent = t('terminalFiles.openFailed', 'Files could not be opened for this session. Check the connection and SFTP availability.');
            } finally {
                request.busy = false;
                if (request === pending) submit.disabled = false;
            }
        });
    }
    if (root.document) root.document.addEventListener('DOMContentLoaded', init);
    return {validPath, quotePath, sourceSession, insertPath, open, openFolder, openSelection};
}));
