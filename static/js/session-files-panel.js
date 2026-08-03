(function (root, factory) {
    const api = factory();
    if (typeof module === 'object' && module.exports) {
        module.exports = api;
    }
    if (root && root.document) {
        root.SessionFilesPanelModule = api;
    }
}(typeof globalThis !== 'undefined' ? globalThis : this, function () {
    'use strict';
    const CONSUMER = 'session-panel';

    function normalizePath(value) {
        const raw = typeof value === 'string' ? value : '/';
        const segments = [];
        raw.replace(/\\/g, '/').split('/').forEach(segment => {
            if (!segment || segment === '.') return;
            if (segment === '..') {
                segments.pop();
                return;
            }
            segments.push(segment);
        });
        return `/${segments.join('/')}` || '/';
    }

    function joinPath(base, name) {
        return normalizePath(`${normalizePath(base)}/${name || ''}`);
    }

    function parentPath(path) {
        const normalized = normalizePath(path);
        if (normalized === '/') return '/';
        const segments = normalized.split('/').filter(Boolean);
        segments.pop();
        return segments.length ? `/${segments.join('/')}` : '/';
    }

    function validName(value) {
        return (
            typeof value === 'string'
            && value.trim().length > 0
            && value !== '.'
            && value !== '..'
            && !value.includes('/')
            && !value.includes('\\')
            && !value.includes('\0')
        );
    }

    function createController(options) {
        const socket = options.socket;
        const render = options.render || (() => {});
        const transferClient = options.transferClient;
        const filePreview = options.filePreview;
        let opened = false;
        let sessionId = null;
        let sessionMeta = {};
        let homePath = '/';
        let path = '/';
        let requestedPath = null;
        let files = [];
        let selectedIndex = -1;
        let status = 'closed';
        let error = null;

        function label() {
            const username = sessionMeta?.username;
            const host = sessionMeta?.host;
            return username && host ? `${username}@${host}` : '';
        }

        function renderState() {
            if (!opened && status !== 'closed') return;
            render({
                open: opened,
                status,
                sessionId,
                label: label(),
                homePath,
                path,
                files: files.slice(),
                selectedIndex,
                error,
            });
        }

        function requestHome() {
            if (!opened || !sessionId) return;
            status = 'loading';
            error = null;
            renderState();
            socket.emit('get_home_directory', {
                session_id: sessionId,
                consumer: CONSUMER,
            });
        }

        function navigate(nextPath) {
            if (!opened || !sessionId) return;
            path = normalizePath(nextPath);
            requestedPath = path;
            selectedIndex = -1;
            status = 'loading';
            error = null;
            renderState();
            socket.emit('list_directory', {
                session_id: sessionId,
                remote_path: path,
                consumer: CONSUMER,
            });
        }

        function refresh() {
            if (opened && sessionId) navigate(path);
        }

        function handleHome(data) {
            if (!opened || data?.consumer !== CONSUMER || data?.session_id !== sessionId) return;
            homePath = normalizePath(data.path);
            navigate(homePath);
        }

        function handleListing(data) {
            if (!opened || data?.consumer !== CONSUMER || data?.session_id !== sessionId) return;
            const responsePath = normalizePath(data.path);
            if (requestedPath !== responsePath) return;
            path = responsePath;
            files = Array.isArray(data.files) ? data.files.slice() : [];
            selectedIndex = -1;
            requestedPath = null;
            status = 'ready';
            error = null;
            renderState();
        }

        function handleMutation(data) {
            if (data?.consumer !== CONSUMER || data?.session_id !== sessionId) return;
            refresh();
        }

        function handleError(data) {
            if (
                !opened
                || data?.consumer !== CONSUMER
                || data?.session_id !== sessionId
            ) return;
            status = 'error';
            error = typeof data.error === 'string' ? data.error : 'SFTP unavailable';
            requestedPath = null;
            renderState();
        }

        const listeners = {
            home_directory: handleHome,
            directory_listing: handleListing,
            directory_created: handleMutation,
            file_renamed: handleMutation,
            item_deleted: handleMutation,
            error: handleError,
        };
        Object.entries(listeners).forEach(([event, handler]) => {
            socket.on(event, handler);
        });

        return {
            open(nextSessionId, meta = {}) {
                opened = true;
                this.follow(nextSessionId, meta);
            },

            follow(nextSessionId, meta = {}) {
                if (!opened) return;
                sessionId = typeof nextSessionId === 'string' && nextSessionId
                    ? nextSessionId
                    : null;
                sessionMeta = meta || {};
                homePath = '/';
                path = '/';
                requestedPath = null;
                files = [];
                selectedIndex = -1;
                error = null;
                status = sessionId ? 'loading' : 'disconnected';
                renderState();
                if (sessionId) requestHome();
            },

            close() {
                opened = false;
                sessionId = null;
                sessionMeta = {};
                files = [];
                selectedIndex = -1;
                requestedPath = null;
                status = 'closed';
                error = null;
                renderState();
            },

            isOpen() {
                return opened;
            },

            navigate,

            goHome() {
                navigate(homePath);
            },

            goParent() {
                navigate(parentPath(path));
            },

            refresh,

            select(index) {
                selectedIndex = Number.isInteger(index) && files[index] ? index : -1;
                renderState();
            },

            activate(index) {
                const item = files[index];
                if (!item || !sessionId) return;
                if (item.is_dir) {
                    navigate(joinPath(path, item.name));
                    return;
                }
                filePreview?.open(sessionId, joinPath(path, item.name), item.name);
            },

            upload(fileList) {
                if (!opened || !sessionId || !transferClient) return;
                Array.from(fileList || []).forEach(file => {
                    if (!file?.name) return;
                    transferClient.uploadFile(file, joinPath(path, file.name), sessionId);
                });
            },

            downloadSelected() {
                const item = files[selectedIndex];
                if (!item || item.is_dir || !sessionId || !transferClient) return;
                transferClient.downloadFile(joinPath(path, item.name), sessionId);
            },

            createFolder(name) {
                if (!validName(name) || !sessionId) return false;
                socket.emit('create_directory', {
                    session_id: sessionId,
                    remote_path: joinPath(path, name.trim()),
                    consumer: CONSUMER,
                });
                return true;
            },

            renameSelected(name) {
                const item = files[selectedIndex];
                if (!item || !validName(name) || !sessionId) return false;
                socket.emit('rename_file', {
                    session_id: sessionId,
                    old_path: joinPath(path, item.name),
                    new_path: joinPath(path, name.trim()),
                    consumer: CONSUMER,
                });
                return true;
            },

            deleteSelected() {
                const item = files[selectedIndex];
                if (!item || !sessionId) return false;
                socket.emit('delete_item', {
                    session_id: sessionId,
                    path: joinPath(path, item.name),
                    consumer: CONSUMER,
                });
                return true;
            },

            setDisconnected(disconnectedSessionId) {
                if (!opened || disconnectedSessionId !== sessionId) return;
                status = 'disconnected';
                requestedPath = null;
                files = [];
                selectedIndex = -1;
                renderState();
            },

            setError(message) {
                if (!opened) return;
                status = 'error';
                error = typeof message === 'string' ? message : 'SFTP unavailable';
                renderState();
            },

            destroy() {
                this.close();
                Object.entries(listeners).forEach(([event, handler]) => {
                    socket.off?.(event, handler);
                });
            },
        };
    }

    return {
        normalizePath,
        joinPath,
        parentPath,
        createController,
    };
}));
