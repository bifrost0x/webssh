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

    function createController(options = {}) {
        const manager = options.manager;
        const container = options.container;
        if (!manager) {
            throw new Error('SFTPFileManager instance is required');
        }
        if (typeof manager.openEmbedded !== 'function') {
            throw new Error('SFTPFileManager must support openEmbedded');
        }
        if (!container) {
            throw new Error('Embedded SFTP container is required');
        }

        return {
            open(sessionId, session = {}) {
                manager.openEmbedded(container, sessionId, session);
            },

            follow(sessionId, session = {}) {
                manager.followEmbedded(sessionId, session);
            },

            close() {
                manager.closeEmbedded();
            },

            isOpen() {
                return Boolean(manager.isEmbeddedOpen?.());
            },

            setDisconnected(sessionId) {
                manager.handleEmbeddedDisconnect?.(sessionId);
            },
        };
    }

    return { createController };
}));
