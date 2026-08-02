const FileTransferManager = {
    transferClient: null,
    ownedTransfers: new Set(),

    t(key, fallback) {
        const translated = window.i18n && i18n.t ? i18n.t(key) : null;
        return translated && translated !== key ? translated : fallback;
    },

    getTransferClient() {
        if (!window.socket || !window.BinaryTransferClient) return null;
        const client = window.BinaryTransferClient.forSocket(window.socket);
        if (this.transferClient === client) return client;

        this.transferClient = client;
        client.on('start', data => {
            if (!this.ownedTransfers.has(data.transferId)) return;
            window.showNotification?.(
                `${this.t('fm.uploading', 'Uploading')} ${data.filename}...`,
                'info'
            );
        });
        client.on('complete', data => {
            if (!this.ownedTransfers.delete(data.transferId)) return;
            window.showNotification?.(
                `${this.t('fm.uploadComplete', 'Upload complete')}: ${data.filename}`,
                'success'
            );
        });
        client.on('error', data => {
            if (!this.ownedTransfers.delete(data.transferId)) return;
            window.showNotification?.(
                `${this.t('fm.transferFailed', 'Transfer failed')}: ${data.filename}`,
                'error'
            );
        });
        client.on('cancel', data => {
            if (!this.ownedTransfers.delete(data.transferId)) return;
            window.showNotification?.(
                this.t('fm.uploadCancelled', 'Upload cancelled'),
                'warning'
            );
        });
        return client;
    },

    uploadFile(sessionId, file, remotePath) {
        const client = this.getTransferClient();
        if (!client) return null;
        const transferId = client.uploadFile(file, remotePath, sessionId);
        this.ownedTransfers.add(transferId);
        return transferId;
    },
};

if (typeof module !== 'undefined' && module.exports) {
    module.exports = FileTransferManager;
}
