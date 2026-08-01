const FileTransferManager = {
    transferClient: null,
    ownedTransfers: new Set(),

    getTransferClient() {
        if (!window.socket || !window.BinaryTransferClient) return null;
        const client = window.BinaryTransferClient.forSocket(window.socket);
        if (this.transferClient === client) return client;

        this.transferClient = client;
        client.on('start', data => {
            if (!this.ownedTransfers.has(data.transferId)) return;
            window.showNotification?.(`Uploading ${data.filename}...`, 'info');
        });
        client.on('complete', data => {
            if (!this.ownedTransfers.delete(data.transferId)) return;
            window.showNotification?.(`Uploaded: ${data.filename}`, 'success');
        });
        client.on('error', data => {
            if (!this.ownedTransfers.delete(data.transferId)) return;
            window.showNotification?.(`Upload failed: ${data.filename}`, 'error');
        });
        client.on('cancel', data => {
            if (!this.ownedTransfers.delete(data.transferId)) return;
            window.showNotification?.('Upload cancelled', 'warning');
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
