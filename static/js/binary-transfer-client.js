const TRANSFER_FAILURES = Object.freeze({
    PERMISSION_DENIED: 'Permission denied for this file operation.',
    CONFLICT: 'A file or folder already exists at the destination.',
    NOT_FOUND: 'The requested file or folder was not found.',
    SHARE_UNAVAILABLE: 'The SMB share is unavailable.',
    TIMEOUT: 'The file operation timed out.',
    SOURCE_UNAVAILABLE: 'The file source is no longer available. Reconnect and try again.',
    LIMIT_EXCEEDED: 'The transfer exceeds the configured limit.',
    CANCELLED: 'The transfer was cancelled.',
    ATOMIC_REPLACE_UNAVAILABLE: 'Safe overwrite is unavailable for this destination.',
    TRANSFER_UNAVAILABLE: 'The transfer could not be completed.',
});

class PublicTransferError extends Error {
    constructor(failure) {
        super(failure.error);
        this.name = 'PublicTransferError';
        this.errorCode = failure.errorCode;
        this.retryable = failure.retryable;
        this.limitKind = failure.limitKind;
        this.limitBytes = failure.limitBytes;
        this.actualBytes = failure.actualBytes;
    }
}

class BinaryTransferClient {
    static forSocket(socket) {
        if (!socket || (typeof socket !== 'object' && typeof socket !== 'function')) {
            throw new TypeError('A Socket.IO client is required');
        }
        this.socketClients ||= new WeakMap();
        if (!this.socketClients.has(socket)) {
            this.socketClients.set(socket, new this(socket));
        }
        return this.socketClients.get(socket);
    }

    constructor(socket) {
        this.socket = socket;
        this.activeTransfers = new Map();
        this.eventListeners = new Map();
        this.operationQueue = [];
        this.activeOperation = null;
        this.setupSocketListeners();
    }

    generateId() {
        return `transfer_${Date.now()}_${Math.random().toString(36).slice(2)}`;
    }

    normalizeSourceId(sourceId) {
        if (typeof sourceId !== 'string' || !sourceId.trim()) return null;
        const normalized = sourceId.trim();
        return normalized.includes(':')
            ? normalized
            : `sftp-session:${normalized}`;
    }

    prepare(direction, sourceId, remotePath, options = {}) {
        const canonicalSourceId = this.normalizeSourceId(sourceId);
        const requestId = this.generateId();
        return new Promise((resolve, reject) => {
            this.socket.emit('prepare_transfer', {
                direction,
                source_id: canonicalSourceId,
                remote_path: remotePath,
                request_id: requestId,
                ...options,
            }, acknowledgement => {
                if (!acknowledgement || !acknowledgement.success) {
                    reject(new PublicTransferError(
                        this.normalizeFailure(acknowledgement),
                    ));
                    return;
                }
                resolve(acknowledgement);
            });
        });
    }

    csrfHeaders() {
        const token = document.querySelector('meta[name="csrf-token"]')?.content;
        return token ? { 'X-CSRFToken': token } : {};
    }

    normalizeFailure(payload = {}) {
        const errorCode = Object.hasOwn(TRANSFER_FAILURES, payload?.error_code)
            ? payload.error_code
            : Object.hasOwn(TRANSFER_FAILURES, payload?.errorCode)
                ? payload.errorCode
                : 'TRANSFER_UNAVAILABLE';
        const supplied = typeof payload?.error === 'string'
            && payload.error.length > 0
            && payload.error.length <= 512
            && !/[\x00-\x1f\x7f]/.test(payload.error)
            ? payload.error
            : null;
        const failure = {
            errorCode,
            error: supplied || TRANSFER_FAILURES[errorCode],
            retryable: payload?.retryable === true,
        };
        const limitKind = payload?.limit_kind ?? payload?.limitKind;
        const limitBytes = payload?.limit_bytes ?? payload?.limitBytes;
        const actualBytes = payload?.actual_bytes ?? payload?.actualBytes;
        if (
            errorCode === 'LIMIT_EXCEEDED'
            && ['upload', 'download', 'archive', 'remote_transfer'].includes(limitKind)
            && Number.isSafeInteger(limitBytes)
            && limitBytes >= 0
            && (
                actualBytes === undefined
                || actualBytes === null
                || (Number.isSafeInteger(actualBytes) && actualBytes >= 0)
            )
        ) {
            failure.limitKind = limitKind;
            failure.limitBytes = limitBytes;
            if (actualBytes !== undefined && actualBytes !== null) {
                failure.actualBytes = actualBytes;
            }
        }
        return failure;
    }

    knownLimitFailure(kind, actualBytes) {
        const key = {
            upload: 'uploadBytes',
            download: 'downloadBytes',
            archive: 'archiveBytes',
            remote_transfer: 'remoteTransferBytes',
        }[kind];
        const limits = typeof window !== 'undefined'
            ? window.WEBSSH_TRANSFER_LIMITS
            : null;
        const limitBytes = key ? limits?.[key] : null;
        if (
            !Number.isSafeInteger(actualBytes)
            || actualBytes < 0
            || !Number.isSafeInteger(limitBytes)
            || limitBytes < 0
            || actualBytes <= limitBytes
        ) return null;
        return this.normalizeFailure({
            error_code: 'LIMIT_EXCEEDED',
            limit_kind: kind,
            limit_bytes: limitBytes,
            actual_bytes: actualBytes,
        });
    }

    async responseFailure(response) {
        let payload = null;
        try {
            payload = await response?.json?.();
        } catch {
            // Non-JSON proxy and framework failures use the safe fallback.
        }
        return new PublicTransferError(this.normalizeFailure(payload));
    }

    createTransfer(properties, withDone = false) {
        const transfer = {
            id: this.generateId(),
            transferred: 0,
            status: 'queued',
            terminalized: false,
            slotReleased: false,
            prepareStarted: false,
            cancelRequested: false,
            cancelSent: false,
            ...properties,
        };
        if (withDone) {
            transfer.done = new Promise((resolve, reject) => {
                transfer.resolveDone = resolve;
                transfer.rejectDone = reject;
            });
        }
        this.activeTransfers.set(transfer.id, transfer);
        return transfer;
    }

    enqueue(transfer, operation) {
        transfer.operation = operation;
        this.operationQueue.push(transfer);
        this.drainQueue();
    }

    drainQueue() {
        if (this.activeOperation) return;
        while (this.operationQueue.length > 0) {
            const transfer = this.operationQueue.shift();
            if (transfer.terminalized) {
                this.releaseSlot(transfer);
                continue;
            }
            this.activeOperation = transfer;
            Promise.resolve()
                .then(() => transfer.operation())
                .catch(error => {
                    if (!transfer.terminalized) this.failOperation(transfer, error);
                });
            return;
        }
    }

    resolveDefaultUploadConflict(details = {}) {
        const browserWindow = typeof window !== 'undefined' ? window : null;
        const fileManager = browserWindow?.sftpFileManager;
        if (typeof fileManager?.resolveUploadConflict === 'function') {
            return fileManager.resolveUploadConflict(details);
        }
        if (typeof browserWindow?.confirm !== 'function') {
            return 'cancel';
        }
        const filename = typeof details.filename === 'string'
            && details.filename.trim()
            ? details.filename
            : 'destination';
        const replace = browserWindow.confirm(
            `A file or folder named "${filename}" already exists. `
            + 'Select OK to overwrite it, or Cancel to skip this upload.',
        );
        return replace ? 'replace' : 'skip';
    }

    uploadFile(file, remotePath, sourceId, options = {}) {
        const transfer = this.createTransfer({
            type: 'upload',
            filename: file.name,
            size: file.size,
            sourceId: this.normalizeSourceId(sourceId),
            remotePath,
            controller: new AbortController(),
            onConflict: typeof options.onConflict === 'function'
                ? options.onConflict
                : details => this.resolveDefaultUploadConflict(details),
        });
        this.enqueue(transfer, () => this.upload(transfer, file));
        return transfer.id;
    }

    async upload(transfer, file) {
        if (transfer.terminalized) {
            this.releaseSlot(transfer);
            return;
        }
        try {
            const preflightFailure = this.knownLimitFailure('upload', file.size);
            if (preflightFailure) throw new PublicTransferError(preflightFailure);
            let conflictPolicy = 'error';
            while (!transfer.terminalized) {
                transfer.status = 'preparing';
                transfer.prepareStarted = true;
                transfer.serverFinished = false;
                const prepared = await this.prepare(
                    'upload',
                    transfer.sourceId,
                    transfer.remotePath,
                    { conflict_policy: conflictPolicy },
                );
                transfer.transferId = prepared.transfer_id;
                if (transfer.terminalized || transfer.cancelRequested) {
                    this.cancelPreparedTransfer(transfer);
                    return;
                }
                transfer.status = 'uploading';
                if (!transfer.started) {
                    transfer.started = true;
                    this.emit('start', {
                        transferId: transfer.id,
                        type: 'upload',
                        filename: transfer.filename,
                    });
                }
                const response = await fetch(prepared.url, {
                    method: 'POST',
                    body: file,
                    credentials: 'same-origin',
                    headers: this.csrfHeaders(),
                    signal: transfer.controller.signal,
                });
                if (response.ok) {
                    this.complete(transfer);
                    return;
                }
                const failure = await this.responseFailure(response);
                if (
                    failure.errorCode !== 'CONFLICT'
                    || conflictPolicy === 'replace'
                    || !transfer.onConflict
                ) {
                    throw failure;
                }
                const decision = await transfer.onConflict({
                    filename: transfer.filename,
                    remotePath: transfer.remotePath,
                    sourceId: transfer.sourceId,
                    error: failure.message,
                    errorCode: failure.errorCode,
                });
                if (decision === 'replace') {
                    conflictPolicy = 'replace';
                    transfer.transferId = null;
                    transfer.serverFinished = false;
                    continue;
                }
                if (decision === 'skip') {
                    this.finalize(transfer, 'skipped');
                    return;
                }
                this.finalize(transfer, 'cancelled');
                return;
            }
        } catch (error) {
            if (transfer.terminalized) {
                if (!transfer.transferId) this.releaseSlot(transfer);
                return;
            }
            if (transfer.cancelRequested) {
                if (!transfer.transferId) this.finalize(transfer, 'cancelled');
                return;
            }
            this.failOperation(transfer, error);
        }
    }

    downloadFile(remotePath, sourceId, options = {}) {
        const filename = remotePath.split('/').pop() || 'download';
        const transfer = this.createTransfer({
            type: 'download',
            filename,
            sourceId: this.normalizeSourceId(sourceId),
            remotePath,
            expectedSize: options.size,
        });
        this.enqueue(transfer, () => this.download(transfer));
        return transfer.id;
    }

    downloadFolder(remotePath, sourceId) {
        const folder = remotePath.replace(/\/$/, '').split('/').pop() || 'download';
        const transfer = this.createTransfer({
            type: 'download',
            filename: `${folder}.zip`,
            sourceId: this.normalizeSourceId(sourceId),
            remotePath,
            archive: true,
        });
        this.enqueue(transfer, () => this.download(transfer));
        return transfer.id;
    }

    downloadFileToWritable(remotePath, sourceId, sinkFactory) {
        const filename = remotePath.split('/').pop() || 'download';
        const transfer = this.createTransfer({
            type: 'download',
            filename,
            sourceId: this.normalizeSourceId(sourceId),
            remotePath,
            controller: new AbortController(),
            writableDestination: true,
        }, true);
        this.enqueue(transfer, () => this.downloadToWritable(transfer, sinkFactory));
        return { id: transfer.id, done: transfer.done };
    }

    async download(transfer) {
        if (transfer.terminalized) {
            this.releaseSlot(transfer);
            return;
        }
        try {
            const preflightFailure = this.knownLimitFailure(
                'download', transfer.expectedSize,
            );
            if (preflightFailure) throw new PublicTransferError(preflightFailure);
            transfer.status = 'preparing';
            transfer.prepareStarted = true;
            const prepared = await this.prepare(
                'download', transfer.sourceId, transfer.remotePath,
                transfer.archive ? { archive: true } : {},
            );
            transfer.transferId = prepared.transfer_id;
            if (transfer.terminalized || transfer.cancelRequested) {
                this.cancelPreparedTransfer(transfer);
                return;
            }
            transfer.status = 'downloading';
            this.emit('start', {
                transferId: transfer.id,
                type: 'download',
                filename: transfer.filename,
            });
            // Native navigation keeps the response out of JS memory. The
            // transfer_finished control event terminalizes this queue slot.
            const anchor = document.createElement('a');
            anchor.href = prepared.url;
            anchor.download = '';
            anchor.style.display = 'none';
            document.body.appendChild(anchor);
            anchor.click();
            anchor.remove();
        } catch (error) {
            if (transfer.terminalized) {
                if (!transfer.transferId) this.releaseSlot(transfer);
                return;
            }
            if (transfer.cancelRequested) {
                if (!transfer.transferId) this.finalize(transfer, 'cancelled');
                return;
            }
            this.failOperation(transfer, error);
        }
    }

    async downloadToWritable(transfer, sinkFactory) {
        let writable;
        if (transfer.terminalized) {
            this.releaseSlot(transfer);
            return;
        }
        try {
            transfer.status = 'preparing';
            transfer.prepareStarted = true;
            const prepared = await this.prepare(
                'download', transfer.sourceId, transfer.remotePath,
            );
            transfer.transferId = prepared.transfer_id;
            if (transfer.terminalized || transfer.cancelRequested) {
                this.cancelPreparedTransfer(transfer);
                return;
            }
            transfer.status = 'downloading';
            this.emit('start', {
                transferId: transfer.id,
                type: 'download',
                filename: transfer.filename,
            });
            const response = await fetch(prepared.url, {
                credentials: 'same-origin',
                signal: transfer.controller.signal,
            });
            if (!response.ok || !response.body) {
                throw await this.responseFailure(response);
            }
            writable = await sinkFactory();
            await response.body.pipeTo(writable, {
                signal: transfer.controller.signal,
            });
            if (!transfer.terminalized) this.complete(transfer);
        } catch (error) {
            try {
                await writable?.abort?.();
            } catch {
                // pipeTo() may already have aborted the destination.
            }
            if (transfer.terminalized) {
                if (!transfer.transferId) this.releaseSlot(transfer);
                return;
            }
            if (transfer.cancelRequested) {
                if (!transfer.transferId) this.finalize(transfer, 'cancelled');
                return;
            }
            transfer.controller.abort();
            this.failOperation(transfer, error);
        }
    }

    cancelTransfer(localId) {
        const transfer = this.activeTransfers.get(localId);
        if (!transfer || transfer.terminalized || transfer.cancelRequested) return false;
        transfer.cancelRequested = true;
        transfer.controller?.abort();

        if (!transfer.prepareStarted || transfer.serverFinished) {
            this.finalize(transfer, 'cancelled');
            return true;
        }

        transfer.status = 'cancelling';
        this.emit('cancelling', { transferId: transfer.id });
        if (transfer.transferId) this.cancelPreparedTransfer(transfer);
        return true;
    }

    cancelPreparedTransfer(transfer) {
        if (!transfer.transferId) return;
        if (transfer.cancelSent) return;
        transfer.cancelSent = true;
        try {
            this.socket.emit('cancel_transfer',
                { transfer_id: transfer.transferId },
                acknowledgement => {
                    if (transfer.terminalized) {
                        this.releaseSlot(transfer);
                        return;
                    }
                    if (acknowledgement?.state !== 'unavailable') return;
                    const failure = this.normalizeFailure({
                        error_code: 'TRANSFER_UNAVAILABLE',
                        error: 'Cancellation could not be confirmed. Refresh the destination before retrying.',
                    });
                    this.finalize(transfer, 'error', {
                        ...failure,
                        rejection: new PublicTransferError(failure),
                    });
                },
            );
        } catch {
            if (transfer.terminalized) {
                this.releaseSlot(transfer);
                return;
            }
            const failure = this.normalizeFailure({
                error_code: 'TRANSFER_UNAVAILABLE',
                error: 'Cancellation could not be sent. Refresh the destination before retrying.',
            });
            this.finalize(transfer, 'error', {
                ...failure,
                rejection: new PublicTransferError(failure),
            });
        }
    }

    failOperation(transfer, error) {
        const failure = error instanceof PublicTransferError
            ? {
                error: error.message,
                errorCode: error.errorCode,
                retryable: error.retryable,
                limitKind: error.limitKind,
                limitBytes: error.limitBytes,
                actualBytes: error.actualBytes,
            }
            : this.normalizeFailure();
        const deferRelease = Boolean(
            transfer === this.activeOperation
            && transfer.transferId
            && !transfer.serverFinished,
        );
        this.finalize(transfer, 'error', {
            ...failure,
            rejection: error,
            deferRelease,
        });
        if (deferRelease) this.cancelPreparedTransfer(transfer);
    }

    setupSocketListeners() {
        this.socket.on('transfer_progress', data => {
            for (const transfer of this.activeTransfers.values()) {
                if (transfer.transferId !== data.transfer_id || transfer.terminalized) continue;
                transfer.transferred = data.transferred;
                transfer.total = data.total;
                transfer.percent = data.total
                    ? Math.floor((data.transferred / data.total) * 100)
                    : 0;
                this.emit('progress', {
                    transferId: transfer.id,
                    ...data,
                    percent: transfer.percent,
                });
            }
        });
        this.socket.on('transfer_finished', data => {
            for (const transfer of this.activeTransfers.values()) {
                if (transfer.transferId !== data.transfer_id) continue;
                if (transfer.terminalized) return;
                if (
                    transfer.writableDestination
                    && data.status === 'completed'
                ) {
                    transfer.serverFinished = true;
                    return;
                }
                if (data.status === 'completed') {
                    this.complete(transfer);
                } else if (data.status === 'cancelled') {
                    transfer.controller?.abort();
                    this.finalize(transfer, 'cancelled');
                } else {
                    const failure = this.normalizeFailure(data);
                    if (
                        failure.errorCode === 'CONFLICT'
                        && transfer.type === 'upload'
                        && transfer.onConflict
                    ) {
                        transfer.serverFinished = true;
                        transfer.serverFailure = failure;
                        return;
                    }
                    transfer.controller?.abort();
                    this.finalize(transfer, 'error', {
                        ...failure,
                        rejection: new PublicTransferError(failure),
                    });
                }
                return;
            }
        });
    }

    complete(transfer) {
        this.finalize(transfer, 'completed');
    }

    finalize(transfer, status, options = {}) {
        if (transfer.terminalized) return false;
        transfer.terminalized = true;
        transfer.status = status;

        if (status === 'completed') {
            transfer.percent = 100;
            this.emit('complete', {
                transferId: transfer.id,
                type: transfer.type,
                filename: transfer.filename,
            });
            transfer.resolveDone?.(true);
        } else if (status === 'cancelled') {
            this.emit('cancel', { transferId: transfer.id });
            transfer.resolveDone?.(false);
        } else if (status === 'skipped') {
            this.emit('skip', { transferId: transfer.id });
            transfer.resolveDone?.(false);
        } else {
            transfer.error = options.error;
            transfer.errorCode = options.errorCode;
            transfer.retryable = options.retryable === true;
            const event = {
                transferId: transfer.id,
                filename: transfer.filename,
                error: options.error,
                errorCode: options.errorCode,
                retryable: options.retryable === true,
            };
            if (options.limitKind !== undefined) {
                event.limitKind = options.limitKind;
                event.limitBytes = options.limitBytes;
                if (options.actualBytes !== undefined) {
                    event.actualBytes = options.actualBytes;
                }
            }
            this.emit('error', event);
            transfer.rejectDone?.(
                options.rejection instanceof Error
                    ? options.rejection
                    : new Error(options.error || 'Transfer unavailable'),
            );
        }

        if (!options.deferRelease) this.releaseSlot(transfer);
        return true;
    }

    releaseSlot(transfer) {
        if (transfer.slotReleased) return;
        transfer.slotReleased = true;
        this.activeTransfers.delete(transfer.id);
        this.operationQueue = this.operationQueue.filter(item => item !== transfer);
        if (this.activeOperation === transfer) this.activeOperation = null;
        Promise.resolve().then(() => this.drainQueue());
    }

    on(event, callback) {
        if (!this.eventListeners.has(event)) this.eventListeners.set(event, []);
        this.eventListeners.get(event).push(callback);
    }

    emit(event, data) {
        for (const callback of this.eventListeners.get(event) || []) {
            try {
                callback(data);
            } catch {
                console.error('Transfer listener failed');
            }
        }
    }
}

if (typeof window !== 'undefined') window.BinaryTransferClient = BinaryTransferClient;
if (typeof module !== 'undefined' && module.exports) module.exports = BinaryTransferClient;
