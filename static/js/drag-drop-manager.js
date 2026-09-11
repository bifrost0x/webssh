
class DragDropManager {
  constructor({sessionManager} = {}) {
    this.sessionManager = sessionManager;
    this.overlay = null;
    this.dropZones = new Set();
    this.isDragging = false;
    this.dragCounter = 0;
    this.transferClient = null;
    this.pendingDrop = null;
    this.directoryRequestSequence = 0;

    this.handleDragEnter = this.handleDragEnter.bind(this);
    this.handleDragOver = this.handleDragOver.bind(this);
    this.handleDragLeave = this.handleDragLeave.bind(this);
    this.handleDrop = this.handleDrop.bind(this);
  }

  init() {
    this.createOverlay();
    this.attachGlobalListeners();
    this.setupUploadDialog();

    if (window.socket && window.BinaryTransferClient) {
      this.transferClient = window.BinaryTransferClient.forSocket(window.socket);
    }
  }

  createOverlay() {
    this.overlay = document.createElement('div');
    this.overlay.className = 'drag-drop-overlay';
    this.overlay.innerHTML = `
      <div class="drag-drop-overlay__content">
        <div class="drag-drop-overlay__icon">
          <span class="material-icons">cloud_upload</span>
        </div>
        <div class="drag-drop-overlay__text">Drop files to upload</div>
        <div class="drag-drop-overlay__hint" id="dragDropHint">
          Files will be uploaded to the current directory
        </div>
      </div>
    `;

    this.overlay.style.cssText = `
      position: fixed;
      inset: 0;
      background: rgba(0, 0, 0, 0.8);
      backdrop-filter: blur(8px);
      display: none;
      align-items: center;
      justify-content: center;
      z-index: 999999;
      pointer-events: none;
    `;

    const style = document.createElement('style');
    style.textContent = `
      .drag-drop-overlay__content {
        text-align: center;
        color: white;
        pointer-events: none;
      }

      .drag-drop-overlay__icon {
        font-size: 120px;
        margin-bottom: 24px;
        animation: bounce 0.6s ease-in-out infinite alternate;
      }

      .drag-drop-overlay__icon .material-icons {
        font-size: inherit;
        color: var(--accent-primary, #58a6ff);
      }

      .drag-drop-overlay__text {
        font-size: 32px;
        font-weight: 500;
        margin-bottom: 12px;
        text-shadow: 0 2px 8px rgba(0, 0, 0, 0.5);
      }

      .drag-drop-overlay__hint {
        font-size: 16px;
        opacity: 0.8;
        text-shadow: 0 1px 4px rgba(0, 0, 0, 0.5);
      }

      @keyframes bounce {
        from { transform: translateY(0); }
        to { transform: translateY(-20px); }
      }

      .drag-drop-zone-highlight {
        outline: 3px dashed var(--accent-primary, #58a6ff) !important;
        outline-offset: -3px;
        background: rgba(138, 180, 248, 0.1) !important;
      }
    `;

    document.head.appendChild(style);
    document.body.appendChild(this.overlay);
  }

  attachGlobalListeners() {
    document.addEventListener('dragenter', this.handleDragEnter);
    document.addEventListener('dragleave', this.handleDragLeave);
    document.addEventListener('dragover', this.handleDragOver);
    document.addEventListener('drop', this.handleDrop);

    document.addEventListener('dragend', () => {
      this.reset();
    });

    document.addEventListener('mouseup', () => {
      setTimeout(() => {
        if (this.dragCounter > 0) {
          this.reset();
        }
      }, 100);
    });
  }

  handleDragEnter(e) {
    if (!this.isFileDrag(e)) return;

    this.dragCounter++;

    if (this.dragCounter === 1) {
      this.showOverlay();
      this.updateOverlayMessage();
    }
  }

  handleDragOver(e) {
    if (!this.isFileDrag(e)) return;

    e.preventDefault();
    e.dataTransfer.dropEffect = 'copy';

    const items = e.dataTransfer?.items;
    if (items && items.length > 0) {
      const count = items.length;
      const hint = this.overlay.querySelector('#dragDropHint');
      if (hint) {
        const plural = count > 1 ? 's' : '';
        hint.textContent = `${count} file${plural} ready to upload`;
      }
    }
  }

  handleDragLeave(e) {
    if (!this.isFileDrag(e)) return;

    this.dragCounter--;

    if (this.dragCounter === 0) {
      this.hideOverlay();
    }
  }

  t(key, fallback) {
    return window.i18n?.t(key, fallback) || fallback;
  }

  setupUploadDialog() {
    const modal = document.getElementById('dropUploadModal');
    const close = () => {
      this.pendingDrop = null;
      window.ModalManager.close(modal);
    };
    document.getElementById('cancelDropUploadBtn')?.addEventListener('click', close);
    document.getElementById('closeDropUploadModal')?.addEventListener('click', close);
    document.getElementById('dropUploadForm')?.addEventListener('submit', async event => {
      event.preventDefault();
      const pending = this.pendingDrop;
      const path = document.getElementById('dropUploadPath').value.trim();
      if (!pending || !path) return;
      close();
      try {
        this.assertConnected(pending.session);
        await this.processEntries(pending.entries, pending.session, path);
      } catch (error) {
        window.showNotification?.(error.message, 'error');
      }
    });
    document.addEventListener('keydown', event => {
      if (event.key === 'Escape' && modal?.classList.contains('show')) this.pendingDrop = null;
    });
    modal?.addEventListener('click', event => {
      if (event.target === modal) this.pendingDrop = null;
    });
  }

  handleDrop(e) {
    if (!this.isFileDrag(e)) return;
    e.preventDefault();
    e.stopPropagation();
    this.hideOverlay();
    const session = this.getActiveSession();
    if (!session) return this.showQuickConnectDialog();

    // Read DataTransfer while the drop event is active; browsers protect it later.
    const items = Array.from(e.dataTransfer?.items || []).filter(item => item.kind === 'file');
    const entries = items.length ? items.map(item => {
      const entry = item.webkitGetAsEntry?.();
      return entry ? {entry} : {file: item.getAsFile?.()};
    }).filter(item => item.entry || item.file)
      : Array.from(e.dataTransfer?.files || [], file => ({file}));
    if (!entries.length) return;
    this.pendingDrop = {session: {...session}, entries};
    document.getElementById('dropUploadFileName').value = entries
      .map(item => (item.entry || item.file).name).join(', ');
    document.getElementById('dropUploadPath').value = '.';
    document.getElementById('dropUploadTarget').textContent =
      `${session.username}@${session.host}:${session.port || 22}`;
    window.ModalManager.open(document.getElementById('dropUploadModal'));
  }

  assertConnected(session) {
    if (!window.socket?.connected || !(this.sessionManager || window.SessionManager)?.getSession(session.id)?.connected) {
      throw new Error(this.t('fm.noActiveSession', 'No active SSH session'));
    }
  }

  joinPath(base, name) {
    return `${base.replace(/\/+$/, '')}/${name}`;
  }

  async processEntries(entries, session, basePath) {
    for (const {entry, file} of entries) {
      if (entry?.isDirectory) {
        await this.uploadDirectory(entry, session, basePath);
      } else {
        const upload = file || await new Promise((resolve, reject) => entry.file(resolve, reject));
        this.uploadFileToPath(upload, this.joinPath(basePath, upload.name), session);
      }
    }
  }

  createDirectory(path, session) {
    this.assertConnected(session);
    const socket = window.socket;
    const sourceId = session.fileSource?.sourceId || `sftp-session:${session.id}`;
    const requestId = `terminal-drop:mkdir:${Date.now()}:${++this.directoryRequestSequence}`;
    return new Promise((resolve, reject) => {
      const cleanup = () => {
        clearTimeout(timer);
        socket.off('directory_created', created);
        socket.off('error', failed);
        socket.off('disconnect', disconnected);
      };
      const finish = error => {
        cleanup();
        if (error) reject(error); else resolve();
      };
      const matches = data => data?.request_id === requestId && data?.source_id === sourceId;
      const created = data => { if (matches(data)) finish(); };
      const failed = data => { if (matches(data)) finish(new Error(data.error)); };
      const disconnected = () => finish(new Error(this.t('fm.noActiveSession', 'No active SSH session')));
      const timer = setTimeout(() => finish(new Error(this.t('dropUpload.timeout', 'Creating the destination folder timed out.'))), 15000);
      socket.on('directory_created', created);
      socket.on('error', failed);
      socket.on('disconnect', disconnected);
      socket.emit('create_directory', {source_id: sourceId, remote_path: path, request_id: requestId});
    });
  }

  async uploadDirectory(directoryEntry, session, basePath) {
    const dirPath = this.joinPath(basePath, directoryEntry.name);
    await this.createDirectory(dirPath, session);
    const reader = directoryEntry.createReader();
    while (true) {
      const entries = await new Promise((resolve, reject) => reader.readEntries(resolve, reject));
      if (!entries.length) break;
      await this.processEntries(entries.map(entry => ({entry})), session, dirPath);
    }
  }

  uploadFileToPath(file, remotePath, session) {
    this.assertConnected(session);
    const sourceId = session.fileSource?.sourceId || `sftp-session:${session.id}`;
    FileTransferManager.uploadFile(sourceId, file, remotePath);
  }

  getActiveSession() {
    const manager = this.sessionManager || window.SessionManager;
    const id = typeof manager?.getWorkspaceSession === 'function'
      ? manager.getWorkspaceSession() : manager?.getActiveSession();
    const session = id ? manager.getSession(id) : null;
    return session?.connected ? session : null;
  }

  showQuickConnectDialog() {
    if (window.showNotification) {
      window.showNotification('Please connect to a server first, then try uploading again.', 'warning');
    }

    const connectionModal = document.getElementById('connectionModal');
    if (connectionModal && window.ModalManager) {
      window.ModalManager.open(connectionModal);
    }
  }

  showOverlay() {
    if (this.overlay) {
      this.overlay.style.display = 'flex';
    }
  }

  hideOverlay() {
    if (this.overlay) {
      this.overlay.style.display = 'none';
    }
    this.dragCounter = 0;
  }

  reset() {
    this.dragCounter = 0;
    this.hideOverlay();
  }

  updateOverlayMessage() {
    const session = this.getActiveSession();
    const hint = this.overlay.querySelector('#dragDropHint');

    if (hint) {
      if (session) {
        hint.textContent = `${session.username}@${session.host} — ${this.t('dropUpload.chooseFolder', 'Choose a destination folder after dropping.')}`;
      } else {
        hint.textContent = 'Connect to a server first';
      }
    }
  }

  isFileDrag(e) {
    const types = e.dataTransfer?.types;
    return types && types.includes('Files');
  }

  registerDropZone(element, options = {}) {
    this.dropZones.add({ element, options });
  }

  unregisterDropZone(element) {
    this.dropZones.forEach(zone => {
      if (zone.element === element) {
        this.dropZones.delete(zone);
      }
    });
  }

  destroy() {
    document.removeEventListener('dragenter', this.handleDragEnter);
    document.removeEventListener('dragleave', this.handleDragLeave);
    document.removeEventListener('dragover', this.handleDragOver);
    document.removeEventListener('drop', this.handleDrop);

    if (this.overlay) {
      this.overlay.remove();
    }
  }
}

if (typeof window !== 'undefined') {
  window.addEventListener('DOMContentLoaded', () => {
    window.dragDropManager = new DragDropManager({sessionManager: SessionManager});
    window.dragDropManager.init();
  });
}

if (typeof module !== 'undefined' && module.exports) {
  module.exports = DragDropManager;
}
