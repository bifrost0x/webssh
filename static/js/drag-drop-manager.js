/**
 * Global Drag & Drop Manager
 *
 * Handles drag-and-drop file uploads anywhere on the page.
 * Features:
 * - Visual feedback with overlay
 * - Multi-file and folder support
 * - Quick connection if no session active
 * - Drag preview with file count
 * - Integration with binary transfer client
 *
 * Usage:
 * const manager = new DragDropManager();
 * manager.init();
 */

class DragDropManager {
  constructor() {
    this.overlay = null;
    this.dropZones = new Set();
    this.isDragging = false;
    this.dragCounter = 0;
    this.transferClient = null;
    this.defaultSessionId = null;

    // Bindings
    this.handleDragEnter = this.handleDragEnter.bind(this);
    this.handleDragOver = this.handleDragOver.bind(this);
    this.handleDragLeave = this.handleDragLeave.bind(this);
    this.handleDrop = this.handleDrop.bind(this);
  }

  init() {
    this.createOverlay();
    this.attachGlobalListeners();

    // Initialize transfer client if available
    if (window.socket && window.BinaryTransferClient) {
      this.transferClient = new BinaryTransferClient(window.socket);
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
    // Prevent default drag behavior on entire document
    document.addEventListener('dragover', (e) => {
      e.preventDefault();
    });

    document.addEventListener('drop', (e) => {
      e.preventDefault();
    });

    // Track drag enter/leave for overlay
    document.addEventListener('dragenter', this.handleDragEnter);
    document.addEventListener('dragleave', this.handleDragLeave);
    document.addEventListener('dragover', this.handleDragOver);
    document.addEventListener('drop', this.handleDrop);

    // Ensure overlay is hidden when drag ends for any reason
    document.addEventListener('dragend', () => {
      this.reset();
    });

    // Also listen for mouseup as a fallback to catch edge cases
    document.addEventListener('mouseup', () => {
      // Small delay to allow drop event to fire first
      setTimeout(() => {
        if (this.dragCounter > 0) {
          this.reset();
        }
      }, 100);
    });
  }

  handleDragEnter(e) {
    // Only handle file drags
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

    // Update file count in overlay
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

  async handleDrop(e) {
    if (!this.isFileDrag(e)) return;

    e.preventDefault();
    e.stopPropagation();

    this.dragCounter = 0;
    this.hideOverlay();

    const items = e.dataTransfer?.items;
    const files = e.dataTransfer?.files;

    // Check if we have an active session
    const session = this.getActiveSession();

    if (!session) {
      // Show quick connection dialog
      this.showQuickConnectDialog(items || files);
      return;
    }

    // Process files
    if (items) {
      await this.processDataTransferItems(items, session);
    } else if (files) {
      this.processFiles(Array.from(files), session);
    }
  }

  async processDataTransferItems(items, session) {
    const entries = Array.from(items)
      .filter(item => item.kind === 'file')
      .map(item => item.webkitGetAsEntry());

    for (const entry of entries) {
      if (entry.isFile) {
        entry.file(file => this.uploadFile(file, session));
      } else if (entry.isDirectory) {
        await this.uploadDirectory(entry, session);
      }
    }
  }

  processFiles(files, session) {
    files.forEach(file => this.uploadFile(file, session));
  }

  async uploadDirectory(directoryEntry, session, basePath = null) {
    if (!this.transferClient) return;

    // Use current path from active file browser or default to home
    const currentPath = basePath || this.getCurrentPath() || '/';
    const dirPath = `${currentPath}/${directoryEntry.name}`;

    // Create directory on remote
    if (window.socket) {
      window.socket.emit('create_directory', {
        session_id: session.id,
        remote_path: dirPath
      });
    }

    // Read directory contents
    const reader = directoryEntry.createReader();
    const entries = await new Promise((resolve, reject) => {
      reader.readEntries(resolve, reject);
    });

    // Process all entries
    for (const entry of entries) {
      if (entry.isFile) {
        entry.file(file => {
          const filePath = `${dirPath}/${file.name}`;
          this.uploadFileToPath(file, filePath, session);
        });
      } else if (entry.isDirectory) {
        await this.uploadDirectory(entry, session, dirPath);
      }
    }
  }

  /**
   * SECURITY: Maximum file size for drag-drop uploads (100MB)
   */
  maxFileSize = 100 * 1024 * 1024;

  /**
   * Validate file before upload
   * @param {File} file - File to validate
   * @returns {string|null} Error message or null if valid
   */
  validateFile(file) {
    if (file.size > this.maxFileSize) {
      return `File "${file.name}" too large (${(file.size / 1024 / 1024).toFixed(2)}MB). Max size: ${this.maxFileSize / 1024 / 1024}MB`;
    }
    if (file.size === 0) {
      return `File "${file.name}" is empty and cannot be uploaded.`;
    }
    return null;
  }

  uploadFile(file, session) {
    // SECURITY: Validate file before upload
    const error = this.validateFile(file);
    if (error) {
      if (window.showNotification) {
        window.showNotification(error, 'error');
      }
      return;
    }

    const currentPath = this.getCurrentPath() || '/';
    const remotePath = `${currentPath}/${file.name}`;
    this.uploadFileToPath(file, remotePath, session);
  }

  uploadFileToPath(file, remotePath, session) {
    if (!this.transferClient) {
      console.error('Transfer client not initialized');
      return;
    }

    this.transferClient.uploadFile(file, remotePath, session.id);

    // Show notification
    if (window.showNotification) {
      window.showNotification(`Uploading ${file.name}...`, 'info');
    }
  }

  getActiveSession() {
    // Try to get from SessionManager
    if (window.SessionManager) {
      const sessions = window.SessionManager.getAllSessions();
      const connected = sessions.filter(s => s.connected);

      if (connected.length > 0) {
        return connected[0]; // Return first connected session
      }
    }

    return null;
  }

  getCurrentPath() {
    // Return default path - file browser not available
    return '/';
  }

  showQuickConnectDialog(filesOrItems) {
    // Show notification to connect first and open connection modal
    if (window.showNotification) {
      window.showNotification('Please connect to a server first, then try uploading again.', 'warning');
    }

    // Open the connection modal if available
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
    // Reset drag counter to prevent stuck state
    this.dragCounter = 0;
  }

  /**
   * Force reset all drag state - call this when closing modals or changing views
   */
  reset() {
    this.dragCounter = 0;
    this.hideOverlay();
  }

  updateOverlayMessage() {
    const session = this.getActiveSession();
    const hint = this.overlay.querySelector('#dragDropHint');

    if (hint) {
      if (session) {
        const path = this.getCurrentPath() || '/';
        hint.textContent = `Uploading to ${session.username}@${session.host}:${path}`;
      } else {
        hint.textContent = 'Connect to a server first';
      }
    }
  }

  isFileDrag(e) {
    // Check if drag contains files
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

// Auto-initialize on page load
if (typeof window !== 'undefined') {
  window.addEventListener('DOMContentLoaded', () => {
    window.dragDropManager = new DragDropManager();
    window.dragDropManager.init();
  });
}

// Export for use in other modules
if (typeof module !== 'undefined' && module.exports) {
  module.exports = DragDropManager;
}
