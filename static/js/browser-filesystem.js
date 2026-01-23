/**
 * Browser File System Access API Wrapper
 * Provides secure access to the user's local filesystem via the File System Access API.
 *
 * Security: Only explicitly user-selected directories are accessible.
 * Requires: HTTPS or localhost, user gesture for initial access.
 * Browser Support: Chrome 86+, Edge 86+, Firefox 111+, Safari 15.2+
 */

class BrowserFileSystem {
    constructor() {
        this.rootHandle = null;
        this.currentHandle = null;
        this.pathStack = [];
        this.isSupported = this.checkSupport();
    }

    /**
     * Check if File System Access API is supported
     */
    checkSupport() {
        return 'showDirectoryPicker' in window;
    }

    /**
     * Request access to a directory from the user
     * MUST be called from a user gesture (click, etc.)
     * @returns {Promise<boolean>} true if access granted, false if cancelled
     */
    async requestAccess() {
        if (!this.isSupported) {
            throw new Error('File System Access API not supported in this browser');
        }

        try {
            this.rootHandle = await window.showDirectoryPicker({
                mode: 'readwrite'
            });
            this.currentHandle = this.rootHandle;
            this.pathStack = [this.rootHandle.name];
            return true;
        } catch (e) {
            if (e.name === 'AbortError') {
                // User cancelled the picker
                return false;
            }
            throw e;
        }
    }

    /**
     * Check if we have an active directory handle
     */
    hasAccess() {
        return this.rootHandle !== null && this.currentHandle !== null;
    }

    /**
     * Get the current path as a string
     */
    getCurrentPath() {
        if (!this.hasAccess()) return '';
        return '/' + this.pathStack.join('/');
    }

    /**
     * Get the root directory name
     */
    getRootName() {
        return this.rootHandle ? this.rootHandle.name : '';
    }

    /**
     * List files and directories in the current directory
     * @returns {Promise<Array>} Array of file/directory info objects
     */
    async listDirectory() {
        if (!this.hasAccess()) {
            throw new Error('No directory access. Call requestAccess() first.');
        }

        const files = [];

        try {
            for await (const entry of this.currentHandle.values()) {
                const fileInfo = {
                    name: entry.name,
                    is_dir: entry.kind === 'directory',
                    handle: entry,
                    permissions: 'rwx' // FSA gives full access to selected dir
                };

                if (entry.kind === 'file') {
                    try {
                        const file = await entry.getFile();
                        fileInfo.size = file.size;
                        fileInfo.modified = Math.floor(file.lastModified / 1000);
                        fileInfo.modified_str = new Date(file.lastModified).toLocaleString();
                    } catch (e) {
                        fileInfo.size = 0;
                        fileInfo.modified = 0;
                        fileInfo.error = e.message;
                    }
                } else {
                    fileInfo.size = 0;
                    fileInfo.modified = 0;
                }

                files.push(fileInfo);
            }
        } catch (e) {
            console.error('Error listing directory:', e);
            throw e;
        }

        // Sort: directories first, then alphabetically
        files.sort((a, b) => {
            if (a.is_dir && !b.is_dir) return -1;
            if (!a.is_dir && b.is_dir) return 1;
            return a.name.localeCompare(b.name);
        });

        return files;
    }

    /**
     * Navigate into a subdirectory
     * @param {string} dirName - Name of the directory to enter
     */
    async navigateInto(dirName) {
        if (!this.hasAccess()) {
            throw new Error('No directory access');
        }

        try {
            const subHandle = await this.currentHandle.getDirectoryHandle(dirName);
            this.currentHandle = subHandle;
            this.pathStack.push(dirName);
        } catch (e) {
            console.error('Error navigating into directory:', e);
            throw e;
        }
    }

    /**
     * Navigate up one directory level
     * @returns {Promise<boolean>} true if navigated up, false if already at root
     */
    async navigateUp() {
        if (!this.hasAccess()) {
            throw new Error('No directory access');
        }

        if (this.pathStack.length <= 1) {
            // Already at root
            return false;
        }

        // Remove current directory from path
        this.pathStack.pop();

        // Navigate from root to current path
        // (FSA API doesn't have a parent handle reference)
        this.currentHandle = this.rootHandle;
        for (let i = 1; i < this.pathStack.length; i++) {
            this.currentHandle = await this.currentHandle.getDirectoryHandle(this.pathStack[i]);
        }

        return true;
    }

    /**
     * Navigate to a specific path (from root)
     * @param {string} path - Path relative to root (e.g., "subdir/another")
     */
    async navigateTo(path) {
        if (!this.hasAccess()) {
            throw new Error('No directory access');
        }

        // Reset to root
        this.currentHandle = this.rootHandle;
        this.pathStack = [this.rootHandle.name];

        if (!path || path === '/' || path === this.rootHandle.name) {
            return;
        }

        // Parse path and navigate
        const parts = path.split('/').filter(p => p && p !== this.rootHandle.name);
        for (const part of parts) {
            await this.navigateInto(part);
        }
    }

    /**
     * Read a file and return its contents as ArrayBuffer
     * @param {FileSystemFileHandle} fileHandle - The file handle to read
     * @returns {Promise<ArrayBuffer>}
     */
    async readFile(fileHandle) {
        const file = await fileHandle.getFile();
        return await file.arrayBuffer();
    }

    /**
     * Read a file by name in the current directory
     * @param {string} fileName - Name of the file to read
     * @returns {Promise<ArrayBuffer>}
     */
    async readFileByName(fileName) {
        if (!this.hasAccess()) {
            throw new Error('No directory access');
        }

        const fileHandle = await this.currentHandle.getFileHandle(fileName);
        return await this.readFile(fileHandle);
    }

    /**
     * Write data to a file in the current directory
     * @param {string} fileName - Name of the file to write
     * @param {ArrayBuffer|Blob|string} data - Data to write
     * @returns {Promise<void>}
     */
    async writeFile(fileName, data) {
        if (!this.hasAccess()) {
            throw new Error('No directory access');
        }

        try {
            const fileHandle = await this.currentHandle.getFileHandle(fileName, { create: true });
            const writable = await fileHandle.createWritable();
            await writable.write(data);
            await writable.close();
        } catch (e) {
            console.error('Error writing file:', e);
            throw e;
        }
    }

    /**
     * Create a new directory in the current directory
     * @param {string} name - Name of the new directory
     * @returns {Promise<FileSystemDirectoryHandle>}
     */
    async createDirectory(name) {
        if (!this.hasAccess()) {
            throw new Error('No directory access');
        }

        try {
            return await this.currentHandle.getDirectoryHandle(name, { create: true });
        } catch (e) {
            console.error('Error creating directory:', e);
            throw e;
        }
    }

    /**
     * Delete a file or directory
     * @param {string} name - Name of the entry to delete
     * @param {boolean} recursive - If true, delete directories recursively
     */
    async deleteEntry(name, recursive = true) {
        if (!this.hasAccess()) {
            throw new Error('No directory access');
        }

        try {
            await this.currentHandle.removeEntry(name, { recursive });
        } catch (e) {
            console.error('Error deleting entry:', e);
            throw e;
        }
    }

    /**
     * Rename a file or directory (copy + delete)
     * Note: FSA API doesn't have native rename, so we copy and delete
     * @param {string} oldName - Current name
     * @param {string} newName - New name
     */
    async rename(oldName, newName) {
        if (!this.hasAccess()) {
            throw new Error('No directory access');
        }

        try {
            // Check if it's a file or directory
            let isDir = false;
            let handle;

            try {
                handle = await this.currentHandle.getFileHandle(oldName);
            } catch {
                handle = await this.currentHandle.getDirectoryHandle(oldName);
                isDir = true;
            }

            if (isDir) {
                // For directories, we need to recursively copy
                await this._copyDirectoryRecursive(handle, this.currentHandle, newName);
            } else {
                // For files, read and write
                const data = await this.readFile(handle);
                await this.writeFile(newName, data);
            }

            // Delete original
            await this.deleteEntry(oldName);
        } catch (e) {
            console.error('Error renaming entry:', e);
            throw e;
        }
    }

    /**
     * Recursively copy a directory
     * @private
     */
    async _copyDirectoryRecursive(sourceHandle, targetParentHandle, newName) {
        const newDirHandle = await targetParentHandle.getDirectoryHandle(newName, { create: true });

        for await (const entry of sourceHandle.values()) {
            if (entry.kind === 'file') {
                const file = await entry.getFile();
                const data = await file.arrayBuffer();
                const newFileHandle = await newDirHandle.getFileHandle(entry.name, { create: true });
                const writable = await newFileHandle.createWritable();
                await writable.write(data);
                await writable.close();
            } else {
                await this._copyDirectoryRecursive(entry, newDirHandle, entry.name);
            }
        }
    }

    /**
     * Get file info for a specific file
     * @param {string} fileName - Name of the file
     * @returns {Promise<Object>} File info object
     */
    async getFileInfo(fileName) {
        if (!this.hasAccess()) {
            throw new Error('No directory access');
        }

        try {
            const fileHandle = await this.currentHandle.getFileHandle(fileName);
            const file = await fileHandle.getFile();
            return {
                name: file.name,
                size: file.size,
                type: file.type,
                modified: Math.floor(file.lastModified / 1000),
                modified_str: new Date(file.lastModified).toLocaleString(),
                is_dir: false,
                handle: fileHandle
            };
        } catch {
            // Try as directory
            const dirHandle = await this.currentHandle.getDirectoryHandle(fileName);
            return {
                name: dirHandle.name,
                size: 0,
                type: 'directory',
                modified: 0,
                is_dir: true,
                handle: dirHandle
            };
        }
    }

    /**
     * Check if an entry exists
     * @param {string} name - Name to check
     * @returns {Promise<boolean>}
     */
    async exists(name) {
        if (!this.hasAccess()) return false;

        try {
            await this.currentHandle.getFileHandle(name);
            return true;
        } catch {
            try {
                await this.currentHandle.getDirectoryHandle(name);
                return true;
            } catch {
                return false;
            }
        }
    }

    /**
     * Release access (clear handles)
     */
    release() {
        this.rootHandle = null;
        this.currentHandle = null;
        this.pathStack = [];
    }
}

// Export for use in other modules
if (typeof window !== 'undefined') {
    window.BrowserFileSystem = BrowserFileSystem;
}
