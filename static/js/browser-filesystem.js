
class BrowserFileSystem {
    constructor() {
        this.rootHandle = null;
        this.currentHandle = null;
        this.pathStack = [];
        this.isSupported = this.checkSupport();
    }

    checkSupport() {
        return 'showDirectoryPicker' in window;
    }

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
                return false;
            }
            throw e;
        }
    }

    hasAccess() {
        return this.rootHandle !== null && this.currentHandle !== null;
    }

    getCurrentPath() {
        if (!this.hasAccess()) return '';
        return '/' + this.pathStack.join('/');
    }

    getRootName() {
        return this.rootHandle ? this.rootHandle.name : '';
    }

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
                    permissions: 'rwx'
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

        files.sort((a, b) => {
            if (a.is_dir && !b.is_dir) return -1;
            if (!a.is_dir && b.is_dir) return 1;
            return a.name.localeCompare(b.name);
        });

        return files;
    }

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

    async navigateUp() {
        if (!this.hasAccess()) {
            throw new Error('No directory access');
        }

        if (this.pathStack.length <= 1) {
            return false;
        }

        this.pathStack.pop();

        this.currentHandle = this.rootHandle;
        for (let i = 1; i < this.pathStack.length; i++) {
            this.currentHandle = await this.currentHandle.getDirectoryHandle(this.pathStack[i]);
        }

        return true;
    }

    async navigateTo(path) {
        if (!this.hasAccess()) {
            throw new Error('No directory access');
        }

        this.currentHandle = this.rootHandle;
        this.pathStack = [this.rootHandle.name];

        if (!path || path === '/' || path === this.rootHandle.name) {
            return;
        }

        const parts = path.split('/').filter(p => p && p !== this.rootHandle.name);
        for (const part of parts) {
            await this.navigateInto(part);
        }
    }

    async readFile(fileHandle) {
        const file = await fileHandle.getFile();
        return await file.arrayBuffer();
    }

    async readFileByName(fileName) {
        if (!this.hasAccess()) {
            throw new Error('No directory access');
        }

        const fileHandle = await this.currentHandle.getFileHandle(fileName);
        return await this.readFile(fileHandle);
    }

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

    async rename(oldName, newName) {
        if (!this.hasAccess()) {
            throw new Error('No directory access');
        }

        try {
            let isDir = false;
            let handle;

            try {
                handle = await this.currentHandle.getFileHandle(oldName);
            } catch {
                handle = await this.currentHandle.getDirectoryHandle(oldName);
                isDir = true;
            }

            if (isDir) {
                await this._copyDirectoryRecursive(handle, this.currentHandle, newName);
            } else {
                const data = await this.readFile(handle);
                await this.writeFile(newName, data);
            }

            await this.deleteEntry(oldName);
        } catch (e) {
            console.error('Error renaming entry:', e);
            throw e;
        }
    }

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

    release() {
        this.rootHandle = null;
        this.currentHandle = null;
        this.pathStack = [];
    }
}

if (typeof window !== 'undefined') {
    window.BrowserFileSystem = BrowserFileSystem;
}
