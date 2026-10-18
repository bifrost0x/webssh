/* Account-scoped, browser-local wallpapers. Only decoded/re-encoded pixels are
 * persisted. No original file, URL, filename, metadata, or server upload. */
(function (root, factory) {
    const api = factory();
    if (typeof module === 'object' && module.exports) module.exports = api;
    if (root?.document) api.init(root);
})(typeof window === 'undefined' ? null : window, function () {
    'use strict';
    const WIDTH = 1920;
    const HEIGHT = 1080;
    const MAX_BYTES = 5 * 1024 * 1024;

    function inspect(bytes) {
        const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
        let width, height, type;
        if (bytes.length >= 33 && view.getUint32(0) === 0x89504e47 && view.getUint32(4) === 0x0d0a1a0a) {
            type = 'image/png';
            if (view.getUint32(8) !== 13 || view.getUint32(12) !== 0x49484452) throw Error('format');
            width = view.getUint32(16); height = view.getUint32(20);
            let ended = false;
            for (let pos = 8; pos + 12 <= bytes.length;) {
                const length = view.getUint32(pos);
                const kind = view.getUint32(pos + 4);
                if (length > bytes.length - pos - 12 || kind === 0x6163544c) throw Error('format'); // APNG
                pos += length + 12;
                if (kind === 0x49454e44) { ended = pos === bytes.length && length === 0; break; }
            }
            if (!ended) throw Error('format');
        } else if (bytes.length >= 4 && view.getUint16(0) === 0xffd8) {
            type = 'image/jpeg';
            for (let pos = 2; pos + 4 <= bytes.length;) {
                if (bytes[pos++] !== 0xff) throw Error('format');
                while (bytes[pos] === 0xff) pos++;
                const marker = bytes[pos++];
                if (marker === 0xda || marker === 0xd9) break;
                if (pos + 2 > bytes.length) throw Error('format');
                const length = view.getUint16(pos);
                if (length < 2 || pos + length > bytes.length) throw Error('format');
                if ([0xc0, 0xc1, 0xc2].includes(marker)) {
                    if (length < 8 || width !== undefined) throw Error('format');
                    height = view.getUint16(pos + 3); width = view.getUint16(pos + 5);
                }
                pos += length;
            }
        } else throw Error('format');
        if (width !== WIDTH || height !== HEIGHT) throw Error('dimensions');
        return type;
    }

    function init(win) {
        const doc = win.document;
        const scope = doc.querySelector('meta[name="background-scope"]')?.content;
        if (!scope || !/^[a-f0-9]{64}$/.test(scope)) return;
        const input = doc.getElementById('themeBackgroundFile');
        const remove = doc.getElementById('themeBackgroundRemove');
        const status = doc.getElementById('themeBackgroundStatus');
        const preview = doc.getElementById('themeBackgroundPreview');
        const validTheme = theme => win.ThemePreference?.isValid(theme) === true;
        const key = theme => `${scope}:${theme}`;
        const theme = () => doc.body.dataset.theme;
        const text = name => win.i18n?.t(`background.${name}`) || name;
        let serial = 0;
        let busy = false;
        let dbPromise;
        function database() {
            if (!dbPromise) dbPromise = new Promise((resolve, reject) => {
                const request = win.indexedDB.open('webssh-theme-backgrounds', 1);
                request.onupgradeneeded = () => request.result.createObjectStore('images');
                request.onerror = () => reject(Error('storage'));
                request.onblocked = () => reject(Error('storage'));
                request.onsuccess = () => {
                    request.result.onversionchange = () => request.result.close();
                    resolve(request.result);
                };
            });
            return dbPromise;
        }
        async function record(mode, action) {
            const db = await database();
            return new Promise((resolve, reject) => {
                try {
                    const tx = db.transaction('images', mode);
                    const request = action(tx.objectStore('images'));
                    tx.oncomplete = () => resolve(request.result);
                    tx.onabort = tx.onerror = () => reject(Error('storage'));
                } catch { reject(Error('storage')); }
            });
        }
        function report(name, error = false) {
            if (!status) return;
            status.dataset.i18n = `background.${name}`;
            status.textContent = text(name);
            status.classList.toggle('text-danger', error);
        }
        function controls() {
            if (input) input.disabled = busy;
            if (remove) remove.disabled = busy || !doc.body.hasAttribute('data-custom-background');
        }
        function clear() {
            doc.body.style.removeProperty('--theme-background-image-source');
            doc.body.style.removeProperty('--theme-background-image');
            doc.body.removeAttribute('data-custom-background');
            if (preview) { preview.hidden = true; preview.removeAttribute('src'); }
            controls();
        }
        async function apply() {
            const revision = ++serial;
            const selected = theme();
            clear();
            if (!validTheme(selected)) return;
            try {
                const data = await record('readonly', store => store.get(key(selected)));
                if (revision !== serial || selected !== theme()) return;
                // Stored data is untrusted too; only our bounded JPEG data format is usable.
                if (typeof data !== 'string' || data.length > MAX_BYTES * 2
                        || !/^data:image\/jpeg;base64,[A-Za-z0-9+/]+=*$/.test(data)) return;
                doc.body.style.setProperty('--theme-background-image-source', `url("${data}")`);
                doc.body.style.setProperty('--theme-background-image', `url("${data}")`);
                doc.body.setAttribute('data-custom-background', '');
                if (preview) { preview.src = data; preview.hidden = false; }
                controls();
            } catch { if (input) report('storage', true); }
        }
        input?.addEventListener('change', async () => {
            const file = input.files?.[0];
            if (!file || busy) return;
            const selected = theme();
            if (!validTheme(selected)) return;
            busy = true; controls(); report('saving');
            try {
                if (!file.size || file.size > MAX_BYTES) throw Error('size');
                const bytes = new Uint8Array(await file.arrayBuffer());
                const type = inspect(bytes); // Size and dimensions checked BEFORE decoding.
                const bitmap = await win.createImageBitmap(new Blob([bytes], {type}), {imageOrientation: 'none'});
                try {
                    if (bitmap.width !== WIDTH || bitmap.height !== HEIGHT) throw Error('dimensions');
                    const canvas = doc.createElement('canvas');
                    canvas.width = WIDTH; canvas.height = HEIGHT;
                    const context = canvas.getContext('2d', {alpha: false});
                    context.fillStyle = '#101820'; context.fillRect(0, 0, WIDTH, HEIGHT);
                    context.drawImage(bitmap, 0, 0);
                    const data = canvas.toDataURL('image/jpeg', 0.9);
                    if (!data.startsWith('data:image/jpeg;base64,') || data.length > MAX_BYTES * 2) throw Error('size');
                    await record('readwrite', store => store.put(data, key(selected)));
                } finally { bitmap.close(); }
                await apply(); report('saved');
            } catch (error) {
                report(['size', 'dimensions', 'format', 'storage'].includes(error.message) ? error.message : 'format', true);
            } finally { input.value = ''; busy = false; controls(); }
        });
        remove?.addEventListener('click', async () => {
            if (busy || !validTheme(theme())) return;
            const selected = theme();
            busy = true; controls();
            try {
                await record('readwrite', store => store.delete(key(selected)));
                await apply(); report('removed');
            } catch { report('storage', true); }
            finally { busy = false; controls(); }
        });
        new win.MutationObserver(apply).observe(doc.body, {attributes: true, attributeFilter: ['data-theme']});
        win.addEventListener('pageshow', apply);
        apply();
    }
    return {inspect, init, WIDTH, HEIGHT, MAX_BYTES};
});
