(function(global) {
    'use strict';

    const STORAGE_KEY = 'websshTheme';
    const THEMES = new Set([
        'glass',
        'retro',
        'solar',
        'paper',
        'noir',
        'arctic-ice',
        'rose-gold',
        'cyberpunk-neon',
        'emerald-matrix',
        'obsidian'
    ]);

    function isValid(themeId) {
        return THEMES.has(themeId);
    }

    function read() {
        try {
            const themeId = global.localStorage.getItem(STORAGE_KEY);
            return isValid(themeId) ? themeId : null;
        } catch {
            return null;
        }
    }

    function store(themeId) {
        if (!isValid(themeId)) {
            return false;
        }
        try {
            global.localStorage.setItem(STORAGE_KEY, themeId);
            return true;
        } catch {
            return false;
        }
    }

    function applyStored(element) {
        const themeId = read();
        if (!themeId || !element) {
            return null;
        }
        element.setAttribute('data-theme', themeId);
        return themeId;
    }

    global.ThemePreference = Object.freeze({
        applyStored,
        isValid,
        read,
        store
    });

    if (document.body?.hasAttribute('data-use-theme-preference')) {
        applyStored(document.body);
    }
    // Resolve the saved theme before allowing CSS to request its background.
    // Do not wait for load or idle: the image is part of the initial appearance.
    if (document.body?.hasAttribute('data-defer-theme-background')) {
        document.body.setAttribute('data-theme-background-ready', '');
    }
})(window);
