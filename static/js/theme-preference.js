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
})(window);
