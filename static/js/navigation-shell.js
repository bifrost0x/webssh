/* Shared navigation controls preserve the workspace and its optional helpers. */
(() => {
    const button = document.getElementById('toggleHostRail');
    if (!button) return;
    const storageKey = 'webssh.hostRailCollapsed';
    let collapsed = true;
    try {
        const saved = localStorage.getItem(storageKey);
        if (saved !== null) collapsed = saved === 'true';
    } catch { /* Storage is optional. */ }
    const render = () => {
        document.body.classList.toggle('hosts-collapsed', collapsed);
        document.body.dataset.hostRailRequested = String(!collapsed);
        button.setAttribute('aria-expanded', String(!collapsed));
        window.dispatchEvent(new Event('host-access-change'));
        window.dispatchEvent(new Event('resize'));
    };
    const save = () => {
        try { localStorage.setItem(storageKey, String(collapsed)); } catch { /* Optional preference. */ }
        render();
    };
    button.addEventListener('click', () => {
        const wasFavorites = document.body.dataset.hostAccessFilter === 'favorites';
        document.body.dataset.hostAccessFilter = '';
        collapsed = wasFavorites ? false : !collapsed;
        save();
    });
    document.getElementById('workspaceFavoritesBtn')?.addEventListener('click', () => {
        document.body.dataset.hostAccessFilter = 'favorites';
        collapsed = false;
        save();
    });
    document.getElementById('shellSearchBtn')?.addEventListener('click', () => window.openCommandPalette?.());
    document.getElementById('shellConnectBtn')?.addEventListener('click', () => window.openDefaultConnectionModal?.());
    document.getElementById('workspaceRecentBtn')?.addEventListener('click', () => {
        window.openDefaultConnectionModal?.();
    });
    document.querySelectorAll('.management-toolbar-menu').forEach(menu => {
        menu.addEventListener('click', event => {
            if (!event.target.closest('button')) return;
            const focusWasInside = menu.contains(document.activeElement);
            menu.open = false;
            if (focusWasInside && menu.contains(document.activeElement)) menu.querySelector('summary')?.focus();
        });
        menu.addEventListener('keydown', event => {
            if (event.key === 'Escape') { menu.open = false; menu.querySelector('summary')?.focus(); event.stopPropagation(); }
        });
    });
    render();
})();
