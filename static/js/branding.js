/* The tab icon uses the same local artwork and theme tokens as the app logo. */
(function () {
    'use strict';
    const icon = document.querySelector('link[rel="icon"][data-theme-logo]');
    if (!icon || !document.body) return;
    const source = icon.href;
    let revision = 0;
    let artwork;

    async function update() {
        const current = ++revision;
        try {
            artwork ??= fetch(source, {credentials: 'omit', cache: 'force-cache'})
                .then(response => response.ok ? response.text() : null);
            const svg = await artwork;
            if (!svg || current !== revision) return;
            const style = getComputedStyle(document.body);
            const colored = svg.replace(/var\((--brand-[a-z-]+),\s*(#[a-f0-9]+)\)/gi,
                (_match, property, fallback) => style.getPropertyValue(property).trim() || fallback);
            icon.href = `data:image/svg+xml,${encodeURIComponent(colored)}`;
        } catch {
            // The shipped standard icon remains usable when loading is blocked.
        }
    }

    new MutationObserver(update).observe(document.body, {
        attributes: true,
        attributeFilter: ['data-theme'],
    });
    window.addEventListener('pageshow', update);
    update();
})();
