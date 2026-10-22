(function(root, factory) {
    const api = factory();
    if (typeof module !== 'undefined' && module.exports) module.exports = api;
    if (root) root.TerminalAppearance = api;
}(typeof window !== 'undefined' ? window : null, function() {
    'use strict';
    const bundledFonts = Object.freeze({
        'WebSSH JetBrains Mono': 'JetBrains Mono',
        'WebSSH Hack': 'Hack',
        'WebSSH Fira Mono': 'Fira Mono',
        'WebSSH Source Code Pro': 'Source Code Pro',
    });
    const fontLoads = new Map();
    const loadedFonts = new Set();
    const symbolFont = 'WebSSH Nerd Symbols';
    function withIconFallback(family) {
        // Respect the user's existing glyphs. Supply missing icons before the
        // platform-dependent generic fallback, never ahead of named fonts.
        const generic = /(?:^|,\s*)(monospace|ui-monospace)\s*$/i.exec(family);
        const preferred = generic ? family.slice(0, generic.index) : family;
        return `${preferred ? `${preferred}, ` : ''}"${symbolFont}", ${generic?.[1] || 'monospace'}`;
    }
    // Only our fixed CSS font families may trigger loading. Local names are never
    // enumerated, converted to URLs or sent to a font service.
    function loadFont(family, fontSet = typeof document !== 'undefined' ? document.fonts : null) {
        if (family !== symbolFont && !Object.hasOwn(bundledFonts, family)) return Promise.resolve(true);
        if (loadedFonts.has(family)) return Promise.resolve(true);
        if (!fontSet?.load) return Promise.resolve(false);
        if (fontLoads.has(family)) return fontLoads.get(family);
        const pending = new Promise(resolveLoad => {
            const timer = setTimeout(() => resolveLoad(false), 8000);
            const weights = family === symbolFont ? [400] : [400, 700];
            Promise.all(weights.map(weight => fontSet.load(`${weight} 14px "${family}"`, 'M\uf07b\ue0b0')))
                .then(faces => {
                    const loaded = faces.every(list => list.length > 0);
                    if (loaded) loadedFonts.add(family);
                    resolveLoad(loaded);
                }, () => resolveLoad(false))
                .finally(() => clearTimeout(timer));
        });
        fontLoads.set(family, pending);
        // Cache successes; a later selection can retry a failed/blocked request.
        pending.then(loaded => { if (!loaded) fontLoads.delete(family); });
        return pending;
    }
    const samples = Object.freeze({
        shell: '\x1b[32mops\x1b[0m@webssh \x1b[36m\ue0a0 main \ue0b0\x1b[0m ~\r\n$ eza -l --icons\r\n\x1b[34m\uf07b projects/\x1b[0m  \x1b[33m\ue73c app.py\x1b[0m  \uf15b config.yml\r\n\uf418 git  \uf489 terminal  \uf013 settings\r\n$ ',
        code: '\x1b[35mconst\x1b[0m connect = \x1b[35masync\x1b[0m (host) => {\r\n  \x1b[35mconst\x1b[0m port = \x1b[33m22\x1b[0m;\r\n  \x1b[32m// Your next workspace\x1b[0m\r\n  \x1b[35mreturn await\x1b[0m ssh(host, port);\r\n};',
        characters: '0O oO  1lI |!  {} [] () <>\r\nAa Bb Cc 0123456789 @#$%&*\r\n\x1b[1mBold: 0O 1lI  => != >=\x1b[0m\r\n┌─────────┐  ├── └── ─── │\r\n│ UTF-8   │  ä é ñ Ω 中 文\r\n└─────────┘  \ue0a0 \ue0b0 \uf07b \uf15b \udb80\udc04',
    });
    function resolve(settings, base, font, size) {
        const value = settings && typeof settings === 'object' ? settings : {};
        const number = (key, min, max, fallback, integer = false) => (
            typeof value[key] === 'number' && Number.isFinite(value[key])
            && value[key] >= min && value[key] <= max
            && (!integer || Number.isInteger(value[key])) ? value[key] : fallback
        );
        const color = (key, fallback) => /^#[\da-f]{6}$/i.test(value[key]) ? value[key] : fallback;
        const family = typeof value.font_family === 'string'
            && value.font_family !== 'theme'
            && (!Object.hasOwn(bundledFonts, value.font_family) || loadedFonts.has(value.font_family))
            && /^[a-z\d][a-z\d _-]{0,63}$/i.test(value.font_family)
            ? `"${value.font_family}", monospace` : font;
        return {
            surface: color('background', base.background),
            opacity: number('background_opacity', 0, 100, 100, true) / 100,
            options: {
                allowTransparency: true,
                theme: {...base, background: '#00000000',
                    foreground: color('foreground', base.foreground),
                    cursor: color('cursor_color', base.cursor),
                    selectionBackground: color('selection_background', base.selectionBackground),
                },
                fontFamily: loadedFonts.has(symbolFont) ? withIconFallback(family) : family,
                fontSize: number('font_size', 8, 32, size, true),
                lineHeight: number('line_height', 1, 2, 1),
                letterSpacing: number('letter_spacing', -1, 3, 0),
                fontWeight: value.font_weight === 'bold' ? 'bold' : 'normal',
                cursorStyle: ['block', 'underline', 'bar'].includes(value.cursor_style) ? value.cursor_style : 'block',
                cursorBlink: typeof value.cursor_blink === 'boolean' ? value.cursor_blink : true,
            },
        };
    }
    let preferences = {};
    if (typeof document !== 'undefined') {
        try { preferences = JSON.parse(document.body.dataset.terminalAppearance || '{}'); } catch { /* Follow theme. */ }
    }
    const getPreferences = () => preferences;
    const setPreferences = value => { preferences = {...value}; };
    const terminalFontLoads = new WeakMap();

    function applyLoadedFont(manager) {
        const family = resolve(preferences, manager.buildTheme(), manager.getMonoFont(), manager.getResponsiveFontSize()).options.fontFamily;
        // Unselected preview fonts must not resize live server PTYs.
        if (Object.values(manager.terminals).some(terminal => terminal.options.fontFamily !== family)) {
            manager.applyThemeToAll();
        }
    }
    function loadForTerminal(manager) {
        if (!Object.keys(manager.terminals).length) return Promise.resolve();
        const family = preferences.font_family;
        const pending = terminalFontLoads.get(manager);
        if (pending && pending.family === family) return pending.promise;
        const promise = Promise.all([loadFont(family), loadFont(symbolFont)]).then(() => {
            if (preferences.font_family === family) applyLoadedFont(manager);
        }).finally(() => {
            if (terminalFontLoads.get(manager)?.promise === promise) terminalFontLoads.delete(manager);
        });
        terminalFontLoads.set(manager, {family, promise});
        return promise;
    }

    function init() {
        const modal = document.getElementById('terminalAppearanceModal');
        if (!modal) return;
        const form = document.getElementById('terminalAppearanceForm');
        const previewElement = document.getElementById('terminalAppearancePreview');
        const status = document.getElementById('terminalAppearanceStatus');
        const manager = window.TerminalManager;
        const controls = Array.from(form.querySelectorAll('[data-appearance]'));
        let draft = {...preferences};
        let preview;
        let fit;
        let saving = false;
        let previewRevision = 0;
        const fontInput = document.getElementById('terminalFontFamily');
        const localFont = document.getElementById('terminalLocalFont');
        const fontRadios = Array.from(form.querySelectorAll('[name="terminalFontPreset"]'));
        const fontStatus = document.getElementById('terminalFontStatus');
        const sample = document.getElementById('terminalPreviewSample');
        let localName = Object.hasOwn(bundledFonts, preferences.font_family) || !preferences.font_family || preferences.font_family === 'theme'
            ? 'monospace' : preferences.font_family;
        const t = key => window.i18n?.t?.(key) || key;

        function syncFontControls() {
            const family = draft.font_family || 'theme';
            const preset = family === 'theme' || Object.hasOwn(bundledFonts, family) ? family : 'custom';
            fontRadios.forEach(radio => { radio.checked = radio.value === preset; });
            localFont.hidden = preset !== 'custom';
            fontInput.disabled = preset !== 'custom';
            fontInput.value = preset === 'custom' ? family : localName;
        }
        function paintSample() {
            if (!preview) return;
            // Queue the reset with the sample: earlier asynchronous writes must
            // finish before clearing, or rapid sample changes leave stale text.
            preview.write('\x1bc' + (samples[sample.value] || samples.shell));
        }
        async function updatePreview() {
            const resolved = resolve(draft, manager.buildTheme(), manager.getMonoFont(), manager.getResponsiveFontSize());
            previewElement.style.setProperty('--terminal-surface-color', resolved.surface);
            previewElement.style.setProperty('--terminal-surface-opacity', `${resolved.opacity * 100}%`);
            if (preview) {
                Object.assign(preview.options, resolved.options);
                fit.fit();
            }
            document.getElementById('terminalOpacityValue').textContent = `${draft.background_opacity ?? 100}%`;
            const family = draft.font_family || 'theme';
            document.getElementById('terminalFontName').textContent = Object.hasOwn(bundledFonts, family)
                ? bundledFonts[family] : (family === 'theme' ? t('terminalAppearance.themeDefault') : family);
            const revision = ++previewRevision;
            const bundled = Object.hasOwn(bundledFonts, family);
            fontStatus.textContent = t(bundled ? 'terminalAppearance.fontLoading' : 'terminalAppearance.localPreview');
            const selectedFont = loadFont(family).then(loaded => {
                // An icon-font retry can remain pending in some browsers. Report
                // the selected text font's result without waiting for that retry.
                if (revision === previewRevision && bundled) {
                    fontStatus.textContent = t(loaded ? 'terminalAppearance.fontReady' : 'terminalAppearance.fontFailed');
                }
                return loaded;
            });
            const [, iconsLoaded] = await Promise.all([selectedFont, loadFont(symbolFont)]);
            if (revision !== previewRevision) return;
            if (!iconsLoaded) fontStatus.textContent = t('terminalAppearance.iconsFailed');
            if (preview && modal.classList.contains('show')) {
                Object.assign(preview.options, resolve(draft, manager.buildTheme(), manager.getMonoFont(), manager.getResponsiveFontSize()).options);
                fit.fit();
                preview.refresh(0, preview.rows - 1);
            }
        }
        function renderControls() {
            const base = manager.buildTheme();
            const colors = {background: base.background, foreground: base.foreground, cursor_color: base.cursor, selection_background: '#587899'};
            const defaults = {font_family: 'theme', font_size: '', line_height: 1, letter_spacing: 0, font_weight: 'normal', background_opacity: 100, cursor_style: 'block', cursor_blink: true};
            controls.forEach(control => {
                const key = control.dataset.appearance;
                if (control.type === 'checkbox') control.checked = draft[key] ?? defaults[key];
                else control.value = draft[key] ?? colors[key] ?? defaults[key];
            });
            form.querySelectorAll('[data-color-override]').forEach(control => {
                control.checked = Boolean(draft[control.dataset.colorOverride]);
                form.querySelector(`[data-appearance="${control.dataset.colorOverride}"]`).disabled = !control.checked;
            });
            syncFontControls();
            updatePreview();
        }
        function open() {
            window.mobileAppShell?.closeMoreMenu();
            draft = {...preferences};
            status.textContent = '';
            renderControls();
            requestAnimationFrame(() => {
                // The mobile menu restores its focus in this frame first.
                window.ModalManager.open(modal);
                if (!preview) {
                    preview = new Terminal({...resolve(draft, manager.buildTheme(), manager.getMonoFont(), manager.getResponsiveFontSize()).options, rows: 6, disableStdin: true, scrollback: 0});
                    fit = new FitAddon.FitAddon();
                    preview.loadAddon(fit);
                    preview.open(previewElement);
                    paintSample();
                }
                updatePreview();
            });
        }
        document.querySelectorAll('[data-open-terminal-appearance]').forEach(button => button.addEventListener('click', open));
        modal.querySelectorAll('[data-close-terminal-appearance]').forEach(button => button.addEventListener('click', () => window.ModalManager.close(modal)));
        sample.addEventListener('change', paintSample);
        fontRadios.forEach(radio => radio.addEventListener('change', () => {
            if (!radio.checked) return;
            status.textContent = '';
            draft.font_family = radio.value === 'custom' ? localName : radio.value;
            syncFontControls();
            updatePreview();
        }));
        controls.forEach(control => control.addEventListener('input', () => {
            status.textContent = '';
            const key = control.dataset.appearance;
            if (control.type === 'checkbox') draft[key] = control.checked;
            else if (control.type === 'number' || control.type === 'range') draft[key] = control.value === '' ? null : Number(control.value);
            else draft[key] = control.value;
            if (key === 'font_family') localName = control.value;
            updatePreview();
        }));
        form.querySelectorAll('[data-color-override]').forEach(control => control.addEventListener('change', () => {
            status.textContent = '';
            const key = control.dataset.colorOverride;
            const picker = form.querySelector(`[data-appearance="${key}"]`);
            picker.disabled = !control.checked;
            if (control.checked) draft[key] = picker.value;
            else delete draft[key];
            updatePreview();
        }));
        document.getElementById('terminalAppearanceReset').addEventListener('click', () => {
            draft = {};
            renderControls();
            status.textContent = t('terminalAppearance.resetHint');
        });
        form.addEventListener('submit', async event => {
            event.preventDefault();
            if (saving || !form.reportValidity()) return;
            saving = true;
            const submitted = {...draft};
            const submit = document.getElementById('terminalAppearanceSave');
            submit.disabled = true;
            form.querySelectorAll('fieldset').forEach(fieldset => { fieldset.disabled = true; });
            document.getElementById('terminalAppearanceReset').disabled = true;
            status.textContent = t('terminalAppearance.saving');
            try {
                const appRoot = (document.querySelector('meta[name="app-root"]')?.content || '').replace(/\/$/, '');
                const response = await fetch(`${appRoot}/api/account/preferences`, {
                    method: 'POST', headers: {'Content-Type': 'application/json', 'Accept': 'application/json', 'X-CSRFToken': document.querySelector('meta[name="csrf-token"]')?.content || ''},
                    body: JSON.stringify({terminal_appearance: submitted}),
                });
                const result = await response.json();
                if (!response.ok || !result.settings?.terminal_appearance) throw new Error('Save failed');
                setPreferences(result.settings.terminal_appearance);
                manager.applyThemeToAll();
                refreshSavedFont();
                status.textContent = t('terminalAppearance.saved');
            } catch {
                status.textContent = t('terminalAppearance.failed');
            } finally {
                saving = false;
                submit.disabled = false;
                form.querySelectorAll('fieldset').forEach(fieldset => { fieldset.disabled = false; });
                document.getElementById('terminalAppearanceReset').disabled = false;
                syncFontControls();
                form.querySelectorAll('[data-color-override]').forEach(control => {
                    form.querySelector(`[data-appearance="${control.dataset.colorOverride}"]`).disabled = !control.checked;
                });
            }
        });
        const refreshPreview = () => {
            if (modal.classList.contains('show')) updatePreview();
        };
        window.addEventListener('resize', refreshPreview);
        window.addEventListener('themeChanged', refreshPreview);
        function refreshSavedFont() {
            return loadForTerminal(manager);
        }
        // A timed-out font can still finish later. Refit both live sessions and
        // the preview then, without changing the user's selection.
        document.fonts?.addEventListener?.('loadingdone', () => {
            applyLoadedFont(manager);
            if (preview && modal.classList.contains('show')) updatePreview();
        });
        refreshSavedFont();
        manager.updateAppearanceSurface();
    }
    if (typeof document !== 'undefined') document.addEventListener('DOMContentLoaded', init);
    return {resolve, getPreferences, setPreferences, bundledFonts, loadFont, loadForTerminal, samples};
}));
