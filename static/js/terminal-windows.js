/*
 * Floating terminal windows for the workspace desktop.
 *
 * The geometry helpers are pure and shared with the unit tests. The desktop
 * controller only owns window chrome, stacking, and pointer interaction; the
 * session manager decides what each window shows and when sessions end.
 */
(function (root, factory) {
    const api = factory(root);
    if (typeof module === 'object' && module.exports) module.exports = api;
    if (root?.document) root.TerminalWindows = api;
}(typeof globalThis !== 'undefined' ? globalThis : this, function (root) {
    'use strict';

    const MIN_WIDTH = 320;
    const MIN_HEIGHT = 180;
    const TITLE_HEIGHT = 36;
    const SNAP_THRESHOLD = 14;
    const CASCADE_STEP = 30;
    const GAP = 8;
    const TERMINAL_ASPECT = 1.6;
    const EDGES = ['n', 's', 'e', 'w', 'ne', 'nw', 'se', 'sw'];
    const SVG_NS = 'http://www.w3.org/2000/svg';

    function finite(value, fallback = 0) {
        const number = Number(value);
        return Number.isFinite(number) ? number : fallback;
    }

    function clamp(value, min, max) {
        return Math.min(Math.max(value, min), Math.max(min, max));
    }

    function minimumSize(bounds, min = {}) {
        return {
            width: Math.min(finite(min?.width, MIN_WIDTH), bounds.width),
            height: Math.min(finite(min?.height, MIN_HEIGHT), bounds.height),
        };
    }

    // Keep the entire terminal and its controls inside the available workspace.
    function clampRect(rect, bounds, min) {
        const size = minimumSize(bounds, min);
        const width = clamp(Math.round(finite(rect.width, size.width)), size.width, bounds.width);
        const height = clamp(Math.round(finite(rect.height, size.height)), size.height, bounds.height);
        return {
            x: clamp(Math.round(finite(rect.x)), 0, bounds.width - width),
            y: clamp(Math.round(finite(rect.y)), 0, bounds.height - height),
            width,
            height,
        };
    }

    // Edges stop at the desktop border unless the window already hangs past it.
    function resizeRect(start, edge, dx, dy, bounds, min) {
        const size = minimumSize(bounds, min);
        let left = start.x;
        let top = start.y;
        let right = start.x + start.width;
        let bottom = start.y + start.height;
        if (edge.includes('w')) left = clamp(left + dx, Math.min(0, start.x), right - size.width);
        if (edge.includes('e')) right = clamp(right + dx, left + size.width, Math.max(bounds.width, right));
        if (edge.includes('n')) top = clamp(top + dy, 0, bottom - size.height);
        if (edge.includes('s')) bottom = clamp(bottom + dy, top + size.height, Math.max(bounds.height, bottom));
        const width = Math.min(right - left, bounds.width);
        const height = Math.min(bottom - top, bounds.height);
        if (edge.includes('w')) left = right - width;
        if (edge.includes('n')) top = bottom - height;
        return {
            x: Math.round(left),
            y: Math.round(top),
            width: Math.round(width),
            height: Math.round(height),
        };
    }

    function snapZone(point, bounds, threshold = SNAP_THRESHOLD) {
        const nearLeft = point.x <= threshold;
        const nearRight = point.x >= bounds.width - threshold;
        const nearTop = point.y <= threshold;
        const nearBottom = point.y >= bounds.height - threshold;
        if (nearTop && nearLeft) return 'top-left';
        if (nearTop && nearRight) return 'top-right';
        if (nearBottom && nearLeft) return 'bottom-left';
        if (nearBottom && nearRight) return 'bottom-right';
        if (nearLeft) return 'left';
        if (nearRight) return 'right';
        if (nearTop) return 'maximize';
        return null;
    }

    function snapRect(zone, bounds, gap = GAP) {
        const halfWidth = Math.round((bounds.width - gap * 3) / 2);
        const halfHeight = Math.round((bounds.height - gap * 3) / 2);
        const rightX = bounds.width - gap - halfWidth;
        const bottomY = bounds.height - gap - halfHeight;
        const fullHeight = bounds.height - gap * 2;
        switch (zone) {
        case 'left': return {x: gap, y: gap, width: halfWidth, height: fullHeight};
        case 'right': return {x: rightX, y: gap, width: halfWidth, height: fullHeight};
        case 'top-left': return {x: gap, y: gap, width: halfWidth, height: halfHeight};
        case 'top-right': return {x: rightX, y: gap, width: halfWidth, height: halfHeight};
        case 'bottom-left': return {x: gap, y: bottomY, width: halfWidth, height: halfHeight};
        case 'bottom-right': return {x: rightX, y: bottomY, width: halfWidth, height: halfHeight};
        case 'maximize': return {x: 0, y: 0, width: bounds.width, height: bounds.height};
        default: return null;
        }
    }

    function defaultSize(bounds) {
        return {
            width: Math.round(clamp(bounds.width * 0.58, Math.min(MIN_WIDTH, bounds.width), 980)),
            height: Math.round(clamp(bounds.height * 0.62, Math.min(MIN_HEIGHT, bounds.height), 640)),
        };
    }

    // Place a new window one step down-right of the newest window, wrapping
    // back to the top-left when the next step would leave the desktop.
    function cascadeRect(rects, bounds, size = defaultSize(bounds)) {
        const width = Math.min(size.width, bounds.width);
        const height = Math.min(size.height, bounds.height);
        const maxX = Math.max(0, bounds.width - width);
        const maxY = Math.max(0, bounds.height - height);
        const start = {x: Math.min(48, maxX), y: Math.min(36, maxY)};
        const taken = new Set((rects || []).map(rect => `${Math.round(rect.x)}:${Math.round(rect.y)}`));
        const last = rects?.length ? rects[rects.length - 1] : null;
        let x = last ? last.x + CASCADE_STEP : start.x;
        let y = last ? last.y + CASCADE_STEP : start.y;
        for (let attempt = 0; attempt < 64; attempt += 1) {
            if (x > maxX || y > maxY) {
                x = Math.min(start.x + (attempt % 8) * CASCADE_STEP, maxX);
                y = start.y;
            }
            if (!taken.has(`${Math.round(x)}:${Math.round(y)}`)) break;
            x += CASCADE_STEP;
            y += CASCADE_STEP;
        }
        return clampRect({x, y, width, height}, bounds);
    }

    function cascadeLayout(count, bounds) {
        const size = defaultSize(bounds);
        const span = Math.max(1, Math.floor(Math.min(
            (bounds.width - size.width - 24) / CASCADE_STEP,
            (bounds.height - size.height - 20) / CASCADE_STEP,
        )) + 1);
        const rects = [];
        for (let index = 0; index < count; index += 1) {
            const step = index % span;
            rects.push(clampRect({
                x: 24 + step * CASCADE_STEP,
                y: 20 + step * CASCADE_STEP,
                width: size.width,
                height: size.height,
            }, bounds));
        }
        return rects;
    }

    // Pick the grid whose cells come closest to a comfortable terminal shape;
    // the last row stretches so the desktop is filled without holes.
    function tileLayout(count, bounds, gap = GAP) {
        if (count <= 0) return [];
        let best = null;
        for (let columns = 1; columns <= count; columns += 1) {
            const rows = Math.ceil(count / columns);
            const cellWidth = (bounds.width - gap * (columns + 1)) / columns;
            const cellHeight = (bounds.height - gap * (rows + 1)) / rows;
            if (cellWidth <= 0 || cellHeight <= 0) continue;
            const score = Math.abs(Math.log((cellWidth / cellHeight) / TERMINAL_ASPECT))
                + (columns * rows - count) * 0.25;
            if (!best || score < best.score) best = {columns, rows, score};
        }
        const {columns, rows} = best || {columns: 1, rows: count};
        const rowHeight = (bounds.height - gap * (rows + 1)) / rows;
        const rects = [];
        for (let row = 0; row < rows; row += 1) {
            const inRow = row === rows - 1 ? count - columns * (rows - 1) : columns;
            const columnWidth = (bounds.width - gap * (inRow + 1)) / inRow;
            for (let column = 0; column < inRow; column += 1) {
                rects.push({
                    x: Math.round(gap + column * (columnWidth + gap)),
                    y: Math.round(gap + row * (rowHeight + gap)),
                    width: Math.round(columnWidth),
                    height: Math.round(rowHeight),
                });
            }
        }
        return rects;
    }

    function toFraction(rect, bounds) {
        const width = Math.max(1, bounds.width);
        const height = Math.max(1, bounds.height);
        return {
            x: rect.x / width,
            y: rect.y / height,
            width: rect.width / width,
            height: rect.height / height,
        };
    }

    function fromFraction(fraction, bounds, min) {
        return clampRect({
            x: finite(fraction?.x) * bounds.width,
            y: finite(fraction?.y) * bounds.height,
            width: finite(fraction?.width, 0.5) * bounds.width,
            height: finite(fraction?.height, 0.5) * bounds.height,
        }, bounds, min);
    }

    function validFraction(value) {
        if (!value || typeof value !== 'object') return null;
        const fraction = {
            x: Number(value.x),
            y: Number(value.y),
            width: Number(value.width),
            height: Number(value.height),
        };
        const ok = Object.values(fraction).every(Number.isFinite)
            && fraction.width > 0 && fraction.height > 0
            && fraction.width <= 1.01 && fraction.height <= 1.01
            && fraction.x > -1 && fraction.x < 1
            && fraction.y >= -0.01 && fraction.y < 1;
        return ok ? fraction : null;
    }

    function prefersReducedMotion() {
        try {
            return Boolean(root?.matchMedia?.('(prefers-reduced-motion: reduce)').matches);
        } catch {
            return false;
        }
    }

    const ICONS = {
        minimize: ['M3.5 8.5h9'],
        maximize: ['M4 4h8v8H4z'],
        restore: ['M6 3.5h6.5V10', 'M3.5 6h6.5v6.5H3.5z'],
        close: ['M4.5 4.5l7 7', 'M11.5 4.5l-7 7'],
    };

    function createDesktop(element, options = {}) {
        const doc = element.ownerDocument;
        const win = doc.defaultView || root;
        const callbacks = options;
        const windows = new Map();
        let order = [];
        let bounds = {width: 0, height: 0};
        let interaction = null;
        let resizeObserver = null;
        let destroyed = false;

        function label(key, fallback) {
            const value = typeof callbacks.label === 'function' ? callbacks.label(key) : null;
            return value && value !== key ? value : fallback;
        }

        function svgIcon(paths) {
            const svg = doc.createElementNS(SVG_NS, 'svg');
            svg.setAttribute('viewBox', '0 0 16 16');
            svg.setAttribute('aria-hidden', 'true');
            svg.setAttribute('focusable', 'false');
            paths.forEach(d => {
                const path = doc.createElementNS(SVG_NS, 'path');
                path.setAttribute('d', d);
                svg.appendChild(path);
            });
            return svg;
        }

        const preview = doc.createElement('div');
        preview.className = 'ws-snap-preview';
        preview.hidden = true;
        element.appendChild(preview);

        const empty = doc.createElement('div');
        empty.className = 'ws-desktop-empty';
        empty.hidden = true;
        element.appendChild(empty);

        // A hidden desktop has no size yet; lay out against the viewport and
        // let the resize observer settle the real geometry once it shows.
        function measure() {
            const width = element.clientWidth;
            const height = element.clientHeight;
            if (width > 0 && height > 0) {
                bounds = {width, height};
            } else if (!bounds.width || !bounds.height) {
                bounds = {
                    width: Math.max(MIN_WIDTH, finite(win.innerWidth, 1280) - 32),
                    height: Math.max(MIN_HEIGHT, finite(win.innerHeight, 800) - 160),
                };
            }
            return bounds;
        }

        function minimumFor(state) {
            // A dense tiled layout must remain non-overlapping. Manual resize
            // keeps the normal minimum; tile cells may be smaller than it.
            return state.tiled ? {width: 1, height: TITLE_HEIGHT + 1} : callbacks.minSize;
        }

        function currentRect(state) {
            if (state.maximized) return {x: 0, y: 0, width: bounds.width, height: bounds.height};
            return fromFraction(state.fraction, bounds, minimumFor(state));
        }

        function applyRect(state, rect) {
            const style = state.frame.style;
            style.left = `${rect.x}px`;
            style.top = `${rect.y}px`;
            style.width = `${rect.width}px`;
            style.height = `${rect.height}px`;
            state.frame.classList.toggle('is-compact', rect.width < 460);
        }

        function layoutWindow(state) {
            applyRect(state, currentRect(state));
        }

        // The snap preview sits just under the front window, which is the
        // one being dragged, and above everything else.
        function stack() {
            order = order.filter(index => windows.has(index));
            order.forEach((index, position) => {
                windows.get(index).frame.style.zIndex = String((position + 1) * 2);
            });
            preview.style.zIndex = String(Math.max(1, order.length * 2 - 1));
        }

        function visibleOrder() {
            return order.filter(index => windows.has(index) && !windows.get(index).minimized);
        }

        function refreshEmpty({rerender = false} = {}) {
            const show = !destroyed && visibleOrder().length === 0;
            if (show && (rerender || !empty.childElementCount)) {
                empty.replaceChildren();
                callbacks.renderEmpty?.(empty);
            }
            empty.hidden = !show;
            element.classList.toggle('ws-desktop-is-empty', show);
        }

        function animate(state, target, keyframes, duration) {
            state.animation?.cancel();
            state.animation = null;
            if (prefersReducedMotion() || typeof target.animate !== 'function') {
                return Promise.resolve();
            }
            try {
                const animation = target.animate(keyframes, {
                    duration,
                    easing: 'cubic-bezier(0.22, 1, 0.36, 1)',
                });
                state.animation = animation;
                return animation.finished.catch(() => undefined).then(() => {
                    if (state.animation === animation) state.animation = null;
                });
            } catch {
                return Promise.resolve();
            }
        }

        function notifyLayout(state, final) {
            callbacks.onLayout?.(state.index, {final});
        }

        // Geometry jumps (maximize, snap, tile) glide; dragging never does.
        // The terminal refits once, after the frame settles.
        function glide(state) {
            const reduced = prefersReducedMotion();
            if (!reduced) state.frame.classList.add('is-gliding');
            win.clearTimeout(state.glideTimer);
            state.glideTimer = win.setTimeout(() => {
                state.frame.classList.remove('is-gliding');
                if (windows.get(state.index) === state) notifyLayout(state, true);
            }, reduced ? 0 : 210);
        }

        function iconButton(kind, action, text) {
            const button = doc.createElement('button');
            button.type = 'button';
            button.className = `ws-window-btn ws-window-${kind}`;
            button.dataset.windowAction = action;
            button.setAttribute('aria-label', text);
            button.title = text;
            button.appendChild(svgIcon(ICONS[kind]));
            return button;
        }

        function updateButtons(state) {
            const maximizeText = state.maximized
                ? label('windows.restore', 'Restore')
                : label('windows.maximize', 'Maximize');
            state.maximizeButton.replaceChildren(svgIcon(ICONS[state.maximized ? 'restore' : 'maximize']));
            state.maximizeButton.setAttribute('aria-label', maximizeText);
            state.maximizeButton.title = maximizeText;
            const minimizeText = label('windows.minimize', 'Minimize');
            state.minimizeButton.setAttribute('aria-label', minimizeText);
            state.minimizeButton.title = minimizeText;
            const closeText = state.closeLabel || label('windows.close', 'Close window');
            state.closeButton.setAttribute('aria-label', closeText);
            state.closeButton.title = closeText;
            state.titlebar.setAttribute('aria-label', label('windows.move', 'Move window'));
            const hint = label('windows.keyboardHint', 'Arrow keys: move. Alt + arrow keys: resize. Enter: maximize or restore.');
            state.titlebar.setAttribute('aria-description', hint);
            state.titlebar.title = hint;
            state.frame.classList.toggle('is-maximized', state.maximized);
        }

        function build(index) {
            const frame = doc.createElement('section');
            frame.className = 'ws-window';
            frame.dataset.windowIndex = String(index);

            const titlebar = doc.createElement('div');
            titlebar.className = 'ws-window-titlebar';
            titlebar.setAttribute('role', 'group');
            titlebar.tabIndex = 0;

            const status = doc.createElement('span');
            status.className = 'ws-window-status';
            status.setAttribute('aria-hidden', 'true');

            const heading = doc.createElement('div');
            heading.className = 'ws-window-heading';
            const title = doc.createElement('span');
            title.className = 'ws-window-title';
            const subtitle = doc.createElement('span');
            subtitle.className = 'ws-window-subtitle';
            heading.append(title, subtitle);

            const badges = doc.createElement('span');
            badges.className = 'ws-window-badges';

            const actions = doc.createElement('div');
            actions.className = 'ws-window-actions';
            const minimizeButton = iconButton('minimize', 'minimize', label('windows.minimize', 'Minimize'));
            const maximizeButton = iconButton('maximize', 'maximize', label('windows.maximize', 'Maximize'));
            const closeButton = iconButton('close', 'close', label('windows.close', 'Close window'));
            actions.append(minimizeButton, maximizeButton, closeButton);
            titlebar.append(status, heading, badges, actions);

            const body = doc.createElement('div');
            body.className = 'ws-window-body';
            const pane = doc.createElement('div');
            pane.className = 'terminal-pane';
            pane.dataset.paneIndex = String(index);
            body.appendChild(pane);

            frame.append(titlebar, body);
            EDGES.forEach(edge => {
                const handle = doc.createElement('div');
                handle.className = `ws-window-resize ws-resize-${edge}`;
                handle.dataset.edge = edge;
                handle.setAttribute('aria-hidden', 'true');
                frame.appendChild(handle);
            });

            const state = {
                index,
                frame,
                titlebar,
                status,
                title,
                subtitle,
                badges,
                pane,
                minimizeButton,
                maximizeButton,
                closeButton,
                closeLabel: null,
                fraction: null,
                restoreFraction: null,
                maximized: false,
                tiled: false,
                minimized: false,
                glideTimer: null,
                animation: null,
            };
            updateButtons(state);
            return state;
        }

        function focus(index) {
            if (!windows.has(index)) return;
            order = order.filter(item => item !== index);
            order.push(index);
            stack();
            windows.forEach(item => {
                item.frame.classList.toggle('is-focused', item.index === index && !item.minimized);
            });
        }

        function open(index, config = {}) {
            measure();
            let state = windows.get(index);
            const created = !state;
            if (!state) {
                state = build(index);
                windows.set(index, state);
                element.appendChild(state.frame);
            }
            const fraction = validFraction(config.fraction);
            if (fraction) {
                state.fraction = fraction;
            } else if (!state.fraction) {
                const others = order
                    .filter(item => item !== index && windows.has(item) && !windows.get(item).minimized)
                    .map(item => currentRect(windows.get(item)));
                state.fraction = toFraction(cascadeRect(others, bounds), bounds);
            }
            if (created || 'tiled' in config) state.tiled = config.tiled === true;
            if (created || 'maximized' in config) state.maximized = Boolean(config.maximized);
            state.restoreFraction = validFraction(config.restoreFraction) || state.restoreFraction;
            state.minimized = Boolean(config.minimized);
            state.frame.hidden = state.minimized;
            updateButtons(state);
            layoutWindow(state);
            if (!order.includes(index)) order.push(index);
            stack();
            refreshEmpty();
            if (created && !state.minimized && config.animate !== false) {
                animate(state, state.frame, [
                    {opacity: 0, transform: 'translateY(10px) scale(0.97)'},
                    {opacity: 1, transform: 'none'},
                ], 240);
            }
            return state.pane;
        }

        function close(index) {
            const state = windows.get(index);
            if (!state) return;
            windows.delete(index);
            order = order.filter(item => item !== index);
            stack();
            win.clearTimeout(state.glideTimer);
            // A slot may reopen at once; retire this frame's identity first.
            state.pane.removeAttribute('data-pane-index');
            state.frame.removeAttribute('data-window-index');
            state.frame.classList.add('is-closing');
            state.frame.classList.remove('is-focused');
            state.frame.inert = true;
            refreshEmpty();
            animate(state, state.frame, [
                {opacity: 1, transform: 'none'},
                {opacity: 0, transform: 'scale(0.96)'},
            ], 160).then(() => state.frame.remove());
        }

        function minimizeOffset(state) {
            const rect = callbacks.minimizeTarget?.(state.index);
            if (!rect || !rect.width) return null;
            const frame = state.frame.getBoundingClientRect();
            return {
                x: Math.round(rect.left + rect.width / 2 - (frame.left + frame.width / 2)),
                y: Math.round(rect.top + rect.height / 2 - (frame.top + frame.height / 2)),
            };
        }

        function minimizedTransform(offset) {
            return offset
                ? `translate(${offset.x}px, ${offset.y}px) scale(0.16)`
                : 'translateY(28px) scale(0.9)';
        }

        function minimize(index) {
            const state = windows.get(index);
            if (!state || state.minimized) return false;
            state.minimized = true;
            state.frame.classList.add('is-minimizing');
            state.frame.classList.remove('is-focused');
            const offset = minimizeOffset(state);
            refreshEmpty();
            callbacks.onMinimizeStart?.(index);
            animate(state, state.frame, [
                {opacity: 1, transform: 'none'},
                {opacity: 0, transform: minimizedTransform(offset)},
            ], 260).then(() => {
                if (!state.minimized || windows.get(index) !== state) return;
                state.frame.hidden = true;
                state.frame.classList.remove('is-minimizing');
                callbacks.onMinimized?.(index);
            });
            return true;
        }

        function restore(index) {
            const state = windows.get(index);
            if (!state || !state.minimized) return false;
            state.minimized = false;
            state.frame.classList.remove('is-minimizing');
            state.frame.hidden = false;
            measure();
            layoutWindow(state);
            refreshEmpty();
            callbacks.onRestored?.(index);
            const offset = minimizeOffset(state);
            animate(state, state.frame, [
                {opacity: 0, transform: minimizedTransform(offset)},
                {opacity: 1, transform: 'none'},
            ], 280);
            return true;
        }

        function setMaximized(index, maximized) {
            const state = windows.get(index);
            if (!state || state.maximized === maximized) return;
            measure();
            if (maximized) {
                state.restoreFraction = state.fraction;
                state.maximized = true;
            } else {
                state.maximized = false;
                if (state.restoreFraction) state.fraction = state.restoreFraction;
                state.restoreFraction = null;
            }
            updateButtons(state);
            glide(state);
            layoutWindow(state);
            callbacks.onChange?.(index);
        }

        function toggleMaximize(index) {
            const state = windows.get(index);
            if (state) setMaximized(index, !state.maximized);
        }

        function setRect(state, rect, {animated = false, tiled = false} = {}) {
            measure();
            state.maximized = false;
            state.restoreFraction = null;
            state.tiled = tiled;
            state.fraction = toFraction(clampRect(rect, bounds, minimumFor(state)), bounds);
            updateButtons(state);
            if (animated) glide(state);
            layoutWindow(state);
        }

        function arrange(mode, indices = visibleOrder(), {animated = true} = {}) {
            measure();
            const targets = indices.filter(index => windows.has(index) && !windows.get(index).minimized);
            if (!targets.length) return;
            const rects = mode === 'tile'
                ? tileLayout(targets.length, bounds)
                : cascadeLayout(targets.length, bounds);
            targets.forEach((index, position) => {
                setRect(windows.get(index), rects[position], {animated, tiled: mode === 'tile'});
                callbacks.onChange?.(index);
            });
            // Cascade restacks in placement order so every title bar shows.
            if (mode === 'cascade') targets.forEach(index => focus(index));
        }

        function setChrome(index, chrome = {}) {
            const state = windows.get(index);
            if (!state) return;
            state.title.textContent = chrome.title || '';
            state.subtitle.textContent = chrome.subtitle || '';
            state.subtitle.hidden = !chrome.subtitle;
            state.frame.setAttribute('aria-label', chrome.title || '');
            state.frame.dataset.status = chrome.status || 'idle';
            state.minimizeButton.hidden = chrome.minimizable === false;
            state.closeLabel = chrome.closeLabel || null;
            state.badges.replaceChildren(...(chrome.badges || []).map(badge => {
                const item = doc.createElement('span');
                item.className = 'ws-window-badge material-icons';
                item.textContent = badge.icon;
                item.title = badge.title || '';
                item.setAttribute('aria-label', badge.title || '');
                return item;
            }));
            updateButtons(state);
        }

        function relabel() {
            windows.forEach(state => updateButtons(state));
            refreshEmpty({rerender: true});
        }

        function snapshot(index) {
            const state = windows.get(index);
            if (!state) return null;
            return {
                fraction: state.fraction ? {...state.fraction} : null,
                restoreFraction: state.restoreFraction ? {...state.restoreFraction} : null,
                maximized: state.maximized,
                tiled: state.tiled,
                minimized: state.minimized,
                z: order.indexOf(index),
            };
        }

        // Pointer interaction ----------------------------------------------
        function localPoint(event) {
            const host = element.getBoundingClientRect();
            return {x: event.clientX - host.left, y: event.clientY - host.top};
        }

        function showPreview(zone) {
            const rect = zone ? snapRect(zone, bounds) : null;
            if (!rect) {
                preview.classList.remove('is-visible');
                preview.hidden = true;
                return;
            }
            const wasHidden = preview.hidden;
            preview.hidden = false;
            preview.style.left = `${rect.x}px`;
            preview.style.top = `${rect.y}px`;
            preview.style.width = `${rect.width}px`;
            preview.style.height = `${rect.height}px`;
            if (wasHidden) void preview.offsetWidth;
            preview.classList.add('is-visible');
        }

        function beginInteraction(event, state, kind, edge = null) {
            measure();
            interaction = {
                kind,
                edge,
                state,
                pointerId: event.pointerId,
                start: localPoint(event),
                rect: currentRect(state),
                moved: false,
                zone: null,
                frame: null,
                lastEvent: null,
                fitTimer: null,
                captureTarget: event.target,
            };
            try {
                event.target.setPointerCapture?.(event.pointerId);
            } catch {
                // Synthetic events cannot always be captured.
            }
            element.classList.add(kind === 'move' ? 'ws-is-dragging' : 'ws-is-resizing');
            if (edge) element.dataset.resizeEdge = edge;
            state.frame.classList.add('is-interacting');
        }

        // A maximized or snapped window dragged by its title bar returns to
        // its previous size, keeping the grab point under the pointer.
        function detachFromLayout(current, point) {
            const state = current.state;
            const restored = fromFraction(state.restoreFraction, bounds, callbacks.minSize);
            const ratio = current.rect.width
                ? (current.start.x - current.rect.x) / current.rect.width
                : 0.5;
            const offsetY = Math.min(current.start.y - current.rect.y, TITLE_HEIGHT - 4);
            state.maximized = false;
            state.restoreFraction = null;
            current.rect = clampRect({
                x: Math.round(point.x - restored.width * ratio),
                y: Math.round(point.y - offsetY),
                width: restored.width,
                height: restored.height,
            }, bounds, callbacks.minSize);
            current.start = point;
            state.fraction = toFraction(current.rect, bounds);
            updateButtons(state);
            applyRect(state, current.rect);
            notifyLayout(state, false);
        }

        function applyInteraction() {
            const current = interaction;
            if (!current?.lastEvent) return;
            current.frame = null;
            const point = localPoint(current.lastEvent);
            const state = current.state;
            if (current.kind === 'move') {
                if (state.restoreFraction) {
                    detachFromLayout(current, point);
                    return;
                }
                const next = clampRect({
                    x: current.rect.x + point.x - current.start.x,
                    y: current.rect.y + point.y - current.start.y,
                    width: current.rect.width,
                    height: current.rect.height,
                }, bounds, minimumFor(state));
                applyRect(state, next);
                state.fraction = toFraction(next, bounds);
                const zone = snapZone(point, bounds);
                if (zone !== current.zone) {
                    current.zone = zone;
                    showPreview(zone);
                }
                return;
            }
            const next = resizeRect(
                current.rect,
                current.edge,
                point.x - current.start.x,
                point.y - current.start.y,
                bounds,
                callbacks.minSize,
            );
            applyRect(state, next);
            state.fraction = toFraction(next, bounds);
            state.restoreFraction = null;
            // Refit at a gentle rate while resizing; the final fit runs on release.
            if (current.fitTimer === null) {
                current.fitTimer = win.setTimeout(() => {
                    current.fitTimer = null;
                    if (interaction === current) notifyLayout(state, false);
                }, 70);
            }
        }

        function onPointerMove(event) {
            const current = interaction;
            if (!current || event.pointerId !== current.pointerId) return;
            if (!current.moved) {
                const point = localPoint(event);
                if (Math.hypot(point.x - current.start.x, point.y - current.start.y) < 4) return;
                current.moved = true;
            }
            event.preventDefault();
            current.lastEvent = event;
            if (current.frame === null) {
                current.frame = win.requestAnimationFrame(applyInteraction);
            }
        }

        function endInteraction(event) {
            const current = interaction;
            if (!current || (event && event.pointerId !== current.pointerId)) return;
            const cancelled = !event || event.type === 'pointercancel';
            if (current.frame !== null) {
                win.cancelAnimationFrame(current.frame);
                current.frame = null;
                if (!cancelled) applyInteraction();
            }
            win.clearTimeout(current.fitTimer);
            interaction = null;
            try {
                current.captureTarget?.releasePointerCapture?.(current.pointerId);
            } catch {
                // The capture may already be gone.
            }
            element.classList.remove('ws-is-dragging', 'ws-is-resizing');
            delete element.dataset.resizeEdge;
            current.state.frame.classList.remove('is-interacting');
            showPreview(null);
            const state = current.state;
            if (windows.get(state.index) !== state) return;
            callbacks.onInteractionEnd?.(state.index);
            if (!current.moved) return;
            if (current.kind === 'move' && current.zone && !cancelled) {
                const before = toFraction(current.rect, bounds);
                if (current.zone === 'maximize') {
                    state.restoreFraction = before;
                    state.maximized = true;
                    updateButtons(state);
                    glide(state);
                    layoutWindow(state);
                } else {
                    setRect(state, snapRect(current.zone, bounds), {animated: true});
                    state.restoreFraction = before;
                }
            } else {
                notifyLayout(state, true);
            }
            callbacks.onChange?.(state.index);
        }

        function windowIndex(target) {
            const frame = target?.closest?.('.ws-window');
            if (!frame || frame.parentElement !== element) return null;
            const index = Number(frame.dataset.windowIndex);
            return windows.has(index) ? index : null;
        }

        function onPointerDown(event) {
            const index = windowIndex(event.target);
            if (index === null) return;
            const state = windows.get(index);
            const wasFocused = order[order.length - 1] === index;
            focus(index);
            if (!wasFocused) callbacks.onActivate?.(index);
            if (event.pointerType === 'mouse' && event.button !== 0) return;
            if (interaction) return;
            const handle = event.target.closest('.ws-window-resize');
            if (handle) {
                if (state.maximized) return;
                event.preventDefault();
                state.tiled = false;
                beginInteraction(event, state, 'resize', handle.dataset.edge);
                return;
            }
            if (event.target.closest('.ws-window-titlebar') && !event.target.closest('.ws-window-btn')) {
                // Keep keyboard focus with the window content while dragging.
                event.preventDefault();
                beginInteraction(event, state, 'move');
            }
        }

        function onFocusIn(event) {
            const index = windowIndex(event.target);
            if (index === null || order[order.length - 1] === index) return;
            // Keyboard navigation must select the same session as pointer focus.
            // Keep the focused title/button after the session manager fits xterm.
            focus(index);
            callbacks.onActivate?.(index);
            event.target.focus?.({preventScroll: true});
        }

        function onClick(event) {
            const button = event.target.closest?.('.ws-window-btn');
            if (!button) return;
            const index = windowIndex(button);
            if (index === null) return;
            event.stopPropagation();
            const action = button.dataset.windowAction;
            if (action === 'minimize') callbacks.onMinimizeRequest?.(index);
            else if (action === 'maximize') toggleMaximize(index);
            else if (action === 'close') callbacks.onCloseRequest?.(index);
        }

        function onDoubleClick(event) {
            if (!event.target.closest?.('.ws-window-titlebar') || event.target.closest('.ws-window-btn')) return;
            const index = windowIndex(event.target);
            if (index !== null) toggleMaximize(index);
        }

        function onKeyDown(event) {
            const titlebar = event.target.closest?.('.ws-window-titlebar');
            if (!titlebar || event.target !== titlebar) return;
            const index = windowIndex(titlebar);
            if (index === null) return;
            const state = windows.get(index);
            if (event.key === 'Enter' || event.key === ' ') {
                event.preventDefault();
                toggleMaximize(index);
                return;
            }
            const step = event.shiftKey ? 48 : 16;
            const move = {
                ArrowLeft: [-step, 0],
                ArrowRight: [step, 0],
                ArrowUp: [0, -step],
                ArrowDown: [0, step],
            }[event.key];
            if (!move || state.maximized) return;
            event.preventDefault();
            const rect = currentRect(state);
            setRect(state, event.altKey
                ? {...rect, width: rect.width + move[0], height: rect.height + move[1]}
                : {...rect, x: rect.x + move[0], y: rect.y + move[1]},
            {tiled: state.tiled && !event.altKey});
            notifyLayout(state, true);
            callbacks.onChange?.(index);
        }

        function reflow() {
            if (destroyed) return;
            const previous = bounds;
            measure();
            if (previous.width === bounds.width && previous.height === bounds.height) return;
            windows.forEach(state => {
                if (!state.minimized) layoutWindow(state);
            });
            callbacks.onReflow?.();
        }

        element.addEventListener('pointerdown', onPointerDown, true);
        element.addEventListener('click', onClick, true);
        element.addEventListener('focusin', onFocusIn);
        element.addEventListener('dblclick', onDoubleClick);
        element.addEventListener('keydown', onKeyDown);
        win.addEventListener('pointermove', onPointerMove, {passive: false});
        win.addEventListener('pointerup', endInteraction);
        win.addEventListener('pointercancel', endInteraction);
        if (typeof win.ResizeObserver === 'function') {
            resizeObserver = new win.ResizeObserver(reflow);
            resizeObserver.observe(element);
        } else {
            win.addEventListener('resize', reflow);
        }
        measure();

        function destroy() {
            if (destroyed) return;
            endInteraction();
            destroyed = true;
            element.removeEventListener('pointerdown', onPointerDown, true);
            element.removeEventListener('click', onClick, true);
            element.removeEventListener('focusin', onFocusIn);
            element.removeEventListener('dblclick', onDoubleClick);
            element.removeEventListener('keydown', onKeyDown);
            win.removeEventListener('pointermove', onPointerMove);
            win.removeEventListener('pointerup', endInteraction);
            win.removeEventListener('pointercancel', endInteraction);
            win.removeEventListener('resize', reflow);
            resizeObserver?.disconnect();
            windows.forEach(state => {
                win.clearTimeout(state.glideTimer);
                state.animation?.cancel();
            });
            windows.clear();
            order = [];
            preview.remove();
            empty.remove();
            element.classList.remove('ws-desktop-is-empty', 'ws-is-dragging', 'ws-is-resizing');
        }

        return {
            open,
            close,
            focus,
            minimize,
            restore,
            setMaximized,
            toggleMaximize,
            arrange,
            setChrome,
            relabel,
            snapshot,
            reflow,
            destroy,
            refreshEmpty,
            isOpen: index => windows.has(index),
            isMinimized: index => Boolean(windows.get(index)?.minimized),
            isMaximized: index => Boolean(windows.get(index)?.maximized),
            frame: index => windows.get(index)?.frame || null,
            topMost() {
                const visible = visibleOrder();
                return visible.length ? visible[visible.length - 1] : null;
            },
            order: () => order.slice(),
            visibleOrder,
            bounds: () => ({...measure()}),
        };
    }

    return {
        MIN_WIDTH,
        MIN_HEIGHT,
        TITLE_HEIGHT,
        clampRect,
        resizeRect,
        snapZone,
        snapRect,
        defaultSize,
        cascadeRect,
        cascadeLayout,
        tileLayout,
        toFraction,
        fromFraction,
        validFraction,
        createDesktop,
    };
}));
