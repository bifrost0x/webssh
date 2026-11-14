/* Overview panel layout: a 12-column board the account can rearrange.
 * Pure layout functions are exported for tests; createBoard() binds them to
 * the DOM. Panels pack densely in 8px rows, so panels of different heights
 * fill the gaps beside each other instead of leaving empty bands. */
(function (root, factory) {
    const api = factory();
    if (typeof module === 'object' && module.exports) module.exports = api;
    if (root?.document) root.OverviewLayout = api;
}(typeof globalThis !== 'undefined' ? globalThis : this, function () {
    'use strict';

    const COLUMNS = 12;
    const ROW = 8;
    const MIN_WIDTH = 3;
    const MIN_HEIGHT = 8;
    const MAX_HEIGHT = 160;
    const DEFAULTS = [
        {id: 'kpis', w: 12, h: null, hidden: false},
        {id: 'topology', w: 8, h: null, hidden: false},
        {id: 'attention', w: 4, h: null, hidden: false},
        {id: 'automation', w: 4, h: null, hidden: false},
        {id: 'hosts', w: 8, h: null, hidden: false},
        {id: 'platforms', w: 4, h: null, hidden: false},
        {id: 'activity', w: 4, h: null, hidden: false},
    ];
    const PANELS = DEFAULTS.map(item => item.id);

    const clamp = (value, low, high) => Math.min(high, Math.max(low, value));
    // Match 14px at 60fps, without slowing down on busy renderers or jumping after a pause.
    const dragScrollDistance = elapsedMs => 840 * clamp(elapsedMs, 0, 100) / 1000;
    const defaults = () => DEFAULTS.map(item => ({...item}));

    /** Accept a stored layout, drop what is unknown and append new panels. */
    function normalize(stored) {
        if (!Array.isArray(stored)) return defaults();
        const seen = new Set();
        const result = [];
        stored.forEach(item => {
            if (!item || !PANELS.includes(item.id) || seen.has(item.id)) return;
            seen.add(item.id);
            const width = Number.isInteger(item.w) ? clamp(item.w, MIN_WIDTH, COLUMNS) : DEFAULTS.find(entry => entry.id === item.id).w;
            const height = Number.isInteger(item.h) ? clamp(item.h, MIN_HEIGHT, MAX_HEIGHT) : null;
            result.push({id: item.id, w: width, h: height, hidden: item.hidden === true});
        });
        DEFAULTS.forEach(item => { if (!seen.has(item.id)) result.push({...item}); });
        return result;
    }

    function isDefault(layout) {
        return JSON.stringify(normalize(layout)) === JSON.stringify(defaults());
    }

    function move(layout, id, offset) {
        const list = normalize(layout);
        const visible = list.filter(item => !item.hidden);
        const from = visible.findIndex(item => item.id === id);
        if (from < 0) return list;
        const to = clamp(from + offset, 0, visible.length - 1);
        if (to === from) return list;
        return moveBefore(list, id, offset > 0 ? visible[to + 1]?.id || null : visible[to].id);
    }

    /** Place `id` before `beforeId` (null: at the end). */
    function moveBefore(layout, id, beforeId) {
        const list = normalize(layout);
        const item = list.find(entry => entry.id === id);
        if (!item || id === beforeId) return list;
        const rest = list.filter(entry => entry.id !== id);
        const index = beforeId ? rest.findIndex(entry => entry.id === beforeId) : -1;
        rest.splice(index < 0 ? rest.length : index, 0, item);
        return rest;
    }

    function resize(layout, id, {w, h} = {}) {
        return normalize(layout).map(item => item.id !== id ? item : {
            ...item,
            w: w === undefined ? item.w : clamp(Math.round(w), MIN_WIDTH, COLUMNS),
            h: h === undefined ? item.h : h === null ? null : clamp(Math.round(h), MIN_HEIGHT, MAX_HEIGHT),
        });
    }

    function setHidden(layout, id, hidden) {
        return normalize(layout).map(item => item.id === id ? {...item, hidden: Boolean(hidden)} : item);
    }

    /** Grid rows a panel occupies for a rendered height, including the gap below it. */
    function rowsFor(pixelHeight, gap) {
        return Math.max(1, Math.ceil((pixelHeight + gap) / ROW));
    }

    /** Column span from a pointer offset measured from the panel's left edge. */
    function widthFromPointer(offset, boardWidth, gap) {
        const column = (boardWidth - gap * (COLUMNS - 1)) / COLUMNS;
        return clamp(Math.round((offset + gap) / (column + gap)), MIN_WIDTH, COLUMNS);
    }

    function heightFromPointer(offset, gap) {
        return clamp(Math.round((offset + gap) / ROW), MIN_HEIGHT, MAX_HEIGHT);
    }

    /**
     * Bind a board element. `panels` maps ids to their section; `save` gets the
     * normalized layout, or null for the default. Labels come from `label(id)`.
     */
    function createBoard({doc, win, board, stored, save, t, label, announce}) {
        let layout = normalize(stored);
        let editing = false;
        let saveTimer = 0;
        const sections = new Map([...board.querySelectorAll(':scope > [data-panel]')].map(section => [section.dataset.panel, section]));
        const gap = () => parseFloat(win.getComputedStyle(board).columnGap) || 20;
        const reduced = () => win.matchMedia?.('(prefers-reduced-motion: reduce)').matches;
        let pending = false;
        const flush = () => {
            win.clearTimeout(saveTimer);
            if (!pending) return;
            pending = false;
            save(isDefault(layout) ? null : layout);
        };
        const persist = () => {
            pending = true;
            win.clearTimeout(saveTimer);
            saveTimer = win.setTimeout(flush, 400);
        };

        function measure() {
            // Read every panel first, then write: interleaving forces a layout per panel.
            const visible = [...sections.values()].filter(section => !section.hidden && section.dataset.userHidden !== 'true');
            const spans = visible.map(section => {
                // The margin below a panel is its share of the gap (wider while editing).
                const below = parseFloat(win.getComputedStyle(section).marginBottom) || gap();
                return rowsFor(section.getBoundingClientRect().height, below);
            });
            visible.forEach((section, index) => { section.style.gridRowEnd = `span ${spans[index]}`; });
        }
        const observer = win.ResizeObserver ? new win.ResizeObserver(() => win.requestAnimationFrame(measure)) : null;
        sections.forEach(section => observer?.observe(section));

        /** FLIP: animate panels from their previous place to the new one. */
        function animate(change) {
            if (reduced()) { change(); return; }
            const before = new Map([...sections].map(([id, section]) => [id, section.getBoundingClientRect()]));
            change();
            sections.forEach((section, id) => {
                const from = before.get(id);
                const to = section.getBoundingClientRect();
                if (!from || !to.width || (from.left === to.left && from.top === to.top)) return;
                section.animate([{transform: `translate(${from.left - to.left}px, ${from.top - to.top}px)`}, {transform: 'none'}],
                    {duration: 260, easing: 'cubic-bezier(.2, .8, .2, 1)'});
            });
        }

        function apply() {
            layout.forEach((item, index) => {
                const section = sections.get(item.id);
                if (!section) return;
                section.style.order = String(index);
                section.style.setProperty('--od-span', String(item.w));
                if (item.h) section.style.setProperty('--od-height', `${item.h * ROW}px`);
                else section.style.removeProperty('--od-height');
                section.dataset.fixedHeight = String(Boolean(item.h));
                section.dataset.userHidden = String(item.hidden);
                section.dataset.width = String(item.w);
            });
            renderControls();
            measure();
        }

        function change(next, message) {
            animate(() => { layout = normalize(next); apply(); });
            persist();
            if (message) announce(message);
        }

        function controlButton(className, text, iconName, onClick) {
            const control = doc.createElement('button');
            control.type = 'button';
            control.className = className;
            control.setAttribute('aria-label', text);
            control.title = text;
            const glyph = doc.createElement('span');
            glyph.className = 'material-icons';
            glyph.setAttribute('aria-hidden', 'true');
            glyph.textContent = iconName;
            control.append(glyph);
            control.addEventListener('click', onClick);
            return control;
        }

        function renderControls() {
            sections.forEach((section, id) => {
                section.querySelector(':scope > .od-panel-tools')?.remove();
                section.querySelector(':scope > .od-resize')?.remove();
                if (!editing) return;
                const name = label(id);
                const item = layout.find(entry => entry.id === id);
                const tools = doc.createElement('div');
                tools.className = 'od-panel-tools';
                tools.setAttribute('role', 'group');
                tools.setAttribute('aria-label', t('overviewWorkspace.panelTools', 'Arrange {name}', {name}));
                const handle = controlButton('od-tool od-drag', t('overviewWorkspace.panelMoveHandle', 'Move {name}. Use arrow keys to move it earlier or later.', {name}), 'drag_indicator', () => {});
                handle.dataset.panelHandle = id;
                handle.addEventListener('keydown', event => {
                    const offset = {ArrowLeft: -1, ArrowUp: -1, ArrowRight: 1, ArrowDown: 1}[event.key];
                    if (!offset) return;
                    event.preventDefault();
                    const next = move(layout, id, offset);
                    const position = next.filter(entry => !entry.hidden).findIndex(entry => entry.id === id) + 1;
                    change(next, t('overviewWorkspace.panelMoved', '{name} moved to position {position}', {name, position}));
                    sections.get(id).querySelector('[data-panel-handle]')?.focus();
                });
                handle.addEventListener('pointerdown', event => startDrag(event, id));
                const size = doc.createElement('span');
                size.className = 'od-tool-size';
                size.textContent = `${item.w}/${COLUMNS}`;
                size.setAttribute('aria-hidden', 'true');
                const narrower = controlButton('od-tool', t('overviewWorkspace.panelNarrower', 'Make {name} narrower', {name}), 'remove', () => {
                    change(resize(layout, id, {w: item.w - 1}), t('overviewWorkspace.panelWidth', '{name}: width {width} of 12', {name, width: Math.max(MIN_WIDTH, item.w - 1)}));
                    sections.get(id).querySelector('[data-tool="narrower"]')?.focus();
                });
                narrower.dataset.tool = 'narrower';
                narrower.disabled = item.w <= MIN_WIDTH;
                const wider = controlButton('od-tool', t('overviewWorkspace.panelWider', 'Make {name} wider', {name}), 'add', () => {
                    change(resize(layout, id, {w: item.w + 1}), t('overviewWorkspace.panelWidth', '{name}: width {width} of 12', {name, width: Math.min(COLUMNS, item.w + 1)}));
                    sections.get(id).querySelector('[data-tool="wider"]')?.focus();
                });
                wider.dataset.tool = 'wider';
                wider.disabled = item.w >= COLUMNS;
                const autoHeight = controlButton('od-tool', t('overviewWorkspace.panelAutoHeight', 'Fit {name} to its content', {name}), 'unfold_less', () => {
                    change(resize(layout, id, {h: null}), t('overviewWorkspace.panelAutoHeightDone', '{name} fits its content', {name}));
                    sections.get(id).querySelector('[data-panel-handle]')?.focus();
                });
                autoHeight.hidden = !item.h;
                const hide = controlButton('od-tool', t('overviewWorkspace.panelHide', 'Hide {name}', {name}), 'visibility_off', () => {
                    change(setHidden(layout, id, true), t('overviewWorkspace.panelHidden', '{name} hidden', {name}));
                    doc.getElementById('odLayoutDone')?.focus();
                });
                tools.append(handle, size, narrower, wider, autoHeight, hide);
                const grip = doc.createElement('span');
                grip.className = 'od-resize';
                grip.setAttribute('aria-hidden', 'true');
                grip.title = t('overviewWorkspace.panelResize', 'Drag to resize');
                grip.addEventListener('pointerdown', event => startResize(event, id));
                section.append(tools, grip);
            });
            const tray = doc.getElementById('odHiddenPanels');
            if (tray) {
                tray.replaceChildren(...layout.filter(item => item.hidden).map(item => {
                    const name = label(item.id);
                    const add = doc.createElement('button');
                    add.type = 'button';
                    add.className = 'od-chip od-chip-button';
                    add.dataset.showPanel = item.id;
                    add.setAttribute('aria-label', t('overviewWorkspace.panelShow', 'Show {name}', {name}));
                    const glyph = doc.createElement('span');
                    glyph.className = 'material-icons';
                    glyph.setAttribute('aria-hidden', 'true');
                    glyph.textContent = 'add';
                    const text = doc.createElement('span');
                    text.textContent = name;
                    add.append(glyph, text);
                    add.addEventListener('click', () => {
                        change(setHidden(layout, item.id, false), t('overviewWorkspace.panelShown', '{name} shown', {name}));
                        sections.get(item.id)?.querySelector('[data-panel-handle]')?.focus();
                    });
                    return add;
                }));
                tray.hidden = !tray.children.length;
            }
        }

        function startDrag(event, id) {
            if (event.button !== 0) return;
            event.preventDefault();
            const section = sections.get(id);
            section.dataset.dragging = 'true';
            board.dataset.dragging = 'true';
            const pointer = event.pointerId;
            event.target.setPointerCapture?.(pointer);
            let last = null;
            let pointerX = event.clientX;
            let pointerY = event.clientY;
            let scrolling = 0;
            let previousFrame = win.performance.now();
            // Near the top or bottom edge the overview scrolls, so a panel can travel the whole board.
            const scroller = board.closest('#connectionOverview') || doc.scrollingElement;
            const autoScroll = timestamp => {
                const distance = dragScrollDistance(timestamp - previousFrame);
                previousFrame = timestamp;
                const frame = scroller.getBoundingClientRect();
                const edge = 70;
                const speed = pointerY < frame.top + edge ? -distance : pointerY > frame.bottom - edge ? distance : 0;
                if (speed) { scroller.scrollTop += speed; place(pointerX, pointerY); }
                scrolling = win.requestAnimationFrame(autoScroll);
            };
            scrolling = win.requestAnimationFrame(autoScroll);
            const onMove = moveEvent => {
                pointerX = moveEvent.clientX;
                pointerY = moveEvent.clientY;
                place(pointerX, pointerY);
            };
            const place = (x, y) => {
                const target = doc.elementsFromPoint(x, y)
                    .map(element => element.closest?.('#odBoard > [data-panel]')).find(element => element && element !== section);
                if (!target) return;
                const box = target.getBoundingClientRect();
                const after = target.dataset.width === '12'
                    ? y > box.top + box.height / 2
                    : x > box.left + box.width / 2;
                const visible = layout.filter(item => !item.hidden).map(item => item.id);
                const beforeId = after ? visible[visible.indexOf(target.dataset.panel) + 1] || null : target.dataset.panel;
                const key = `${beforeId}`;
                if (key === last || beforeId === id) return;
                last = key;
                animate(() => { layout = moveBefore(layout, id, beforeId); apply(); });
            };
            const onUp = () => {
                win.cancelAnimationFrame(scrolling);
                doc.removeEventListener('pointermove', onMove);
                doc.removeEventListener('pointerup', onUp);
                doc.removeEventListener('pointercancel', onUp);
                delete section.dataset.dragging;
                delete board.dataset.dragging;
                persist();
                const position = layout.filter(item => !item.hidden).findIndex(item => item.id === id) + 1;
                announce(t('overviewWorkspace.panelMoved', '{name} moved to position {position}', {name: label(id), position}));
            };
            doc.addEventListener('pointermove', onMove);
            doc.addEventListener('pointerup', onUp);
            doc.addEventListener('pointercancel', onUp);
        }

        function startResize(event, id) {
            if (event.button !== 0) return;
            event.preventDefault();
            const section = sections.get(id);
            const boardBox = board.getBoundingClientRect();
            const box = section.getBoundingClientRect();
            section.dataset.resizing = 'true';
            const onMove = moveEvent => {
                const w = widthFromPointer(moveEvent.clientX - box.left, boardBox.width, gap());
                const h = heightFromPointer(moveEvent.clientY - box.top, gap());
                const item = layout.find(entry => entry.id === id);
                if (item.w === w && item.h === h) return;
                layout = resize(layout, id, {w, h});
                apply();
            };
            const onUp = () => {
                doc.removeEventListener('pointermove', onMove);
                doc.removeEventListener('pointerup', onUp);
                doc.removeEventListener('pointercancel', onUp);
                delete section.dataset.resizing;
                persist();
                const item = layout.find(entry => entry.id === id);
                announce(t('overviewWorkspace.panelWidth', '{name}: width {width} of 12', {name: label(id), width: item.w}));
            };
            doc.addEventListener('pointermove', onMove);
            doc.addEventListener('pointerup', onUp);
            doc.addEventListener('pointercancel', onUp);
        }

        function setEditing(value) {
            // Leaving edit mode stores the last change right away.
            if (!value) flush();
            editing = Boolean(value);
            board.dataset.editing = String(editing);
            apply();
        }

        apply();
        return {
            setEditing,
            isEditing: () => editing,
            reset() { change(defaults(), t('overviewWorkspace.layoutResetDone', 'Default layout restored')); },
            layout: () => layout.map(item => ({...item})),
            relabel: renderControls,
            measure,
        };
    }

    return {COLUMNS, ROW, PANELS, defaults, normalize, isDefault, move, moveBefore, resize, setHidden, rowsFor, widthFromPointer, heightFromPointer, dragScrollDistance, createBoard};
}));
