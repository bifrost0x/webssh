/* Arrange mode of the overview hosts pane: a handle on every card moves it
   with the pointer (mouse, pen, touch) or the keyboard (arrows, Home, End).
   The order is flat across groups; favourites always stay first. It is
   saved to the account through the overview preferences. */
(function (root) {
    'use strict';
    if (!root?.document) return;

    const SAVE_DELAY = 400;

    /**
     * panel: the hosts panel; list: its card list; hosts(): the cards in
     * pane order, unfiltered; filtered(): a search or filter is active;
     * order: {get(), set(ids)}; save(ids|null) stores the order and
     * resolves false when it failed; rerender() draws the cards again.
     */
    function create({window: win, document: doc, panel, list, hosts, filtered, order, save, tw, announce, rerender}) {
        const Order = win.OverviewHostOrder;
        let active = false;
        let timer = 0;
        let pending = null;
        const node = (tag, className, text) => {
            const element = doc.createElement(tag);
            if (className) element.className = className;
            if (text !== undefined && text !== null) element.textContent = text;
            return element;
        };
        const icon = name => {
            const element = node('span', 'material-icons', name);
            element.setAttribute('aria-hidden', 'true');
            return element;
        };
        const nameOf = id => hosts().find(host => host.id === id)?.name || '';

        // The switch sits in the panel heading, the bar with the help under it.
        const toggle = node('button', 'od-ghost-button od-arrange-toggle');
        toggle.type = 'button';
        toggle.id = 'odArrangeHosts';
        toggle.setAttribute('aria-pressed', 'false');
        toggle.setAttribute('aria-controls', list.id);
        const toggleLabel = node('span', '', tw('arrange', 'Arrange'));
        toggle.append(icon('swap_vert'), toggleLabel);
        const head = panel.querySelector('.od-panel-head');
        head.insertBefore(toggle, head.querySelector('[data-host-discovery]'));
        const bar = node('div', 'od-arrange-bar');
        bar.hidden = true;
        const hint = node('p', '', '');
        hint.id = 'odArrangeHint';
        const reset = node('button', 'od-ghost-button', tw('arrangeReset', 'Reset order'));
        reset.type = 'button';
        const done = node('button', 'btn btn-primary', tw('arrangeDone', 'Done'));
        done.type = 'button';
        bar.append(icon('info'), hint, reset, done);
        head.after(bar);

        function sync() {
            toggle.setAttribute('aria-pressed', String(active));
            toggleLabel.textContent = tw('arrange', 'Arrange');
            bar.hidden = !active;
            hint.textContent = filtered()
                ? tw('arrangeFiltered', 'Clear the search and filters to change the order.')
                : tw('arrangeHint', 'Drag a host by its handle, or focus the handle and use the arrow keys to move it earlier or later (Home, End: first, last). Favorites always come first. Your order is saved to your account.');
            reset.textContent = tw('arrangeReset', 'Reset order');
            done.textContent = tw('arrangeDone', 'Done');
            reset.disabled = !Array.isArray(order.get());
            list.dataset.arranging = String(active);
        }
        function setActive(value, focus) {
            if (active === value) return;
            active = value;
            sync();
            rerender();
            announce(active ? tw('arrangeStarted', 'Arranging hosts. Each card has a handle.') : tw('arrangeEnded', 'Arranging ended.'));
            if (!active && focus) toggle.focus({preventScroll: true});
        }
        toggle.addEventListener('click', () => setActive(!active, false));
        done.addEventListener('click', () => setActive(false, true));
        panel.addEventListener('keydown', event => {
            if (event.key !== 'Escape' || !active || drag.active() || event.target.closest?.('input, textarea, select')) return;
            event.preventDefault();
            setActive(false, true);
        });

        function flush() {
            win.clearTimeout(timer);
            timer = 0;
            const ids = pending;
            pending = null;
            // Nothing waits: a reset already saved the default order.
            if (ids === null) return;
            save(ids).then(ok => {
                if (!ok) announce(tw('arrangeSaveFailed', 'The order could not be saved. It applies until you reload.'));
            });
        }
        function store(ids) {
            order.set(ids);
            pending = ids;
            win.clearTimeout(timer);
            // Several quick moves are saved once.
            timer = win.setTimeout(flush, SAVE_DELAY);
            sync();
        }
        reset.addEventListener('click', () => {
            win.clearTimeout(timer);
            order.set(null);
            pending = null;
            save(null).then(ok => announce(ok ? tw('arrangeResetDone', 'The default order is back.')
                : tw('arrangeSaveFailed', 'The order could not be saved. It applies until you reload.')));
            sync();
            rerender();
            done.focus({preventScroll: true});
        });

        function moved(id, ids) {
            store(ids);
            rerender();
            const shown = hosts();
            announce(tw('arrangeMoved', '{name} moved to position {position} of {count}.', {
                name: nameOf(id), position: shown.findIndex(host => host.id === id) + 1, count: shown.length}));
        }
        /** Keyboard moves: one step, or to the first or last place of the section. */
        function step(id, key) {
            if (filtered()) { announce(tw('arrangeFiltered', 'Clear the search and filters to change the order.')); return; }
            const shown = hosts();
            const {index, count} = Order.position(shown, id);
            const target = {ArrowUp: index - 1, ArrowLeft: index - 1, ArrowDown: index + 1, ArrowRight: index + 1, Home: 0, End: count - 1}[key];
            const ids = Order.moveTo(shown, id, target);
            if (ids) { moved(id, ids); return; }
            const favourite = shown.find(host => host.id === id)?.favorite === true;
            const others = shown.some(host => (host.favorite === true) !== favourite);
            const name = nameOf(id);
            if (target < index) {
                announce(!favourite && others ? tw('arrangeAfterFavorites', '{name} is first after the favorites. Favorites always come first.', {name})
                    : tw('arrangeFirst', '{name} is already first.', {name}));
            } else {
                announce(favourite && others ? tw('arrangeLastFavorite', '{name} is the last favorite. Favorites always come first.', {name})
                    : tw('arrangeLast', '{name} is already last.', {name}));
            }
        }

        const drag = win.OverviewHostDrag.create({window: win, document: doc, list,
            scroller: () => panel.closest('#connectionOverview'),
            allowed: (id, targetId) => !filtered() && id !== targetId && Order.section(hosts(), id).some(host => host.id === targetId),
            drop: (id, targetId, after) => {
                const ids = Order.place(hosts(), id, targetId, after);
                if (ids) moved(id, ids);
                else rerender();
            },
            cancel: rerender});

        /** The handle of a card in arrange mode. */
        function handle(host) {
            const shown = hosts();
            const button = node('button', 'od-host-handle');
            button.type = 'button';
            button.dataset.key = `handle:${host.id}`;
            button.disabled = filtered();
            button.setAttribute('aria-label', tw('arrangeHandle', 'Move {name}, position {position} of {count}', {
                name: host.name, position: shown.findIndex(item => item.id === host.id) + 1, count: shown.length}));
            button.setAttribute('aria-describedby', hint.id);
            button.append(icon('drag_indicator'));
            button.addEventListener('keydown', event => {
                if (!['ArrowUp', 'ArrowDown', 'ArrowLeft', 'ArrowRight', 'Home', 'End'].includes(event.key)) return;
                if (event.altKey || event.ctrlKey || event.metaKey) return;
                event.preventDefault();
                step(host.id, event.key);
            });
            button.addEventListener('pointerdown', event => { if (!filtered()) drag.start(event, host.id); });
            return button;
        }

        // Unsaved moves go out before the page goes away.
        win.addEventListener('pagehide', () => { if (pending !== null) flush(); });
        win.addEventListener('languageChanged', sync);
        sync();
        return {active: () => active, handle, refresh: sync, dragging: drag.active};
    }

    root.OverviewHostArrange = {create};
}(typeof window !== 'undefined' ? window : globalThis));
