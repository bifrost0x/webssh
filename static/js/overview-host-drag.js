/* Dragging an overview host card by its handle. A marker in the gap shows
   where the card will go; the page scrolls near its edges. Pointer events,
   so mouse, pen and touch behave alike. Placing the card is the caller's. */
(function (root) {
    'use strict';
    if (!root?.document) return;

    const EDGE = 48;
    const STEP = 12;
    const THRESHOLD = 5;

    /**
     * list: the card list; scroller(): the element that scrolls the page;
     * allowed(id, targetId): whether a card may go next to another;
     * drop(id, targetId, after) places it; cancel() after a drag without drop.
     */
    function create({window: win, document: doc, list, scroller, allowed, drop, cancel}) {
        const marker = doc.createElement('span');
        marker.className = 'od-drop-marker';
        marker.setAttribute('aria-hidden', 'true');
        marker.hidden = true;
        // Positioned in the panel body (position: relative), which may scroll itself.
        list.parentElement.append(marker);
        let current = null;

        function area() {
            const body = list.parentElement;
            return body.scrollHeight > body.clientHeight + 1 && ['auto', 'scroll'].includes(win.getComputedStyle(body).overflowY)
                ? body : scroller();
        }
        function clear() {
            list.querySelectorAll('[data-drop]').forEach(card => card.removeAttribute('data-drop'));
            marker.hidden = true;
        }
        function mark(card, after, single) {
            clear();
            card.dataset.drop = after ? 'after' : 'before';
            const box = card.getBoundingClientRect();
            const holder = marker.parentElement;
            const frame = holder.getBoundingClientRect();
            const gap = parseFloat(win.getComputedStyle(list).columnGap) || 12;
            const left = box.left - frame.left + holder.scrollLeft;
            const top = box.top - frame.top + holder.scrollTop;
            marker.dataset.axis = single ? 'row' : 'column';
            marker.style.left = `${single ? left : (after ? left + box.width + gap / 2 : left - gap / 2) - 1.5}px`;
            marker.style.top = `${single ? (after ? top + box.height + gap / 2 : top - gap / 2) - 1.5 : top}px`;
            marker.style.width = single ? `${box.width}px` : '';
            marker.style.height = single ? '' : `${box.height}px`;
            marker.hidden = false;
        }
        function track() {
            const card = doc.elementFromPoint(current.x, current.y)?.closest?.('.od-host[data-host-id]');
            if (!card || !list.contains(card) || !allowed(current.id, card.dataset.hostId)) {
                clear();
                current.target = null;
                return;
            }
            const box = card.getBoundingClientRect();
            current.target = card.dataset.hostId;
            current.after = current.single ? current.y > box.top + box.height / 2 : current.x > box.left + box.width / 2;
            mark(card, current.after, current.single);
        }
        function autoscroll() {
            if (!current) return;
            const element = area();
            const frame = element.getBoundingClientRect();
            const step = current.y < frame.top + EDGE ? -STEP : current.y > frame.bottom - EDGE ? STEP : 0;
            if (step) {
                element.scrollTop += step;
                track();
            }
            current.frame = win.requestAnimationFrame(autoscroll);
        }

        /** Starts on pointerdown on a handle; the drag begins after a few pixels. */
        function start(event, id) {
            if (event.button !== 0 || current) return;
            const handle = event.currentTarget;
            const card = handle.closest('.od-host');
            event.preventDefault();
            handle.setPointerCapture?.(event.pointerId);
            const columns = win.getComputedStyle(list).gridTemplateColumns.split(' ').filter(Boolean).length;
            const drag = {id, x: event.clientX, y: event.clientY, target: null, after: false, single: columns < 2, frame: 0};
            let started = false;
            const move = moveEvent => {
                drag.x = moveEvent.clientX;
                drag.y = moveEvent.clientY;
                if (!started) {
                    if (Math.hypot(drag.x - event.clientX, drag.y - event.clientY) < THRESHOLD) return;
                    started = true;
                    current = drag;
                    card.dataset.dragging = 'true';
                    list.dataset.dragging = 'true';
                    drag.frame = win.requestAnimationFrame(autoscroll);
                }
                track();
            };
            const finish = place => {
                doc.removeEventListener('pointermove', move);
                doc.removeEventListener('pointerup', up);
                doc.removeEventListener('pointercancel', abort);
                doc.removeEventListener('keydown', escape, true);
                win.cancelAnimationFrame(drag.frame);
                clear();
                delete card.dataset.dragging;
                delete list.dataset.dragging;
                current = null;
                if (place && started && drag.target) drop(id, drag.target, drag.after);
                else cancel();
            };
            const up = () => finish(true);
            const abort = () => finish(false);
            const escape = keyEvent => {
                if (keyEvent.key !== 'Escape') return;
                keyEvent.preventDefault();
                finish(false);
            };
            doc.addEventListener('pointermove', move);
            doc.addEventListener('pointerup', up);
            doc.addEventListener('pointercancel', abort);
            doc.addEventListener('keydown', escape, true);
        }

        return {start, active: () => Boolean(current)};
    }

    root.OverviewHostDrag = {create};
}(typeof window !== 'undefined' ? window : globalThis));
