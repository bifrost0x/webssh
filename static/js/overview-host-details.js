/* Details of an overview host card: the host profile and the configuration
   checks open in a popover beside the card instead of unfolding inside it,
   so every card keeps the height of its row. On a phone it is a sheet at the
   bottom of the screen. */
(function (root) {
    'use strict';
    if (!root?.document) return;

    /**
     * list: the card list; panel: the hosts panel; hosts(): the shown host
     * model; sections(host): the content nodes; tw: translations.
     */
    function create({window: win, document: doc, list, panel, hosts, sections, tw}) {
        let hostId = null;
        const node = (tag, className, text) => {
            const element = doc.createElement(tag);
            if (className) element.className = className;
            if (text !== undefined && text !== null) element.textContent = text;
            return element;
        };
        const hostById = id => hosts().find(host => host.id === id) || null;
        const trigger = id => list.querySelector(`[data-key="head:${CSS.escape(id)}"]`);
        const compact = () => win.matchMedia?.('(max-width: 640px)').matches;
        const isOpen = () => sheet.matches(':popover-open');

        // The popover lives in the panel, outside the list the cards are rebuilt in.
        const sheet = node('div', 'od-host-details');
        sheet.id = 'odHostDetails';
        sheet.setAttribute('role', 'dialog');
        sheet.popover = 'auto';
        sheet.tabIndex = -1;
        panel.append(sheet);

        function place(anchor) {
            if (!anchor?.isConnected || compact()) {
                sheet.style.removeProperty('left');
                sheet.style.removeProperty('top');
                return;
            }
            const rect = anchor.getBoundingClientRect();
            const width = sheet.offsetWidth;
            const height = sheet.offsetHeight;
            const left = Math.max(8, Math.min(rect.left, win.innerWidth - width - 8));
            const below = rect.bottom + 6;
            const top = below + height <= win.innerHeight - 8 ? below : Math.max(8, Math.min(rect.top - 6 - height, win.innerHeight - 8 - height));
            sheet.style.left = `${left}px`;
            sheet.style.top = `${top}px`;
        }
        function fill(host) {
            const title = node('h2', '', host.name);
            title.id = 'odHostDetailsTitle';
            const close = node('button', 'od-icon-button od-host-details-close');
            close.type = 'button';
            close.dataset.key = 'details-close';
            close.setAttribute('aria-label', tw('detailsClose', 'Close'));
            close.title = tw('detailsClose', 'Close');
            const glyph = node('span', 'material-icons', 'close');
            glyph.setAttribute('aria-hidden', 'true');
            close.append(glyph);
            close.addEventListener('click', () => hide(true));
            const copy = node('div', 'od-host-details-copy');
            copy.append(title, node('p', 'od-host-destination', host.destination));
            const head = node('div', 'od-host-details-head');
            head.append(copy, close);
            sheet.setAttribute('aria-labelledby', title.id);
            sheet.replaceChildren(head, ...sections(host));
        }
        function show(id) {
            const host = hostById(id);
            if (!host) return;
            hostId = id;
            fill(host);
            if (!isOpen()) sheet.showPopover();
            trigger(id)?.setAttribute('aria-expanded', 'true');
            place(trigger(id));
            sheet.querySelector('.od-host-details-close').focus();
        }
        function hide(focus) {
            if (isOpen()) sheet.hidePopover();
            if (focus && hostId) trigger(hostId)?.focus();
        }
        sheet.addEventListener('toggle', event => {
            if (event.newState === 'open') return;
            trigger(hostId)?.setAttribute('aria-expanded', 'false');
            // Escape and a click elsewhere close it; keyboard focus goes back to the card.
            if (!doc.activeElement || doc.activeElement === doc.body || sheet.contains(doc.activeElement)) trigger(hostId)?.focus({preventScroll: true});
            hostId = null;
        });
        sheet.addEventListener('keydown', event => {
            if (event.key !== 'Escape') return;
            event.preventDefault();
            hide(true);
        });

        /** After the cards were rebuilt: follow the host the open details belong to. */
        function refresh() {
            if (!isOpen()) return;
            const host = hostById(hostId);
            if (!host) { hide(false); return; }
            const focused = sheet.contains(doc.activeElement) ? doc.activeElement.dataset.key : null;
            fill(host);
            trigger(hostId)?.setAttribute('aria-expanded', 'true');
            place(trigger(hostId));
            if (focused) sheet.querySelector(`[data-key="${CSS.escape(focused)}"]`)?.focus({preventScroll: true});
        }
        const view = panel.closest('#connectionOverview');
        const follow = () => { if (isOpen()) place(trigger(hostId)); };
        view?.addEventListener('scroll', follow, {capture: true, passive: true});
        win.addEventListener('resize', follow);
        // The popover sits in the top layer; leaving the overview must not leave it behind.
        win.addEventListener('primary-workspace-change', () => { if (view?.hidden) hide(false); });

        /** Toggles the details of a host from its card. */
        function toggle(id) {
            if (isOpen() && hostId === id) hide(true);
            else show(id);
        }
        return {toggle, refresh, isOpen: id => isOpen() && hostId === id};
    }

    root.OverviewHostDetails = {create};
}(typeof window !== 'undefined' ? window : globalThis));
