/* Account-scoped host rail and navigation labels, plus presentation helpers shared with the dashboard. */
(function(root, factory) {
    const api = factory();
    if (typeof module !== 'undefined' && module.exports) module.exports = api;
    if (root) root.ConnectionOverview = api;
})(typeof window !== 'undefined' ? window : globalThis, function() {
    'use strict';

    // Deliberately whitelist display fields. Addresses, users, credentials and
    // arbitrary graph relationships never enter this presentation model.
    function buildAccessModel(profiles = [], jumpHosts = [], jumpsLoaded = false, socksProxies = [], socksLoaded = false) {
        const jumps = new Map(jumpHosts.filter(jump => jump && typeof jump.id === 'string')
            .map(jump => [jump.id, {id: jump.id, name: String(jump.name || '')}]));
        const socks = new Map(socksProxies.filter(proxy => proxy && typeof proxy.id === 'string').map(proxy => [proxy.id, {id: proxy.id, name: String(proxy.name || '')}]));
        const seen = new Set();
        const hosts = profiles.filter(profile => {
            if (!profile || typeof profile.id !== 'string' || seen.has(profile.id)) return false;
            seen.add(profile.id);
            return true;
        }).map(profile => {
            const jump = jumpsLoaded && profile.jump_host_id
                ? jumps.get(profile.jump_host_id) : null;
            const proxy = socksLoaded && profile.socks_proxy_id ? socks.get(profile.socks_proxy_id) : null;
            return {
                id: profile.id,
                name: String(profile.name || ''),
                group: String(profile.group || ''),
                favorite: profile.favorite === true,
                platform: globalThis.HostPlatform?.resolve(profile) || {id: 'server', source: 'fallback'},
                order: Number(profile.sort_order) || 0,
                routeRef: typeof profile.socks_proxy_id === 'string' ? profile.socks_proxy_id : typeof profile.jump_host_id === 'string' ? profile.jump_host_id : '',
                ...(profile.socks_proxy_id ? {routeKind: 'socks', socks: proxy || null} : {}),
                route: profile.socks_proxy_id ? (proxy ? 'configured' : (socksLoaded ? 'unavailable' : 'loading')) : profile.jump_host_id ? (jump ? 'configured' : (jumpsLoaded ? 'unavailable' : 'loading')) : 'none',
                jump: jump || null,
            };
        });
        hosts.sort((a, b) => a.group.localeCompare(b.group) || a.order - b.order || a.name.localeCompare(b.name));
        return hosts;
    }

    // Group color denotes a saved label only, never health or reachability.
    function groupTone(group) {
        let hash = 0;
        for (const character of String(group)) hash = (hash * 31 + character.codePointAt(0)) >>> 0;
        return String(hash % 5);
    }

    // Saved presentation order never changes group membership or SSH routes.
    function orderedGroups(groups, saved = []) {
        const available = new Set(groups);
        const result = [];
        for (const group of saved) {
            if (available.delete(group)) result.push(group);
        }
        return result.concat([...available].sort((a, b) => a.localeCompare(b)));
    }

    function readGroupOrder(storage, key) {
        try {
            if (!key) return [];
            const raw = storage?.getItem(key);
            if (!raw || raw.length > 1024 * 1024) return [];
            const values = JSON.parse(raw);
            if (!Array.isArray(values) || values.length > 5000
                || values.some(value => typeof value !== 'string' || value.length > 512)) return [];
            return [...new Set(values)];
        } catch { return []; }
    }

    // The dashboard in overview-workspace.js owns the Overview page. This
    // controller only maintains the workspace host rail and navigation labels;
    // an overviewPage option from older callers is ignored.
    function createController({window: win, document: doc, sessionManager}) {
        const view = doc.getElementById('connectionOverview');
        const byId = id => doc.getElementById(id);
        const collapsedGroups = new Set();
        let storage = null;
        const scope = doc.querySelector('meta[name="background-scope"]')?.content;
        const orderKey = /^[a-f0-9]{64}$/.test(scope || '') ? `webssh:overview-group-order:${scope}` : null;
        try { storage = win.localStorage; } catch { /* Optional browser preference. */ }
        const groupOrder = readGroupOrder(storage, orderKey);
        const t = (key, fallback = key) => { const value = win.i18n?.t(key); return value && value !== key ? value : fallback; };
        const node = (tag, className, text) => {
            const element = doc.createElement(tag);
            if (className) element.className = className;
            if (text !== undefined) element.textContent = text;
            return element;
        };
        const icon = name => {
            const element = node('span', 'material-icons', name);
            element.setAttribute('aria-hidden', 'true');
            return element;
        };
        function button(label, action, className) {
            const element = node('button', className);
            element.type = 'button';
            element.setAttribute('aria-label', label);
            element.addEventListener('click', event => {
                // WebKit does not focus clicked buttons. Establish the keyed
                // return target before the action switches views.
                if (element.dataset.overviewKey) element.focus({preventScroll: true});
                action(event);
            });
            return element;
        }
        function workspaces() {
            win.primaryWorkspaceController.showWorkspaces();
            const navigation = byId('workspaceNavBtn');
            const target = navigation.getClientRects().length
                ? navigation : doc.querySelector('[data-mobile-view="workspaces"]');
            target?.focus({preventScroll: true});
        }
        function launch(id) {
            // The existing launcher re-resolves the profile and checks readiness.
            workspaces();
            win.launchProfileForPane?.(id);
        }
        function retainFocus(container, render) {
            const active = doc.activeElement;
            const key = container.contains(active) ? active.dataset.overviewKey : null;
            render();
            if (key) {
                const next = Array.from(container.querySelectorAll('[data-overview-key]'))
                    .find(item => item.dataset.overviewKey === key);
                (next || byId('overviewNavBtn')).focus({preventScroll: true});
            }
        }
        function orderedModel(profiles) {
            const order = orderedGroups(profiles.map(profile => String(profile.group || '')), groupOrder);
            const ranks = new Map(order.map((group, index) => [group, index]));
            return buildAccessModel(profiles).sort((a, b) => ranks.get(a.group) - ranks.get(b.group));
        }
        function renderSidebar() {
            const hosts = orderedModel(win.ProfileManager?.profiles || []);
            const groups = new Map();
            hosts.forEach(host => {
                if (!groups.has(host.group)) groups.set(host.group, []);
                groups.get(host.group).push(host);
            });
            const container = byId('shellGroups');
            const showTree = win.primaryWorkspaceController?.getActiveView() === 'workspaces'
                && (sessionManager.getAllSessions().length > 0 || doc.body.dataset.hostRailRequested === 'true');
            container.parentElement.hidden = !showTree;
            retainFocus(container, () => {
                container.replaceChildren();
                if (!showTree) return;
                const favoritesOnly = doc.body.dataset.hostAccessFilter === 'favorites';
                let shown = 0;
                groups.forEach((allItems, group) => {
                    const items = favoritesOnly ? allItems.filter(host => host.favorite) : allItems;
                    if (!items.length) return;
                    shown += items.length;
                    const section = node('details', 'shell-host-group');
                    section.dataset.tone = groupTone(group);
                    section.open = !collapsedGroups.has(group);
                    const summary = node('summary', 'shell-group');
                    summary.dataset.overviewKey = `group:${group}`;
                    summary.append(icon('expand_more'), icon('folder_open'), node('span', '', group || t('profiles.ungrouped')));
                    section.append(summary);
                    items.forEach(host => {
                        const item = button(host.name, () => launch(host.id), 'shell-host');
                        item.dataset.overviewKey = `host:${host.id}`;
                        item.append(win.HostPlatform?.render(host.platform, doc) || icon('dns'), node('span', '', host.name));
                        section.append(item);
                    });
                    section.addEventListener('toggle', () => {
                        if (section.open) collapsedGroups.delete(group);
                        else collapsedGroups.add(group);
                    });
                    container.append(section);
                });
                if (!shown) container.append(node('p', 'shell-host-empty', favoritesOnly
                    ? t('profiles.noFavorites', 'No favorite hosts yet.') : t('profiles.none')));
            });
        }
        function updateNavigation() {
            const key = {overview: 'overview.title', workspaces: 'navigation.workspaces',
                hosts: 'connectionAssets.hosts', files: 'files.fileManager', commands: 'commands.workspace', automation: 'automation.title'}[
                win.primaryWorkspaceController?.getActiveView()] || 'navigation.workspaces';
            byId('shellLocation').dataset.i18n = key;
            byId('shellLocation').textContent = t(key);
        }
        function init() {
            if (!view) return;
            ['profile-list-change', 'languageChanged', 'primary-workspace-change', 'session-workspace-change', 'host-access-change']
                .forEach(event => win.addEventListener(event, renderSidebar));
            win.addEventListener('primary-workspace-change', updateNavigation);
            win.addEventListener('languageChanged', updateNavigation);
            renderSidebar();
            updateNavigation();
        }
        return {init};
    }
    return {buildAccessModel, groupTone, orderedGroups, readGroupOrder, createController};
});
