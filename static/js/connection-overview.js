/* Account-scoped connection overview; mutations use the existing profile manager. */
(function(root, factory) {
    const api = factory();
    if (typeof module !== 'undefined' && module.exports) module.exports = api;
    if (root) root.ConnectionOverview = api;
})(typeof window !== 'undefined' ? window : globalThis, function() {
    'use strict';

    // Deliberately whitelist display fields. Addresses, users, credentials and
    // arbitrary graph relationships never enter this presentation model.
    function buildAccessModel(profiles = [], jumpHosts = [], jumpsLoaded = false) {
        const jumps = new Map(jumpHosts.filter(jump => jump && typeof jump.id === 'string')
            .map(jump => [jump.id, {id: jump.id, name: String(jump.name || '')}]));
        const seen = new Set();
        const hosts = profiles.filter(profile => {
            if (!profile || typeof profile.id !== 'string' || seen.has(profile.id)) return false;
            seen.add(profile.id);
            return true;
        }).map(profile => {
            const jump = jumpsLoaded && profile.jump_host_id
                ? jumps.get(profile.jump_host_id) : null;
            return {
                id: profile.id,
                name: String(profile.name || ''),
                group: String(profile.group || ''),
                favorite: profile.favorite === true,
                platform: globalThis.HostPlatform?.resolve(profile) || {id: 'server', source: 'fallback'},
                order: Number(profile.sort_order) || 0,
                routeRef: typeof profile.jump_host_id === 'string' ? profile.jump_host_id : '',
                route: profile.jump_host_id ? (jump ? 'configured' : (jumpsLoaded ? 'unavailable' : 'loading')) : 'none',
                jump: jump || null,
            };
        });
        hosts.sort((a, b) => a.group.localeCompare(b.group) || a.order - b.order || a.name.localeCompare(b.name));
        return hosts;
    }

    function pageItems(items, requested = 0, size = 8) {
        const pageSize = Number.isInteger(size) ? Math.max(1, Math.min(20, size)) : 8;
        const pages = Math.max(1, Math.ceil(items.length / pageSize));
        const page = Number.isInteger(requested) ? Math.max(0, Math.min(pages - 1, requested)) : 0;
        return {page, pages, total: items.length, items: items.slice(page * pageSize, (page + 1) * pageSize)};
    }

    function selectRouteTarget(bundles, route, host, highlighted) {
        const chosen = bundles.find(bundle => bundle.key === route)
            || bundles.find(bundle => bundle.key === highlighted) || bundles[0];
        return {route: chosen?.key || null,
            host: chosen?.hosts.find(target => target.id === host)?.id || chosen?.hosts[0]?.id || null};
    }

    function atlasConnections(origin, steps) {
        const above = steps.filter(step => step.y < origin.y).sort((a, b) => a.y - b.y);
        const below = steps.filter(step => step.y >= origin.y).sort((a, b) => b.y - a.y);
        return steps.map((step, index) => {
            const side = step.y < origin.y ? above : below;
            const lane = origin.right + 18 + side.indexOf(step) * 10;
            const port = origin.y + (index - (steps.length - 1) / 2) * 5;
            return {root: [[origin.right, port], [lane, port], [lane, step.y], [step.left, step.y]],
                target: [[step.right, step.y], [step.targetLeft, step.y]]};
        });
    }

    function summarizeResources(data = {}) {
        const records = (items, loaded) => {
            if (loaded !== true || !Array.isArray(items)) return null;
            const seen = new Set();
            return items.filter(item => {
                if (!item || typeof item.id !== 'string' || seen.has(item.id)) return false;
                seen.add(item.id);
                return true;
            });
        };
        const profiles = records(data.profiles, data.profilesLoaded);
        return {
            hosts: profiles?.length ?? null,
            groups: profiles ? new Set(profiles.map(profile => String(profile.group || '').trim()).filter(Boolean)).size : null,
            jumps: records(data.jumps, data.jumpsLoaded)?.length ?? null,
            keys: records(data.keys, data.keysLoaded)?.length ?? null,
            commandSets: records(data.commandSets, data.commandSetsLoaded)?.length ?? null,
        };
    }

    function aggregateRoutes(hosts, {query = '', group = null} = {}) {
        const bundles = new Map();
        const seen = new Set();
        const search = String(query).trim().slice(0, 128).toLocaleLowerCase();
        let matches = 0;
        hosts.forEach(host => {
            if (seen.has(host.id)) return;
            seen.add(host.id);
            const key = JSON.stringify([host.group, host.route, host.routeRef || host.jump?.id || '']);
            if (!bundles.has(key)) bundles.set(key, {
                key, group: host.group, route: host.route, jump: host.jump,
                count: 0, hosts: [],
            });
            const bundle = bundles.get(key);
            bundle.count++;
            if (group !== null && host.group !== group) return;
            if (search && !`${host.name} ${host.group} ${host.jump?.name || ''}`.toLocaleLowerCase().includes(search)) return;
            bundle.hosts.push(host);
            matches++;
        });
        return {totalHosts: seen.size, totalBundles: bundles.size, matches,
            bundles: [...bundles.values()].filter(bundle => bundle.hosts.length)};
    }

    // Group color denotes a saved label only, never health or reachability.
    function groupTone(group) {
        let hash = 0;
        for (const character of String(group)) hash = (hash * 31 + character.codePointAt(0)) >>> 0;
        return String(hash % 5);
    }

    function hasOpenSession(profile, sessions = []) {
        return Boolean(profile && sessions.some(session => session.connected === true
            && session.profileId === profile.id && session.host === profile.host
            && Number(session.port || 22) === Number(profile.port || 22)
            && String(session.username || '') === String(profile.username || '')
            && (session.jumpHostId || '') === (profile.jump_host_id || '')));
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

    function moveGroupOrder(groups, group, position) {
        if (!groups.includes(group) || !Number.isInteger(position) || position < 0 || position >= groups.length) return groups;
        const result = groups.filter(value => value !== group);
        result.splice(position, 0, group);
        return result;
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

    // overviewPage=false: another module owns the Overview page; this controller
    // then only maintains the workspace host rail and navigation labels.
    function createController({window: win, document: doc, sessionManager, overviewPage = true}) {
        const view = doc.getElementById('connectionOverview');
        const byId = id => doc.getElementById(id);
        let graph = false;
        let mapMode = 'list';
        let mapCleanup = () => {};
        const mapPositions = new Map();
        let returnPosition = null;
        let selectedGroup = null;
        let selectedRoute = null;
        let selectedHost = null;
        let followingMove = null;
        const inventoryPages = new Map();
        let targetPage = 0;
        let sessionPage = 0;
        const collapsedGroups = new Set();
        let edgesScheduled = false;
        let inventorySelectionKey = null;
        let scheduled = false;
        let transfersScheduled = false;
        let loadError = false;
        let commandSetsLoaded = win.CommandSetManager?.loaded === true || Boolean(win.CommandSetManager?.commandSets?.length);
        let draggedHost = null;
        let draggedGroup = null;
        let arranging = false;
        let groupObserver = null;
        let storage = null;
        const scope = doc.querySelector('meta[name="background-scope"]')?.content;
        const orderKey = /^[a-f0-9]{64}$/.test(scope || '') ? `webssh:overview-group-order:${scope}` : null;
        try { storage = win.localStorage; } catch { /* Optional browser preference. */ }
        const mapKey = orderKey ? `webssh:overview-map:${scope}` : null;
        const groupPositions = new Map();
        const validPoint = p => p && Number.isFinite(p.x) && Number.isFinite(p.y) && Math.abs(p.x) <= 100000 && Math.abs(p.y) <= 100000;
        try {
            const raw = mapKey && storage?.getItem(mapKey);
            const saved = raw && raw.length < 500000 ? JSON.parse(raw) : null;
            if (saved?.version === 1) {
                if (['auto', 'details', 'groups', 'list'].includes(saved.mode)) mapMode = saved.mode;
                if (Array.isArray(saved.groups)) for (const [name, point] of saved.groups.slice(0, 1000)) {
                    if (typeof name === 'string' && validPoint(point) && point.x >= 0 && point.y >= 0) groupPositions.set(name, {x:point.x,y:point.y});
                }
                if (Array.isArray(saved.cameras)) for (const [key, point] of saved.cameras.slice(0,30)) {
                    if (typeof key === 'string' && validPoint(point) && point.scale >= .2 && point.scale <= 2) mapPositions.set(key, point);
                }
            }
        } catch { /* Invalid or unavailable preferences must not prevent opening hosts. */ }
        function saveMap() {
            try { if (mapKey) storage?.setItem(mapKey, JSON.stringify({version:1, mode:mapMode, groups:[...groupPositions].slice(-1000), cameras:[...mapPositions]})); }
            catch { /* Map remains usable if browser storage is unavailable. */ }
        }
        win.addEventListener('pagehide', saveMap);
        let groupOrder = readGroupOrder(storage, orderKey);
        let displayGroupOrder = [];
        let displayGroupRanks = new Map();
        const visible = () => win.primaryWorkspaceController?.getActiveView() === 'overview';
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
        function button(label, action, className = 'overview-row') {
            const element = node('button', className);
            element.type = 'button';
            element.setAttribute('aria-label', label);
            element.addEventListener('click', event => {
                // WebKit does not focus clicked buttons. Establish the keyed
                // return target before an action leaves the overview.
                if (element.dataset.overviewKey) element.focus({preventScroll: true});
                action(event);
            });
            return element;
        }
        function rememberPosition() {
            if (win.primaryWorkspaceController.getActiveView() !== 'overview') return;
            returnPosition = {
                top: view.scrollTop,
                hostsTop: byId('overviewHosts').scrollTop,
                key: doc.activeElement?.dataset?.overviewKey,
            };
        }
        function workspaces() {
            rememberPosition();
            win.primaryWorkspaceController.showWorkspaces();
            const navigation = byId('workspaceNavBtn');
            const target = navigation.getClientRects().length
                ? navigation : doc.querySelector('[data-mobile-view="workspaces"]');
            target?.focus({preventScroll: true});
        }
        function quickConnect() {
            workspaces();
            return win.openDefaultConnectionModal?.() === true;
        }
        function launch(id) {
            // The existing launcher re-resolves the profile and checks readiness.
            workspaces();
            win.launchProfileForPane?.(id);
        }
        function editHost(id) {
            rememberPosition();
            const manager = win.ProfileManager;
            if (!manager?.profiles.some(profile => profile.id === id)) return;
            const modal = byId('profileManagementModal');
            if (!win.primaryWorkspaceController.open('hosts', modal)) return;
            manager.loadKeys();
            win.JumpHostManager?.load();
            manager.openEditor(id);
        }
        function hostActions(host, context = 'host') {
            const actions = node('div', 'overview-host-actions');
            const connectLabel = t('connection.actionConnect', 'Connect');
            const editLabel = t('common.edit', 'Edit');
            const connect = button(`${connectLabel} ${host.name}`, () => launch(host.id), 'overview-host-connect');
            connect.dataset.overviewKey = `${context}:connect:${host.id}`;
            connect.append(icon('terminal'), node('span', '', connectLabel));
            const edit = button(`${editLabel} ${host.name}`, () => editHost(host.id), 'overview-host-edit');
            edit.title = `${editLabel} ${host.name}`;
            edit.dataset.overviewKey = `${context}:edit:${host.id}`;
            edit.append(icon('edit'));
            actions.append(connect, edit);
            return actions;
        }
        function message(container, key) {
            const empty = node('p', 'overview-empty');
            empty.append(icon('inbox'), node('span', '', t(key)));
            container.append(empty);
        }
        function retainFocus(container, render) {
            const active = doc.activeElement;
            const key = container.contains(active) ? active.dataset.overviewKey : null;
            render();
            if (key) {
                const next = Array.from(container.querySelectorAll('[data-overview-key]'))
                    .find(item => item.dataset.overviewKey === key);
                (next || (container.id === 'shellGroups' ? byId('overviewNavBtn') : byId('overviewHostSearch'))).focus({preventScroll: true});
            }
        }
        function currentGroupOrder() {
            return orderedGroups((win.ProfileManager?.profiles || []).map(profile => String(profile.group || '')), groupOrder);
        }
        function orderedModel(profiles, jumps, loaded) {
            displayGroupOrder = currentGroupOrder();
            displayGroupRanks = new Map(displayGroupOrder.map((group, index) => [group, index]));
            return buildAccessModel(profiles, jumps, loaded).sort((a, b) => displayGroupRanks.get(a.group) - displayGroupRanks.get(b.group));
        }
        function saveGroupOrder(next) {
            if (!win.ProfileManager?.profilesLoaded) return;
            groupOrder = next;
            let saved = false;
            try {
                if (orderKey && storage) { storage.setItem(orderKey, JSON.stringify(next)); saved = true; }
            } catch { /* Keep the working arrangement usable without storage. */ }
            const status = byId('overviewArrangeStatus');
            status.dataset.i18n = saved ? 'overview.arrangeSaved' : 'overview.arrangeUnsaved';
            status.textContent = t(status.dataset.i18n);
            renderSidebar();
            renderHosts();
        }
        function repositionGroup(group, position) {
            const current = currentGroupOrder();
            if (!Number.isInteger(position) || position < 0 || position >= current.length || !current.includes(group)) return;
            saveGroupOrder(moveGroupOrder(current, group, position));
        }
        function groupControls(section, group, order, ranks, context) {
            section.dataset.overviewGroup = group;
            const controls = node('div', 'overview-group-controls');
            const name = group || t('profiles.ungrouped');
            const handle = button(t('overview.moveGroup').replace('{name}', name), () => position.focus(), 'overview-group-drag');
            handle.title = t('overview.moveGroup').replace('{name}', name);
            handle.dataset.overviewKey = `group-drag:${JSON.stringify([context, group])}`;
            handle.draggable = true;
            handle.append(icon('drag_indicator'));
            handle.addEventListener('dragstart', event => {
                if (!arranging) { event.preventDefault(); return; }
                draggedGroup = group;
                event.dataTransfer.setData('application/x-webssh-overview-group', group);
                event.dataTransfer.effectAllowed = 'move';
            });
            const clearDrag = () => {
                draggedGroup = null;
                view.querySelectorAll('.overview-group-drop').forEach(item => item.classList.remove('overview-group-drop'));
            };
            handle.addEventListener('dragend', clearDrag);
            section.addEventListener('dragover', event => {
                if (!arranging || draggedGroup === null || draggedGroup === group) return;
                event.preventDefault();
                event.stopPropagation();
                event.dataTransfer.dropEffect = 'move';
                section.classList.add('overview-group-drop');
            });
            section.addEventListener('dragleave', event => {
                if (!section.contains(event.relatedTarget)) section.classList.remove('overview-group-drop');
            });
            section.addEventListener('drop', event => {
                if (!arranging || draggedGroup === null) return;
                event.preventDefault();
                event.stopPropagation();
                const source = draggedGroup;
                clearDrag();
                if (source !== group) repositionGroup(source, currentGroupOrder().indexOf(group));
            });
            const label = node('label', '', t('overview.groupPosition'));
            const position = node('input');
            position.type = 'number';
            position.min = '1';
            position.max = String(order.length);
            position.value = String(ranks.get(group) + 1);
            position.setAttribute('aria-label', t('overview.groupPositionLabel').replace('{name}', name));
            position.dataset.overviewKey = `group-position:${JSON.stringify([context, group])}`;
            position.addEventListener('change', () => {
                const value = position.valueAsNumber;
                if (position.validity.valid && Number.isInteger(value)) repositionGroup(group, value - 1);
                else position.value = String(currentGroupOrder().indexOf(group) + 1);
            });
            position.addEventListener('keydown', event => {
                if (event.key === 'Enter') { event.preventDefault(); position.dispatchEvent(new win.Event('change')); }
            });
            label.append(position);
            controls.append(handle, label);
            section.prepend(controls);
        }
        function layoutGroups() {
            if (!visible()) return;
            // Read all natural card heights first, then update grid spans in one batch.
            // Small rows allow the next card to occupy the space below a shorter card.
            const sizes = [];
            byId('overviewHosts').querySelectorAll('.overview-host-group').forEach(card => {
                if (card.parentElement.classList.contains('overview-group-layout')) {
                    sizes.push([card, Math.ceil((card.getBoundingClientRect().height + 16) / 8)]);
                }
            });
            sizes.forEach(([card, span]) => {
                const value = `span ${span}`;
                if (card.style.gridRowEnd !== value) card.style.gridRowEnd = value;
            });
        }
        function moveHost(id, group) {
            const manager = win.ProfileManager;
            const profiles = manager?.profiles || [];
            const source = profiles.find(profile => profile.id === id);
            if (!source || String(source.group || '').trim().toLocaleLowerCase() === group.trim().toLocaleLowerCase()) return;
            const count = profiles.filter(profile => profile.favorite !== true
                && String(profile.group || '').trim().toLocaleLowerCase() === group.trim().toLocaleLowerCase()).length;
            const move = win.ProfileLauncherUtils?.resolveProfileDrop(profiles, id, group, count);
            if (move) {
                if (visible()) followingMove = {id, group: String(move.targetGroup || '')};
                if (!manager.requestProfileMove(move)) followingMove = null;
            }
        }
        function dropGroup(element, group) {
            element.dataset.hostDropGroup = group;
            element.addEventListener('dragover', event => {
                if (!draggedHost) return;
                event.preventDefault();
                event.dataTransfer.dropEffect = 'move';
                element.classList.add('host-drop-active');
            });
            element.addEventListener('dragleave', event => {
                if (!element.contains(event.relatedTarget)) element.classList.remove('host-drop-active');
            });
            element.addEventListener('drop', event => {
                if (!draggedHost) return;
                event.preventDefault();
                const id = draggedHost;
                draggedHost = null;
                doc.querySelectorAll('.host-drop-active').forEach(item => item.classList.remove('host-drop-active'));
                moveHost(id, group);
            });
        }
        function moveControl(host) {
            const menu = node('details', 'overview-host-move');
            const toggle = node('summary');
            const label = t('profiles.moveToGroup').replace('{name}', host.name);
            toggle.setAttribute('aria-label', label);
            toggle.dataset.overviewKey = `move:${host.id}`;
            toggle.title = label;
            toggle.append(icon('drive_file_move'));
            const select = node('select');
            select.setAttribute('aria-label', label);
            select.dataset.overviewKey = `move:${host.id}`;
            // Build options only for an open menu, not N group lists for N hosts.
            menu.addEventListener('toggle', () => {
                if (!menu.open) { select.replaceChildren(); return; }
                const groups = new Set(['', ...(win.ProfileManager?.profiles || []).map(profile => String(profile.group || '').trim())]);
                select.replaceChildren();
                groups.forEach(group => select.add(new win.Option(group || t('profiles.ungrouped'), group)));
                select.value = host.group.trim();
            });
            const close = () => { menu.open = false; toggle.focus({preventScroll: true}); };
            select.addEventListener('change', () => {
                const group = select.value;
                close();
                moveHost(host.id, group);
            });
            menu.addEventListener('keydown', event => {
                if (event.key === 'Escape') { event.preventDefault(); close(); }
            });
            menu.append(toggle, select);
            return menu;
        }
        function hostButton(host) {
            const target = button(`${t('overview.inspectPath', 'Inspect SSH path')}: ${host.name}`, () => {
                selectedHost = host.id;
                renderHosts();
                byId('overviewAccessTitle')?.focus({preventScroll: win.innerWidth > 1100});
            });
            target.dataset.overviewKey = `host:${host.id}`;
            target.dataset.hostId = host.id;
            target.setAttribute('aria-pressed', String(host.id === selectedHost));
            target.draggable = true;
            target.addEventListener('dragstart', event => {
                if (win.ProfileManager?.organizationPending?.has(host.id)) { event.preventDefault(); return; }
                draggedHost = host.id;
                event.dataTransfer.setData('application/x-webssh-profile-id', host.id);
                event.dataTransfer.effectAllowed = 'move';
            });
            target.addEventListener('dragend', () => {
                draggedHost = null;
                doc.querySelectorAll('.host-drop-active').forEach(item => item.classList.remove('host-drop-active'));
            });
            target.dataset.tone = groupTone(host.group);
            target.append(win.HostPlatform?.render(host.platform, doc) || icon('dns'), node('span', 'overview-row-title', host.name));
            if (host.favorite) {
                const favorite = icon('star');
                favorite.classList.add('overview-favorite');
                target.append(favorite);
                target.setAttribute('aria-label', `${t('profiles.favorites')} · ${t('overview.inspectPath', 'Inspect SSH path')}: ${host.name}`);
            }
            target.append(icon('chevron_right'));
            return target;
        }
        function hostGroups(hosts, showUnlinked = false, editable = true, context = 'direct') {
            const order = displayGroupOrder;
            const ranks = displayGroupRanks;
            const groups = new Map();
            hosts.forEach(host => {
                if (!groups.has(host.group)) groups.set(host.group, []);
                groups.get(host.group).push(host);
            });
            const fragment = doc.createDocumentFragment();
            groups.forEach((items, group) => {
                const section = node('section', 'overview-host-group');
                dropGroup(section, group);
                section.dataset.tone = groupTone(group);
                const heading = node('h3', 'overview-group-heading');
                heading.title = group || t('profiles.ungrouped');
                heading.append(icon('folder_open'), node('span', '', group || t('profiles.ungrouped')), node('small', '', String(items.length)));
                section.append(heading);
                const list = node('ul', 'overview-host-list');
                [...items].sort((a, b) => Number(b.favorite) - Number(a.favorite)).forEach(host => {
                    const row = node('li', 'overview-host-entry');
                    if (showUnlinked) {
                        const key = host.route === 'loading' ? 'overview.loading'
                            : host.route === 'unavailable' ? 'overview.missingJump' : 'overview.noJump';
                        row.append(node('span', 'overview-route-unlinked', t(key)));
                    }
                    row.append(hostButton(host), hostActions(host), moveControl(host));
                    list.append(row);
                });
                section.append(list);
                if (editable && arranging) groupControls(section, group, order, ranks, context);
                fragment.append(section);
            });
            return fragment;
        }
        function drawEdges() {
            if (!visible()) return;
            view.querySelectorAll('.overview-inventory-canvas').forEach(canvas => {
                const svg = canvas.querySelector('.overview-inventory-edges');
                if (!canvas.getClientRects().length) {
                    svg.replaceChildren();
                    delete svg.dataset.geometryKey;
                    return;
                }
                const frame = canvas.getBoundingClientRect();
                const scale = frame.width / canvas.offsetWidth || 1;
                const segments = [];
                const line = (points, state, selected, live = false) => segments.push({points, state, selected, live});
                canvas.querySelectorAll('.overview-route-bundle').forEach(bundle => {
                    if (!bundle.getClientRects().length) return;
                    const step = bundle.querySelector('.overview-route-step').getBoundingClientRect();
                    const cards = [...bundle.querySelectorAll('.overview-platform-card')];
                    const lane = (bundle.getBoundingClientRect().left - frame.left) / scale + 6;
                    const branch = [lane, (step.bottom - frame.top) / scale];
                    cards.forEach(card => {
                        const target = card.getBoundingClientRect();
                        const end = [(target.left - frame.left) / scale, (target.top + target.height / 2 - frame.top) / scale];
                        line([branch, [lane, end[1]], end], bundle.dataset.routeState, Boolean(card.querySelector('[aria-pressed="true"]')), card.dataset.live === 'true');
                    });
                });
                segments.sort((a, b) => Number(a.selected) - Number(b.selected));
                const geometryKey = JSON.stringify(segments);
                if (svg.dataset.geometryKey === geometryKey) return;
                const reveal = Boolean(selectedHost) && svg.dataset.selectedHost !== selectedHost;
                svg.dataset.geometryKey = geometryKey;
                svg.dataset.selectedHost = selectedHost || '';
                svg.replaceChildren();
                const defs = doc.createElementNS('http://www.w3.org/2000/svg', 'defs');
                const arrow = doc.createElementNS('http://www.w3.org/2000/svg', 'marker');
                arrow.id = 'overviewLocalArrow';
                for (const [key, value] of Object.entries({viewBox:'0 0 6 6', refX:'5', refY:'3', markerWidth:'5', markerHeight:'5', orient:'auto'})) arrow.setAttribute(key,value);
                const tip = doc.createElementNS('http://www.w3.org/2000/svg', 'polygon');
                tip.setAttribute('points','0,0 6,3 0,6');
                tip.setAttribute('fill','var(--ws2-text-secondary)');
                arrow.append(tip); defs.append(arrow); svg.append(defs);
                segments.forEach(({points, state, selected, live}) => {
                    const path = doc.createElementNS('http://www.w3.org/2000/svg', 'path');
                    path.setAttribute('d', points.map((point, index) => `${index ? 'L' : 'M'} ${point.join(' ')}`).join(' '));
                    path.setAttribute('marker-end','url(#overviewLocalArrow)');
                    path.dataset.routeState = state;
                    path.dataset.selected = String(selected);
                    path.dataset.live = String(live);
                    const animate = reveal && selected && !['loading', 'unavailable'].includes(state);
                    path.dataset.reveal = String(animate);
                    if (animate && !live) path.setAttribute('pathLength', '1');
                    svg.append(path);
                });
            });
        }
        function scheduleEdges() {
            if (!visible() || edgesScheduled) return;
            edgesScheduled = true;
            win.requestAnimationFrame(() => { edgesScheduled = false; layoutGroups(); drawEdges(); });
        }
        function routeLabel(bundle) {
            if (bundle.route === 'configured') return bundle.jump.name || t('connectionAssets.jumpHosts');
            return bundle.route === 'loading' ? t('overview.routeLoading', 'SSH route loading')
                : bundle.route === 'unavailable' ? t('overview.missingJump') : t('overview.directRoute', 'Direct SSH');
        }
        function pager(container, page, change, context) {
            if (page.pages <= 1) return;
            const navigation = node('nav', 'overview-pagination');
            navigation.setAttribute('aria-label', context);
            const previous = button(t('overview.previousPage', 'Previous page'), () => change(page.page - 1), 'overview-page-button');
            previous.append(icon('chevron_left'));
            previous.disabled = page.page === 0;
            previous.dataset.overviewKey = `${context}:previous`;
            const next = button(t('overview.nextPage', 'Next page'), () => change(page.page + 1), 'overview-page-button');
            next.append(icon('chevron_right'));
            next.disabled = page.page + 1 === page.pages;
            next.dataset.overviewKey = `${context}:next`;
            const label = node('span', '', t('overview.pageOf', 'Page {page} of {pages}')
                .replace('{page}', String(page.page + 1)).replace('{pages}', String(page.pages)));
            label.setAttribute('aria-live', 'polite');
            navigation.append(previous, label, next);
            container.append(navigation);
        }
        function focusGroup(group) {
            selectedGroup = group;
            selectedRoute = `group:${group}`;
            selectedHost = null;
            targetPage = 0;
            renderSidebar();
            renderHosts();
        }
        function mountMap(canvas, container, groups) {
            const count = groups.reduce((sum, [, routes]) => sum + routes.reduce((n, r) => n + r.hosts.length, 0), 0);
            const compact = mapMode === 'groups' || (mapMode === 'auto' && (count > 30 || groups.length > 6 || (container.clientWidth < 1100 && count > 12)));
            let list = mapMode === 'list' || (mapMode === 'auto' && win.innerWidth < 600);
            const shell = node('section', 'overview-map');
            const toolbar = node('div', 'overview-map-toolbar');
            const mode = node('select');
            mode.setAttribute('aria-label', t('overview.mapDetail', 'Map detail'));
            for (const [value, label] of [['auto', t('overview.mapAuto', 'Automatic')], ['details', t('overview.mapDetails', 'Host details')], ['groups', t('overview.mapGroups', 'Groups / Enterprise')], ['list', t('overview.mapList', 'List')]]) {
                const option = node('option', '', label); option.value = value; mode.append(option);
            }
            mode.value = mapMode;
            mode.addEventListener('change', () => { mapMode = mode.value; saveMap(); renderHosts(); });
            const viewport = node('div', 'overview-map-viewport');
            viewport.tabIndex = 0;
            viewport.setAttribute('aria-label', 'Infrastructure map. Drag background to pan. Arrow keys move, plus and minus zoom.');
            viewport.dataset.list = String(list);
                shell.dataset.list = String(list);
            canvas.dataset.compact = String(compact && mapMode !== 'list');
            const columns = win.innerWidth < 600 ? 1 : Math.max(1, Math.min(Math.ceil(Math.sqrt(groups.length)), Math.round(container.clientWidth / 364)));
            canvas.style.setProperty('--map-columns', String(columns));
            const zoomLabel = node('output', 'overview-map-zoom');
            const key = JSON.stringify([mapMode, groups.map(([name]) => name), byId('overviewHostSearch').value]);
            let position = mapPositions.get(key);
            let dragging = null;
            let saveTimer;
            const persist = () => { win.clearTimeout(saveTimer); saveTimer = win.setTimeout(saveMap, 180); };
            const cards = [...canvas.querySelectorAll('.overview-network-group')];
            const board = canvas.querySelector('.overview-inventory-bundles');
            const layout = () => {
                if (list) { board.style.height = ''; board.style.width = ''; for (const card of cards) { card.style.left = ''; card.style.top = ''; } return; }
                const existing = cards.some(card => groupPositions.has(card.dataset.group));
                let bottom = 0;
                for (const card of cards) {
                    const point = groupPositions.get(card.dataset.group);
                    if (point) bottom = Math.max(bottom, point.y + card.offsetHeight + 24);
                }
                const rowHeight = Math.max(120, ...cards.map(card => card.offsetHeight)) + 24;
                cards.forEach((card, index) => {
                    if (!groupPositions.has(card.dataset.group)) {
                        groupPositions.set(card.dataset.group, existing ? {x:0, y:bottom} : {x:(index % columns)*364, y:Math.floor(index/columns)*rowHeight});
                        if (existing) bottom += card.offsetHeight + 24;
                    }
                    const point = groupPositions.get(card.dataset.group);
                    card.style.left = `${point.x}px`; card.style.top = `${point.y}px`;
                });
                board.style.width = `${Math.max(340,...cards.map(card => groupPositions.get(card.dataset.group).x + 340))}px`;
                board.style.height = `${Math.max(120,...cards.map(card => groupPositions.get(card.dataset.group).y + card.offsetHeight))}px`;
                scheduleEdges();
            };
            const paint = () => {
                if (!position || list) return;
                canvas.style.transform = `translate(${position.x}px, ${position.y}px) scale(${position.scale})`;
                canvas.dataset.mapScale = String(position.scale);
                zoomLabel.textContent = `${Math.round(position.scale * 100)}%`;
                mapPositions.set(key, {...position});
                if (mapPositions.size > 30) mapPositions.delete(mapPositions.keys().next().value);
                scheduleEdges(); persist();
            };
            const fit = () => {
                if (!viewport.isConnected || list) return;
                const scale = Math.max(.2, Math.min(1, (viewport.clientWidth - 32) / canvas.offsetWidth, (viewport.clientHeight - 32) / canvas.offsetHeight));
                position = {scale, x: (viewport.clientWidth - canvas.offsetWidth * scale) / 2, y: (viewport.clientHeight - canvas.offsetHeight * scale) / 2};
                paint();
            };
            const zoom = (factor, center = {x:viewport.clientWidth / 2, y:viewport.clientHeight / 2}) => {
                if (!position) return;
                const scale = Math.max(.2, Math.min(2, position.scale * factor));
                const ratio = scale / position.scale;
                position = {scale, x: center.x - (center.x - position.x) * ratio, y: center.y - (center.y - position.y) * ratio};
                paint();
            };
            const out = button(t('overview.mapZoomOut', 'Zoom out'), () => zoom(1 / 1.25)); out.textContent = '−';
            const plus = button(t('overview.mapZoomIn', 'Zoom in'), () => zoom(1.25)); plus.textContent = '+';
            const reset = button(t('overview.mapFit', 'Fit map'), fit); reset.textContent = t('overview.mapFit', 'Fit map');
            const arrangeReset = button(t('overview.mapReset', 'Reset arrangement'), () => { groupPositions.clear(); mapPositions.clear(); layout(); fit(); saveMap(); });
            arrangeReset.textContent = t('overview.mapReset', 'Reset arrangement');
            const options = node('details', 'overview-map-options');
            options.append(node('summary', '', t('overview.mapOptions', 'Map options')), arrangeReset);
            toolbar.append(mode, node('span', 'overview-map-hint', `${count} ${t('connectionAssets.hosts')} · ${compact ? t('overview.mapGroupHint', 'Group overview') : t('overview.mapDragHint', 'Drag background to explore')}`), out, zoomLabel, plus, reset, options);
            for (const control of [out, plus, reset]) control.disabled = list;
            viewport.append(canvas); shell.append(toolbar, viewport); container.append(shell);
            for (const card of cards) {
                const handle = button(t('overview.mapMove', 'Move group'), () => {}, 'overview-map-handle');
                handle.append(icon('drag_indicator'));
                handle.title = t('overview.mapMoveHint', 'Drag to move; use arrow keys for fine positioning');
                card.prepend(handle);
                handle.addEventListener('keydown', event => {
                    const shifts = {ArrowLeft:[-20,0],ArrowRight:[20,0],ArrowUp:[0,-20],ArrowDown:[0,20]};
                    if (list || !shifts[event.key]) return;
                    event.preventDefault(); event.stopPropagation();
                    const point = groupPositions.get(card.dataset.group);
                    point.x = Math.max(0,point.x+shifts[event.key][0]); point.y = Math.max(0,point.y+shifts[event.key][1]); layout(); saveMap();
                });
            }
            layout();
            viewport.addEventListener('pointerdown', event => {
                if (list || !position || event.button !== 0) return;
                const handle = event.target.closest('.overview-map-handle');
                if (handle) {
                    const card = handle.closest('.overview-network-group');
                    dragging = {id:event.pointerId, x:event.clientX, y:event.clientY, card, start:{...groupPositions.get(card.dataset.group)}, scale:canvas.getBoundingClientRect().width/canvas.offsetWidth};
                    event.preventDefault(); viewport.setPointerCapture(event.pointerId); viewport.dataset.dragging = 'true'; return;
                }
                if (event.target.closest('button,input,select,a,[draggable=true]')) return;
                dragging = {id: event.pointerId, x: event.clientX, y: event.clientY, start: {...position}};
                viewport.setPointerCapture(event.pointerId);
                viewport.dataset.dragging = 'true';
            });
            viewport.addEventListener('pointermove', event => {
                if (!dragging || dragging.id !== event.pointerId) return;
                if (dragging.card) {
                    groupPositions.set(dragging.card.dataset.group, {x:Math.max(0, dragging.start.x + (event.clientX-dragging.x)/dragging.scale),y:Math.max(0, dragging.start.y + (event.clientY-dragging.y)/dragging.scale)});
                    layout(); return;
                }
                position = {...position, x: dragging.start.x + event.clientX - dragging.x, y: dragging.start.y + event.clientY - dragging.y}; paint();
            });
            const end = () => { if (dragging) saveMap(); dragging = null; delete viewport.dataset.dragging; };
            viewport.addEventListener('pointerup', end); viewport.addEventListener('pointercancel', end);
            viewport.addEventListener('lostpointercapture', end);
            viewport.addEventListener('wheel', event => {
                if (list) return;
                event.preventDefault(); const bounds = viewport.getBoundingClientRect(); zoom(Math.exp(-Math.max(-100,Math.min(100,event.deltaY))*.002), {x:event.clientX-bounds.left,y:event.clientY-bounds.top});
            }, {passive:false});
            viewport.addEventListener('focusin', event => {
                if (list || event.target === viewport || !position || event.target.dataset.mapRestoreFocus) return;
                const bounds = viewport.getBoundingClientRect();
                const group = event.target.closest('.overview-network-group')?.getBoundingClientRect();
                const item = group && group.width <= bounds.width && group.height <= bounds.height
                    ? group : event.target.getBoundingClientRect();
                if (item.left < bounds.left || item.right > bounds.right || item.top < bounds.top || item.bottom > bounds.bottom) {
                    position.x += bounds.left + bounds.width / 2 - (item.left + item.width / 2);
                    position.y += bounds.top + bounds.height / 2 - (item.top + item.height / 2); paint();
                }
            });
            viewport.addEventListener('keydown', event => {
                if (event.target !== viewport || list || !position) return;
                const shifts = {ArrowLeft:[60,0], ArrowRight:[-60,0], ArrowUp:[0,60], ArrowDown:[0,-60]};
                if (shifts[event.key]) { event.preventDefault(); position.x += shifts[event.key][0]; position.y += shifts[event.key][1]; paint(); }
                else if (['+', '=', '-'].includes(event.key)) { event.preventDefault(); zoom(event.key === '-' ? .8 : 1.25); }
                else if (event.key === 'Home') { event.preventDefault(); fit(); }
            });
            win.requestAnimationFrame(() => { if (!viewport.isConnected) return; position ? paint() : fit(); });
            viewport.addEventListener('overview-map-fit', fit);
            let firstResize = true;
            const observer = new win.ResizeObserver(() => {
                list = mapMode === 'list' || (mapMode === 'auto' && win.innerWidth < 600);
                viewport.dataset.list = String(list);
                shell.dataset.list = String(list);
                canvas.style.setProperty('--map-columns', String(win.innerWidth < 600 ? 1 : columns));
                for (const control of [out, plus, reset]) control.disabled = list;
                layout();
                if (list) { canvas.style.transform = ''; canvas.dataset.mapScale = '1'; zoomLabel.textContent = '—'; scheduleEdges(); }
                else if (firstResize && position) paint();
                else if (!dragging) fit();
                firstResize = false;
            });
            observer.observe(viewport);
            mapCleanup = () => { observer.disconnect(); win.clearTimeout(saveTimer); saveMap(); };
        }
        function renderGraph(bundles, container) {
            const grouped = new Map();
            bundles.forEach(bundle => {
                if (!grouped.has(bundle.group)) grouped.set(bundle.group, []);
                grouped.get(bundle.group).push(bundle);
            });
            const groupsToShow = [...grouped];
            const canvas = node('div', 'overview-inventory-canvas');
            const origin = node('div', 'overview-inventory-origin');
            origin.append(icon('terminal'), node('strong', '', t('overview.serverOrigin')));
            origin.setAttribute('aria-label', t('overview.routeOrigin', 'SSH connection origin'));
            const svg = doc.createElementNS('http://www.w3.org/2000/svg', 'svg');
            svg.classList.add('overview-inventory-edges');
            svg.setAttribute('aria-hidden', 'true');
            const groups = node('div', 'overview-inventory-bundles');
            groupsToShow.forEach(([group, routes]) => {
                const section = node('section', 'overview-network-group');
                section.dataset.group = group;
                dropGroup(section, group);
                const count = routes.reduce((sum, route) => sum + route.hosts.length, 0);
                const total = routes.reduce((sum, route) => sum + route.count, 0);
                const target = button(`${group || t('profiles.ungrouped')}, ${count} ${t('connectionAssets.hosts')}`, () => focusGroup(group), 'overview-bundle-button');
                target.dataset.overviewKey = `group:${group}`;
                const folder = icon('folder_open');
                folder.classList.add('overview-bundle-folder');
                const title = node('span', 'overview-bundle-title');
                title.append(node('strong', '', group || t('profiles.ungrouped')));
                const summary = node('span', 'overview-bundle-count', `${count} ${t('connectionAssets.hosts')}`);
                if (byId('overviewHostSearch').value.trim()) summary.textContent = t('overview.matchCount', '{matches} matches in {total} hosts')
                    .replace('{matches}', String(count)).replace('{total}', String(total));
                title.append(summary);
                target.append(folder, title, icon('chevron_right'));
                section.append(target);
                const totals = node('p', 'overview-map-group-summary');
                const direct = routes.filter(r => r.route === 'none').reduce((n, r) => n + r.hosts.length, 0);
                const indirect = routes.filter(r => r.route === 'configured').reduce((n, r) => n + r.hosts.length, 0);
                const unresolved = count - direct - indirect;
                totals.textContent = `${direct} ${t('overview.directRouteShort', 'Direct')} · ${indirect} ${t('overview.mapIndirect', 'via jump host')}`;
                if (unresolved) totals.textContent += ` · ${unresolved} ${t('overview.mapUnresolved', 'unresolved routes')}`;
                section.append(totals);
                // Distribute the bounded preview across routes so a direct route
                // cannot conceal every jump-host route in the same group.
                const ordered = routes.map(route => [...route.hosts].sort((a, b) => Number(b.favorite) - Number(a.favorite)));
                const visibleIds = new Set();
                for (let row = 0; visibleIds.size < Math.min(3, count); row++) {
                    for (const hosts of ordered) {
                        if (hosts[row]) visibleIds.add(hosts[row].id);
                        if (visibleIds.size === Math.min(3, count)) break;
                    }
                }
                routes.forEach((bundle, index) => {
                    const hosts = ordered[index].filter(host => visibleIds.has(host.id));
                    if (!hosts.length) return;
                    const route = node('div', 'overview-route-bundle');
                    route.dataset.routeState = bundle.route;
                    route.dataset.bundleKey = bundle.key;
                    route.dataset.selected = String(hosts.some(host => host.id === selectedHost));
                    const step = node('div', `overview-route-step${bundle.route === 'none' ? ' overview-route-direct' : ''}`);
                    if (bundle.route === 'configured') {
                        const copy = node('span', 'overview-route-step-copy');
                        copy.append(node('strong', '', routeLabel(bundle)), node('small', '', t('connectionAssets.jumpHosts')));
                        step.append(icon('vpn_key'), copy);
                    } else step.append(node('span', '', routeLabel(bundle)));
                    const platforms = node('div', 'overview-bundle-platforms');
                    for (const host of hosts) {
                        const marker = node('div', 'overview-platform-card');
                        const profile = win.ProfileManager?.profiles?.find(item => item.id === host.id);
                        const live = win.socket?.connected === true && hasOpenSession(profile, sessionManager.getAllSessions());
                        marker.dataset.live = String(live);
                        const inspect = hostButton(host);
                        inspect.classList.add('overview-platform-name');
                        const copy = node('span', 'overview-platform-copy');
                        copy.append(node('strong', 'overview-platform-host', host.name), node('small', '', live ? t('overview.openSession', 'Open session') : host.route === 'configured' ? t('overview.viaJump').replace('{name}', host.jump.name) : routeLabel(host)));
                        inspect.replaceChildren(win.HostPlatform?.render(host.platform, doc) || icon('dns'), copy);
                        marker.append(inspect, hostActions(host, `atlas:${bundle.key}`));
                        platforms.append(marker);
                    }
                    route.append(step, platforms);
                    section.append(route);
                });
                if (count > visibleIds.size) {
                    const more = button(`${t('overview.expandGroup', 'Expand')} ${group || t('profiles.ungrouped')}`, () => focusGroup(group), 'overview-bundle-more');
                    more.textContent = `${t('overview.expandGroup', 'Expand')} (+${count - visibleIds.size})`;
                    more.dataset.overviewKey = `more:group:${group}`;
                    section.append(more);
                }
                if (arranging) groupControls(section, group, displayGroupOrder, displayGroupRanks, group);
                groups.append(section);
            });
            canvas.append(svg, origin, groups);
            mountMap(canvas, container, groupsToShow);
            const legend = node('div', 'overview-atlas-legend');
            legend.append(icon('account_tree'), node('span', '', t('overview.configuredOnly', 'Configured SSH path. Reachability is not measured.')));
            legend.append(node('small', 'overview-map-meaning', t('overview.mapMeaning', 'Groups label saved hosts; lines show configured SSH routes, not reachability.')));
            container.append(legend);

            scheduleEdges();
        }
        function renderPath(host, container) {
            const path = node('section', 'overview-selected-path');
            path.setAttribute('aria-label', t('overview.inspectPath', 'Inspect SSH path'));
            const list = node('ol', 'overview-path-stops');
            const stop = (label, symbol) => {
                const item = node('li');
                item.append(symbol, node('strong', '', label));
                list.append(item);
            };
            stop(t('overview.serverOrigin'), icon('terminal'));
            if (host.route === 'configured') stop(host.jump.name, icon('hub'));
            else if (host.route !== 'none') stop(routeLabel(host), icon('help_outline'));
            stop(host.name, win.HostPlatform?.render(host.platform, doc) || icon('dns'));
            path.append(list, node('p', '', t('overview.configuredOnly', 'Configured SSH path. Reachability is not measured.')));
            container.append(path);
        }
        function renderInspector(host, container) {
            container.classList.toggle('overview-with-inspector', Boolean(host));
            if (!host) return;
            const panel = node('aside', 'overview-access-inspector');
            panel.setAttribute('aria-labelledby', 'overviewAccessTitle');
            const close = () => {
                selectedHost = null;
                renderHosts();
                const target = Array.from(container.querySelectorAll('[data-host-id]')).find(item => item.dataset.hostId === host.id);
                // Let the remounted map restore its geometry before revealing focus.
                win.requestAnimationFrame(() => {
                    container.querySelector('.overview-map-viewport')?.dispatchEvent(new Event('overview-map-fit'));
                    if (target?.isConnected) {
                        target.dataset.mapRestoreFocus = 'true';
                        target.focus({preventScroll: true});
                        delete target.dataset.mapRestoreFocus;
                    }
                    else byId('overviewHostSearch').focus({preventScroll: true});
                });
            };
            const header = node('div', 'overview-access-heading');
            const heading = node('h3', '', host.name);
            heading.id = 'overviewAccessTitle';
            heading.tabIndex = -1;
            heading.dataset.overviewKey = `inspector:title:${host.id}`;
            const dismiss = button(t('common.close', 'Close'), close, 'overview-host-edit');
            dismiss.dataset.overviewKey = `inspector:close:${host.id}`;
            dismiss.append(icon('close'));
            header.append(heading, dismiss);
            panel.append(header, node('p', 'overview-access-group', host.group || t('profiles.ungrouped')));
            panel.append(node('h4', '', t('overview.accessRoute')));
            renderPath(host, panel);
            const profile = win.ProfileManager?.profiles.find(item => item.id === host.id);
            const facts = node('dl', 'overview-access-facts');
            for (const [label, value] of [[t('overview.destination'), profile ? `${profile.host}:${profile.port || 22}` : '—'],
                [t('overview.accessType'), routeLabel(host)]]) {
                const row = node('div');
                row.append(node('dt', '', label), node('dd', '', value));
                facts.append(row);
            }
            panel.append(facts);
            if (host.route === 'unavailable') panel.append(node('p', 'overview-access-error', t('overview.repairJump')));
            const actions = node('div', 'overview-access-actions');
            const connect = button(t('overview.checkConnect'), () => launch(host.id), 'btn btn-primary');
            connect.append(icon('terminal'), node('span', '', t('overview.checkConnect')));
            connect.disabled = host.route === 'loading' || host.route === 'unavailable';
            connect.dataset.overviewKey = `inspector:connect:${host.id}`;
            const edit = button(t('overview.editAccess'), () => editHost(host.id), 'btn btn-secondary');
            edit.append(icon('edit'), node('span', '', t('overview.editAccess')));
            edit.dataset.overviewKey = `inspector:edit:${host.id}`;
            const files = button(t('overview.openFiles'), () => {
                rememberPosition();
                byId('fileTransferBtn').click();
                win.sftpFileManager?.openQuickConnect(host.id);
            }, 'btn btn-secondary');
            files.dataset.overviewKey = `inspector:files:${host.id}`;
            files.append(icon('folder_open'), node('span', '', t('overview.openFiles')));
            actions.append(connect, edit, files);
            panel.append(actions, node('p', 'overview-access-note', t('overview.checkConnectHint')));
            const jumps = button(t('overview.manageJumps'), () => {
                rememberPosition();
                win.openConnectionAssetManager?.('jump-hosts');
            }, 'overview-link');
            jumps.dataset.overviewKey = `inspector:jumps:${host.id}`;
            jumps.append(icon('hub'), node('span', '', t('overview.manageJumps')));
            panel.append(jumps);
            panel.addEventListener('keydown', event => {
                if (event.key === 'Escape') { event.preventDefault(); event.stopPropagation(); close(); }
            });
            container.append(panel);
        }
        function renderHosts() {
            mapCleanup();
            const container = byId('overviewHosts');
            const preview = byId('overviewRoutePreview');
            groupObserver?.disconnect();
            draggedGroup = null;
            container.classList.remove('overview-group-layout', 'overview-with-inspector');
            container.classList.add('overview-inventory');
            retainFocus(view, () => {
                preview.replaceChildren();
                preview.hidden = true;
                byId('overviewRouteCard').hidden = true;
                const selectionKey = `${selectedGroup}:${selectedRoute}`;
                container.dataset.transition = String(inventorySelectionKey !== null && inventorySelectionKey !== selectionKey);
                inventorySelectionKey = selectionKey;
                container.replaceChildren();
                const manager = win.ProfileManager;
                const loaded = manager?.profilesLoaded === true;
                container.setAttribute('aria-busy', String(!loaded && !loadError && win.socket?.connected === true));
                if (!loaded) {
                    byId('overviewHostCount').textContent = '—';
                    message(container, loadError || !win.socket?.connected ? 'overview.unavailable' : 'overview.loading');
                    return;
                }
                const model = orderedModel(manager.profiles, win.JumpHostManager?.jumpHosts, win.JumpHostManager?.loaded);
                const moved = followingMove && model.find(host => host.id === followingMove.id && host.group === followingMove.group);
                if (moved) {
                    selectedGroup = moved.group;
                    selectedRoute = JSON.stringify([moved.group, moved.route, moved.routeRef || moved.jump?.id || '']);
                    selectedHost = moved.id;
                    const siblings = model.filter(host => host.group === moved.group && host.route === moved.route && host.routeRef === moved.routeRef)
                        .sort((a, b) => Number(b.favorite) - Number(a.favorite));
                    targetPage = Math.floor(siblings.findIndex(host => host.id === moved.id) / 10);
                    followingMove = null;
                    byId('overviewGroupFilter').value = `group:${moved.group}`;
                }
                const query = byId('overviewHostSearch').value.trim();
                if (!model.some(host => host.id === selectedHost)) selectedHost = null;
                const inventory = aggregateRoutes(model, {query, group: selectedGroup});
                if (!inventory.bundles.some(bundle => bundle.hosts.some(host => host.id === selectedHost))) selectedHost = null;
                view.dataset.journey = selectedGroup !== null || query || selectedRoute || graph ? 'inventory' : 'welcome';
                view.setAttribute('aria-labelledby', view.dataset.journey === 'inventory' ? 'overviewHostsTitle' : 'overviewTitle');
                byId('overviewHostCount').textContent = String(inventory.matches);
                if (byId('overviewRouteMap')) {
                    const list = node('div', 'overview-compact-list');
                    let scrollFrame = 0, scrollDirection = 0;
                    const scrollDuringDrag = () => {
                        scrollFrame = 0;
                        if (!list.isConnected || !arranging || draggedGroup === null || !scrollDirection) return;
                        list.scrollTop += scrollDirection * 12;
                        scrollFrame = win.requestAnimationFrame(scrollDuringDrag);
                    };
                    const updateDragScroll = event => {
                        if (draggedGroup === null || !arranging) return;
                        const bounds = list.getBoundingClientRect();
                        scrollDirection = event.clientY < bounds.top + 36 ? -1 : event.clientY > bounds.bottom - 36 ? 1 : 0;
                        if (!scrollFrame) scrollDuringDrag();
                    };
                    // WebKit may enter a new child without sending dragover until
                    // the pointer moves again. Begin scrolling on entry as well.
                    list.addEventListener('dragenter', updateDragScroll, true);
                    list.addEventListener('dragover', updateDragScroll, true);
                    list.addEventListener('dragleave', event => {
                        // WebKit leaves relatedTarget null when crossing child elements.
                        // Stop only when the pointer actually leaves the scroll viewport.
                        const bounds = list.getBoundingClientRect();
                        if (event.clientX < bounds.left || event.clientX > bounds.right
                            || event.clientY < bounds.top || event.clientY > bounds.bottom) scrollDirection = 0;
                    });
                    const hosts = inventory.bundles.flatMap(item => item.hosts);
                    const groups = new Map();
                    for (const host of hosts) {
                        if (!groups.has(host.group)) groups.set(host.group, []);
                        groups.get(host.group).push(host);
                    }
                    for (const [group, members] of groups) {
                        const section = node('section', 'overview-list-group');
                        const heading = node('h3', '', group || t('profiles.ungrouped'));
                        heading.append(node('small', '', String(members.length)));
                        section.append(heading); dropGroup(section, group);
                        if (arranging) groupControls(section, group, displayGroupOrder, displayGroupRanks, group);
                        for (const host of members) {
                            const row = node('div', 'overview-compact-row');
                            const profile = win.ProfileManager?.profiles?.find(item => item.id === host.id);
                            const live = win.socket?.connected === true && hasOpenSession(profile, sessionManager.getAllSessions());
                            row.dataset.live = String(live);
                            row.append(hostButton(host), node('span', 'overview-compact-route', host.route === 'none'
                                ? t('overview.directSsh', 'Direct SSH') : host.jump?.name || t(host.route === 'loading' ? 'overview.loading' : 'overview.missingJump')),
                                hostActions(host), moveControl(host));
                            if (live) {
                                const status = node('span', 'overview-session-indicator');
                                status.setAttribute('role', 'img');
                                status.setAttribute('aria-label', t('overview.openSession', 'Open session'));
                                status.title = t('overview.openSession', 'Open session');
                                row.querySelector(':scope > button').append(status);
                            }
                            section.append(row);
                        }
                        list.append(section);
                    }
                    if (!hosts.length) message(list, query || selectedGroup !== null ? 'profiles.noMatches' : 'profiles.none');
                    container.append(list);
                    renderInspector(hosts.find(host => host.id === selectedHost), container);
                    return;
                }
                const context = node('nav', 'overview-inventory-context');
                context.dataset.focused = String(selectedGroup !== null || Boolean(query));
                context.setAttribute('aria-label', t('overview.inventoryBreadcrumb', 'Inventory navigation'));
                const all = button(t('overview.allGroups'), () => { selectedGroup = null; selectedRoute = null; selectedHost = null; renderSidebar(); renderHosts(); }, 'overview-context-button');
                all.textContent = t('overview.allGroups');
                all.dataset.overviewKey = 'inventory:all';
                context.append(all);
                if (selectedGroup !== null) {
                    const group = button(selectedGroup || t('profiles.ungrouped'), () => { selectedRoute = null; selectedHost = null; renderHosts(); }, 'overview-context-button');
                    group.textContent = selectedGroup || t('profiles.ungrouped');
                    group.dataset.overviewKey = 'inventory:group';
                    context.append(icon('chevron_right'), group);
                }
                const count = node('span', 'overview-inventory-total', query
                    ? t('overview.matchCount', '{matches} matches in {total} hosts').replace('{matches}', String(inventory.matches)).replace('{total}', String(inventory.totalHosts))
                    : (inventory.bundles.length === 1
                        ? t('overview.inventoryCountOne', '{hosts} hosts · 1 route bundle')
                        : t('overview.inventoryCount', '{hosts} hosts · {routes} route bundles'))
                        .replace('{hosts}', String(inventory.matches)).replace('{routes}', String(inventory.bundles.length)));
                count.setAttribute('role', 'status');
                context.append(count);
                container.append(context);
                const expandedGroup = selectedGroup !== null && (!selectedRoute || selectedRoute === `group:${selectedGroup}`);
                const bundle = expandedGroup ? {hosts: inventory.bundles.flatMap(item => item.hosts)}
                    : inventory.bundles.find(item => item.key === selectedRoute);
                if (selectedRoute && !bundle) { selectedRoute = null; selectedHost = null; }
                if (!inventory.bundles.length) {
                    message(container, query || selectedGroup !== null ? 'profiles.noMatches' : 'profiles.none');
                    return;
                }
                if (query && !bundle && !graph) {
                    const targets = pageItems(inventory.bundles.flatMap(item => item.hosts), targetPage, 10);
                    targetPage = targets.page;
                    const selection = node('div', 'overview-target-selection');
                    selection.append(hostGroups(targets.items, false, false));
                    container.append(selection);
                    pager(container, targets, next => { targetPage = next; selectedHost = null; renderHosts(); }, t('connectionAssets.hosts'));
                } else if (bundle) {
                    if (!expandedGroup) context.append(icon('chevron_right'), node('span', '', routeLabel(bundle)));
                    {
                        const title = node('h3', 'overview-target-heading', expandedGroup ? selectedGroup || t('profiles.ungrouped') : routeLabel(bundle));
                        container.append(title, node('p', 'overview-detail-hint', t('overview.selectPath', 'Select a host to inspect its configured SSH path.')));
                    }
                    const targets = pageItems([...bundle.hosts].sort((a, b) => Number(b.favorite) - Number(a.favorite)), targetPage, 10);
                    targetPage = targets.page;
                    const selection = node('div', 'overview-target-selection');
                    selection.append(hostGroups(targets.items, false, false));
                    container.append(selection);
                    pager(container, targets, next => { targetPage = next; selectedHost = null; renderHosts(); }, t('connectionAssets.hosts'));
                } else renderGraph(inventory.bundles, container);
                const selected = inventory.bundles.flatMap(item => item.hosts).find(host => host.id === selectedHost);
                if (!selected) selectedHost = null;
                renderInspector(selected, container);
            });
            scheduleEdges();
        }
        function renderSidebar() {
            const hosts = orderedModel(win.ProfileManager?.profiles || []);
            const groups = new Map();
            hosts.forEach(host => {
                if (!groups.has(host.group)) groups.set(host.group, []);
                groups.get(host.group).push(host);
            });
            if (selectedGroup !== null && !groups.has(selectedGroup)) {
                selectedGroup = null;
                selectedRoute = null;
                selectedHost = null;
                targetPage = 0;
            }
            const select = byId('overviewGroupFilter');
            if (select) {
                select.replaceChildren(new win.Option(t('overview.allGroups'), ''));
                groups.forEach((items, group) => select.add(new win.Option(group || t('profiles.ungrouped'), `group:${group}`)));
                select.value = selectedGroup === null ? '' : `group:${selectedGroup}`;
            }
            const inventoryNav = byId('overviewInventoryGroups');
            if (inventoryNav) retainFocus(inventoryNav, () => {
                inventoryNav.replaceChildren();
                const choose = group => {
                    selectedGroup = group; selectedRoute = null; selectedHost = null;
                    targetPage = 0;
                    byId('overviewHostSearch').value = '';
                    renderSidebar(); renderHosts();
                };
                const all = button(t('overview.allGroups'), () => choose(null), 'overview-inventory-group');
                all.id = 'overviewInventoryAll';
                all.dataset.overviewKey = 'inventory-nav:all';
                all.append(icon('dns'), node('span', '', t('overview.allGroups')), node('small', '', win.ProfileManager?.profilesLoaded === true ? String(hosts.length) : '—'));
                if (selectedGroup === null) all.setAttribute('aria-current', 'true');
                inventoryNav.append(all);
                groups.forEach((items, group) => {
                    const entry = button(group || t('profiles.ungrouped'), () => choose(group), 'overview-inventory-group');
                    entry.dataset.group = group;
                    entry.dataset.overviewKey = `inventory-nav:${group}`;
                    entry.append(icon('folder_open'), node('span', '', group || t('profiles.ungrouped')), node('small', '', String(items.length)));
                    if (selectedGroup === group) entry.setAttribute('aria-current', 'true');
                    inventoryNav.append(entry);
                });
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
                    dropGroup(section, group);
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
        function recentConnections() {
            if (!quickConnect()) return false;
            const recent = byId('recentConnectionsCard');
            recent.classList.remove('hidden');
            recent.open = true;
            recent.querySelector('summary').focus();
            return true;
        }
        function renderResourceSummary() {
            let summary = view.querySelector('.overview-resource-summary');
            if (!summary) {
                summary = node('dl', 'overview-resource-summary');
                byId('overviewInventorySummary').append(summary);
            }
            const manager = win.ProfileManager;
            const counts = summarizeResources({
                profiles: manager?.profiles, profilesLoaded: manager?.profilesLoaded,
                keys: manager?.keys, keysLoaded: manager?.keysLoaded,
                jumps: win.JumpHostManager?.jumpHosts, jumpsLoaded: win.JumpHostManager?.loaded,
                commandSets: win.CommandSetManager?.commandSets, commandSetsLoaded,
            });
            const labels = {hosts: t('connectionAssets.hosts'), groups: t('overview.namedGroups', 'Named groups'),
                jumps: t('connectionAssets.jumpHosts'), keys: t('connectionAssets.keys'), commandSets: t('commandSets.manage')};
            summary.replaceChildren();
            Object.entries(counts).forEach(([key, count]) => {
                if (key === 'groups') return;
                const item = node('div');
                item.dataset.resource = key;
                const symbol = {hosts:'dns', groups:'groups', jumps:'account_tree', keys:'vpn_key', commandSets:'terminal'}[key];
                const label = node('dt');
                const action = button(labels[key], () => {
                    if (key === 'commandSets') win.CommandSetManager?.openManagement();
                    else win.openConnectionAssetManager?.({hosts: 'hosts', jumps: 'jump-hosts', keys: 'keys'}[key]);
                }, 'overview-resource-link');
                action.append(icon(symbol), node('span', '', labels[key]));
                action.setAttribute('aria-describedby', `overview-resource-${key}`);
                label.append(action);
                const value = node('dd', '', count === null ? '—' : String(count));
                value.id = `overview-resource-${key}`;
                if (count === null) value.setAttribute('aria-label', t('overview.loading'));
                item.append(label, value);
                summary.append(item);
            });
        }
        function renderHistory() {
            const container = byId('overviewHistory');
            retainFocus(container, () => {
                container.replaceChildren();
                const history = win.ConnectionHistory?.getHistory() || [];
                container.parentElement.hidden = history.length === 0;
                history.slice(0, 2).forEach(entry => {
                    const item = button(entry.host, () => {
                        if (!recentConnections()) return;
                        // Re-resolve after opening the existing dialog; its handlers own
                        // profile clearing, credential review and connection selection.
                        const current = win.ConnectionHistory.getHistory();
                        const index = current.findIndex(value => value.host === entry.host
                            && value.port === entry.port && value.username === entry.username);
                        if (index >= 0) byId('recentConnectionsList').children[index]?.click();
                    });
                    item.dataset.overviewKey = JSON.stringify([entry.host, entry.port, entry.username]);
                    const copy = node('span', 'overview-row-copy');
                    copy.append(node('strong', '', entry.host), node('small', '', win.ConnectionHistory.formatTime(entry.timestamp)));
                    item.append(icon('terminal'), copy, icon('arrow_forward'));
                    container.append(item);
                });
            });
            updateContinuationVisibility();
        }
        function updateContinuationVisibility() {
            const sessions = sessionManager.getAllSessions();
            const favorites = (win.ProfileManager?.profiles || []).some(host => host.favorite);
            const history = win.ConnectionHistory?.getHistory() || [];
            const strip = view.querySelector('.overview-session-strip');
            if (strip) {
                strip.hidden = !sessions.length && !favorites && !history.length;
                strip.dataset.historyOnly = String(!sessions.length && !favorites);
                strip.dataset.hasHistory = String(history.length > 0);
                strip.setAttribute('aria-labelledby', !sessions.length && !favorites ? 'overviewHistoryTitle' : 'overviewSessionsTitle');
            }
            byId('overviewSessions').hidden = !sessions.length && !favorites;
            byId('overviewSessionsTitle').parentElement.hidden = !sessions.length && !favorites;
        }
        function renderSessions() {
            const container = byId('overviewSessions');
            retainFocus(container, () => {
                container.replaceChildren();
                const sessions = sessionManager.getAllSessions();
                const selected = sessionManager.getWorkspaceSession?.() || sessionManager.getActiveSession?.();
                view.dataset.sessionSelected = String(Boolean(selected && sessionManager.getSession(selected)));
                byId('overviewSessionCount').textContent = String(sessions.length);
                byId('overviewSessionCount').hidden = sessions.length === 0;
                const heading = byId('overviewSessionsTitle').querySelector('[data-i18n]');
                heading.dataset.i18n = sessions.length ? 'overview.browserSessions' : 'profiles.favorites';
                heading.textContent = t(heading.dataset.i18n);
                if (!sessions.length) {
                    const favorites = orderedModel(win.ProfileManager?.profiles || [])
                        .filter(host => host.favorite).slice(0, 4);
                    if (favorites.length) {
                        const shortcuts = node('section', 'overview-favorite-shortcuts');
                        shortcuts.setAttribute('aria-label', t('profiles.favorites', 'Favorites'));
                        const list = node('div', 'overview-favorite-list');
                        favorites.forEach(host => {
                            const item = node('div', 'overview-favorite-item');
                            item.append(win.HostPlatform?.render(host.platform, doc) || icon('dns'), node('strong', '', host.name), hostActions(host, 'favorite'));
                            list.append(item);
                        });
                        shortcuts.append(list);
                        container.append(shortcuts);
                    }
                }
                const page = pageItems(sessions, sessionPage, 2);
                sessionPage = page.page;
                page.items.forEach(session => {
                    const label = session.displayName || session.host || t('workspace.sshSession');
                    const item = button(label, () => {
                        workspaces();
                        if (sessionManager.getSession(session.id)) sessionManager.switchSession(session.id);
                    });
                    item.dataset.overviewKey = `session:${session.id}`;
                    const copy = node('span', 'overview-row-copy');
                    copy.append(node('strong', '', label));
                    if (session.username && session.host) copy.append(node('small', '', `${session.username}@${session.host}:${session.port || 22}`));
                    const profile = win.ProfileManager?.profiles.find(record => record.id === session.profileId);
                    const action = node('span', 'overview-session-continue', t('overview.continueSession', 'Continue'));
                    action.append(icon('east'));
                    item.append(win.HostPlatform?.renderSession(session, profile, doc) || icon('terminal'), copy, action);
                    container.append(item);
                });
                pager(container, page, next => { sessionPage = next; renderSessions(); }, t('overview.browserSessions'));
            });
            updateContinuationVisibility();
        }
        function renderTransfers() {
            const transfers = win.sftpFileManager?.transferQueue || [];
            byId('overviewAllTransfers').hidden = transfers.length === 0;
            byId('overviewAllTransfers').parentElement.hidden = transfers.length === 0;
            byId('overviewTransferCount').textContent = String(transfers.length);
        }
        function openTransfers() {
            byId('fileTransferBtn').click();
            // Open the original queue and its controls, without duplicating state.
            if (byId('fmQueue')?.classList.contains('collapsed')) win.sftpFileManager?.toggleQueue();
        }
        const routeMap = win.OverviewRouteMap?.create({
            root: overviewPage ? byId('overviewRouteMap') : null,
            loaded: () => win.ProfileManager?.profilesLoaded === true,
            model: () => buildAccessModel(win.ProfileManager?.profiles || [], win.JumpHostManager?.jumpHosts || [], win.JumpHostManager?.loaded),
            hostActions,
            inspect: host => {
                selectedGroup = null; selectedRoute = null; selectedHost = host.id;
                byId('overviewHostSearch').value = ''; byId('overviewGroupFilter').value = '';
                renderHosts();
                byId('overviewAccessTitle')?.focus();
            },
        });
        function render() {
            if (!overviewPage || !visible()) return;
            byId('overviewConnectionNotice').hidden = win.socket?.connected === true;
            renderResourceSummary();
            renderHosts();
            routeMap?.render();
            renderSessions();
            renderTransfers();
            renderHistory();
            view.dataset.motionPaused = 'false';

        }
        function schedule() {
            if (!visible() || scheduled) return;
            scheduled = true;
            win.requestAnimationFrame(() => { scheduled = false; render(); });
        }
        function setGraph() {
            graph = false;
            view.classList.remove('overview-graph');
            byId('overviewGraphLegend').hidden = true;
            updateNavigation();
            renderHosts();
        }
        function updateNavigation() {
            const key = {overview: 'overview.title', workspaces: 'navigation.workspaces',
                hosts: 'connectionAssets.hosts', files: 'files.fileManager', commands: 'commands.workspace'}[
                win.primaryWorkspaceController?.getActiveView()] || 'navigation.workspaces';
            byId('shellLocation').dataset.i18n = key;
            byId('shellLocation').textContent = t(key);
        }
        function openOverview(showGraph = graph) {
            win.primaryWorkspaceController.open('overview', view);
            setGraph(showGraph);
            render();
            const heading = byId(view.dataset.journey === 'inventory' ? 'overviewHostsTitle' : 'overviewTitle');
            heading.setAttribute('tabindex', '-1');
            heading.focus({preventScroll: true});
            if (returnPosition) {
                const position = returnPosition;
                returnPosition = null;
                win.requestAnimationFrame(() => {
                    if (!visible()) return;
                    const target = Array.from(view.querySelectorAll('[data-overview-key]'))
                        .find(item => item.dataset.overviewKey === position.key);
                    target?.focus({preventScroll: true});
                    view.scrollTop = position.top;
                    byId('overviewHosts').scrollTop = position.hostsTop;
                });
            }
        }
        function init() {
            if (!view) return;
            if (overviewPage) bindOverviewPage();
            ['profile-list-change', 'jump-host-list-change', 'session-workspace-change',
                'primary-workspace-change', 'languageChanged'].forEach(event => win.addEventListener(event, schedule));
            ['profile-list-change', 'languageChanged', 'primary-workspace-change', 'session-workspace-change', 'host-access-change'].forEach(event => win.addEventListener(event, renderSidebar));
            win.addEventListener('primary-workspace-change', updateNavigation);
            win.addEventListener('languageChanged', updateNavigation);
            renderSidebar();
            updateNavigation();
            render();
            if (!overviewPage) return;
            bindOverviewRuntime();
        }
        function bindOverviewPage() {
            byId('overviewNavBtn').addEventListener('click', () => {
                if (win.primaryWorkspaceController.getActiveView() !== 'overview') {
                    openOverview();
                    return;
                }
                selectedGroup = null;
                selectedRoute = null;
                selectedHost = null;
                byId('overviewHostSearch').value = '';
                inventoryPages.clear();
                renderSidebar();
                openOverview(false);
            });
            byId('overviewGroupFilter').addEventListener('change', () => {
                const value = byId('overviewGroupFilter').value;
                selectedGroup = value === '' ? null : value.slice('group:'.length);
                selectedRoute = null;
                selectedHost = null;
                inventoryPages.delete(selectedGroup);
                targetPage = 0;
                byId('overviewHostSearch').value = '';
                renderSidebar();
                renderHosts();
            });
            byId('overviewArrangeGroups').addEventListener('click', () => {
                arranging = !arranging;
                draggedGroup = null;
                byId('overviewArrangeGroups').setAttribute('aria-expanded', String(arranging));
                byId('overviewArrangePanel').hidden = !arranging;
                renderHosts();
            });
            byId('overviewSortGroupsAsc').addEventListener('click', () => saveGroupOrder(orderedGroups(currentGroupOrder())));
            byId('overviewSortGroupsDesc').addEventListener('click', () => saveGroupOrder(orderedGroups(currentGroupOrder()).reverse()));
            win.addEventListener('storage', event => {
                if (!orderKey || (event.key !== orderKey && event.key !== null)) return;
                groupOrder = readGroupOrder(storage, orderKey);
                renderSidebar();
                schedule();
            });
            byId('overviewQuickConnect')?.addEventListener('click', quickConnect);
            byId('overviewResumeWork')?.addEventListener('click', workspaces);
            byId('overviewCreateHost').addEventListener('click', () => {
                byId('manageProfilesBtn').click();
                byId('newProfileBtn').click();
            });
            byId('overviewAllTransfers').addEventListener('click', openTransfers);
            byId('overviewHostSearch').addEventListener('input', () => {
                selectedRoute = null;
                inventoryPages.clear();
                targetPage = 0;
                renderHosts();
            });
            byId('overviewListBtn').addEventListener('click', () => setGraph(false));
            byId('overviewGraphBtn').addEventListener('click', () => setGraph(true));
            byId('overviewExpandRoutes').addEventListener('click', () => setGraph(true));
        }
        function bindOverviewRuntime() {
            win.addEventListener('resize', scheduleEdges);
            if (win.ResizeObserver) {
                groupObserver = new win.ResizeObserver(scheduleEdges);
                const observer = new win.ResizeObserver(scheduleEdges);
                observer.observe(byId('overviewHosts'));
                observer.observe(byId('overviewRoutePreview'));
            }
            // Queue progress must not rebuild focusable host/session buttons.
            win.addEventListener('file-transfer-queue-change', () => {
                if (!visible() || transfersScheduled) return;
                transfersScheduled = true;
                win.requestAnimationFrame(() => {
                    transfersScheduled = false;
                    if (visible()) renderTransfers();
                });
            });
            win.socket?.on('command_sets_list', data => {
                if (data && data.success !== false && Array.isArray(data.command_sets)) commandSetsLoaded = true;
                schedule();
            });
            ['keys_list', 'key_uploaded', 'key_deleted'].forEach(event => win.socket?.on(event, schedule));
            win.socket?.on('connect', () => { loadError = false; schedule(); });
            win.socket?.on('disconnect', schedule);
            win.socket?.on('error', () => {
                if (!win.ProfileManager?.profilesLoaded) loadError = true;
                schedule();
            });
        }
        return {init};
    }
    return {buildAccessModel, selectRouteTarget, atlasConnections, summarizeResources, aggregateRoutes, pageItems, groupTone, orderedGroups, moveGroupOrder, readGroupOrder, hasOpenSession, createController};
});
