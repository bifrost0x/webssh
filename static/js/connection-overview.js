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
                order: Number(profile.sort_order) || 0,
                route: profile.jump_host_id ? (jump ? 'configured' : (jumpsLoaded ? 'unavailable' : 'loading')) : 'none',
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

    function createController({window: win, document: doc, sessionManager}) {
        const view = doc.getElementById('connectionOverview');
        const byId = id => doc.getElementById(id);
        let graph = false;
        let selectedGroup = null;
        const collapsedGroups = new Set();
        let edgesScheduled = false;
        let scheduled = false;
        let transfersScheduled = false;
        let loadError = false;
        let draggedHost = null;
        const visible = () => win.primaryWorkspaceController?.getActiveView() === 'overview';
        const t = key => win.i18n?.t(key) || key;
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
            element.addEventListener('click', action);
            return element;
        }
        function workspaces() {
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
        function moveHost(id, group) {
            const manager = win.ProfileManager;
            const profiles = manager?.profiles || [];
            const source = profiles.find(profile => profile.id === id);
            if (!source || String(source.group || '').trim().toLocaleLowerCase() === group.trim().toLocaleLowerCase()) return;
            const count = profiles.filter(profile => profile.favorite !== true
                && String(profile.group || '').trim().toLocaleLowerCase() === group.trim().toLocaleLowerCase()).length;
            const move = win.ProfileLauncherUtils?.resolveProfileDrop(profiles, id, group, count);
            if (move) manager.requestProfileMove(move);
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
            const target = button(`${t('overview.openHost')}: ${host.name}`, () => launch(host.id));
            target.dataset.overviewKey = `host:${host.id}`;
            target.dataset.hostId = host.id;
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
            target.append(icon('dns'), node('span', 'overview-row-title', host.name));
            if (host.favorite) {
                const favorite = icon('star');
                favorite.classList.add('overview-favorite');
                target.append(favorite);
                target.setAttribute('aria-label', `${t('profiles.favorites')} · ${t('overview.openHost')}: ${host.name}`);
            }
            target.append(icon('chevron_right'));
            return target;
        }
        function hostGroups(hosts, showUnlinked = false) {
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
                    row.append(hostButton(host), moveControl(host));
                    list.append(row);
                });
                section.append(list);
                fragment.append(section);
            });
            return fragment;
        }
        function drawEdges() {
            if (!visible()) return;
            view.querySelectorAll('.overview-graph-branch[data-jump-id]').forEach(branch => {
                if (!branch.getClientRects().length) return;
                const svg = branch.querySelector('.overview-edges');
                svg.replaceChildren();
                const frame = branch.getBoundingClientRect();
                const source = branch.querySelector('.overview-jump').getBoundingClientRect();
                const horizontal = branch.closest('.overview-route-preview') && win.innerWidth >= 768;
                const sx = (horizontal ? source.right : source.left + source.width / 2) - frame.left;
                const sy = (horizontal ? source.top + source.height / 2 : source.bottom) - frame.top;
                branch.querySelectorAll('[data-host-id]').forEach(target => {
                    const rect = target.getBoundingClientRect();
                    const tx = (horizontal ? rect.left : rect.left + rect.width / 2) - frame.left;
                    const ty = (horizontal ? rect.top + rect.height / 2 : rect.top) - frame.top;
                    const bend = Math.max(24, (ty - sy) * 0.5);
                    const path = doc.createElementNS('http://www.w3.org/2000/svg', 'path');
                    const curve = horizontal
                        ? `M ${sx} ${sy} C ${sx + 36} ${sy}, ${tx - 36} ${ty}, ${tx} ${ty} m -6 -4 l 6 4 l -6 4`
                        : `M ${sx} ${sy} C ${sx} ${sy + bend}, ${tx} ${ty - bend}, ${tx} ${ty} m -4 -6 l 4 6 l 4 -6`;
                    path.setAttribute('d', curve);
                    path.dataset.sourceId = branch.dataset.jumpId;
                    path.dataset.targetId = target.dataset.hostId;
                    svg.append(path);
                });
            });
        }
        function scheduleEdges() {
            if (!visible() || edgesScheduled) return;
            edgesScheduled = true;
            win.requestAnimationFrame(() => { edgesScheduled = false; drawEdges(); });
        }
        function renderGraph(hosts, container) {
            const branches = new Map();
            const unlinked = [];
            hosts.forEach(host => {
                if (!host.jump) { unlinked.push(host); return; }
                if (!branches.has(host.jump.id)) branches.set(host.jump.id, {jump: host.jump, hosts: []});
                branches.get(host.jump.id).hosts.push(host);
            });
            container.dataset.routeBranches = String(branches.size);
            branches.forEach(({jump, hosts: targets}) => {
                const branch = node('section', 'overview-graph-branch');
                branch.dataset.jumpId = jump.id;
                branch.setAttribute('aria-label', `${t('overview.configuredRoute')}: ${jump.name}`);
                const source = node('div', 'overview-jump');
                source.append(icon('hub'), node('span', '', jump.name || t('connectionAssets.jumpHosts')));
                const svg = doc.createElementNS('http://www.w3.org/2000/svg', 'svg');
                svg.classList.add('overview-edges');
                svg.setAttribute('aria-hidden', 'true');
                const groups = node('div', 'overview-graph-groups');
                groups.append(hostGroups(targets));
                branch.append(svg, source, groups);
                container.append(branch);
            });
            if (unlinked.length) {
                const section = node('section', 'overview-graph-branch overview-graph-groups');
                section.append(hostGroups(unlinked, true));
                container.append(section);
            }
            scheduleEdges();
        }
        function renderHosts() {
            const container = byId('overviewHosts');
            const preview = byId('overviewRoutePreview');
            const heading = byId('overviewTitle');
            heading.dataset.i18n = graph ? 'overview.routesHeading' : 'overview.heading';
            heading.textContent = t(heading.dataset.i18n);
            const intro = view.querySelector('.overview-intro');
            intro.dataset.i18n = graph ? 'overview.routesIntro' : 'overview.intro';
            intro.textContent = t(intro.dataset.i18n);
            retainFocus(view, () => {
                preview.replaceChildren();
                byId('overviewRouteCard').hidden = true;
                container.replaceChildren();
                const manager = win.ProfileManager;
                const loaded = manager?.profilesLoaded === true;
                container.setAttribute('aria-busy', String(!loaded && !loadError && win.socket?.connected === true));
                byId('overviewHostCount').textContent = loaded ? String(manager.profiles.length) : '—';
                if (!loaded) {
                    message(container, loadError || !win.socket?.connected ? 'overview.unavailable' : 'overview.loading');
                    return;
                }
                const model = buildAccessModel(manager.profiles, win.JumpHostManager?.jumpHosts, win.JumpHostManager?.loaded);
                const query = byId('overviewHostSearch').value.trim().toLocaleLowerCase();
                const hosts = model.filter(host => (selectedGroup === null || host.group === selectedGroup)
                    && `${host.name} ${host.group}`.toLocaleLowerCase().includes(query));
                if (!hosts.length) {
                    message(container, query || selectedGroup !== null ? 'profiles.noMatches' : 'profiles.none');
                    return;
                }
                if (graph) renderGraph(hosts, container);
                else {
                    container.append(hostGroups(hosts));
                    const configured = hosts.filter(host => host.jump);
                    if (configured.length) {
                        // Preview the largest complete branch; the full view contains every route.
                        const counts = new Map();
                        configured.forEach(host => counts.set(host.jump.id, (counts.get(host.jump.id) || 0) + 1));
                        const previewJump = [...counts].sort((a, b) => b[1] - a[1])[0][0];
                        renderGraph(configured.filter(host => host.jump.id === previewJump), preview);
                        preview.querySelectorAll('[data-overview-key]').forEach(item => {
                            item.dataset.overviewKey = `preview:${item.dataset.hostId}`;
                        });
                        byId('overviewRouteCard').hidden = false;
                    }
                }
            });
        }
        function renderSidebar() {
            const hosts = buildAccessModel(win.ProfileManager?.profiles || []);
            const groups = new Map();
            hosts.forEach(host => {
                if (!groups.has(host.group)) groups.set(host.group, []);
                groups.get(host.group).push(host);
            });
            if (selectedGroup !== null && !groups.has(selectedGroup)) selectedGroup = null;
            const select = byId('overviewGroupFilter');
            select.replaceChildren(new win.Option(t('overview.allGroups'), ''));
            groups.forEach((items, group) => select.add(new win.Option(group || t('profiles.ungrouped'), `group:${group}`)));
            select.value = selectedGroup === null ? '' : `group:${selectedGroup}`;
            const container = byId('shellGroups');
            const showTree = win.primaryWorkspaceController?.getActiveView() === 'workspaces'
                && sessionManager.getAllSessions().length > 0;
            container.parentElement.hidden = !showTree;
            retainFocus(container, () => {
                container.replaceChildren();
                if (!showTree) return;
                groups.forEach((items, group) => {
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
                        item.append(icon('dns'), node('span', '', host.name));
                        section.append(item);
                    });
                    section.addEventListener('toggle', () => {
                        if (section.open) collapsedGroups.delete(group);
                        else collapsedGroups.add(group);
                    });
                    container.append(section);
                });
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
        function renderHistory() {
            const container = byId('overviewHistory');
            retainFocus(container, () => {
                container.replaceChildren();
                const history = win.ConnectionHistory?.getHistory() || [];
                if (!history.length) message(container, 'connection.noRecentConnections');
                history.slice(0, 5).forEach(entry => {
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
        }
        function renderSessions() {
            const container = byId('overviewSessions');
            retainFocus(container, () => {
                container.replaceChildren();
                const sessions = sessionManager.getAllSessions();
                const selected = sessionManager.getWorkspaceSession?.() || sessionManager.getActiveSession?.();
                view.dataset.sessionSelected = String(Boolean(selected && sessionManager.getSession(selected)));
                byId('overviewSessionCount').textContent = String(sessions.length);
                if (!sessions.length) message(container, 'overview.noSessions');
                sessions.forEach(session => {
                    const label = session.displayName || session.host || t('workspace.sshSession');
                    const item = button(label, () => {
                        workspaces();
                        if (sessionManager.getSession(session.id)) sessionManager.switchSession(session.id);
                    });
                    item.dataset.overviewKey = `session:${session.id}`;
                    const copy = node('span', 'overview-row-copy');
                    copy.append(node('strong', '', label));
                    item.append(icon('terminal'), copy, icon('arrow_forward'));
                    container.append(item);
                });
            });
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
        function render() {
            if (!visible()) return;
            byId('overviewConnectionNotice').hidden = win.socket?.connected === true;
            renderHosts();
            renderSessions();
            renderTransfers();
            renderHistory();
        }
        function schedule() {
            if (!visible() || scheduled) return;
            scheduled = true;
            win.requestAnimationFrame(() => { scheduled = false; render(); });
        }
        function setGraph(enabled) {
            const changed = graph !== enabled;
            graph = enabled;
            view.classList.toggle('overview-graph', graph);
            updateNavigation();
            byId('overviewGraphLegend').hidden = !graph;
            byId('overviewListBtn').setAttribute('aria-pressed', String(!graph));
            byId('overviewGraphBtn').setAttribute('aria-pressed', String(graph));
            renderHosts();
            if (changed) {
                view.scrollTop = 0;
                byId('overviewTitle').focus({preventScroll: true});
            }
        }
        function updateNavigation() {
            const key = {overview: 'overview.title', workspaces: 'navigation.workspaces',
                hosts: 'connectionAssets.hosts', files: 'files.fileManager', commands: 'commands.workspace'}[
                win.primaryWorkspaceController?.getActiveView()] || 'navigation.workspaces';
            byId('shellLocation').dataset.i18n = key;
            byId('shellLocation').textContent = t(key);
        }
        function openOverview(showGraph = false) {
            win.primaryWorkspaceController.open('overview', view);
            setGraph(showGraph);
            render();
            byId('overviewTitle').focus({preventScroll: true});
        }
        function init() {
            if (!view) return;
            byId('overviewNavBtn').addEventListener('click', () => {
                selectedGroup = null;
                renderSidebar();
                openOverview(false);
            });
            byId('overviewGroupFilter').addEventListener('change', () => {
                const value = byId('overviewGroupFilter').value;
                selectedGroup = value === '' ? null : value.slice('group:'.length);
                renderHosts();
            });
            byId('overviewQuickConnect').addEventListener('click', quickConnect);
            byId('overviewAllTransfers').addEventListener('click', openTransfers);
            byId('overviewHostSearch').addEventListener('input', renderHosts);
            byId('overviewListBtn').addEventListener('click', () => setGraph(false));
            byId('overviewGraphBtn').addEventListener('click', () => setGraph(true));
            byId('overviewExpandRoutes').addEventListener('click', () => setGraph(true));
            ['profile-list-change', 'jump-host-list-change', 'session-workspace-change',
                'primary-workspace-change', 'languageChanged'].forEach(event => win.addEventListener(event, schedule));
            ['profile-list-change', 'languageChanged', 'primary-workspace-change', 'session-workspace-change'].forEach(event => win.addEventListener(event, renderSidebar));
            win.addEventListener('primary-workspace-change', updateNavigation);
            win.addEventListener('languageChanged', updateNavigation);
            win.addEventListener('resize', scheduleEdges);
            if (win.ResizeObserver) {
                const observer = new win.ResizeObserver(scheduleEdges);
                observer.observe(byId('overviewHosts'));
                observer.observe(byId('overviewRoutePreview'));
            }
            renderSidebar();
            updateNavigation();
            render();
            // Queue progress must not rebuild focusable host/session buttons.
            win.addEventListener('file-transfer-queue-change', () => {
                if (!visible() || transfersScheduled) return;
                transfersScheduled = true;
                win.requestAnimationFrame(() => {
                    transfersScheduled = false;
                    if (visible()) renderTransfers();
                });
            });
            win.socket?.on('connect', () => { loadError = false; schedule(); });
            win.socket?.on('disconnect', schedule);
            win.socket?.on('error', () => {
                if (!win.ProfileManager?.profilesLoaded) loadError = true;
                schedule();
            });
        }
        return {init};
    }
    return {buildAccessModel, groupTone, createController};
});
