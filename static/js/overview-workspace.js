/* Overview dashboard: state of the instance, its hosts and automation at a glance.
   Data comes from existing managers plus /api/overview/status and, by user
   choice, /api/overview/reachability. Model logic lives in overview-model.js. */
(function (root) {
    'use strict';
    if (!root?.document) return;

    const SVG = 'http://www.w3.org/2000/svg';
    const AUTOMATIC_INTERVAL = 5 * 60 * 1000;

    function createController({window: win, document: doc, sessionManager}) {
        const view = doc.getElementById('connectionOverview');
        const Model = win.OverviewModel;
        if (!view || !view.hasAttribute('data-overview-workspace') || !Model) return null;
        const $ = id => doc.getElementById(id);
        const motion = () => !win.matchMedia?.('(prefers-reduced-motion: reduce)').matches;
        const t = (key, fallback, values = {}) => {
            let text = win.i18n?.t(key);
            if (!text || text === key) text = fallback;
            return Object.entries(values).reduce((value, [name, replacement]) => value.replaceAll(`{${name}}`, String(replacement)), text);
        };
        const tw = (key, fallback, values) => t(`overviewWorkspace.${key}`, fallback, values);
        const node = (tag, className, text) => {
            const element = doc.createElement(tag);
            if (className) element.className = className;
            if (text !== undefined && text !== null) element.textContent = text;
            return element;
        };
        const svg = (tag, attributes = {}) => {
            const element = doc.createElementNS(SVG, tag);
            Object.entries(attributes).forEach(([name, value]) => element.setAttribute(name, String(value)));
            return element;
        };
        const icon = name => {
            const element = node('span', 'material-icons', name);
            element.setAttribute('aria-hidden', 'true');
            return element;
        };
        const button = (className, label, onClick, text) => {
            const element = node('button', className, text);
            element.type = 'button';
            if (label) element.setAttribute('aria-label', label);
            element.addEventListener('click', onClick);
            return element;
        };

        const wf = (key, fallback, values) => t(`workFirst.${key}`, fallback, values);
        const fileSessions = new Set();
        const openHostContexts = new Set();
        const search = $('overviewSearch');
        const hostList = $('overviewHostList');
        const mode = () => view.dataset.reachability || 'manual';
        const state = {readiness: null, reachability: null, checkedAt: null, readinessAt: null, checking: false, reachError: null,
            shown: new Map(), scheduled: false, readinessTimer: 0, automaticTimer: 0, routeMap: null, firstPaint: true, returnKey: null, topologyNarrow: false, stateFilter: null, focusId: null, idFilter: null,
            dismissed: [], dismissSequence: 0, attention: [], board: null};

        const profiles = () => win.ProfileManager?.profiles || [];
        const sessions = () => sessionManager?.getAllSessions?.() || [];
        const snapshot = () => win.WebSSHAutomation?.getRunSnapshot?.() || {enabled: false, runs: [], schedules: []};
        const hostModel = () => Model.hosts({
            profiles: profiles(), jumps: win.JumpHostManager?.jumpHosts || [], jumpsLoaded: win.JumpHostManager?.loaded === true,
            sessions: sessions(), readiness: state.readiness, reachability: state.reachability,
        });

        // Navigation and actions reuse the existing application entry points.
        const showWorkspaces = () => win.primaryWorkspaceController?.showWorkspaces();
        function connect(host) {
            state.returnKey = `connect:${host.id}`;
            showWorkspaces();
            if (host.sessionId && sessionManager?.getSession?.(host.sessionId)) sessionManager.switchSession(host.sessionId);
            else if (host.profile) win.launchProfileForPane?.(host.id);
        }
        function edit(hostId) {
            const manager = win.ProfileManager;
            if (!manager?.profiles.some(profile => profile.id === hostId)) return;
            if (!win.primaryWorkspaceController?.open('hosts', $('profileManagementModal'))) return;
            manager.loadKeys?.();
            win.JumpHostManager?.load?.();
            manager.openEditor(hostId, {returnAfterSave: returnToOverview});
        }
        /** After saving from the overview, come back to it with the saved host in view. */
        function returnToOverview(hostId) {
            win.primaryWorkspaceController?.open('overview', view);
            render();
            const card = hostList.querySelector(`[data-host-id="${CSS.escape(hostId)}"]`);
            card?.scrollIntoView?.({block: 'nearest'});
            (card?.querySelector('.od-connect') || $('overviewTitle'))?.focus({preventScroll: true});
        }
        const openAutomation = () => $('automationNavBtn')?.click();
        function createHost() {
            const manager = win.ProfileManager;
            if (!manager?.openEditor || !win.primaryWorkspaceController?.open('hosts', $('profileManagementModal'))) {
                $('manageProfilesBtn')?.click();
                $('newProfileBtn')?.click();
                return;
            }
            manager.loadKeys?.();
            win.JumpHostManager?.load?.();
            manager.openEditor(null, {returnAfterSave: returnToOverview});
        }
        const relative = timestamp => {
            const minutes = Math.round((Date.now() - Number(timestamp)) / 60000);
            const format = new Intl.RelativeTimeFormat(win.i18n?.getLanguage?.() || undefined, {numeric: 'auto'});
            if (Math.abs(minutes) < 1) return format.format(0, 'minute');
            if (Math.abs(minutes) < 60) return format.format(-minutes, 'minute');
            if (Math.abs(minutes) < 1440) return format.format(-Math.round(minutes / 60), 'hour');
            return format.format(-Math.round(minutes / 1440), 'day');
        };

        function countUp(element, value, suffix = '') {
            const previous = state.shown.get(element.id || element);
            state.shown.set(element.id || element, value);
            // The first value appears at once; only later changes count towards it.
            if (typeof value !== 'number' || typeof previous !== 'number' || !motion() || previous === value) {
                element.textContent = typeof value === 'number' ? `${value}${suffix}` : value;
                return;
            }
            const from = previous;
            const started = win.performance.now();
            const step = now => {
                const progress = Math.min(1, (now - started) / 700);
                const eased = 1 - (1 - progress) ** 3;
                element.textContent = `${Math.round(from + (value - from) * eased)}${suffix}`;
                if (progress < 1) win.requestAnimationFrame(step);
            };
            win.requestAnimationFrame(step);
        }
        function ring(fraction, tone) {
            const holder = svg('svg', {viewBox: '0 0 48 48', class: 'od-ring', 'aria-hidden': 'true'});
            const circumference = 2 * Math.PI * 20;
            holder.append(svg('circle', {cx: 24, cy: 24, r: 20, class: 'od-ring-track'}));
            const arc = svg('circle', {cx: 24, cy: 24, r: 20, class: 'od-ring-value', 'data-tone': tone,
                'stroke-dasharray': `${(Math.max(0, Math.min(1, fraction)) * circumference).toFixed(1)} ${circumference.toFixed(1)}`});
            holder.append(arc);
            return holder;
        }
        function kpi(id, {label, iconName, value, suffix = '', sub, tone = 'neutral', ringFraction = null, action = null}) {
            const tile = $(id);
            tile.dataset.tone = tone;
            const head = node('p', 'od-kpi-label');
            head.append(icon(iconName), node('span', '', label));
            const body = node('div', 'od-kpi-body');
            if (ringFraction !== null) body.append(ring(ringFraction, tone));
            const number = node('p', 'od-kpi-value');
            number.id = `${id}Value`;
            body.append(number);
            tile.replaceChildren(head, body, node('p', 'od-kpi-sub', sub));
            if (action) tile.append(action);
            countUp(number, value, suffix);
        }

        function renderWorkFirst(hosts) {
            const holder = $('overviewShortcuts');
            if (!holder) return;
            const groups = Model.workFirst({hostList: visibleHosts(hosts), sessions: filtered() ? [] : sessions(), history: win.ConnectionHistory?.getHistory?.() || []});
            const signature = JSON.stringify([groups, win.i18n?.getLanguage?.()]);
            if (state.shortcutSignature !== signature) {
                state.shortcutSignature = signature;
                holder.replaceChildren();
                Object.entries(groups).forEach(([kind, list]) => {
                    if (!list.length) return;
                    const group = node('section', 'od-shortcut-group');
                    group.append(node('h3', '', wf(kind, {resume:'Resume sessions', favorites:'Favorites', recent:'Recent hosts', saved:'Saved hosts'}[kind])));
                    list.forEach(host => {
                        const action = button('od-shortcut', host.name, () => connect(host));
                        action.append(node('span', '', host.name));
                        action.dataset.key = `shortcut:${host.id}`;
                        action.append(node('small', '', host.destination), icon(kind === 'resume' ? 'east' : 'terminal'));
                        group.append(action);
                    });
                    holder.append(group);
                });
                if (!holder.childElementCount) holder.append(button('btn btn-secondary', null, createHost, t('profiles.newHost', 'New host')));
            }
            const select = $('overviewSetupHost');
            const chosen = select.value;
            const options = JSON.stringify([hosts.map(host => [host.id, host.name]), win.i18n?.getLanguage?.()]);
            if (options !== state.setupOptions) {
                state.setupOptions = options;
                select.replaceChildren();
                if (!hosts.length) select.append(node('option', '', wf('noHost', 'Create a saved host to begin')));
                hosts.forEach(host => { const option = node('option', '', host.name); option.value = host.id; select.append(option); });
                if (hosts.some(host => host.id === chosen)) select.value = chosen;
                select.disabled = !hosts.length;
            }
            const host = hosts.find(item => item.id === select.value);
            const progress = Model.setupProgress(host, fileSessions);
            $('overviewSetupCount').textContent = `${Object.values(progress).filter(Boolean).length} / ${Object.keys(progress).length}`;
            if (!state.setupInitialized && win.ProfileManager?.profilesLoaded === true) {
                state.setupInitialized = true;
                if (!hosts.length) $('overviewFirstConnection').open = true;
            }
            const setupSignature = JSON.stringify([host?.id, progress, host?.status, win.i18n?.getLanguage?.()]);
            if (setupSignature === state.setupSignature) return;
            state.setupSignature = setupSignature;
            const list = $('overviewSetupSteps'); list.replaceChildren();
            const names = {host:'Save host and username', auth:'Authenticate to the host', trust:'Verify the SSH host key', terminal:'Open a terminal', files:'Open Files for this session'};
            const nextStep = Object.keys(progress).find(key => !progress[key]);
            Object.entries(progress).forEach(([key, done]) => {
                const row = node('li', 'od-setup-step'); row.dataset.step = key; row.dataset.complete = String(done);
                row.append(icon(done ? 'check_circle' : 'radio_button_unchecked'), node('span', '', wf(key, names[key])));
                const label = done ? wf('verified', 'Observed') : wf('pending', 'Pending');
                row.append(node('small', '', label));
                if (key === nextStep) {
                    const action = () => {
                        if (!host) return createHost();
                        if (key === 'host' || (key === 'auth' && ['key_missing', 'password_changed'].includes(host.status?.auth))) return edit(host.id);
                        connect(host);
                        if (key === 'files' && host.sessionId) {
                            win.workspaceLayoutController?.openContext?.('files', 'user');
                            win.sessionWorkspace?.openSftpPanel?.();
                        }
                    };
                    row.append(button('od-link', null, action, !host ? t('profiles.newHost', 'New host')
                        : key === 'host' || (key === 'auth' && ['key_missing', 'password_changed'].includes(host.status?.auth)) ? t('common.edit', 'Edit')
                            : key === 'files' && host.sessionId ? wf('openFiles', 'Open Files') : t('connection.actionConnect', 'Connect')));
                }
                list.append(row);
            });
        }

        function renderHero(hosts, attentionItems) {
            const name = view.dataset.username || '';
            $('overviewTitle').textContent = tw(Model.greetingKey(new Date().getHours()),
                {greetingMorning: 'Good morning, {name}', greetingDay: 'Hello, {name}', greetingEvening: 'Good evening, {name}'}[Model.greetingKey(new Date().getHours())],
                {name});
            const language = win.i18n?.getLanguage?.() || undefined;
            const today = new Date();
            const dateKey = `${language}|${today.toDateString()}`;
            if (state.dateKey !== dateKey) {
                state.dateKey = dateKey;
                $('overviewDate').textContent = today.toLocaleDateString(language, {weekday: 'long', day: 'numeric', month: 'long'});
            }
            const line = Model.headline({connected: win.socket?.connected !== false, hostList: hosts, attentionItems});
            $('overviewStatus').dataset.tone = line.tone;
            $('overviewStatusText').textContent = {
                disconnected: t('overview.stale', 'Connection to WebSSH interrupted. Displayed data may be out of date.'),
                attention: line.count === 1 ? tw('statusOneIssue', '1 item needs attention') : tw('statusIssues', '{count} items need attention', {count: line.count}),
                empty: tw('statusEmpty', 'Ready for your first host'),
                ready: wf('configReady', 'Saved configuration is ready'),
            }[line.key];
            $('overviewStatusButton').disabled = line.key !== 'attention';
        }

        function renderKpis(hosts, metrics, runInfo) {
            const loaded = win.ProfileManager?.profilesLoaded === true;
            const {total, ready, needsAttention} = metrics.hosts;
            // Readiness arrives separately; never show a provisional count.
            const known = loaded && (metrics.hosts.loaded || !total);
            kpi('odKpiHosts', {
                label: wf('configTitle', 'Configuration readiness'), iconName: 'dns',
                value: known ? ready : '–', suffix: known ? ` / ${total}` : '',
                sub: !known ? tw('loading', 'Loading…') : !total ? tw('kpiHostsNone', 'No saved hosts yet')
                    : needsAttention > 0 ? tw('kpiHostsAttention', '{count} need attention', {count: needsAttention}) : tw('kpiHostsAll', 'All hosts ready'),
                tone: !known || !total ? 'neutral' : needsAttention > 0 ? 'warning' : 'success',
                ringFraction: known && total ? ready / total : 0,
            });
            const open = sessions().filter(item => item.connected === true);
            kpi('odKpiSessions', {
                label: tw('kpiSessions', 'Open sessions'), iconName: 'terminal', value: open.length,
                sub: open.length ? open.slice(0, 2).map(item => hosts.find(host => host.sessionId === item.id)?.name || item.host).join(', ')
                    : tw('kpiSessionsNone', 'No session open in this browser'),
                tone: open.length ? 'live' : 'neutral',
            });
            const automation = metrics.automation;
            kpi('odKpiAutomation', runInfo.enabled ? {
                label: tw('kpiAutomation', 'Automation, 14 days'), iconName: 'smart_toy',
                value: automation.rate === null ? '–' : automation.rate, suffix: automation.rate === null ? '' : ' %',
                sub: automation.runs ? tw('kpiAutomationRuns', '{runs} runs · {failed} failed', {runs: automation.runs, failed: automation.failed})
                    : tw('kpiAutomationNone', 'No runs yet'),
                tone: !automation.runs ? 'neutral' : automation.failed ? 'warning' : 'success',
                ringFraction: automation.runs ? automation.succeeded / automation.runs : 0,
            } : {
                label: tw('automationTitle', 'Automation'), iconName: 'smart_toy', value: tw('kpiOff', 'Off'),
                sub: tw('kpiAutomationOff', 'Not enabled on this instance'), tone: 'neutral',
            });
            renderReachKpi(metrics);
        }
        function renderReachKpi(metrics) {
            const current = mode();
            let action = null;
            if (current === 'off') {
                const link = node('a', 'od-link', tw('reachEnable', 'Enable in settings'));
                link.href = $('accountSettingsBtn')?.getAttribute('href') || '/settings#preferences';
                action = link;
            } else if (current === 'manual') {
                action = button('od-kpi-action', tw('reachCheck', 'Check now'), checkReachability,
                    state.checking ? tw('reachChecking', 'Checking…') : tw('reachCheck', 'Check now'));
                action.disabled = state.checking || !profiles().length;
                action.dataset.key = 'reach-check';
            }
            const result = metrics.reachability;
            kpi('odKpiReach', {
                label: wf('tcpTitle', 'TCP reachability'), iconName: 'sensors',
                value: current === 'off' ? tw('kpiOff', 'Off') : result ? result.reachable : '–',
                suffix: result && current !== 'off' ? ` / ${result.checked}` : '',
                sub: state.reachError || (current === 'off' ? tw('reachOff', 'Reachability checks are off')
                    : state.checking ? tw('reachChecking', 'Checking…')
                        : result ? tw('reachCheckedAt', 'Checked {when}', {when: relative(state.checkedAt)})
                            : tw('reachNotChecked', 'Not checked yet')),
                tone: !result || current === 'off' ? 'neutral' : result.reachable === result.checked ? 'success' : 'warning',
                ringFraction: result && current !== 'off' ? result.reachable / Math.max(1, result.checked) : null,
                action,
            });
        }

        function renderRouteList(holder, layout) {
            holder.dataset.mode = 'list';
            const list = node('ul', 'od-route-list');
            layout.hubs.forEach(hub => {
                const item = node('li', 'od-route-item');
                const name = hub.kind === 'direct' ? tw('routeDirect', 'Direct') : hub.kind === 'jump' ? tw('routeVia', 'via {name}', {name: hub.name}) : t('overview.missingJump', 'Saved jump host unavailable');
                const dots = node('ul', 'od-route-dots');
                dots.setAttribute('aria-hidden', 'true');
                hub.hosts.forEach(host => { const dot = node('li'); dot.dataset.state = host.state; dot.title = host.name; dots.append(dot); });
                item.append(node('strong', '', name), node('span', 'od-count', String(hub.hosts.length)), dots);
                list.append(item);
            });
            holder.replaceChildren(list);
        }
        const stateGroup = value => (value === 'broken' ? 'unreachable' : value);
        function visibleHosts(hosts) {
            const shown = state.idFilter ? hosts.filter(host => state.idFilter.ids.has(host.id))
                : state.focusId ? hosts.filter(host => host.id === state.focusId) : Model.filter(hosts, search.value);
            return state.stateFilter ? shown.filter(host => stateGroup(host.state) === state.stateFilter) : shown;
        }
        const filtered = () => Boolean(state.idFilter || state.focusId || state.stateFilter || search.value.trim());
        function resetFilters() {
            search.value = '';
            state.focusId = null;
            state.stateFilter = null;
            state.idFilter = null;
            schedule();
        }
        /** Show exactly the hosts an attention item is about, in the drawing and the cards. */
        function filterHosts(ids, label) {
            search.value = '';
            state.focusId = null;
            state.stateFilter = null;
            state.idFilter = {ids: new Set(ids), label};
            render();
            const panel = view.querySelector('[data-panel="hosts"]');
            panel?.scrollIntoView?.({block: 'nearest', behavior: motion() ? 'smooth' : 'auto'});
            hostList.querySelector('.od-connect')?.focus({preventScroll: true});
        }
        function renderHostFilter() {
            const chip = $('overviewHostFilter');
            if (!chip) return;
            chip.hidden = !state.idFilter;
            if (!state.idFilter) return;
            $('overviewHostFilterText').textContent = state.idFilter.label;
            chip.title = tw('showAll', 'Show all hosts');
            chip.setAttribute('aria-label', `${state.idFilter.label} · ${tw('showAll', 'Show all hosts')}`);
        }
        function renderLegend(hosts) {
            const counts = new Map();
            hosts.forEach(host => counts.set(stateGroup(host.state), (counts.get(stateGroup(host.state)) || 0) + 1));
            view.querySelectorAll('.od-legend-filter').forEach(button => {
                const active = state.stateFilter === button.dataset.state;
                button.setAttribute('aria-pressed', String(active));
                button.title = tw('filterState', 'Show only hosts with this state');
                const count = button.querySelector('.od-legend-count');
                if (count) count.textContent = String(counts.get(button.dataset.state) || 0);
            });
            view.querySelector('.od-legend')?.toggleAttribute('data-filtering', Boolean(state.stateFilter));
            $('odTopology').toggleAttribute('data-filtered', filtered());
        }
        function renderTopology(hosts) {
            const holder = $('odTopology');
            const matching = new Set(visibleHosts(hosts).map(host => host.id));
            // Hysteresis: re-rendering can change the panel width by a scrollbar or a
            // wrapped line, which must not flip the topology layout back and forth.
            const width = state.topologyWidth ?? holder.clientWidth;
            const narrow = Boolean(width && (state.topologyNarrow ? width < 600 : width < 560));
            state.topologyNarrow = narrow;
            // Like the host cards, the drawing is rebuilt only when what it shows changed.
            const signature = JSON.stringify([narrow, win.i18n?.getLanguage?.() || '', hosts.map(host => [host.id, host.name,
                host.destination, host.state, host.route.kind, host.route.name, matching.has(host.id)])]);
            if (signature === state.topologySignature && holder.firstChild) return;
            state.topologySignature = signature;
            const layout = Model.topology(hosts);
            if (narrow) {
                renderRouteList(holder, layout);
                finishTopology(holder, hosts, layout);
                return;
            }
            holder.dataset.mode = 'graph';
            const canvas = svg('svg', {viewBox: `0 0 ${layout.width} ${layout.height}`, class: 'od-topology-svg', 'aria-hidden': 'true', preserveAspectRatio: 'xMidYMid meet'});
            const edges = svg('g', {class: 'od-edges'});
            const nodes = svg('g', {class: 'od-nodes'});
            const hubById = new Map(layout.hubs.map(hub => [hub.key, hub]));
            layout.hubs.forEach(hub => {
                edges.append(svg('path', {d: `M${layout.center.x} ${layout.center.y} L${hub.x} ${hub.y}`, class: 'od-edge od-edge-hub'}));
            });
            layout.nodes.forEach(item => {
                const hub = hubById.get(item.hub);
                const live = item.host.state === 'live';
                const middleX = (hub.x + item.x) / 2;
                edges.append(svg('path', {
                    d: `M${hub.x} ${hub.y} Q${middleX} ${hub.y} ${item.x} ${item.y}`,
                    class: `od-edge${live ? ' od-edge-live' : ''}`, 'data-dim': String(!matching.has(item.host.id)),
                }));
                const group = svg('g', {class: 'od-node', 'data-state': item.host.state, 'data-dim': String(!matching.has(item.host.id)),
                    transform: `translate(${item.x.toFixed(1)} ${item.y.toFixed(1)})`});
                const title = svg('title');
                title.textContent = `${item.host.name} · ${item.host.destination} · ${stateLabel(item.host.state)}`;
                group.append(title, svg('circle', {r: 14, class: 'od-node-halo'}), svg('circle', {r: 7, class: 'od-node-dot'}));
                const offset = item.anchor === 'start' ? 16 : item.anchor === 'end' ? -16 : 0;
                const clip = (value, size) => value.length > size ? `${value.slice(0, size - 1)}…` : value;
                const label = svg('text', {x: offset, y: -1, 'text-anchor': item.anchor, class: 'od-node-label'});
                label.textContent = clip(item.host.name, 18);
                const sub = svg('text', {x: offset, y: 13, 'text-anchor': item.anchor, class: 'od-node-sub'});
                sub.textContent = clip(item.host.destination, 24);
                group.append(label, sub);
                group.addEventListener('click', () => focusHost(item.host.id));
                nodes.append(group);
            });
            layout.hubs.forEach(hub => {
                const group = svg('g', {class: 'od-hub', 'data-kind': hub.kind, transform: `translate(${hub.x.toFixed(1)} ${hub.y.toFixed(1)})`});
                const text = hub.kind === 'direct' ? tw('routeDirect', 'Direct') : hub.kind === 'jump' ? hub.name : t('overview.missingJump', 'Saved jump host unavailable');
                const width = Math.max(70, Math.min(170, text.length * 8 + 28));
                group.append(svg('rect', {x: -width / 2, y: -16, width, height: 32, rx: 16, class: 'od-hub-box'}));
                const label = svg('text', {y: 5, 'text-anchor': 'middle', class: 'od-hub-label'});
                label.textContent = text;
                group.append(label);
                if (hub.hidden) {
                    const more = svg('text', {y: 34, 'text-anchor': 'middle', class: 'od-node-more'});
                    more.textContent = `+${hub.hidden}`;
                    group.append(more);
                }
                nodes.append(group);
            });
            const core = svg('g', {class: 'od-core', transform: `translate(${layout.center.x} ${layout.center.y})`});
            const coreTitle = svg('title');
            coreTitle.textContent = tw('showAll', 'Show all hosts');
            core.append(coreTitle, svg('circle', {r: 46, class: 'od-core-pulse'}), svg('circle', {r: 40, class: 'od-core-ring'}), svg('circle', {r: 30, class: 'od-core-disc'}));
            const coreLabel = svg('text', {y: 5, 'text-anchor': 'middle', class: 'od-core-label'});
            coreLabel.textContent = 'WebSSH';
            core.append(coreLabel);
            canvas.append(edges, nodes, core);
            holder.replaceChildren(canvas);
            finishTopology(holder, hosts, layout);
        }
        function finishTopology(holder, hosts, layout) {
            const jumps = layout.hubs.filter(hub => hub.kind === 'jump').length;
            holder.setAttribute('role', 'img');
            holder.setAttribute('aria-label', tw('topologySummary', '{hosts} hosts, {direct} direct, {jumps} jump hosts, {live} with an open session', {
                hosts: hosts.length, direct: hosts.filter(host => host.route.kind === 'direct').length, jumps,
                live: hosts.filter(host => host.state === 'live').length,
            }));
            view.querySelector('.od-topology').hidden = !hosts.length;
            $('overviewOpenMap').hidden = !jumps || !state.routeMap;
        }
        function stateLabel(value) {
            return {
                ready: wf('configReady', 'Saved configuration is ready'), action: tw('stateAction', 'Needs action'), broken: tw('stateBroken', 'Route broken'),
                unreachable: tw('stateUnreachable', 'Unreachable'), live: tw('stateLive', 'Session open'), unknown: tw('loading', 'Loading…'),
            }[value] || value;
        }
        function focusHost(id) {
            // Filter by identity, not by name: "192.0.2.1" must not also match 192.0.2.12.
            state.focusId = id;
            state.stateFilter = null;
            state.idFilter = null;
            search.value = profiles().find(profile => profile.id === id)?.name || '';
            render();
            hostList.querySelector(`[data-host-id="${CSS.escape(id)}"] .od-connect`)?.focus();
        }
        function reasonFor(host) {
            if (host.state === 'live') return tw('reasonLive', 'Session open');
            if (host.state === 'broken') return t('overview.missingJump', 'Saved jump host unavailable');
            if (host.state === 'unreachable') return host.reach?.via_jump ? tw('reasonJumpUnreachable', 'Jump host not reachable') : tw('reasonUnreachable', 'SSH port not reachable');
            if (host.status?.host_key === 'unknown') return tw('reasonHostKey', 'Host key not verified yet');
            if (host.status?.auth === 'key_missing') return tw('reasonKeyMissing', 'SSH key missing');
            if (host.status?.auth === 'password_changed') return tw('reasonPasswordChanged', 'Saved password needs review');
            if (host.reach?.state === 'reachable') return tw('reasonReachable', 'Reachable · {ms} ms', {ms: host.reach.latency_ms});
            // The route has its own chip; the badge only states readiness.
            return host.state === 'unknown' ? tw('loading', 'Loading…') : stateLabel(host.state);
        }
        function hostCard(host) {
            const item = node('li', 'od-host');
            item.dataset.hostId = host.id;
            item.dataset.state = host.state;
            const top = node('div', 'od-host-top');
            const logo = node('span', 'od-host-logo');
            logo.append(win.HostPlatform?.render(host.profile, doc) || icon('dns'));
            const copy = node('div', 'od-host-copy');
            copy.append(node('span', 'od-host-name', host.name), node('span', 'od-host-destination', host.destination));
            const meta = node('div', 'od-host-meta');
            const route = node('span', 'od-chip');
            route.dataset.route = host.route.kind;
            route.append(icon(host.route.kind === 'direct' ? 'arrow_forward' : 'alt_route'),
                node('span', '', host.route.kind === 'direct' ? tw('routeDirect', 'Direct')
                    : host.route.kind === 'jump' ? tw('routeVia', 'via {name}', {name: host.route.name})
                        : t('overview.missingJump', 'Saved jump host unavailable')));
            meta.append(route);
            if (host.group) {
                const group = node('span', 'od-chip');
                group.append(icon('folder_open'), node('span', '', host.group));
                meta.append(group);
            }
            // What runs on the host, as detected when connecting; three at most, the rest counted.
            const services = win.HostPlatform?.services?.(host.profile) || [];
            if (services.length) {
                const labels = services.map(id => win.HostPlatform.serviceLabels[id]);
                services.slice(0, 3).forEach((id, index) => {
                    const chip = node('span', 'od-chip od-service-chip', labels[index]);
                    chip.dataset.service = id;
                    chip.title = tw('servicesDetected', 'Detected when connecting');
                    meta.append(chip);
                });
                if (services.length > 3) {
                    const more = node('span', 'od-chip od-service-chip', `+${services.length - 3}`);
                    more.title = labels.slice(3).join(', ');
                    meta.append(more);
                }
            }
            // Updates and restart state as reported by the last run of the Updates and restart status workflow.
            const upkeep = Model.maintenance(host.profile);
            if (upkeep) {
                const checked = upkeep.checkedAt ? new Date(upkeep.checkedAt).toLocaleString(win.i18n?.getLanguage?.() || undefined) : '';
                const source = tw('maintenanceChecked', 'From the host\'s package cache, checked {time}', {time: checked});
                if (upkeep.reboot_required) {
                    const chip = node('span', 'od-chip od-maintenance-chip');
                    chip.dataset.kind = 'reboot';
                    chip.title = source;
                    chip.append(icon('restart_alt'), node('span', '', tw('chipReboot', 'Restart required')));
                    meta.append(chip);
                }
                if (upkeep.updates > 0) {
                    const chip = node('span', 'od-chip od-maintenance-chip');
                    chip.dataset.kind = upkeep.security_updates > 0 ? 'security' : 'updates';
                    chip.title = source;
                    chip.append(icon('system_update'), node('span', '', upkeep.security_updates > 0
                        ? tw('chipUpdatesSecurity', '{count} updates, {security} security', {count: upkeep.updates, security: upkeep.security_updates})
                        : tw('chipUpdates', '{count} updates', {count: upkeep.updates})));
                    meta.append(chip);
                }
            }
            const favoriteLabel = host.favorite
                ? tw('favoriteRemove', 'Remove {name} from favorites', {name: host.name})
                : tw('favoriteAdd', 'Add {name} to favorites', {name: host.name});
            const favorite = button('od-icon-button', favoriteLabel, () => win.ProfileManager?.toggleFavorite?.(host.id));
            favorite.title = favoriteLabel;
            favorite.dataset.key = `favorite:${host.id}`;
            favorite.setAttribute('aria-pressed', String(host.favorite));
            favorite.append(icon(host.favorite ? 'star' : 'star_border'));
            top.append(logo, copy, favorite);
            const bottom = node('div', 'od-host-bottom');
            const badge = node('span', 'od-state');
            badge.dataset.state = host.state;
            badge.append(node('span', 'od-state-dot'), node('span', '', reasonFor(host)));
            const editLabel = `${t('common.edit', 'Edit')} ${host.name}`;
            const editButton = button('od-icon-button', editLabel, () => edit(host.id));
            editButton.title = editLabel;
            editButton.dataset.key = `edit:${host.id}`;
            editButton.append(icon('edit'));
            const primary = host.sessionId ? tw('open', 'Open') : t('connection.actionConnect', 'Connect');
            const connectButton = button('od-connect', `${primary} ${host.name}`, () => connect(host));
            connectButton.dataset.key = `connect:${host.id}`;
            connectButton.append(icon(host.sessionId ? 'east' : 'terminal'), node('span', '', primary));
            bottom.append(badge, editButton, connectButton);
            const context = node('details', 'od-host-context');
            context.dataset.contextHostId = host.id;
            context.open = openHostContexts.has(host.id);
            const summary = node('summary', '', wf('configTitle', 'Configuration readiness'));
            summary.dataset.key = `context:${host.id}`;
            context.append(summary,
                node('small', '', wf('configHint', 'Configuration checks do not test login or permissions.')));
            if (state.readinessAt) context.append(node('small', '', wf('configChecked', 'Configuration checked {time}', {time: new Date(state.readinessAt).toLocaleString(win.i18n?.getLanguage?.() || undefined)})));
            if (host.reach && state.checkedAt) context.append(node('small', '', wf('tcpChecked', 'TCP {state} · {time}', {state: wf(host.reach.state, host.reach.state), time: new Date(state.checkedAt).toLocaleString(win.i18n?.getLanguage?.() || undefined)})));
            if (host.reach) context.append(node('small', '', wf('tcpHint', 'TCP checks do not authenticate. For jump routes only the jump host is checked.')));
            item.append(top, meta, bottom, context);
            return item;
        }
        function renderHosts(hosts) {
            const loaded = win.ProfileManager?.profilesLoaded === true;
            const visible = visibleHosts(hosts);
            $('overviewHostsEmpty').hidden = !loaded || hosts.length > 0;
            $('overviewHostsNoMatch').hidden = !loaded || !hosts.length || visible.length > 0;
            $('overviewHostTotal').textContent = loaded ? String(visible.length === hosts.length ? hosts.length : `${visible.length} / ${hosts.length}`) : '';
            // Status updates arrive often; rebuild cards only when what they show changed,
            // so focus, hover and scroll position stay where the user left them.
            const signature = JSON.stringify([loaded, win.i18n?.getLanguage?.() || '', visible.map(host => [host.id, host.state, host.name,
                host.destination, host.favorite, host.group, host.route.kind, host.route.name, host.sessionId, reasonFor(host),
                win.HostPlatform?.resolve?.(host.profile)?.id || '', win.HostPlatform?.services?.(host.profile) || [],
                Model.maintenance(host.profile)]), state.readinessAt, state.checkedAt]);
            if (signature === state.hostSignature) return;
            state.hostSignature = signature;
            const focusedKey = hostList.contains(doc.activeElement) ? doc.activeElement.dataset.key : null;
            hostList.setAttribute('aria-busy', String(!loaded));
            hostList.querySelectorAll('.od-host-context').forEach(context => {
                if (context.open) openHostContexts.add(context.dataset.contextHostId);
                else openHostContexts.delete(context.dataset.contextHostId);
            });
            hostList.replaceChildren();
            if (!loaded) {
                for (let index = 0; index < 6; index += 1) hostList.append(node('li', 'od-host od-skeleton'));
                return;
            }
            visible.forEach(host => hostList.append(hostCard(host)));
            if (focusedKey) [...hostList.querySelectorAll('[data-key]')].find(item => item.dataset.key === focusedKey)?.focus({preventScroll: true});
        }

        function renderAttention(items, hiddenCount) {
            const section = $('odAttention');
            const list = section.querySelector('.od-list');
            section.dataset.clear = String(!items.length);
            $('odAttentionClear').hidden = items.length > 0;
            $('odAttentionDismissAll').hidden = items.length < 2;
            $('odAttentionFoot').hidden = !hiddenCount;
            $('odAttentionDismissed').textContent = hiddenCount
                ? tw(hiddenCount === 1 ? 'dismissedOne' : 'dismissedMany', '{count} dismissed', {count: hiddenCount}) : '';
            list.replaceChildren(...items.map(item => {
                const entry = node('li');
                const config = describeAttention(item);
                const action = button('od-row', config[1], config[2]);
                action.dataset.key = `attention:${item.key}`;
                action.dataset.kind = item.kind;
                action.append(icon(config[0]), node('span', 'od-row-label', config[1]), icon('chevron_right'));
                const dismissLabel = tw('dismissItem', 'Dismiss: {label}', {label: config[1]});
                const dismiss = button('od-dismiss', dismissLabel, () => dismissAttention([item.key]));
                dismiss.title = tw('dismiss', 'Dismiss');
                dismiss.dataset.key = `dismiss:${item.key}`;
                dismiss.append(icon('close'));
                entry.append(action);
                const upgrade = item.kind === 'security-updates' ? upgradePlan(item.hostIds) : null;
                if (upgrade) {
                    const label = tw('openUpgrade', 'Open upgrade workflow for {count} hosts', {count: upgrade.hostIds.length});
                    const open = button('od-dismiss', label, () => win.WebSSHAutomation.openTemplate(upgrade.template, upgrade.hostIds));
                    open.title = label;
                    open.dataset.key = `upgrade:${item.key}`;
                    open.append(icon('system_update_alt'));
                    entry.append(open);
                }
                // A restart hint only changes when the host is asked again; this opens that check as a draft.
                if (item.kind === 'reboot' && win.WebSSHAutomation?.openTemplate && state.automationEnabled) {
                    const label = tw('openRecheck', 'Check restart status again for {count} hosts', {count: item.hostIds.length});
                    const recheck = button('od-dismiss', label, () => win.WebSSHAutomation.openTemplate('maintenance', item.hostIds));
                    recheck.title = label;
                    recheck.dataset.key = `recheck:${item.key}`;
                    recheck.append(icon('refresh'));
                    entry.append(recheck);
                }
                entry.append(dismiss);
                return entry;
            }));
        }
        async function saveDismissed(next) {
            const previous = state.dismissed;
            // Only the latest save may apply its answer or roll back.
            const sequence = ++state.dismissSequence;
            // Keep the most recent acknowledgements within the stored limit.
            state.dismissed = [...new Set(next)].slice(-100);
            $('odAttentionError').hidden = true;
            schedule();
            try {
                const data = await request('/api/overview/preferences', {method: 'PUT', body: JSON.stringify({dismissed: state.dismissed})});
                if (sequence !== state.dismissSequence) return;
                state.dismissed = Array.isArray(data.dismissed) ? data.dismissed : state.dismissed;
            } catch {
                if (sequence !== state.dismissSequence) return;
                state.dismissed = previous;
                $('odAttentionError').textContent = tw('dismissFailed', 'The change could not be saved. Try again.');
                $('odAttentionError').hidden = false;
                schedule();
            }
        }
        function dismissAttention(keys) {
            const next = [...state.dismissed, ...keys];
            const remaining = state.attention.filter(item => !next.includes(item.key));
            saveDismissed(next);
            // Keep keyboard users in the panel after the row disappears.
            win.requestAnimationFrame(() => {
                const target = remaining.length ? $('odAttention').querySelector('.od-row') : $('odAttentionTitle');
                if (target === $('odAttentionTitle')) target.setAttribute('tabindex', '-1');
                target?.focus({preventScroll: true});
            });
        }
        function describeAttention(item) {
            switch (item.kind) {
            // One affected host is named; several are counted.
            case 'host-keys': return ['key', item.count === 1
                ? tw('attentionHostKeysOne', '{name}: host key not verified yet. Connect once to verify it.', {name: hostName(item.hostIds[0])})
                : tw('attentionHostKeys', '{count} hosts: host key not verified yet. Connect once to verify it.', {count: item.count}),
            item.count === 1 ? () => focusHost(item.hostIds[0]) : () => filterHosts(item.hostIds, tw('filterHostKeys', 'Host key not verified'))];
            case 'jump-missing': return ['alt_route', tw('jumpMissing', 'Jump host missing for {name}', {name: item.name}), () => edit(item.hostId)];
            case 'unreachable': return ['wifi_off', item.count === 1
                ? tw('attentionUnreachableOne', '{name} is not reachable', {name: item.names[0]})
                : tw('attentionUnreachable', '{count} hosts not reachable: {names}', {count: item.count, names: item.names.join(', ')}),
            item.count === 1 ? () => focusHost(item.hostIds?.[0] || hostIdByName(item.names[0])) : () => filterHosts(item.hostIds, tw('stateUnreachable', 'Unreachable'))];
            case 'credentials': return ['password', item.count === 1
                ? tw('attentionCredentialsOne', '{name}: SSH key missing or saved password changed', {name: hostName(item.hostIds[0])})
                : tw('attentionCredentials', '{count} hosts: SSH key missing or saved password changed', {count: item.count}),
            item.count === 1 ? () => edit(item.hostIds[0]) : () => filterHosts(item.hostIds, tw('filterCredentials', 'Sign-in needs review'))];
            case 'reboot': return ['restart_alt', item.count === 1
                ? tw('attentionRebootOne', '{name}: restart required', {name: hostName(item.hostIds[0])})
                : tw('attentionReboot', '{count} hosts: restart required', {count: item.count}),
            item.count === 1 ? () => focusHost(item.hostIds[0]) : () => filterHosts(item.hostIds, tw('filterReboot', 'Restart required'))];
            case 'security-updates': return ['security_update_warning', item.count === 1
                ? tw('attentionSecurityOne', '{name}: security updates pending', {name: hostName(item.hostIds[0])})
                : tw('attentionSecurity', '{count} hosts: security updates pending', {count: item.count}),
            item.count === 1 ? () => focusHost(item.hostIds[0]) : () => filterHosts(item.hostIds, tw('filterSecurity', 'Security updates pending'))];
            case 'run-failed': return ['error_outline', tw('runFailed', 'Run failed: {name}', {name: item.name}), () => win.WebSSHAutomation?.openRun?.(item.runId)];
            default: return ['schedule', tw('scheduleReview', 'Schedule needs review: {name}', {name: item.name}), openAutomation];
            }
        }
        /**
         * The Debian/Ubuntu upgrade template with only the hosts it supports; update
         * counts exist only for those. Null while Automation is off. It opens a draft.
         */
        function upgradePlan(hostIds = []) {
            if (!win.WebSSHAutomation?.openTemplate || !state.automationEnabled) return null;
            const apt = hostIds.filter(id => ['debian', 'ubuntu', 'raspberrypi', 'proxmox']
                .includes(win.HostPlatform?.resolve?.(profiles().find(profile => profile.id === id) || {})?.id));
            return apt.length ? {template: 'apt-upgrade', hostIds: apt} : null;
        }
        function hostName(id) {
            const profile = profiles().find(item => item.id === id);
            return String(profile?.name || profile?.host || '');
        }
        function hostIdByName(name) {
            return profiles().find(profile => profile.name === name)?.id || '';
        }
        function renderAutomation(runInfo, metrics) {
            const section = $('odAutomation');
            section.hidden = !runInfo.enabled;
            if (!runInfo.enabled) return;
            const bins = metrics.automation.bins;
            const max = Math.max(1, ...bins.map(bin => bin.succeeded + bin.failed + bin.other));
            // HTML bars stay crisp at every panel width; SVG text would scale with it.
            const dayLabel = bin => new Date(bin.start).toLocaleDateString(win.i18n?.getLanguage?.() || undefined, {day: 'numeric', month: 'short'});
            const chart = node('div', 'od-chart-bars');
            chart.setAttribute('role', 'img');
            chart.setAttribute('aria-label', tw('chartLabel', 'Automation runs per day over 14 days: {runs} runs, {failed} failed', {runs: metrics.automation.runs, failed: metrics.automation.failed}));
            bins.forEach(bin => {
                const total = bin.succeeded + bin.failed + bin.other;
                const column = node('div', 'od-bar');
                column.title = `${dayLabel(bin)}: ${bin.succeeded} ✓ · ${bin.failed} ✕ · ${bin.other} ?`;
                const stack = node('div', 'od-bar-stack');
                stack.style.setProperty('--od-fill', `${total ? Math.max(8, (total / max) * 100) : 0}%`);
                [['failed', bin.failed], ['other', bin.other], ['succeeded', bin.succeeded]].forEach(([kind, count]) => {
                    if (!count) return;
                    const segment = node('span', 'od-bar-value');
                    segment.dataset.kind = kind;
                    segment.style.setProperty('--od-count', String(count));
                    stack.append(segment);
                });
                column.append(stack);
                chart.append(column);
            });
            const axis = node('div', 'od-chart-axis');
            axis.setAttribute('aria-hidden', 'true');
            axis.append(node('span', '', dayLabel(bins[0])), node('span', '', dayLabel(bins[bins.length - 1])));
            // An empty chart is noise; the status line explains the state instead.
            // Status is never colour alone: a legend names each colour with its count.
            const legend = node('ul', 'od-chart-legend');
            [['succeeded', metrics.automation.succeeded], ['failed', metrics.automation.failed],
                ['other', metrics.automation.runs - metrics.automation.succeeded - metrics.automation.failed]].forEach(([kind, count]) => {
                if (!count && kind !== 'succeeded') return;
                const entry = node('li');
                entry.dataset.kind = kind;
                entry.append(node('span', 'od-legend-swatch'), node('span', '', tw(`legend${kind[0].toUpperCase()}${kind.slice(1)}`, kind)), node('strong', '', String(count)));
                legend.append(entry);
            });
            $('odAutomationChart').replaceChildren(...(metrics.automation.runs ? [chart, axis, legend] : []));
            const next = metrics.nextRun;
            $('odNextRun').textContent = !runInfo.loaded ? (runInfo.stale ? tw('automationUnavailable', 'Automation data is unavailable right now.') : tw('loading', 'Loading…'))
                : runInfo.stale ? tw('automationStale', 'Showing the last known runs. Automation could not be refreshed.')
                : next ? tw('nextRun', 'Next: {name}, {when}', {name: next.name, when: relativeFuture(next.due)})
                    : metrics.automation.runs ? '' : tw('kpiAutomationNone', 'No runs yet');
        }
        function relativeFuture(timestamp) {
            const minutes = Math.max(0, Math.round((timestamp - Date.now()) / 60000));
            const format = new Intl.RelativeTimeFormat(win.i18n?.getLanguage?.() || undefined, {numeric: 'auto'});
            if (minutes < 60) return format.format(minutes, 'minute');
            if (minutes < 1440) return format.format(Math.round(minutes / 60), 'hour');
            return format.format(Math.round(minutes / 1440), 'day');
        }
        function renderPlatforms(hosts) {
            const section = $('odPlatforms');
            const entries = Model.platforms(hosts, profile => win.HostPlatform?.resolve?.(profile));
            section.hidden = !entries.length;
            renderServices(section, hosts);
            const total = Math.max(1, hosts.length);
            section.querySelector('.od-platforms').replaceChildren(...entries.map(entry => {
                const item = node('li', 'od-platform');
                const name = entry.platform.id === 'server' ? t('platform.server', 'Server') : win.HostPlatform?.labels?.[entry.platform.id] || entry.platform.id;
                const bar = node('span', 'od-platform-bar');
                bar.style.setProperty('--od-share', `${Math.round((entry.count / total) * 100)}%`);
                item.append(win.HostPlatform?.render(entry.platform, doc) || icon('dns'), node('span', 'od-platform-name', name), node('span', 'od-count', String(entry.count)), bar);
                return item;
            }));
        }
        /** Detected services with their host counts; each filters the overview to those hosts. */
        function renderServices(section, hosts) {
            const counts = new Map();
            hosts.forEach(host => (win.HostPlatform?.services?.(host.profile) || []).forEach(id => {
                if (!counts.has(id)) counts.set(id, []);
                counts.get(id).push(host.id);
            }));
            const list = section.querySelector('.od-services');
            const heading = section.querySelector('.od-services-title');
            if (!list || !heading) return;
            heading.hidden = list.hidden = !counts.size;
            const labels = win.HostPlatform?.serviceLabels || {};
            list.replaceChildren(...[...counts].sort((a, b) => b[1].length - a[1].length || String(labels[a[0]]).localeCompare(String(labels[b[0]])))
                .map(([id, ids]) => {
                    const item = node('li');
                    const label = labels[id] || id;
                    const action = button('od-service', tw('serviceFilter', 'Show hosts running {name}', {name: label}),
                        () => filterHosts(ids, label));
                    action.dataset.service = id;
                    action.append(node('span', 'od-service-name', label), node('span', 'od-count', String(ids.length)));
                    item.append(action);
                    return item;
                }));
        }
        function renderActivity(hosts, runInfo) {
            const events = Model.activity({hostList: hosts, sessions: sessions(), history: win.ConnectionHistory?.getHistory?.() || [], runs: runInfo.runs || []});
            const list = $('odActivity').querySelector('.od-timeline');
            $('odActivityEmpty').hidden = events.length > 0;
            list.replaceChildren(...events.map(event => {
                const item = node('li', 'od-event');
                item.dataset.kind = event.kind;
                const text = {
                    session: tw('eventSession', 'Session open: {name}', {name: event.name}),
                    connection: tw('eventConnection', 'Connected to {name}', {name: event.name}),
                    'run-succeeded': tw('eventRunSucceeded', '{name} succeeded', {name: event.name}),
                    'run-failed': tw('eventRunFailed', '{name} failed', {name: event.name}),
                    'run-other': tw('eventRunOther', '{name}: outcome unknown', {name: event.name}),
                }[event.kind];
                const marker = node('span', 'od-event-marker');
                marker.append(icon({session: 'terminal', connection: 'history', 'run-succeeded': 'check', 'run-failed': 'close', 'run-other': 'help_outline'}[event.kind]));
                const time = node('time', 'od-event-time', event.kind === 'session' ? tw('openNow', 'open') : relative(event.at));
                time.dateTime = new Date(event.at).toISOString();
                item.append(marker, node('span', 'od-event-text', text), time);
                return item;
            }));
        }

        function render() {
            state.scheduled = false;
            if (view.hidden) return;
            const focusKey = view.contains(doc.activeElement) ? doc.activeElement.dataset.key : null;
            const hosts = hostModel();
            $('odBoard')?.setAttribute('data-empty', String(win.ProfileManager?.profilesLoaded === true && hosts.length === 0));
            const runInfo = snapshot();
            const allAttention = Model.attention({hostList: hosts, runs: runInfo.runs || [], schedules: runInfo.schedules || []});
            const dismissed = new Set(state.dismissed);
            const attentionItems = allAttention.filter(item => !dismissed.has(item.key));
            state.attention = allAttention;
            const metrics = Model.metrics({hostList: hosts, sessions: sessions(), runs: runInfo.runs || [], schedules: runInfo.schedules || [],
                reachability: state.reachability});
            renderWorkFirst(hosts);
            renderHero(hosts, attentionItems);
            renderKpis(hosts, metrics, runInfo);
            renderLegend(hosts);
            renderHostFilter();
            renderTopology(hosts);
            renderHosts(hosts);
            state.automationEnabled = runInfo.enabled === true;
            renderAttention(attentionItems, allAttention.length - attentionItems.length);
            renderAutomation(runInfo, metrics);
            renderPlatforms(hosts);
            renderActivity(hosts, runInfo);
            if (state.firstPaint) {
                state.firstPaint = false;
                view.dataset.settled = 'true';
            }
            if (focusKey) view.querySelector(`[data-key="${CSS.escape(focusKey)}"]`)?.focus({preventScroll: true});
        }
        function schedule() {
            if (state.scheduled) return;
            state.scheduled = true;
            win.requestAnimationFrame(render);
        }

        async function request(path, options = {}) {
            const appRoot = (doc.querySelector('meta[name="app-root"]')?.content || '').replace(/\/$/, '');
            const response = await win.fetch(appRoot + path, {credentials: 'same-origin', cache: 'no-store', ...options,
                headers: {'Content-Type': 'application/json', 'X-CSRFToken': doc.querySelector('meta[name="csrf-token"]')?.content || '', ...options.headers}});
            const data = await response.json().catch(() => ({}));
            if (!response.ok) {
                const error = new Error(data.error || 'request failed');
                error.code = data.code;
                throw error;
            }
            return data;
        }
        async function loadReadiness() {
            if (!win.ProfileManager?.profilesLoaded) return;
            try {
                const data = await request('/api/overview/status');
                state.readiness = Array.isArray(data.hosts) ? data.hosts : [];
                state.readinessAt = Number(data.generated_at) * 1000 || Date.now();
            } catch {
                // Readiness is optional context; hosts still render without it.
            }
            schedule();
        }
        function queueReadiness() {
            win.clearTimeout(state.readinessTimer);
            // The first load runs at once; later changes are coalesced.
            state.readinessTimer = win.setTimeout(loadReadiness, state.readiness === null ? 0 : 400);
        }
        async function checkReachability() {
            if (state.checking || mode() === 'off' || !profiles().length) return;
            state.checking = true;
            state.reachError = null;
            schedule();
            // Snapshot before the request: an address edited meanwhile must not inherit the result.
            const targets = reachTargets();
            try {
                const data = await request('/api/overview/reachability', {method: 'POST', body: JSON.stringify({})});
                state.reachability = data.results || {};
                // The check read SSH greetings and stored new platform hints; show them.
                if (data.platforms_updated) win.ProfileManager?.loadProfiles?.();
                state.reachTargets = targets;
                pruneReachability();
                state.checkedAt = Number(data.checked_at) * 1000 || Date.now();
            } catch (error) {
                state.reachError = error.code === 'busy' ? tw('reachBusy', 'Too many checks. Try again in a minute.') : tw('reachFailed', 'The check could not be completed.');
            } finally {
                state.checking = false;
                schedule();
            }
        }
        // A result belongs to the address and route that were checked.
        const reachTarget = profile => [profile.host, profile.port || 22, profile.jump_host_id || ''].join('|');
        function reachTargets() {
            return new Map(profiles().map(profile => [profile.id, reachTarget(profile)]));
        }
        /** Forget results of hosts that were removed or now point somewhere else. */
        function pruneReachability() {
            if (!state.reachability || !state.reachTargets) return;
            const current = reachTargets();
            const loaded = win.ProfileManager?.profilesLoaded === true;
            Object.keys(state.reachability).forEach(id => {
                // A result restored before the hosts loaded adopts the first known target.
                if (!state.reachTargets.has(id)) {
                    if (current.has(id)) state.reachTargets.set(id, current.get(id));
                    else if (loaded) delete state.reachability[id];
                    return;
                }
                if (current.get(id) !== state.reachTargets.get(id)) delete state.reachability[id];
            });
        }
        /** Show the last check after a page load; this never contacts a host. */
        async function restoreReachability() {
            if (mode() === 'off' || state.checkedAt) return;
            state.restoring = true;
            try {
                const data = await request('/api/overview/reachability');
                if (data.results && !state.checkedAt) {
                    state.reachability = data.results;
                    state.reachTargets = reachTargets();
                    state.checkedAt = Number(data.checked_at) * 1000 || null;
                    schedule();
                }
            } catch {
                // Without a stored result the tile simply shows "Not checked yet".
            } finally {
                state.restoring = false;
            }
        }
        function syncAutomatic() {
            win.clearInterval(state.automaticTimer);
            if (state.restoring || mode() !== 'automatic' || view.hidden) return;
            if (!state.checkedAt || Date.now() - state.checkedAt > AUTOMATIC_INTERVAL) checkReachability();
            state.automaticTimer = win.setInterval(() => { if (!doc.hidden && !view.hidden) checkReachability(); }, AUTOMATIC_INTERVAL);
        }

        function bindKeyboard() {
            search.addEventListener('input', () => { state.focusId = null; state.idFilter = null; schedule(); });
            search.addEventListener('keydown', event => {
                if (event.key === 'Enter') { event.preventDefault(); hostList.querySelector('.od-connect')?.click(); }
                else if (event.key === 'ArrowDown') { event.preventDefault(); hostList.querySelector('.od-connect')?.focus(); }
                else if (event.key === 'Escape' && filtered()) resetFilters();
            });
            doc.addEventListener('keydown', event => {
                if (event.key !== '/' || event.ctrlKey || event.metaKey || event.altKey || view.hidden) return;
                if (event.target.closest?.('input, textarea, select, [contenteditable="true"], .xterm, dialog')) return;
                event.preventDefault();
                search.focus();
            });
            hostList.addEventListener('keydown', event => {
                if (!['ArrowDown', 'ArrowUp'].includes(event.key) || !event.target.classList.contains('od-connect')) return;
                const buttons = [...hostList.querySelectorAll('.od-connect')];
                const index = buttons.indexOf(event.target) + (event.key === 'ArrowDown' ? 1 : -1);
                event.preventDefault();
                if (index < 0) search.focus();
                else buttons[Math.min(index, buttons.length - 1)].focus();
            });
        }
        function createRouteMap() {
            const mount = $('overviewRouteMap');
            if (!mount || !win.OverviewRouteMap || !win.ConnectionOverview?.buildAccessModel) return null;
            // The expand button toggles; the map may already have closed itself.
            const close = () => { if (mount.closest('dialog')?.open) mount.querySelector('[data-route-map-expand]')?.click(); };
            return win.OverviewRouteMap.create({
                root: mount,
                loaded: () => win.ProfileManager?.profilesLoaded === true,
                model: () => win.ConnectionOverview.buildAccessModel(profiles(), win.JumpHostManager?.jumpHosts || [], win.JumpHostManager?.loaded),
                hostActions: host => {
                    const actions = node('div', 'overview-host-actions');
                    const connectButton = button('overview-host-connect', `${t('connection.actionConnect', 'Connect')} ${host.name}`, () => {
                        close();
                        const entry = hostModel().find(item => item.id === host.id);
                        if (entry) connect(entry);
                    });
                    connectButton.append(icon('terminal'), node('span', '', t('connection.actionConnect', 'Connect')));
                    actions.append(connectButton);
                    return actions;
                },
                inspect: host => { close(); focusHost(host.id); },
            });
        }
        function openOverview() {
            win.primaryWorkspaceController?.open('overview', view);
            render();
            // Keyboard users return to the host they launched, not to the top of the page.
            const key = state.returnKey;
            state.returnKey = null;
            const target = key ? [...hostList.querySelectorAll('[data-key]')].find(item => item.dataset.key === key) : null;
            (target || $('overviewTitle'))?.focus({preventScroll: !target});
        }

        function preferences() {
            try {
                const data = JSON.parse($('overviewPreferences')?.textContent || '{}');
                return {panels: Array.isArray(data.panels) ? data.panels : null, dismissed: Array.isArray(data.dismissed) ? data.dismissed : []};
            } catch {
                return {panels: null, dismissed: []};
            }
        }
        function panelLabel(id) {
            return {
                kpis: tw('kpisLabel', 'Key figures'), topology: tw('topologyTitle', 'Infrastructure'), hosts: tw('hostsTitle', 'Hosts'),
                attention: tw('attentionTitle', 'Needs attention'), automation: tw('automationTitle', 'Automation'),
                platforms: tw('platformsTitle', 'Platforms'), activity: tw('activityTitle', 'Activity'),
                continue: wf('title', 'Continue working'),
            }[id] || id;
        }
        function announce(message) {
            const status = $('odLayoutStatus');
            status.textContent = '';
            win.requestAnimationFrame(() => { status.textContent = message; });
        }
        async function saveLayout(panels) {
            try {
                await request('/api/overview/preferences', {method: 'PUT', body: JSON.stringify({panels})});
            } catch {
                announce(tw('layoutSaveFailed', 'The layout could not be saved. Your changes apply until you reload.'));
            }
        }
        function setEditing(value) {
            if (!state.board) return;
            state.board.setEditing(value);
            $('odEditBar').hidden = !value;
            $('overviewCustomize').setAttribute('aria-pressed', String(value));
            view.dataset.editing = String(value);
            announce(value ? tw('editStarted', 'Layout editing on. Each panel has its own controls.') : tw('editEnded', 'Layout saved'));
            if (value) $('odBoard').querySelector('[data-panel-handle]')?.focus({preventScroll: true});
            else $('overviewCustomize').focus({preventScroll: true});
        }
        function createBoard() {
            if (!win.OverviewLayout || !$('odBoard')) return null;
            return win.OverviewLayout.createBoard({
                doc, win, board: $('odBoard'), stored: preferences().panels, save: saveLayout,
                t, label: panelLabel, announce,
            });
        }

        function init() {
            state.dismissed = preferences().dismissed;
            state.board = createBoard();
            $('overviewCustomize')?.addEventListener('click', () => setEditing(!state.board?.isEditing()));
            $('odLayoutDone')?.addEventListener('click', () => setEditing(false));
            $('odLayoutReset')?.addEventListener('click', () => state.board?.reset());
            $('overviewCustomize').hidden = !state.board;
            view.addEventListener('keydown', event => {
                if (event.key === 'Escape' && state.board?.isEditing() && !event.target.closest?.('input, dialog')) {
                    event.preventDefault();
                    setEditing(false);
                }
            });
            $('odAttentionDismissAll')?.addEventListener('click', () => {
                const dismissed = new Set(state.dismissed);
                dismissAttention(state.attention.filter(item => !dismissed.has(item.key)).map(item => item.key));
            });
            $('odAttentionRestore')?.addEventListener('click', () => {
                const current = new Set(state.attention.map(item => item.key));
                saveDismissed(state.dismissed.filter(key => !current.has(key)));
                win.requestAnimationFrame(() => $('odAttention').querySelector('.od-row')?.focus({preventScroll: true}));
            });
            win.addEventListener('languageChanged', () => state.board?.relabel());
            bindKeyboard();
            $('overviewNewHost').addEventListener('click', createHost);
            $('overviewEmptyCreate')?.addEventListener('click', createHost);
            $('overviewOpenAutomation')?.addEventListener('click', openAutomation);
            state.routeMap = createRouteMap();
            $('overviewOpenMap').addEventListener('click', () => {
                state.routeMap?.render();
                $('overviewRouteMap')?.querySelector('[data-route-map-expand]')?.click();
            });
            $('overviewNavBtn')?.addEventListener('click', openOverview);
            view.querySelectorAll('.od-legend-filter').forEach(button => button.addEventListener('click', () => {
                state.focusId = null;
                state.idFilter = null;
                state.stateFilter = state.stateFilter === button.dataset.state ? null : button.dataset.state;
                schedule();
            }));
            // A click on empty space or on the WebSSH core shows everything again; host nodes keep their focus click.
            $('odTopology').addEventListener('click', event => {
                if (!event.target.closest?.('.od-node') && filtered()) resetFilters();
            });
            $('overviewHostFilter')?.addEventListener('click', () => { resetFilters(); search.focus(); });
            // The status pill leads to what needs attention.
            $('overviewStatusButton')?.addEventListener('click', () => {
                const panel = $('odAttention');
                const first = panel?.querySelector('.od-row');
                if (first && !panel.hidden && panel.dataset.userHidden !== 'true') {
                    panel.scrollIntoView?.({block: 'nearest', behavior: motion() ? 'smooth' : 'auto'});
                    // A mouse click does not show a focus ring, so mark the list visibly as well.
                    first.focus({preventScroll: true, focusVisible: true});
                    panel.classList.remove('od-panel-flash');
                    void panel.offsetWidth;
                    panel.classList.add('od-panel-flash');
                    return;
                }
                const ids = [...new Set(state.attention.flatMap(item => item.hostIds || (item.hostId ? [item.hostId] : [])))];
                if (ids.length) {
                    filterHosts(ids, $('overviewStatusText').textContent);
                    return;
                }
                // The list is hidden and no item names a host (a failed run): open the first item directly.
                const dismissed = new Set(state.dismissed);
                const item = state.attention.find(entry => !dismissed.has(entry.key));
                if (item) describeAttention(item)[2]();
            });
            $('odAttention')?.addEventListener('animationend', event => {
                if (event.animationName === 'od-panel-flash') event.currentTarget.classList.remove('od-panel-flash');
            });
            $('overviewSetupHost')?.addEventListener('change', schedule);
            view.addEventListener('wheel', event => {
                if (event.defaultPrevented || event.ctrlKey || event.metaKey || event.shiftKey || !event.deltaY || Math.abs(event.deltaX) >= Math.abs(event.deltaY)) return;
                const body = event.target.closest?.('[data-panel][data-fixed-height="true"] > .od-panel-body');
                if (!body || !view.contains(body)) return;
                const canScroll = element => event.deltaY < 0 ? element.scrollTop > 0
                    : element.scrollTop + element.clientHeight < element.scrollHeight - 1;
                // Keep nested controls and overflowing lists native until their edge.
                for (let element = event.target; element && body.contains(element); element = element.parentElement) {
                    if (['auto', 'scroll'].includes(win.getComputedStyle(element).overflowY) && canScroll(element)) return;
                }
                if (!canScroll(view)) return;
                // Some browsers keep the wheel latched to a panel after it reaches its edge.
                const unit = event.deltaMode === 1 ? 16 : event.deltaMode === 2 ? view.clientHeight : 1;
                event.preventDefault();
                view.scrollTop += event.deltaY * unit;
            }, {passive: false});
            win.socket?.on?.('directory_listing', data => {
                const id = typeof data?.source_id === 'string' && data.source_id.startsWith('sftp-session:') ? data.source_id.slice(13) : null;
                if (id && Array.isArray(data.files) && sessionManager?.getSession?.(id)?.connected) { fileSessions.add(id); schedule(); }
            });
            ['session-workspace-change', 'languageChanged', 'automation-runs-updated'].forEach(name => win.addEventListener(name, schedule));
            ['profile-list-change', 'jump-host-list-change', 'host-access-change'].forEach(name => win.addEventListener(name, () => { schedule(); queueReadiness(); }));
            // The first automatic check needs the saved hosts, which may load after init.
            win.addEventListener('profile-list-change', () => {
                pruneReachability();
                if (!state.checkedAt && !state.checking && !view.hidden) syncAutomatic();
            });
            win.addEventListener('primary-workspace-change', () => { schedule(); if (!view.hidden) { queueReadiness(); syncAutomatic(); } else win.clearInterval(state.automaticTimer); });
            ['connect', 'disconnect'].forEach(name => win.socket?.on?.(name, schedule));
            win.setInterval(() => { if (!view.hidden && !doc.hidden) schedule(); }, 60 * 1000);
            if (win.ResizeObserver) {
                new win.ResizeObserver(entries => {
                    // Layout is clean here, so reading the width costs nothing; renders reuse it.
                    const width = entries[0].target.clientWidth;
                    state.topologyWidth = width;
                    const narrow = Boolean(width && (state.topologyNarrow ? width < 600 : width < 560));
                    if (narrow !== state.topologyNarrow) schedule();
                }).observe($('odTopology'));
            }
            render();
            queueReadiness();
            restoreReachability().finally(syncAutomatic);
        }
        return {init, render};
    }

    root.OverviewWorkspace = {createController};
}(typeof globalThis !== 'undefined' ? globalThis : this));
