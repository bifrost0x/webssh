(function () {
    'use strict';
    const t = (key, fallback) => {
        const value = window.i18n?.t(key);
        return value && value !== key ? value : fallback;
    };
    const el = (tag, text, className) => {
        const node = document.createElement(tag);
        if (text !== undefined) node.textContent = text;
        if (className) node.className = className;
        return node;
    };
    const icon = name => {
        const node = el('span', name, 'material-icons');
        node.setAttribute('aria-hidden', 'true');
        return node;
    };
    const manager = () => typeof SessionManager !== 'undefined' ? SessionManager : window.SessionManager;
    const snapshots = new WeakMap();
    let workspaceSequence = 0;
    let activeWorkspace = null;
    function updateSnapshot(sessionId, session, model) {
        if (!session || manager()?.sessions?.[sessionId] !== session) return;
        snapshots.set(session, model);
        window.dispatchEvent(new CustomEvent('server-management-snapshot', {detail: {sessionId}}));
    }
    async function api(path, options = {}) {
        const root = document.querySelector('meta[name="app-root"]')?.content || '';
        const response = await fetch(root + path, {
            credentials: 'same-origin', ...options,
            headers: {
                'Content-Type': 'application/json',
                'X-CSRFToken': document.querySelector('meta[name="csrf-token"]')?.content || '',
                ...options.headers
            },
            ...(options.body ? {body: JSON.stringify(options.body)} : {})
        });
        const data = await response.json();
        if (!response.ok) {
            const messages = {
                unknown: 'The outcome is unknown. Inspect the server before trying another action; do not retry automatically.',
                timeout: 'The server did not respond within the time limit.',
                output_limit: 'The response exceeded the output limit.',
                unavailable: 'This SSH session is no longer available.',
                invalid_intent: 'This confirmation expired or was already used. Review the action again.',
                confirmation_required: 'Type the exact host shown in the confirmation.',
                invalid_target: 'This target is unsupported or invalid.',
                busy: 'Another operation is in progress. Wait for its result.',
                disabled: 'Server mutations are disabled by the operator.'
            };
            const error = new Error(t(`serverOps.${data.code}`, messages[data.code] || data.error || t('serverOps.failed', 'Operation failed.')));
            error.code = data.code;
            throw error;
        }
        return data;
    }
    function bytes(value) {
        return Uint8Array.from(atob(value.replace(/-/g, '+').replace(/_/g, '/')), character => character.charCodeAt(0));
    }
    function encoded(value) {
        return btoa(String.fromCharCode(...new Uint8Array(value))).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
    }
    function credentialJSON(credential) {
        return {
            id: credential.id, rawId: encoded(credential.rawId), type: credential.type,
            authenticatorAttachment: credential.authenticatorAttachment,
            clientExtensionResults: credential.getClientExtensionResults(),
            response: {
                clientDataJSON: encoded(credential.response.clientDataJSON),
                authenticatorData: encoded(credential.response.authenticatorData),
                signature: encoded(credential.response.signature),
                userHandle: credential.response.userHandle ? encoded(credential.response.userHandle) : null
            }
        };
    }
    function open(sessionId, kind, sourceTarget = {}) {
        const session = manager()?.sessions?.[sessionId];
        if (!session?.connected) return;
        if (activeWorkspace?.isConnected) {
            activeWorkspace.querySelector('.close')?.focus();
            return;
        }
        window.dispatchEvent(new CustomEvent('server-management-opening', {detail: {sessionId}}));
        const modal = el('div', undefined, 'modal server-management');
        modal.setAttribute('role', 'dialog');
        modal.setAttribute('aria-modal', 'true');
        modal.setAttribute('aria-label', t('serverOps.title', 'Server management'));
        const content = el('div', undefined, 'modal-content');
        const header = el('div', undefined, 'modal-header');
        const identity = el('div', undefined, 'server-management-identity');
        const identityText = el('div');
        identityText.append(el('span', t('serverOps.title', 'Server management'), 'server-management-eyebrow'),
            el('h2', session.host || ''));
        identity.append(icon('dns'), identityText);
        header.append(identity);
        const close = el('button', 'close', 'close material-icons');
        close.setAttribute('aria-label', t('serverOps.close', 'Close'));
        header.append(close);
        const body = el('div', undefined, 'modal-body');
        const targetLabel = el('p', `${session.username || ''}@${session.host || ''}:${session.port || 22}`, 'server-management-host');
        identityText.append(targetLabel);
        const hostMeta = el('div', undefined, 'server-management-host-meta');
        identityText.append(hostMeta);
        const tabs = el('div', undefined, 'server-management-tabs');
        tabs.setAttribute('role', 'tablist');
        const narrowLayout = window.matchMedia('(max-width: 600px)');
        const updateTabOrientation = () => tabs.setAttribute('aria-orientation', narrowLayout.matches ? 'horizontal' : 'vertical');
        updateTabOrientation();
        narrowLayout.addEventListener('change', updateTabOrientation);
        tabs.setAttribute('aria-label', t('serverOps.sections', 'Server sections'));
        const workspace = el('section', undefined, 'server-management-workspace');
        const workspaceId = `server-management-workspace-${++workspaceSequence}`;
        workspace.id = workspaceId;
        workspace.setAttribute('role', 'tabpanel');
        const overview = el('div', undefined, 'server-management-overview');
        const inventory = el('div', undefined, 'server-management-inventory');
        const search = el('input', undefined, 'form-control');
        search.type = 'search';
        search.placeholder = t('serverOps.search', 'Search resources…');
        search.setAttribute('aria-label', t('serverOps.search', 'Search resources…'));
        const filter = el('select', undefined, 'form-control');
        filter.setAttribute('aria-label', t('serverOps.statusFilter', 'Filter by status'));
        for (const [value, label] of [['all', t('serverOps.all', 'All statuses')], ['running', t('serverOps.running', 'Running / active')], ['stopped', t('serverOps.stopped', 'Stopped / inactive')], ['failed', t('serverOps.failedState', 'Failed')]]) {
            const option = el('option', label);
            option.value = value;
            filter.append(option);
        }
        const list = el('div', undefined, 'server-management-list');
        const detail = el('section', undefined, 'server-management-detail');
        const selectionIcon = icon('touch_app');
        selectionIcon.classList.add('server-management-selection-icon');
        const detailTitle = el('h3');
        detailTitle.tabIndex = -1;
        const detailHint = el('p', undefined, 'server-management-hint');
        const facts = el('dl', undefined, 'server-management-facts');
        const notice = el('p', undefined, 'server-management-notice');
        const toolbar = el('div', undefined, 'server-management-toolbar');
        toolbar.append(search, filter);
        inventory.append(toolbar, list);
        workspace.append(overview, inventory, detail);
        const status = el('p', t('serverOps.loading', 'Loading…'), 'server-management-status');
        status.setAttribute('role', 'status');
        const output = el('pre', undefined, 'server-operation-output');
        output.hidden = true;
        const sudoLabel = el('label', t('serverOps.sudo', 'Use non-interactive sudo (requires remote permission)'));
        const sudo = el('input');
        sudo.type = 'checkbox';
        sudoLabel.prepend(sudo);
        const controls = el('div', undefined, 'form-actions');
        const review = el('section', undefined, 'server-management-review');
        review.tabIndex = -1;
        const authentication = el('section');
        const outputArea = el('div', undefined, 'server-management-output');
        const outputTitle = el('h4', t('serverOps.output', 'Output'));
        outputArea.append(outputTitle, output);
        detail.append(selectionIcon, detailTitle, review, authentication, detailHint, facts, controls, sudoLabel, status, outputArea);
        const main = el('div', undefined, 'server-management-main');
        main.append(notice, workspace);
        body.append(tabs, main);
        content.append(header, body);
        modal.append(content);
        document.body.append(modal);
        activeWorkspace = modal;
        let generation = 0;
        let pending = false;
        let capabilities = null;
        let resolved = null;
        let processRows = [];
        let answer = null;
        let authorizationController = null;
        function cancelAuthorization() {
            authorizationController?.abort();
            authorizationController = null;
            if (answer) { answer(null); answer = null; authentication.replaceChildren(); }
        }
        let selected = Boolean(kind === 'service' ? sourceTarget.unit : kind === 'container' ? sourceTarget.name : kind === 'process' ? sourceTarget.pid : false);
        const labels = {
            system: t('serverOps.overview', 'Overview'),
            service: t('serverOps.services', 'Services'),
            container: t('serverOps.containers', 'Containers'),
            process: t('serverOps.processes', 'Processes')
        };
        function drawWorkspace() {
            const model = snapshots.get(session);
            for (const tab of tabs.children) {
                const active = tab.dataset.kind === kind;
                tab.setAttribute('aria-selected', String(active));
                tab.tabIndex = active ? 0 : -1;
                if (active) workspace.setAttribute('aria-labelledby', tab.id);
            }
            workspace.dataset.kind = kind;
            detail.classList.toggle('is-empty', kind !== 'system' && !selected);
            selectionIcon.hidden = kind === 'system' || selected;
            sudoLabel.hidden = (kind !== 'system' && !selected) || (kind === 'system' && !capabilities?.mutations_enabled);
            hostMeta.textContent = [model?.os, model?.secondary?.uptime].filter(Boolean).join(' · ');
            overview.hidden = kind !== 'system';
            inventory.hidden = kind === 'system';
            filter.hidden = kind === 'process';
            detailTitle.textContent = kind === 'system' ? t('serverOps.hostActions', 'Host actions')
                : selected ? String(sourceTarget.unit || sourceTarget.name || sourceTarget.pid || '') : labels[kind];
            detailHint.textContent = kind === 'process'
                ? t('serverOps.processScope', 'Snapshot of all visible processes. CPU is the lifetime average. Refresh to update; select a process to inspect its identity before control.')
                : selected ? t('serverOps.targetDetail', 'Inspect the selected resource and review an action before executing it.')
                    : kind === 'system' ? ''
                        : t('serverOps.selectResource', 'Select a resource to view details and available actions.');
            notice.textContent = [model?.status, model?.inventory?.stale ? t('serverOps.staleInventory', 'Inventory is out of date. Refresh before choosing a target.') : '',
                ...(model?.permissionNotices || []), capabilities && !capabilities.mutations_enabled
                    ? t('serverOps.disabled', 'Server mutations are disabled by the operator. Read-only inspection remains available.') : ''].filter(Boolean).join(' · ');
            notice.classList.toggle('is-warning', !!model?.inventory?.stale || !!model?.permissionNotices?.length);
            overview.replaceChildren();
            const cards = el('div', undefined, 'server-management-cards');
            for (const [key, label] of [['cpu', 'CPU'], ['memory', t('diagnostics.memory', 'Memory')], ['disk', t('diagnostics.rootDisk', 'Root disk')], ['load', t('diagnostics.normalizedLoad', 'Normalized load')]]) {
                const value = model?.resources?.[key];
                const card = el('article', undefined, 'server-management-card');
                card.dataset.metric = key;
                card.classList.toggle('is-warning', value?.severity === 'warning');
                const meter = el('div', undefined, 'server-management-meter');
                meter.setAttribute('aria-hidden', 'true');
                const fill = el('span');
                fill.style.width = `${Math.max(0, Math.min(100, Number(value?.barPercent) || 0))}%`;
                meter.append(fill);
                card.append(el('span', label), el('strong', value?.label || '—'), meter,
                    el('small', value?.detail || t('serverOps.noMeasurements', 'Waiting for measurements')));
                cards.append(card);
            }
            overview.append(cards);
            const resourceLinks = el('div', undefined, 'server-management-resources');
            const resourceIcons = {service: 'settings_suggest', container: 'view_in_ar', process: 'memory'};
            for (const [key, value] of [['service', model?.systemd?.countsAvailable ? model.systemd.total : null],
                ['container', model?.docker?.countsAvailable ? model.docker.total : null], ['process', model?.secondary?.processTotal]]) {
                const link = button('', () => select(key), resourceLinks);
                link.className = 'server-management-resource';
                link.setAttribute('aria-label', labels[key]);
                const copy = el('span', undefined, 'server-management-resource-copy');
                copy.append(el('strong', labels[key]));
                const description = key === 'service' && model?.systemd?.countsAvailable
                    ? `${model.systemd.active} ${t('serverOps.running', 'Running / active')} · ${model.systemd.failed} ${t('serverOps.failedState', 'Failed')}`
                    : key === 'container' && model?.docker?.countsAvailable
                        ? `${model.docker.running} ${t('serverOps.running', 'Running / active')}`
                        : key === 'process' ? t('serverOps.sampledProcesses', 'Browse all visible processes')
                            : t('serverOps.noMeasurements', 'Waiting for measurements');
                copy.append(el('small', description));
                link.classList.toggle('is-warning', key === 'service' && model?.systemd?.failed > 0);
                link.append(icon(resourceIcons[key]), copy, el('strong', String(value ?? '—'), 'server-management-resource-count'), icon('chevron_right'));
                link.disabled = pending;
            }
            overview.append(resourceLinks);
            const findings = el('div', undefined, 'server-management-findings');
            for (const finding of model?.findings || []) {
                const row = el('p');
                row.append(icon('info'), el('span', finding.text));
                findings.append(row);
            }
            if (findings.children.length) overview.append(findings);
            const traffic = el('div', undefined, 'server-management-traffic');
            for (const [label, value] of [[t('serverOps.received', 'Received'), model?.secondary?.received],
                [t('serverOps.transmitted', 'Transmitted'), model?.secondary?.transmitted]]) {
                if (value) traffic.append(el('span', `${label}  ${value}`));
            }
            if (traffic.children.length) overview.append(traffic);
            if (kind === 'service' && selected) {
                facts.replaceChildren();
                const service = model?.systemd?.rows?.find(row => row.unit === sourceTarget.unit);
                if (service) {
                    facts.append(el('dt', t('serverOps.state', 'State')), el('dd', service.active));
                    if (service.description) detailHint.textContent = service.description;
                }
            }
            list.replaceChildren();
            let rows = kind === 'service' ? model?.systemd?.rows : kind === 'container' ? model?.docker?.rows
                : processRows;
            rows = [...(rows || [])];
            if (kind === 'service') {
                const rank = row => row.active === 'failed' ? 0 : row.active === 'active' ? 1 : 2;
                rows.sort((a, b) => rank(a) - rank(b) || a.unit.localeCompare(b.unit));
            } else if (kind === 'container') {
                const rank = row => /^(up\b|running$)/i.test(row.status) ? 0 : 1;
                rows.sort((a, b) => rank(a) - rank(b) || a.name.localeCompare(b.name));
            }
            const query = search.value.trim().toLowerCase();
            if (kind === 'process') list.append(el('p', `${rows.length} ${t('serverOps.processes', 'Processes')}`));
            for (const row of rows.filter(row => {
                const state = String(row.active || row.status || '').toLowerCase();
                const running = state === 'active' || state.startsWith('up') || state === 'running';
                return Object.values(row).join(' ').toLowerCase().includes(query)
                    && (kind === 'process' || filter.value === 'all' || filter.value === 'running' && running
                        || filter.value === 'failed' && state === 'failed' || filter.value === 'stopped' && !running && state !== 'failed');
            })) {
                const name = row.unit || row.name || `${row.pid} · ${row.command}`;
                const rowButton = button('', () => select(kind, row.unit ? {unit: row.unit} : row.name ? {name: row.name} : {pid: Number(row.pid)}), list);
                rowButton.className = 'server-management-row';
                rowButton.append(el('strong', name), el('span', row.active || row.status || row.user, 'server-management-badge'),
                    el('small', row.description || (row.pid ? `CPU: ${row.cpu}% · ${t('diagnostics.memory', 'Memory')}: ${row.memory}%` : '')));
                rowButton.dataset.protected = String(row.pid === 1);
                const state = String(row.active || row.status || '').toLowerCase();
                rowButton.dataset.state = state === 'failed' ? 'failed' : /^(active$|up\b|running$)/.test(state) ? 'running' : 'other';
                rowButton.setAttribute('aria-pressed', String(selected && (sourceTarget.unit === row.unit && !!row.unit || sourceTarget.name === row.name && !!row.name || Number(sourceTarget.pid) === Number(row.pid) && !!row.pid)));
            }
            if (!list.querySelector('button')) list.append(el('p', rows.length ? t('serverOps.noMatches', 'No matching resources.')
                : t('serverOps.noInventory', 'No inventory available. The remote tool may be unsupported, access may be restricted, or sampling is still in progress.')));
            const truncation = kind === 'service' ? model?.systemd?.truncationLabel : kind === 'container' ? model?.docker?.truncationLabel : '';
            if (truncation) list.append(el('p', truncation));
            for (const node of list.querySelectorAll('button')) node.disabled = pending || node.dataset.protected === 'true';
        }
        function select(nextKind, target) {
            if (pending || !current()) return;
            generation++;
            cancelAuthorization();
            kind = nextKind;
            sourceTarget = target || {};
            selected = !!target;
            resolved = null;
            if (nextKind !== workspace.dataset.kind) {
                search.value = '';
                filter.value = 'all';
            }
            facts.replaceChildren();
            review.replaceChildren();
            output.textContent = '';
            output.hidden = true;
            status.textContent = '';
            drawWorkspace();
            if (target) detailTitle.focus();
            load();
        }
        for (const [key, label] of Object.entries(labels)) {
            const tab = button('', () => select(key), tabs);
            tab.setAttribute('aria-label', label);
            tab.append(icon({system: 'space_dashboard', service: 'settings_suggest', container: 'view_in_ar', process: 'memory'}[key]), el('span', label));
            tab.dataset.kind = key;
            tab.id = `${workspaceId}-${key}`;
            tab.setAttribute('role', 'tab');
            tab.setAttribute('aria-controls', workspaceId);
            tab.addEventListener('keydown', event => {
                const available = Array.from(tabs.children).filter(node => !node.disabled);
                const index = available.indexOf(tab);
                const offset = ['ArrowRight', 'ArrowDown'].includes(event.key) ? 1 : ['ArrowLeft', 'ArrowUp'].includes(event.key) ? -1 : 0;
                const next = event.key === 'Home' ? available[0] : event.key === 'End' ? available.at(-1)
                    : offset && available[(index + offset + available.length) % available.length];
                if (!next || pending) return;
                event.preventDefault();
                next.click();
                next.focus();
            });
        }
        search.addEventListener('input', drawWorkspace);
        filter.addEventListener('change', drawWorkspace);
        const onSnapshot = event => {
            if (event.detail?.sessionId === sessionId && current() && !list.contains(document.activeElement) && !overview.contains(document.activeElement)) drawWorkspace();
        };
        window.addEventListener('server-management-snapshot', onSnapshot);
        const current = () => modal.isConnected && modal.classList.contains('show')
            && manager()?.sessions?.[sessionId] === session
            && session.connected && manager()?.activeSessionId === sessionId;
        function invalidate() {
            if (current()) return;
            generation++;
            review.replaceChildren();
            controls.replaceChildren();
            status.textContent = t('serverOps.targetChanged', 'The active session changed. Reopen server management.');
            sudo.disabled = true;
            cancelAuthorization();
        }
        const dismiss = () => {
            generation++;
            cancelAuthorization();
            window.removeEventListener('session-workspace-change', invalidate);
            window.removeEventListener('session-removed', invalidate);
            window.removeEventListener('server-management-snapshot', onSnapshot);
            document.removeEventListener('keydown', escape, true);
            narrowLayout.removeEventListener('change', updateTabOrientation);
            window.ModalManager.close(modal);
            modal.remove();
            if (activeWorkspace === modal) activeWorkspace = null;
            window.dispatchEvent(new CustomEvent('server-management-closed', {detail: {sessionId}}));
        };
        const escape = event => {
            if (event.key === 'Escape') { event.preventDefault(); event.stopImmediatePropagation(); dismiss(); }
        };
        close.addEventListener('click', dismiss);
        modal.addEventListener('click', event => {
            if (event.target === modal) { event.stopPropagation(); dismiss(); }
        });
        document.addEventListener('keydown', escape, true);
        window.addEventListener('session-workspace-change', invalidate);
        window.addEventListener('session-removed', invalidate);
        function button(label, handler, parent = controls) {
            const node = el('button', label, 'btn btn-secondary');
            node.type = 'button';
            node.addEventListener('click', handler);
            parent.append(node);
            return node;
        }
        function question(method, choices) {
            if (!current()) return Promise.resolve(null);
            authentication.replaceChildren();
            const form = el('form');
            const label = el('label', choices
                ? t('serverOps.method', 'Choose an authentication method')
                : t('serverOps.authenticate', 'Confirm with your WebSSH sign-in method'));
            const input = el(choices ? 'select' : 'input', undefined, 'form-control');
            if (choices) {
                for (const choice of choices) {
                    const option = el('option', choice);
                    option.value = choice;
                    option.selected = choice === method;
                    input.append(option);
                }
            } else {
                input.type = method === 'totp' ? 'text' : 'password';
                input.autocomplete = method === 'totp' ? 'one-time-code' : 'current-password';
                input.required = true;
                input.maxLength = 4096;
            }
            label.append(input);
            const submit = el('button', t('serverOps.continue', 'Continue'), 'btn btn-primary');
            submit.type = 'submit';
            form.append(label, submit);
            button(t('serverOps.cancel', 'Cancel'), () => finish(null), form);
            authentication.append(form);
            input.focus();
            function finish(value) {
                const resolve = answer;
                answer = null;
                input.value = '';
                authentication.replaceChildren();
                resolve?.(value);
            }
            form.addEventListener('submit', event => {
                event.preventDefault();
                finish(current() ? input.value : null);
            });
            return new Promise(resolve => { answer = resolve; });
        }
        function createStepUp(revision, signal) {
            const guard = () => {
                if (signal.aborted || !current() || generation !== revision) {
                    throw new DOMException('Authorization cancelled', 'AbortError');
                }
            };
            return window.WebSSHSecurityUI.createAccountStepUpClient({
                api: async (path, options) => {
                    guard();
                    const result = await api(path, {...options, signal});
                    guard();
                    return result;
                },
                chooseMethod: (methods, preferred) => { guard(); return question(preferred, methods); },
                requestSecret: method => { guard(); return question(method); },
                getPasskeyAssertion: options => {
                    guard();
                    return navigator.credentials.get({
                        signal,
                        publicKey: {
                            ...options, challenge: bytes(options.challenge),
                            allowCredentials: (options.allowCredentials || []).map(item => ({...item, id: bytes(item.id)}))
                        }
                    });
                },
                serializeCredential: credentialJSON,
                openAuthorization: url => {
                    guard();
                    const popup = window.open(url, 'webssh-server-step-up', 'popup,width=720,height=760');
                    if (!popup) throw new Error(t('serverOps.popup', 'Allow the authentication popup and try again.'));
                    signal.addEventListener('abort', () => popup.close(), {once: true});
                },
                wait: milliseconds => new Promise((resolve, reject) => {
                    guard();
                    const abort = () => {
                        clearTimeout(timer);
                        reject(new DOMException('Authorization cancelled', 'AbortError'));
                    };
                    const timer = setTimeout(() => {
                        signal.removeEventListener('abort', abort);
                        resolve();
                    }, milliseconds);
                    signal.addEventListener('abort', abort, {once: true});
                })
            });
        }
        function writeTarget() {
            if (kind === 'container') return resolved?.id ? {container: resolved.id} : null;
            if (kind === 'process') return resolved?.pidfd_supported
                ? {pid: resolved.pid, start_time: resolved.start_time} : null;
            return sourceTarget;
        }
        function renderActions() {
            controls.replaceChildren();
            button(t('serverOps.refresh', 'Refresh'), load);
            if (kind !== 'system' && !selected) return;
            if (kind === 'container' && resolved?.id) {
                button(t('serverOps.logs', 'Logs'), () => read('container.logs', {container: resolved.id}));
            }
            if (!capabilities?.mutations_enabled) return;
            if (!writeTarget()) {
                status.textContent = t('serverOps.unsupported', 'Safe control is unavailable for this target. Check remote tool support and permissions.');
                if (kind === 'process') {
                    status.textContent += ' ' + t('serverOps.processManual',
                        'Use the terminal to inspect the process and stop its owning service. Safe process termination here requires Linux pidfds, Python 3 and signal permission.');
                }
                return;
            }
            const actions = kind === 'service' || kind === 'container'
                ? ['start', 'stop', 'restart'] : kind === 'process' ? ['terminate'] : ['reboot'];
            for (const action of actions) {
                const actionButton = button(t(`serverOps.${action}`, action), () => prepare(`${kind}.${action}`));
                actionButton.classList.add(['stop', 'terminate', 'reboot'].includes(action) ? 'server-management-danger' : 'server-management-action');
            }
        }
        function setPending(value) {
            pending = value;
            for (const node of [...tabs.children, ...list.querySelectorAll('button'), ...overview.querySelectorAll('button')]) node.disabled = value || node.dataset.protected === 'true';
        }
        async function read(action, target) {
            if (pending || !current()) return;
            setPending(true);
            sudo.disabled = true;
            const revision = ++generation;
            review.replaceChildren();
            status.textContent = t('serverOps.loading', 'Loading…');
            try {
                const result = await api('/api/server-operations/read', {
                    method: 'POST', body: {session_id: sessionId, action, target, use_sudo: sudo.checked}
                });
                if (!current() || generation !== revision) return;
                outputTitle.textContent = t(action.endsWith('.logs') ? 'serverOps.logs' : 'serverOps.output', action.endsWith('.logs') ? 'Logs' : 'Output');
                output.textContent = [result.output, result.error_output].filter(Boolean).join('\n');
                output.hidden = false;
                output.scrollTop = 0;
                status.textContent = result.status === 'completed' ? t('serverOps.readComplete', 'Read complete.') : t('serverOps.failed', 'Operation failed.');
                if (action === 'container.inspect' || action === 'process.inspect') {
                    resolved = result.status === 'completed' ? JSON.parse(result.output) : null;
                    if (resolved) {
                        output.hidden = true;
                        facts.replaceChildren();
                        const fields = {name: t('serverOps.name', 'Name'), id: t('serverOps.identity', 'Immutable ID'),
                            state: t('serverOps.state', 'State'), image: t('serverOps.image', 'Image'),
                            pid: 'PID', command: t('serverOps.command', 'Command'), start_time: t('serverOps.startTime', 'Process start identity')};
                        for (const [key, label] of Object.entries(fields)) {
                            if (resolved[key] !== undefined) facts.append(el('dt', label), el('dd', String(resolved[key])));
                        }
                    }
                }
            } catch (error) {
                if (current() && generation === revision) status.textContent = error.message;
            } finally {
                setPending(false);
                sudo.disabled = !current();
                if (current() && generation === revision) renderActions();
            }
        }
        async function load() {
            resolved = null;
            if (kind === 'process' && !selected) {
                if (pending || !current()) return;
                const revision = ++generation;
                const restoreTabFocus = tabs.contains(document.activeElement);
                processRows = [];
                setPending(true);
                drawWorkspace();
                status.textContent = t('serverOps.loading', 'Loading…');
                try {
                    const result = await api('/api/server-operations/read', {
                        method: 'POST', body: {session_id: sessionId, action: 'process.list', target: {}, use_sudo: false}
                    });
                    if (!current() || generation !== revision) return;
                    if (result.status !== 'completed' || !Array.isArray(result.processes)) {
                        throw new Error(t('serverOps.failed', 'Operation failed.'));
                    }
                    processRows = result.processes;
                    status.textContent = t('serverOps.readComplete', 'Read complete.');
                } catch (error) {
                    if (current() && generation === revision) status.textContent = error.message;
                } finally {
                    if (current() && generation === revision) {
                        setPending(false);
                        drawWorkspace();
                        renderActions();
                        if (restoreTabFocus && document.activeElement === document.body) {
                            tabs.querySelector('[aria-selected="true"]')?.focus();
                        }
                    }
                }
                return;
            }
            if (kind === 'system' || !selected) {
                window.dispatchEvent(new CustomEvent('server-operation-completed', {detail: {sessionId}}));
                drawWorkspace();
                status.textContent = '';
                renderActions();
                return;
            }
            const action = kind === 'service' ? 'service.logs' : `${kind}.inspect`;
            await read(action, sourceTarget);
        }
        async function prepare(action) {
            if (pending || !current()) return;
            const target = writeTarget();
            if (!target) return;
            setPending(true);
            sudo.disabled = true;
            const revision = ++generation;
            review.replaceChildren();
            try {
                const intent = await api('/api/server-operations/intents', {
                    method: 'POST', body: {session_id: sessionId, action, target, use_sudo: sudo.checked}
                });
                if (!current() || revision !== generation) return;
                review.append(el('p', t('serverOps.review', 'Review the exact command and target. This action may interrupt services or your connection.')));
                review.append(el('pre', intent.command, 'server-operation-output'));
                let confirmation;
                if (intent.confirmation) {
                    const label = el('label', `${t('serverOps.typeHost', 'Type the host to confirm:')} ${intent.confirmation}`);
                    confirmation = el('input', undefined, 'form-control');
                    confirmation.autocomplete = 'off';
                    label.append(confirmation);
                    review.append(label);
                }
                const commit = button(t('serverOps.execute', 'Confirm and execute'), async () => {
                    if (pending || !current() || revision !== generation) return;
                    setPending(true);
                    commit.disabled = true;
                    sudo.disabled = true;
                    let dispatched = false;
                    const controller = new AbortController();
                    authorizationController = controller;
                    const stepUp = createStepUp(revision, controller.signal);
                    try {
                        const grant = await stepUp.authorize('server.operation', intent.intent);
                        if (!grant || !current() || revision !== generation) return;
                        dispatched = true;
                        cancel.disabled = true;
                        const result = await api('/api/server-operations/execute', {
                            method: 'POST', headers: stepUp.header(grant),
                            body: {intent: intent.intent, confirmation: confirmation?.value || ''}
                        });
                        if (!current() || revision !== generation) return;
                        outputTitle.textContent = t('serverOps.output', 'Output');
                        output.textContent = [result.output, result.error_output].filter(Boolean).join('\n');
                        output.hidden = false;
                        const outcome = result.status === 'completed'
                            ? t('serverOps.completed', 'The command completed. Refresh the observed server state.')
                            : result.status === 'requested'
                                ? t('serverOps.requested', 'Reboot requested. A completed reboot has not been verified.')
                                : t('serverOps.failed', 'Operation failed. Inspect the server response.');
                        status.textContent = outcome;
                        window.dispatchEvent(new CustomEvent('server-operation-completed', {detail: {sessionId}}));
                    } catch (error) {
                        if (current() && revision === generation) status.textContent = dispatched && !error.code
                            ? t('serverOps.unknown', 'The outcome is unknown. Inspect the server before trying another action; do not retry automatically.')
                            : error.message;
                    } finally {
                        controller.abort();
                        if (authorizationController === controller) authorizationController = null;
                        if (generation === revision) {
                            setPending(false);
                            review.replaceChildren();
                            sudo.disabled = !current();
                        }
                        // Intent and grant are never retried after execution or uncertainty.
                    }
                }, review);
                if (confirmation) {
                    commit.disabled = true;
                    confirmation.addEventListener('input', () => {
                        commit.disabled = confirmation.value !== intent.confirmation || pending;
                    });
                }
                const cancel = button(t('serverOps.cancel', 'Cancel'), () => {
                    generation++;
                    review.replaceChildren();
                    cancelAuthorization();
                    setPending(false);
                    sudo.disabled = !current();
                }, review);
                review.focus({preventScroll: true});
                main.scrollTop += review.getBoundingClientRect().top - main.getBoundingClientRect().top - 16;
            } catch (error) {
                if (current() && revision === generation) status.textContent = error.message;
            } finally { setPending(false); sudo.disabled = !current(); }
        }
        sudo.addEventListener('change', () => {
            generation++;
            review.replaceChildren();
            controls.replaceChildren();
            resolved = null;
            if (!pending) load();
        });
        window.ModalManager.open(modal);
        drawWorkspace();
        api(`/api/server-operations/${encodeURIComponent(sessionId)}`).then(result => {
            if (!current()) { invalidate(); return; }
            capabilities = result;
            drawWorkspace();
            return load();
        }).catch(error => { if (modal.isConnected) status.textContent = error.message; });
    }
    window.ServerOperations = Object.freeze({open, updateSnapshot});
})();
