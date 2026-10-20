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
    const manager = () => typeof SessionManager !== 'undefined' ? SessionManager : window.SessionManager;
    const snapshots = new WeakMap();
    let workspaceSequence = 0;
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
        const modal = el('div', undefined, 'modal server-management');
        modal.setAttribute('role', 'dialog');
        modal.setAttribute('aria-modal', 'true');
        modal.setAttribute('aria-label', t('serverOps.title', 'Server management'));
        const content = el('div', undefined, 'modal-content');
        const header = el('div', undefined, 'modal-header');
        header.append(el('h2', t('serverOps.title', 'Server management')));
        const close = el('button', 'close', 'close material-icons');
        close.setAttribute('aria-label', t('serverOps.close', 'Close'));
        header.append(close);
        const body = el('div', undefined, 'modal-body');
        const targetLabel = el('p', `${session.username || ''}@${session.host || ''}:${session.port || 22}`, 'server-management-host');
        const tabs = el('div', undefined, 'server-management-tabs');
        tabs.setAttribute('role', 'tablist');
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
        const detailTitle = el('h3');
        detailTitle.tabIndex = -1;
        const detailHint = el('p', undefined, 'server-management-hint');
        const facts = el('dl', undefined, 'server-management-facts');
        const notice = el('p', undefined, 'server-management-notice');
        inventory.append(search, filter, list);
        workspace.append(overview, inventory, detail);
        const status = el('p', t('serverOps.loading', 'Loading…'));
        status.setAttribute('role', 'status');
        const output = el('pre', undefined, 'server-operation-output');
        output.hidden = true;
        const sudoLabel = el('label', t('serverOps.sudo', 'Use non-interactive sudo (requires remote permission)'));
        const sudo = el('input');
        sudo.type = 'checkbox';
        sudoLabel.prepend(sudo);
        const controls = el('div', undefined, 'form-actions');
        const review = el('section');
        const authentication = el('section');
        detail.append(detailTitle, detailHint, facts, sudoLabel, controls, status, output, review, authentication);
        body.append(targetLabel, tabs, notice, workspace);
        content.append(header, body);
        modal.append(content);
        document.body.append(modal);
        let generation = 0;
        let pending = false;
        let capabilities = null;
        let resolved = null;
        let answer = null;
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
            sudoLabel.hidden = kind === 'system' && !capabilities?.mutations_enabled;
            overview.hidden = kind !== 'system';
            inventory.hidden = kind === 'system';
            filter.hidden = kind === 'process';
            detailTitle.textContent = kind === 'system' ? t('serverOps.hostActions', 'Host actions')
                : selected ? String(sourceTarget.unit || sourceTarget.name || sourceTarget.pid || '') : labels[kind];
            detailHint.textContent = kind === 'process'
                ? t('serverOps.processScope', 'Showing sampled top CPU and memory processes. Select a process to inspect its identity before control.')
                : selected ? t('serverOps.targetDetail', 'Inspect the selected resource and review an action before executing it.')
                    : kind === 'system' ? ''
                        : t('serverOps.selectResource', 'Select a resource to view details and available actions.');
            notice.textContent = [model?.status, model?.inventory?.stale ? t('serverOps.staleInventory', 'Inventory is out of date. Refresh before choosing a target.') : '',
                ...(model?.permissionNotices || []), capabilities && !capabilities.mutations_enabled
                    ? t('serverOps.disabled', 'Server mutations are disabled by the operator. Read-only inspection remains available.') : ''].filter(Boolean).join(' · ');
            overview.replaceChildren();
            const cards = el('div', undefined, 'server-management-cards');
            for (const [key, label] of [['cpu', 'CPU'], ['memory', t('diagnostics.memory', 'Memory')], ['disk', t('diagnostics.rootDisk', 'Root disk')], ['load', t('diagnostics.normalizedLoad', 'Normalized load')]]) {
                const value = model?.resources?.[key];
                const card = el('article', undefined, 'server-management-card');
                card.append(el('span', label), el('strong', value?.label || '—'), el('small', value?.detail || t('serverOps.noMeasurements', 'Waiting for measurements')));
                cards.append(card);
            }
            overview.append(cards, el('p', [model?.os, model?.secondary?.uptime].filter(Boolean).join(' · ')));
            const counts = el('div', undefined, 'server-management-counts');
            for (const [label, value] of [[labels.service, model?.systemd?.total], [labels.container, model?.docker?.total],
                [labels.process, model?.secondary?.processTotal], [t('serverOps.received', 'Received'), model?.secondary?.received],
                [t('serverOps.transmitted', 'Transmitted'), model?.secondary?.transmitted]]) {
                counts.append(el('span', `${label}: ${value ?? '—'}`));
            }
            overview.append(counts);
            for (const finding of model?.findings || []) overview.append(el('p', finding.text, 'server-management-hint'));
            list.replaceChildren();
            let rows = kind === 'service' ? model?.systemd?.rows : kind === 'container' ? model?.docker?.rows
                : [...(model?.processes?.topCpu || []).map(row => ({...row, metric: 'CPU'})),
                    ...(model?.processes?.topMemory || []).map(row => ({...row, metric: t('diagnostics.memory', 'Memory')}))]
                    .filter((row, index, all) => all.findIndex(other => other.pid === row.pid) === index);
            rows = [...(rows || [])];
            if (kind === 'service') {
                const rank = row => row.active === 'failed' ? 0 : row.active === 'active' ? 1 : 2;
                rows.sort((a, b) => rank(a) - rank(b) || a.unit.localeCompare(b.unit));
            } else if (kind === 'container') {
                const rank = row => /^(up\b|running$)/i.test(row.status) ? 0 : 1;
                rows.sort((a, b) => rank(a) - rank(b) || a.name.localeCompare(b.name));
            }
            const query = search.value.trim().toLowerCase();
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
                    el('small', row.description || (row.pid ? `${row.metric}: ${row.label || `${row.percent ?? '—'}%`}` : '')));
                rowButton.setAttribute('aria-pressed', String(selected && (sourceTarget.unit === row.unit && !!row.unit || sourceTarget.name === row.name && !!row.name || Number(sourceTarget.pid) === Number(row.pid) && !!row.pid)));
            }
            if (!list.children.length) list.append(el('p', rows.length ? t('serverOps.noMatches', 'No matching resources.')
                : t('serverOps.noInventory', 'No inventory available. The remote tool may be unsupported, access may be restricted, or sampling is still in progress.')));
            const truncation = kind === 'service' ? model?.systemd?.truncationLabel : model?.docker?.truncationLabel;
            if (truncation) list.append(el('p', truncation));
            for (const node of list.querySelectorAll('button')) node.disabled = pending;
        }
        function select(nextKind, target) {
            if (pending || !current()) return;
            generation++;
            if (answer) { answer(null); answer = null; authentication.replaceChildren(); }
            kind = nextKind;
            sourceTarget = target || {};
            selected = !!target;
            resolved = null;
            search.value = '';
            filter.value = 'all';
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
            const tab = button(label, () => select(key), tabs);
            tab.dataset.kind = key;
            tab.id = `${workspaceId}-${key}`;
            tab.setAttribute('role', 'tab');
            tab.setAttribute('aria-controls', workspaceId);
            tab.addEventListener('keydown', event => {
                const available = Array.from(tabs.children).filter(node => !node.disabled);
                const index = available.indexOf(tab);
                const offset = event.key === 'ArrowRight' ? 1 : event.key === 'ArrowLeft' ? -1 : 0;
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
            if (event.detail?.sessionId === sessionId && current() && !list.contains(document.activeElement)) drawWorkspace();
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
            if (answer) { answer(null); answer = null; authentication.replaceChildren(); }
        }
        const dismiss = () => {
            generation++;
            if (answer) answer(null);
            window.removeEventListener('session-workspace-change', invalidate);
            window.removeEventListener('session-removed', invalidate);
            window.removeEventListener('server-management-snapshot', onSnapshot);
            document.removeEventListener('keydown', escape, true);
            window.ModalManager.close(modal);
            modal.remove();
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
        const stepUp = window.WebSSHSecurityUI.createAccountStepUpClient({
            api: async (...args) => {
                if (!current()) throw new Error(t('serverOps.targetChanged', 'The active session changed.'));
                return api(...args);
            },
            chooseMethod: (methods, preferred) => question(preferred, methods),
            requestSecret: method => question(method),
            getPasskeyAssertion: options => navigator.credentials.get({
                publicKey: {
                    ...options, challenge: bytes(options.challenge),
                    allowCredentials: (options.allowCredentials || []).map(item => ({...item, id: bytes(item.id)}))
                }
            }),
            serializeCredential: credentialJSON,
            openAuthorization: url => {
                if (!window.open(url, 'webssh-server-step-up', 'popup,width=720,height=760')) {
                    throw new Error(t('serverOps.popup', 'Allow the authentication popup and try again.'));
                }
            }
        });
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
                button(t(`serverOps.${action}`, action), () => prepare(`${kind}.${action}`));
            }
        }
        function setPending(value) {
            pending = value;
            for (const node of [...tabs.children, ...list.querySelectorAll('button')]) node.disabled = value;
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
                output.textContent = [result.output, result.error_output].filter(Boolean).join('\n');
                output.hidden = false;
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
                        setPending(false);
                        review.replaceChildren();
                        sudo.disabled = !current();
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
                    if (answer) { answer(null); answer = null; authentication.replaceChildren(); }
                }, review);
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
