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
        const modal = el('div', undefined, 'modal');
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
        const targetLabel = el('p', `${session.username || ''}@${session.host || ''}:${session.port || 22}`);
        const status = el('p', t('serverOps.loading', 'Loading…'));
        status.setAttribute('role', 'status');
        const output = el('pre', undefined, 'server-operation-output');
        const sudoLabel = el('label', t('serverOps.sudo', 'Use non-interactive sudo (requires remote permission)'));
        const sudo = el('input');
        sudo.type = 'checkbox';
        sudoLabel.prepend(sudo);
        const controls = el('div', undefined, 'form-actions');
        const review = el('section');
        const authentication = el('section');
        body.append(targetLabel, sudoLabel, status, output, controls, review, authentication);
        content.append(header, body);
        modal.append(content);
        document.body.append(modal);
        let generation = 0;
        let pending = false;
        let capabilities = null;
        let resolved = null;
        let answer = null;
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
        async function read(action, target) {
            if (pending || !current()) return;
            pending = true;
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
                status.textContent = result.status === 'completed' ? t('serverOps.readComplete', 'Read complete.') : t('serverOps.failed', 'Operation failed.');
                if (action === 'container.inspect' || action === 'process.inspect') {
                    resolved = result.status === 'completed' ? JSON.parse(result.output) : null;
                }
            } catch (error) {
                if (current() && generation === revision) status.textContent = error.message;
            } finally {
                pending = false;
                sudo.disabled = !current();
                if (current() && generation === revision) renderActions();
            }
        }
        async function load() {
            resolved = null;
            const action = kind === 'service' ? 'service.logs' : `${kind}.inspect`;
            await read(action, sourceTarget);
        }
        async function prepare(action) {
            if (pending || !current()) return;
            const target = writeTarget();
            if (!target) return;
            pending = true;
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
                    pending = true;
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
                        pending = false;
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
            } finally { pending = false; sudo.disabled = !current(); }
        }
        sudo.addEventListener('change', () => {
            generation++;
            review.replaceChildren();
            controls.replaceChildren();
            resolved = null;
            if (!pending) load();
        });
        window.ModalManager.open(modal);
        api(`/api/server-operations/${encodeURIComponent(sessionId)}`).then(result => {
            if (!current()) { invalidate(); return; }
            capabilities = result;
            if (!result.mutations_enabled) {
                body.insertBefore(el('p', t('serverOps.disabled', 'Server mutations are disabled by the operator. Read-only inspection remains available.')), controls);
            }
            return load();
        }).catch(error => { if (modal.isConnected) status.textContent = error.message; });
    }
    window.ServerOperations = Object.freeze({open});
})();
