/* Gateway prompts are transient and scoped to a locally initiated request. */
(function () {
    'use strict';
    const attempts = new Map();
    let socket;
    let cancelTerminal;
    let modal;
    let content;
    let active = null;
    const t = (key, fallback) => window.i18n?.t(key, fallback) || fallback;
    function element(tag, text) {
        const node = document.createElement(tag);
        if (text !== undefined) node.textContent = text;
        return node;
    }
    function close(id) {
        const attempt = attempts.get(id);
        if (!attempt) return;
        attempt.terminal?.dispose();
        attempt.content?.replaceChildren();
        attempts.delete(id);
        if (active === id) {
            window.ModalManager.close(modal);
            content.replaceChildren();
            active = null;
        }
        if (active === null && !document.getElementById('sshAuthBannerModal')?.classList.contains('show')) {
            const next = [...attempts].find(([, pending]) => pending.content);
            if (next) open(next[0]);
        }
    }
    function cancel() {
        const attempt = attempts.get(active);
        if (!attempt) return;
        const id = active;
        if (!attempt.quick) {
            cancelTerminal(id, cancelled => { if (cancelled) close(id); });
            return;
        }
        socket.emit(attempt.quick ? 'ssh_gateway_quick_cancel' : 'ssh_connect_cancel',
            {client_request_id: id}, result => {
                if (result?.success || result?.reason === 'not_found') {
                    close(id);
                    attempt.onCancel?.();
                }
            });
    }
    function open(id) {
        const attempt = attempts.get(id);
        if (!attempt) return null;
        attempt.content ||= element('div');
        if (active !== id) {
            content.replaceChildren(attempt.content);
            active = id;
        }
        const heading = modal.querySelector('#sshGatewayTitle');
        heading.textContent = attempt.gateway
            ? t('gateway.title', 'Gateway connection') : t('ssh.authentication', 'SSH authentication');
        heading.dataset.i18n = attempt.gateway ? 'gateway.title' : 'ssh.authentication';
        window.ModalManager.open(modal);
        attempt.terminal?.focus();
        attempt.content.querySelector('input, button')?.focus();
        return attempt;
    }
    function appendInstructions(parent, text) {
        // Server text remains text; only explicit HTTP(S) links are clickable.
        const paragraph = element('p');
        paragraph.className = 'gateway-instructions';
        const pieces = String(text).split(/(https?:\/\/[^\s<>"']+)/g);
        for (const piece of pieces) {
            let url;
            try { url = new URL(piece); } catch { /* Plain server text. */ }
            if (url && ['https:', 'http:'].includes(url.protocol) && !url.username && !url.password) {
                const link = element('a', piece);
                link.href = url.href;
                link.target = '_blank';
                link.rel = 'noopener noreferrer';
                paragraph.append(link);
            } else {
                paragraph.append(document.createTextNode(piece));
            }
        }
        parent.append(paragraph);
    }
    function challenge(data) {
        const attempt = open(data?.client_request_id);
        if (!attempt || !Array.isArray(data.prompts) || data.prompts.length > 8) return;
        const content = attempt.content;
        content.replaceChildren();
        const title = element('h3', data.title || (attempt.gateway ? t('gateway.authentication', 'Gateway authentication') : t('ssh.authentication', 'SSH authentication')));
        title.className = 'gateway-challenge-title';
        content.append(title);
        appendInstructions(content, data.instructions || '');
        const form = element('form');
        form.className = 'gateway-challenge-form';
        const inputs = [];
        for (const prompt of data.prompts) {
            const label = element('label', prompt.label || t('gateway.response', 'Response'));
            const input = element('input');
            input.className = 'form-control';
            input.type = 'password';
            input.autocomplete = 'off';
            input.spellcheck = false;
            input.maxLength = 16384;
            label.append(input);
            form.append(label);
            inputs.push(input);
        }
        const submit = element('button', t('gateway.continue', 'Continue'));
        submit.type = 'submit';
        submit.className = 'btn btn-primary';
        form.append(submit);
        form.addEventListener('submit', event => {
            event.preventDefault();
            if (submit.disabled) return;
            const answers = inputs.map(input => input.value);
            if (answers.reduce((total, value) => total + new TextEncoder().encode(value).length, 0) > 16384) return;
            submit.disabled = true;
            socket.emit('ssh_gateway_answer', {
                client_request_id: data.client_request_id,
                challenge_id: data.challenge_id, answers,
            }, result => {
                if (!result?.success && attempts.has(data.client_request_id)) submit.disabled = false;
            });
            inputs.forEach(input => { input.value = ''; });

        });
        content.append(form);
        (inputs[0] || submit).focus();
    }
    function setup(data) {
        const attempt = open(data?.client_request_id);
        if (!attempt || attempt.terminal) return;
        const content = attempt.content;
        content.replaceChildren();
        content.append(element('p', t('gateway.target', 'Waiting for target access. Review gateway prompts below.')));
        const terminalNode = element('div');
        terminalNode.className = 'gateway-terminal';
        content.append(terminalNode);
        const terminal = new window.Terminal({
            cols: 80, rows: 16, scrollback: 200, fontSize: 13,
            convertEol: true, allowProposedApi: false,
        });
        attempt.terminal = terminal;
        terminal.open(terminalNode);
        terminal.onData(value => {
            if (new TextEncoder().encode(value).length <= 1024) {
                socket.emit('ssh_gateway_input', {client_request_id: data.client_request_id, data: value});
            }
        });
        terminal.focus();
    }
    window.SSHGatewayDialog = {
        init(connection, cancelConnection) {
            socket = connection;
            cancelTerminal = cancelConnection;
            modal = element('div');
            modal.id = 'sshGatewayModal';
            modal.className = 'modal gateway-modal';
            modal.setAttribute('role', 'dialog');
            modal.setAttribute('aria-modal', 'true');
            modal.setAttribute('aria-label', t('gateway.title', 'Gateway connection'));
            modal.setAttribute('aria-hidden', 'true');
            const box = element('div');
            box.className = 'modal-content';
            const header = element('div');
            header.className = 'modal-header';
            const heading = element('h2', t('gateway.title', 'Gateway connection'));
            heading.id = 'sshGatewayTitle';
            heading.dataset.i18n = 'gateway.title';
            header.append(heading);
            modal.setAttribute('aria-labelledby', heading.id);
            content = element('div');
            content.className = 'modal-body';
            const footer = element('div');
            footer.className = 'gateway-footer';
            const button = element('button', t('gateway.cancel', 'Cancel connection'));
            button.type = 'button';
            button.className = 'btn btn-secondary';
            button.dataset.i18n = 'gateway.cancel';
            button.addEventListener('click', cancel);
            footer.append(button);
            box.append(header, content, footer);
            modal.append(box);
            document.body.append(modal);
            modal.addEventListener('keydown', event => {
                if (event.key === 'Escape') {
                    event.preventDefault();
                    event.stopPropagation();
                    cancel();
                }
            });
            socket.on('ssh_host_key', data => {
                if (data?.client_request_id === active) window.ModalManager.close(modal);
            });
            socket.on('ssh_auth_banner', data => {
                if (data?.client_request_id === active) {
                    window.ModalManager.close(modal);
                    content.replaceChildren();
                    active = null;
                }
            });
            socket.on('ssh_gateway_challenge', challenge);
            socket.on('ssh_gateway_progress', setup);
            socket.on('ssh_gateway_output', data => {
                const attempt = attempts.get(data?.client_request_id);
                if (!attempt?.terminal || typeof data.data !== 'string') return;
                attempt.terminal.write(data.data, () => socket.emit('ssh_gateway_ack', {
                    client_request_id: data.client_request_id, sequence: data.sequence,
                }));
            });
            for (const event of ['ssh_connected', 'ssh_error', 'quick_connect_success', 'quick_connect_error']) {
                socket.on(event, data => close(data?.client_request_id));
            }
            socket.on('disconnect', () => [...attempts.keys()].forEach(close));
        },
        prepare(payload, quick = false, onCancel = null) {
            const gateway = window.ConnectionValidation.isGateway(payload.username);
            if (!gateway && (quick || payload.username?.includes(':') || payload.auth_type === 'tailscale')) return;
            if (gateway) payload.gateway_interaction = 1;
            else payload.ssh_interaction = 1;
            payload.client_request_id ||= 'gateway_' + window.crypto.randomUUID();
            if (!attempts.has(payload.client_request_id) && attempts.size < 8) {
                attempts.set(payload.client_request_id, {quick, gateway, terminal: null, onCancel});
            }
        },
        has: id => attempts.has(id),
        close,
    };
}());
