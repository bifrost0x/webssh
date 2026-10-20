(function () {
    'use strict';
    window.SSHHostTrust = {
        init(socket, isExpected) {
            const modal = document.getElementById('sshHostKeyModal');
            let pending = null;
            const close = () => {
                pending = null;
                window.ModalManager.close(modal);
            };
            const answer = accepted => {
                if (!pending) return;
                socket.emit('ssh_host_key_decision', {
                    prompt_id: pending.prompt_id,
                    client_request_id: pending.client_request_id,
                    accepted: accepted === true && isExpected(pending.client_request_id),
                });
                close();
            };
            socket.on('ssh_host_key', data => {
                if (!data || typeof data.prompt_id !== 'string' || typeof data.fingerprint !== 'string') return;
                if (!isExpected(data.client_request_id) || pending) {
                    socket.emit('ssh_host_key_decision', {
                        prompt_id: data.prompt_id, client_request_id: data.client_request_id, accepted: false,
                    });
                    return;
                }
                pending = data;
                const contextKey = data.context === 'jump_host' ? 'connection.authBannerJumpHost' : 'connection.authBannerTarget';
                const label = window.i18n ? window.i18n.t(contextKey) : (data.context === 'jump_host' ? 'Jump host' : 'Target host');
                document.getElementById('sshHostKeyTarget').textContent = `${label}: ${data.host}:${data.port}`;
                document.getElementById('sshHostKeyFingerprint').textContent = `${data.key_type}\n${data.fingerprint}`;
                window.ModalManager.open(modal);
            });
            socket.on('ssh_host_key_closed', data => {
                if (pending?.prompt_id === data?.prompt_id) close();
            });
            for (const event of ['ssh_error', 'ssh_connected']) {
                socket.on(event, data => {
                    if (pending?.client_request_id === data?.client_request_id) close();
                });
            }
            socket.on('disconnect', close);
            document.getElementById('sshHostKeyCancel').addEventListener('click', () => answer(false));
            document.getElementById('sshHostKeyAccept').addEventListener('click', () => answer(true));
            modal.addEventListener('click', event => {
                if (event.target !== modal) return;
                event.stopPropagation();
                answer(false);
            });
            modal.addEventListener('keydown', event => {
                if (event.key === 'Escape') {
                    event.preventDefault();
                    event.stopPropagation();
                    answer(false);
                }
            });
        },
    };
})();
