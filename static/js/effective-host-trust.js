(function () {
    'use strict';
    const t = (key, fallback) => {
        const value = window.i18n?.t(key);
        return value && value !== key ? value : fallback;
    };
    const node = (tag, text, className) => {
        const element = document.createElement(tag);
        if (text) element.textContent = text;
        if (className) element.className = className;
        return element;
    };
    let generation = 0;
    async function load(api) {
        const container = document.getElementById('effectiveHostTrust');
        if (!container) return;
        const request = ++generation;
        container.replaceChildren(node('p', t('trustFiles.loading', 'Loading effective trust…')));
        try {
            const data = await api('/api/host-keys/effective');
            if (request !== generation) return;
            render(container, data.targets || []);
        } catch {
            if (request === generation) container.replaceChildren(node('p', t('trustFiles.loadFailed', 'Effective trust could not be loaded. Refresh to try again.')));
        }
    }
    function render(container, targets, afterDelete = false) {
        const title = node('h3', afterDelete ? t('trustFiles.afterDelete', 'After deleting this personal entry') : t('trustFiles.effectiveTitle', 'Effective trust for saved SSH targets'));
        const hint = node('p', t('trustFiles.effectiveHint', 'Configuration only; no connection is made. Personal keys take precedence per algorithm. Revocations apply across both sources.'), 'admin-muted');
        const searchLabel = node('label', t('trustFiles.search', 'Search saved targets'));
        const search = node('input', null, 'form-control');
        search.type = 'search';
        searchLabel.append(search);
        const list = node('div');
        const controls = node('div', null, 'admin-toolbar effective-trust-pagination');
        const previous = node('button', t('trustFiles.previous', 'Previous'), 'btn btn-secondary');
        const next = node('button', t('trustFiles.next', 'Next'), 'btn btn-secondary');
        previous.type = next.type = 'button';
        const status = node('span');
        status.setAttribute('role', 'status');
        controls.append(previous, status, next);
        container.replaceChildren(title, hint, searchLabel, list, controls);
        let page = 0;
        const draw = () => {
            const query = search.value.toLowerCase();
            const filtered = targets.filter(target => `${target.name} ${target.host}:${target.port}`.toLowerCase().includes(query));
            const pages = Math.max(1, Math.ceil(filtered.length / 20));
            controls.hidden = pages === 1;
            page = Math.min(page, pages - 1);
            status.textContent = `${page + 1} / ${pages} · ${filtered.length}`;
            previous.disabled = page === 0;
            next.disabled = page + 1 >= pages;
            list.replaceChildren();
            for (const target of filtered.slice(page * 20, (page + 1) * 20)) {
                const details = node('details', null, 'effective-trust-target');
                details.open = afterDelete;
                const summary = node('summary', `${target.name || target.host} · ${target.host}:${target.port}`);
                details.append(summary);
                const keys = target.keys || [];
                if (!keys.some(key => key.status === 'effective')) details.append(node('p', t('trustFiles.noTrust', 'No effective trusted key. A connection still requires host-key verification.')));
                for (const key of keys) {
                    const row = node('div', null, 'effective-trust-key');
                    const source = key.scope === 'user' ? t('trustFiles.personal', 'Personal') : t('trustFiles.global', 'Global');
                    const states = {effective: ['trustFiles.effective', 'Effective'], overridden: ['trustFiles.overridden', 'Overridden'], revoked: ['trustFiles.revoked', 'Revoked']};
                    const state = states[key.status] || ['trustFiles.unknown', 'Unknown'];
                    row.append(node('strong', `${source} · ${t(...state)} · ${key.algorithm}`), node('code', key.fingerprint));
                    details.append(row);
                }
                list.append(details);
            }
            if (!filtered.length) list.append(node('p', afterDelete ? t('trustFiles.noAffectedTargets', 'No matching saved SSH targets. Remaining trust cannot be determined for this entry.') : t('trustFiles.noTargets', 'No matching saved SSH targets. Personal entries remain manageable below.')));
        };
        search.oninput = () => { page = 0; draw(); };
        previous.onclick = () => { page--; draw(); };
        next.onclick = () => { page++; draw(); };
        draw();
    }
    function confirmDeletion(entry, hostLabel, impact) {
        return new Promise(resolve => {
            const opener = document.activeElement;
            const dialog = node('dialog', null, 'trust-deletion-dialog');
            const title = node('h2', t('trustFiles.deleteTitle', 'Review personal host-key deletion'));
            title.id = 'trustDeletionTitle';
            dialog.setAttribute('aria-labelledby', title.id);
            const explanation = node('p', window.WebSSHSecurityUI.hostKeyConfirmation(entry, hostLabel, t));
            const fingerprint = node('code', `${entry.algorithm} · ${entry.fingerprint}`);
            const preview = node('div');
            render(preview, impact.targets || [], true);
            dialog.append(title, explanation, fingerprint, preview);
            if (impact.unresolved) dialog.append(node('p', t('trustFiles.unresolved', 'Other hosts matched by this entry are not saved targets. Their remaining trust is unknown; this includes unmatched aliases, wildcard matches and hashed hosts.')));
            const actions = node('div', null, 'trust-deletion-actions');
            const cancel = node('button', t('common.cancel', 'Cancel'), 'btn btn-secondary');
            const remove = node('button', window.WebSSHSecurityUI.describeHostKey(entry, t).action, 'btn btn-danger');
            cancel.type = remove.type = 'button';
            actions.append(cancel, remove);
            dialog.append(actions);
            let confirmed = false;
            cancel.onclick = () => dialog.close();
            remove.onclick = () => { confirmed = true; dialog.close(); };
            dialog.onclose = () => { dialog.remove(); if (opener?.isConnected) opener.focus(); resolve(confirmed); };
            dialog.addEventListener('keydown', event => event.stopPropagation());
            document.body.append(dialog);
            dialog.showModal();
            cancel.focus();
        });
    }
    window.EffectiveHostTrust = {load, render, confirmDeletion};
}());
