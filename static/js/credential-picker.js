(function () {
    'use strict';
    const bindings = new Map();
    const t = (key, fallback) => { const value = window.i18n?.t(key); return value && value !== key ? value : fallback; };
    function available(state, id, target) {
        const resource = state?.profiles?.find(item => String(item.id) === String(id));
        const native = state?.enabled && state.credentials?.some(item => item.uses?.some(use => String(use.resource_id || use.id) === String(id) && use.valid !== false));
        const legacy = state?.enabled !== false && state?.vault?.unlocked && state.vault.credentials?.some(item => String(item.profile_id) === String(id) && item.valid === true);
        return Boolean(id && resource && (native || legacy)
            && Object.entries(target).every(([key, value]) => key === 'port'
                ? Number(resource[key] || 22) === Number(value || 22)
                : String(resource[key] || '') === String(value || '')));
    }
    function get(inputId) {
        const binding = bindings.get(inputId);
        if (!binding) return null;
        if (binding.id && (binding.snapshot !== JSON.stringify(binding.target()) || binding.resourceId !== binding.resource())) binding.clear();
        return binding.id || null;
    }
    function clear(inputId) { bindings.get(inputId)?.clear(); }
    function attachInline(input, resource, target, modalId) {
        const method = document.getElementById('authTypeSelect');
        const group = document.createElement('div');
        group.id = 'savedPasswordGroup'; group.className = 'form-group hidden';
        const label = document.createElement('label');
        label.htmlFor = 'savedPasswordSelect'; label.dataset.i18n = 'credentials.savedPassword';
        label.textContent = t('credentials.savedPassword', 'Saved password');
        const select = document.createElement('select'); select.id = 'savedPasswordSelect'; select.className = 'form-control';
        const status = document.createElement('span'); status.setAttribute('role', 'status');
        group.append(label, select, status); document.getElementById('passwordGroup').after(group);
        const modal = document.getElementById(modalId);
        const active = () => method.value === 'saved-password' && (!modal || modal.classList.contains('show'));
        let observedTarget = JSON.stringify(target());
        const binding = {resource, target, id: null, token: null, generation: 0, clear() {
            this.generation++; this.id = null; this.token = null; this.snapshot = null; this.resourceId = null;
            observedTarget = JSON.stringify(target());
            select.value = ''; status.textContent = '';
        }};
        function sync() {
            const saved = method.value === 'saved-password';
            group.classList.toggle('hidden', !saved); select.required = saved;
            input.disabled = saved;
            if (saved) { input.required = false; document.getElementById('passwordGroup').classList.add('hidden'); }
        }
        binding.sync = sync;
        let loadSequence = 0;
        async function load() {
            const generation = ++loadSequence;
            select.disabled = true; status.textContent = t('credentials.loading', 'Loading passwords…');
            try {
                const state = await window.NativeCredentials.load();
                if (generation !== loadSequence) return;
                select.replaceChildren();
                const empty = document.createElement('option'); empty.value = ''; empty.textContent = t('credentials.choosePassword', 'Choose a saved password'); select.append(empty);
                if (!state.enabled) throw new Error(t('credentials.disabled', 'Password storage is disabled by your administrator.'));
                (state.credentials || []).forEach(item => { const option = document.createElement('option'); option.value = item.id; option.textContent = item.name; select.append(option); });
                status.textContent = state.credentials?.length ? '' : t('credentials.empty', 'No passwords found.');
                return state;
            } catch (error) { if (generation === loadSequence) status.textContent = error.message; }
            finally { if (generation === loadSequence) select.disabled = false; }
        }
        binding.restore = async () => {
            binding.clear(); const generation = binding.generation, snapshot = JSON.stringify(target()), id = resource();
            if (!id || input.value || method.value !== 'password') return;
            const state = await load();
            if (generation !== binding.generation || snapshot !== JSON.stringify(target()) || id !== resource() || input.value || !available(state, id, target())) return;
            const credential = state.credentials?.find(item => item.uses?.some(use => String(use.resource_id || use.id) === String(id) && use.valid !== false));
            if (!credential) return;
            method.value = 'saved-password'; window.ProfileManager?.handleAuthTypeChange?.(method.value); sync(); select.value = credential.id;
        };
        binding.resolve = async () => {
            if (!active() || select.disabled || !select.value) throw new Error(t('credentials.choosePassword', 'Choose a saved password'));
            const selected = select.value, snapshot = JSON.stringify(target()), id = resource(), generation = binding.generation;
            const current = () => active() && select.value === selected && snapshot === JSON.stringify(target()) && resource() === id && generation === binding.generation;
            const result = await window.NativeCredentials.authorizeTarget(selected, target(), current);
            if (!current()) throw new DOMException('Cancelled', 'AbortError');
            if (!result?.credential_target_token) throw new Error(t('credentials.failed', 'Passwords could not be saved. Check your authorization and try again.'));
            binding.id = selected; binding.resourceId = id; binding.snapshot = snapshot; binding.token = result.credential_target_token;
            return selected;
        };
        bindings.set(input.id, binding);
        method.addEventListener('change', () => { binding.clear(); sync(); if (method.value === 'saved-password') load(); });
        select.addEventListener('change', () => { binding.generation++; binding.id = null; binding.token = null; });
        const form = input.closest('form');
        const targetFields = new Set(['hostInput', 'portInput', 'usernameInput', 'jumpHostSelect', 'socksProxySelect']);
        const invalidate = event => {
            if (!targetFields.has(event.target.id)) return;
            const nextTarget = JSON.stringify(target());
            if (nextTarget !== observedTarget) { observedTarget = nextTarget; binding.clear(); }
        };
        form?.addEventListener('input', invalidate);
        form?.addEventListener('change', invalidate);
        form?.addEventListener('reset', () => { binding.clear(); queueMicrotask(sync); });
        if (modal) new MutationObserver(() => { if (!modal.classList.contains('show')) binding.clear(); }).observe(modal, {attributes: true, attributeFilter: ['class']});
        sync();
    }
    function attach(inputId, resource, target, modalId) {
        const input = document.getElementById(inputId);
        if (!input || bindings.has(inputId)) return;
        if (inputId === 'passwordInput' && document.getElementById('authTypeSelect')) { attachInline(input, resource, target, modalId); return; }
        const row = document.createElement('div');
        row.className = 'credential-picker-controls';
        const use = document.createElement('button');
        use.type = 'button'; use.className = 'btn btn-secondary btn-sm';
        use.dataset.i18n = 'credentials.use';
        use.textContent = t('credentials.use', 'Use saved password');
        const manual = document.createElement('button');
        manual.type = 'button'; manual.className = 'btn btn-secondary btn-sm'; manual.hidden = true;
        manual.dataset.i18n = 'credentials.manual';
        manual.textContent = t('credentials.manual', 'Enter manually');
        const status = document.createElement('span');
        status.setAttribute('role', 'status');
        row.append(use, manual, status);
        (input.closest('.input-with-icon') || input.parentElement).after(row);
        const required = input.required;
        const binding = { resource, target, id: null, resourceId: null, token: null, snapshot: null, clear() {
            this.generation = (this.generation || 0) + 1; this.id = null; this.resourceId = null; this.token = null; this.snapshot = null;
            input.disabled = false; input.required = required;
            manual.hidden = true; status.textContent = '';
        } };
        binding.restore = async () => {
            binding.clear();
            const id = resource(), snapshot = JSON.stringify(target()), generation = binding.generation;
            if (!id || input.value) return;
            try {
                const state = await window.NativeCredentials.load();
                if (generation !== binding.generation || resource() !== id || JSON.stringify(target()) !== snapshot || input.value || !available(state,id,target())) return;
                input.required = false; input.disabled = true;
                binding.id = id; binding.resourceId = id; binding.snapshot = snapshot;
                manual.hidden = false; status.textContent = t('credentials.selected','Saved password selected');
            } catch { /* Manual authentication remains available when metadata is unavailable. */ }
        };
        bindings.set(inputId, binding);
        input.addEventListener('input', () => binding.clear());
        const form = input.closest('form');
        form?.addEventListener('input', event => { if (event.target !== input) get(inputId); });
        form?.addEventListener('change', event => {
            if (event.target.id === 'authTypeSelect' || event.target.name === 'fmQcAuth') binding.clear();
            else get(inputId);
        });
        form?.addEventListener('reset', () => binding.clear());
        manual.addEventListener('click', () => { binding.clear(); input.value = ''; input.focus(); });
        const modal = document.getElementById(modalId);
        if (modal) new MutationObserver(() => {
            if (!modal.classList.contains('show')) binding.clear();
        }).observe(modal, { attributes: true, attributeFilter: ['class'] });
        use.addEventListener('click', async () => {
            const id = resource();
            const snapshot = JSON.stringify(target());
            use.disabled = true;
            try {
                const selected = await window.NativeCredentials.pick(id, target(), () => resource() === id && JSON.stringify(target()) === snapshot && (!modal || modal.classList.contains('show')));
                if (!selected || resource() !== id || JSON.stringify(target()) !== snapshot) return;
                input.value = ''; input.required = false; input.disabled = true;
                binding.id = selected.id; binding.resourceId = id; binding.token = selected.token; binding.snapshot = snapshot;
                manual.hidden = false; status.textContent = t('credentials.selected', 'Saved password selected');
            } catch (error) { if (error.name !== 'AbortError') status.textContent = error.message; }
            finally { use.disabled = false; use.focus(); }
        });
    }
    const value = id => document.getElementById(id)?.value || '';
    function install() {
        attach('passwordInput', () => window.ProfileManager?.selectedProfileId || null,
            () => ({host: value('hostInput'), port: Number(value('portInput')) || 22, username: value('usernameInput'), auth_type: value('authTypeSelect') === 'saved-password' ? 'password' : value('authTypeSelect') || 'password', jump_host_id: value('jumpHostSelect') || null, socks_proxy_id: value('socksProxySelect') || null}), 'connectionModal');
        attach('socksProxyPasswordInput', () => value('socksProxySelect') ? `socks:${value('socksProxySelect')}` : null,
            () => { const proxy = window.SocksProxyManager?.getById(value('socksProxySelect')); return {host: proxy?.host, port: proxy?.port, username: proxy?.username, auth_type: proxy?.auth_type, remote_dns: proxy?.remote_dns}; }, 'connectionModal');
        attach('jumpHostPasswordInput', () => value('jumpHostSelect') ? `jump:${value('jumpHostSelect')}` : null,
            () => { const jump = window.JumpHostManager?.getById(value('jumpHostSelect')); return {host: jump?.host, port: jump?.port, username: jump?.username}; }, 'connectionModal');
        attach('fmQcPassword', () => value('fmQcProfile') || null,
            () => ({host: value('fmQcHost').trim(), port: Number(value('fmQcPort')) || 22, username: value('fmQcUsername').trim(), auth_type: 'password'}), 'fmQuickConnectModal');
        attach('smbSourcePassword', () => value('smbSourceSaved') ? `smb:${value('smbSourceSaved')}` : null,
            () => ({host: value('smbSourceHost').trim(), username: value('smbSourceUsername').trim(), share: value('smbSourceShare').trim(), domain: value('smbSourceDomain').trim()}), 'smbSourceModal');
    }
    window.CredentialPicker = { sync: inputId => bindings.get(inputId)?.sync?.(), resolve: inputId => bindings.get(inputId)?.resolve?.(), available, get, clear, install, restore: inputId => bindings.get(inputId)?.restore(), token: inputId => { get(inputId); return bindings.get(inputId)?.token || null; } };
    document.addEventListener('DOMContentLoaded', install);
}());
