(function(root, factory) {
    const api = factory();
    if (typeof module === 'object' && module.exports) module.exports = api;
    if (root) { root.CustomerWorkflows = api; root.addEventListener('load', () => api.init(root), {once: true}); }
}(typeof window === 'undefined' ? null : window, function() {
    'use strict';
    function layoutAssignments(requested, existing, current) {
        const assigned = [...new Set(existing.filter(Boolean))];
        if (assigned.length > 4) throw new RangeError('Too many assigned sessions');
        const needed = [1, 2, 4].find(count => count >= assigned.length);
        const layout = Math.max([1, 2, 4].includes(requested) ? requested : 1,
            [1, 2, 4].includes(current) ? current : needed, needed);
        const slots = current === 'windows' || existing.slice(layout).some(Boolean) ? assigned : existing;
        return {layout, assignments: Array.from({length: layout}, (_, index) => slots[index] || null)};
    }
    function presetId(crypto) {
        if (typeof crypto?.randomUUID === 'function') return crypto.randomUUID();
        // Metadata identifiers carry no authority; HTTP homelabs lack randomUUID.
        return `preset_${Date.now().toString(36)}_${Math.random().toString(36).slice(2)}`;
    }
    function continuityKey(session, transport) {
        if (!session) return 'none';
        if (session.connected && !transport) return 'transport';
        if (session.useTmux) return session.connected ? 'tmux' : 'tmuxDisconnected';
        return session.connected ? 'normal' : 'disconnected';
    }
    function adviceKey(code) {
        if (code === 'PERMISSION_DENIED') return 'permission';
        if (code === 'OUTCOME_UNKNOWN' || code === 'TIMEOUT') return 'unknown';
        if (code === 'CONFLICT' || code === 'SOURCE_CHANGED') return 'conflict';
        if (code === 'SOURCE_UNAVAILABLE' || code === 'SHARE_UNAVAILABLE') return 'source';
        return 'failure';
    }
    function init(root) {
        const sessions = root.SessionManager || (typeof SessionManager === 'undefined' ? null : SessionManager);
        const document = root.document;
        const t = key => root.i18n?.t('customer.' + key) || key;
        const el = (tag, text, className) => { const item = document.createElement(tag); if (text) item.textContent = text; if (className) item.className = className; return item; };
        const button = (text, action) => { const item = el('button', text, 'btn btn-secondary'); item.type='button'; item.addEventListener('click', action); return item; };
        const api = async (path, body, method = 'PUT') => {
            const prefix = document.querySelector('meta[name="app-root"]')?.content || '';
            const response = await root.fetch(prefix + '/api/account/' + path, {
                method: body ? method : 'GET', credentials:'same-origin',
                headers:{'Content-Type':'application/json', 'X-CSRFToken':document.querySelector('meta[name="csrf-token"]')?.content || ''},
                ...(body ? {body:JSON.stringify(body)} : {})
            });
            if (!response.ok) { const error=Error(t('requestFailed')); error.status=response.status; throw error; }
            return response.json();
        };
        function dialog(title) {
            const previous = document.activeElement;
            const modal = el('dialog', '', 'customer-dialog');
            const heading = el('h2', title); heading.id='customerDialogTitle'; modal.setAttribute('aria-labelledby', heading.id);
            modal.append(heading, button(t('close'), () => modal.close()));
            modal.addEventListener('close', () => { modal.remove(); previous?.focus(); }, {once:true});
            document.body.append(modal); modal.showModal(); return modal;
        }
        function report(modal, error) {
            let status=modal.querySelector('[role="alert"]'); if (!status) { status=el('p');status.role='alert';modal.append(status); }
            status.textContent=error.message || t('requestFailed');
        }
        const notice = document.getElementById('restoreRecoveryNotice');
        async function refreshRecoveryNotice() {
            if (!notice) return;
            try { const data=await api('recovery-check'); notice.hidden=data.needs_review !== true; }
            catch { /* Optional guidance must not block normal work. */ }
        }
        async function openRecovery() {
            const modal=dialog(t('recoveryTitle')); modal.append(el('p',t('recoveryHint')));
            const loading=el('p',t('loading'));modal.append(loading);
            try {
                const data=await api('recovery-check'); if (!modal.isConnected) return; loading.remove();
                modal.append(el('h3',t('coverageTitle')),el('p',t('included')),el('p',t('excluded')));
                if(data.restored_at) modal.append(el('p',t('restoredAt')+' '+new Date(data.restored_at).toLocaleString(root.i18n?.getLanguage?.())));
                const list=el('ol');
                for(const key of ['recoveryKeys','recoveryHosts','recoverySchedules','recoveryTest']) list.append(el('li',t(key)));
                modal.append(list);
                for(const host of data.hosts) {
                    const row=el('div','', 'customer-row');
                    const problems=[host.credential==='ready' ? null : t(host.credential),host.route==='missing_jump'?t('missingJump'):null,host.host_key==='review_required'?t('trustReview'):null].filter(Boolean);
                    row.append(el('strong',host.name),el('p',problems.join(' · ') || t('prepared')));
                    if(root.ProfileManager) row.append(button(t('editHost'),()=>{modal.close(); root.document.getElementById('manageProfilesBtn')?.click();root.ProfileManager.openEditor(host.id);}));
                    modal.append(row);
                }
                if(!data.hosts.length) modal.append(el('p',t('noHosts')));
                for(const schedule of data.schedules) modal.append(el('p',schedule.name+' · '+t(schedule.enabled?'scheduleEnabled':'scheduleReview')));
                const schedules=el('a',t('openSchedules'),'btn btn-secondary');schedules.href=(document.querySelector('meta[name="app-root"]')?.content || '')+'/automation#schedules';modal.append(schedules);
                if (data.needs_review && data.restored_at) {
                    const acknowledgement=el('p',t('recoveryReviewHint'));modal.append(acknowledgement);
                    const review=button(t('reviewRecovery'),async()=>{
                        review.disabled=true;
                        try {
                            await api('recovery-check',{restored_at:data.restored_at},'POST');
                            await refreshRecoveryNotice();
                            modal.close();
                        } catch(error) {
                            if (error.status===409) {
                                await refreshRecoveryNotice();
                                report(modal,Error(t('recoveryChanged')));
                                modal.append(button(t('reloadRecovery'),()=>{modal.close();openRecovery();}));
                            } else {review.disabled=false;report(modal,error);}
                        }
                    });
                    review.dataset.reviewRecovery='';modal.append(review);
                }

            }catch(error){loading.remove();report(modal,error);}
        }
        async function openPresets() {
            const modal=dialog(t('presetsTitle'));modal.append(el('p',t('presetsHint')));
            let presets;
            try {presets=(await api('workspace-presets')).presets;}catch(error){report(modal,error);return;}
            if(!modal.isConnected) return;
            const saved=el('div');modal.append(saved);
            async function save(next) { const data=await api('workspace-presets',{presets:next}); presets=data.presets; render(); }
            function render() {
                saved.replaceChildren();
                for(const preset of presets) {
                    const row=el('section','', 'customer-row');row.append(el('h3',preset.name));
                    const choices=el('div'); choices.hidden=true;
                    row.append(button(t('applyLayout'),()=>{
                        const manager=sessions; if(!manager)return;
                        if(manager.windowMode && manager.paneAssignments.filter(Boolean).length>4){report(modal,Error(t('extraWindowLayout')));return;}
                        let next;
                        try { next=layoutAssignments(preset.layout,manager.paneAssignments,manager.layout); }
                        catch { report(modal,Error(t('extraWindowLayout')));return; }
                        manager.applyPaneAssignments(next.layout,next.assignments);
                        document.getElementById('workspaceNavBtn')?.click(); choices.hidden=false;
                    }));
                    for(const id of preset.profile_ids) {
                        const profile=root.ProfileManager?.profiles.find(item=>item.id===id);
                        const connect=button(profile ? t('connect')+' '+profile.name : t('missingHost'),()=>{
                            modal.close(); const manager=sessions;
                            const free=manager?.paneAssignments?.findIndex(item=>!item);
                            root.launchProfileForPane?.(id,free>=0?free:undefined);
                        });connect.disabled=!profile;choices.append(connect);
                    }
                    row.append(choices,button(t('removePreset'),async()=>{try{await save(presets.filter(item=>item.id!==preset.id));}catch(error){report(modal,error);}}));
                    saved.append(row);
                }
            }
            render();
            const form=el('form');const name=el('input');name.required=true;name.maxLength=80;name.id='workspacePresetName';
            const label=el('label',t('presetName'));label.htmlFor=name.id;
            const layout=el('select');layout.id='workspacePresetLayout';const layoutLabel=el('label',t('layout'));layoutLabel.htmlFor=layout.id;
            for(const count of [1,2,4]){const option=el('option',String(count));option.value=String(count);layout.append(option);}layout.value=String([1,2,4].includes(sessions?.layout) ? sessions.layout : [1,2,4].find(count=>count>=(sessions?.paneAssignments?.filter(Boolean).length || 1)) || 4);
            form.append(label,name,layoutLabel,layout);
            const hosts=el('fieldset');hosts.append(el('legend',t('chooseHosts')));
            const current=new Set(sessions?.getAllSessions?.().map(item=>item.profileId));
            for(const profile of root.ProfileManager?.profiles || []) { const label=el('label','', 'customer-choice');const check=el('input');check.type='checkbox';check.value=profile.id;check.checked=current.has(profile.id);label.append(check,document.createTextNode(profile.name));hosts.append(label); }
            form.append(hosts);const submit=el('button',t('savePreset'),'btn btn-primary');submit.type='submit';form.append(submit);modal.append(form);
            form.addEventListener('submit',async event=>{
                event.preventDefault();submit.disabled=true;
                try {
                    const ids=[...hosts.querySelectorAll('input:checked')].map(item=>item.value);
                    if(ids.length>Number(layout.value))throw Error(t('tooManyHosts'));
                    if(presets.length>=12)throw Error(t('presetLimit'));
                    await save([...presets,{id:presetId(root.crypto),name:name.value.trim(),layout:Number(layout.value),profile_ids:ids}]);name.value='';
                }catch(error){report(modal,error);}finally{submit.disabled=false;}
            });
        }
        document.querySelectorAll('[data-workspace-presets]').forEach(item=>item.addEventListener('click',openPresets));
        document.querySelectorAll('[data-recovery-check]').forEach(item=>item.addEventListener('click',openRecovery));
        const status=document.getElementById('workspaceContinuity');
        function renderContinuity() {
            if(!status)return;
            const manager=sessions;const session=manager?.getSession(manager.getWorkspaceSession?.() || manager.getActiveSession?.());
            status.textContent=t('continuity.'+continuityKey(session,root.socket?.connected!==false));
            status.hidden=!session;
        }
        root.addEventListener('session-workspace-change',renderContinuity);root.addEventListener('languageChanged',renderContinuity);
        for(const event of ['connect','disconnect','ssh_disconnected','ssh_session_restored']) root.socket?.on(event,()=>root.setTimeout(renderContinuity,0));
        renderContinuity();
        refreshRecoveryNotice();
    }
    return {layoutAssignments, presetId, continuityKey, adviceKey, init};
}));
