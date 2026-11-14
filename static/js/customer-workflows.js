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
        const layout = Math.max([1, 2, 4].includes(requested) ? requested : 1, needed);
        const slots = current === 'windows' || existing.slice(layout).some(Boolean) ? assigned : existing;
        return {layout, assignments: Array.from({length: layout}, (_, index) => slots[index] || null)};
    }
    function presetId(crypto) {
        if (typeof crypto?.randomUUID === 'function') return crypto.randomUUID();
        // Metadata identifiers carry no authority; HTTP homelabs lack randomUUID.
        return `preset_${Date.now().toString(36)}_${Math.random().toString(36).slice(2)}`;
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
            const header=el('header','','customer-dialog-header');header.append(heading,button(t('close'),()=>modal.close()));modal.body=el('div','','customer-dialog-body');modal.footer=el('footer','','customer-dialog-footer');modal.append(header,modal.body,modal.footer);
            modal.addEventListener('close', () => { modal.remove(); previous?.focus(); }, {once:true});
            document.body.append(modal); modal.showModal(); return modal;
        }
        function report(modal, error) {
            let status=modal.querySelector('[role="alert"]'); if (!status) { status=el('p','','customer-feedback');status.role='alert';modal.body.prepend(status); }
            status.textContent=error.message || t('requestFailed');
            status.tabIndex=-1;status.focus({preventScroll:true});status.scrollIntoView({block:'nearest'});
        }
        const notice = document.getElementById('restoreRecoveryNotice');
        async function refreshRecoveryNotice() {
            if (!notice) return;
            try { const data=await api('recovery-check'); notice.hidden=data.needs_review !== true; }
            catch { /* Optional guidance must not block normal work. */ }
        }
        async function openRecovery() {
            const modal=dialog(t('recoveryTitle')); modal.body.append(el('p',t('recoveryHint'),'customer-intro'));
            const loading=el('p',t('loading'),'customer-muted');loading.role='status';modal.body.append(loading);
            try {
                const data=await api('recovery-check'); if (!modal.isConnected) return; loading.remove();
                const coverage=el('details','','customer-disclosure');coverage.append(el('summary',t('coverageTitle')),el('p',t('included')),el('p',t('excluded')));
                if(data.restored_at) modal.body.append(el('p',t('restoredAt')+' '+new Date(data.restored_at).toLocaleString(root.i18n?.getLanguage?.())));
                const list=el('ol','','customer-checklist');const steps={};
                for(const key of ['recoveryKeys','recoveryHosts','recoverySchedules','recoveryTest']) {const step=el('li');step.append(el('h3',t(key+'Title')),el('p',t(key)));list.append(step);steps[key]=step;}
                modal.body.append(list,coverage);
                for(const host of data.hosts) {
                    const row=el('div','', 'customer-row');
                    const problems=[host.credential==='ready' ? null : t(host.credential),host.route==='missing_jump'?t('missingJump'):null,host.host_key==='review_required'?t('trustReview'):null].filter(Boolean);
                    const content=el('div');content.append(el('strong',host.name),el('p',problems.join(' · ') || t('prepared'),'customer-muted'));row.append(content);
                    if(root.ProfileManager) row.append(button(t('editHost'),()=>{modal.close(); root.document.getElementById('manageProfilesBtn')?.click();root.ProfileManager.openEditor(host.id);}));
                    steps.recoveryHosts.append(row);
                }
                if(!data.hosts.length) steps.recoveryHosts.append(el('p',t('noHosts'),'customer-muted'));
                for(const schedule of data.schedules) {const row=el('div','','customer-row');const content=el('div');content.append(el('strong',schedule.name),el('p',t(schedule.enabled?'scheduleEnabled':'scheduleReview'),'customer-muted'));row.append(content);steps.recoverySchedules.append(row);}
                const schedules=el('a',t('openSchedules'),'btn btn-secondary');schedules.href=(document.querySelector('meta[name="app-root"]')?.content || '')+'/automation#schedules';steps.recoverySchedules.append(schedules);
                if (data.needs_review && data.restored_at) {
                    const acknowledgement=el('p',t('recoveryReviewHint'),'customer-muted');acknowledgement.id='recoveryReviewHint';modal.footer.append(acknowledgement);
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
                                modal.footer.append(button(t('reloadRecovery'),()=>{modal.close();openRecovery();}));
                            } else {review.disabled=false;report(modal,error);}
                        }
                    });
                    review.dataset.reviewRecovery='';review.className='btn btn-primary';review.setAttribute('aria-describedby','recoveryReviewHint');modal.footer.append(review);
                }

            }catch(error){loading.remove();report(modal,error);}
        }
        const picker=document.getElementById('workspaceLayoutPicker');
        const presetOptions=document.getElementById('workspacePresetOptions');
        let savedPresets=[];
        let presetState='idle';
        let presetError=null;
        let presetLoad=null;
        let presetRevision=0;
        function applyPreset(preset) {
            if(!sessions) return false;
            let next;
            try { next=layoutAssignments(preset.layout,sessions.paneAssignments,sessions.layout); }
            catch { throw Error(t('extraWindowLayout')); }
            sessions.applyPaneAssignments(next.layout,next.assignments);
            document.getElementById('workspaceNavBtn')?.click();
            return true;
        }
        function renderPresetOptions() {
            if(!presetOptions) return;
            presetOptions.replaceChildren();
            if(presetState!=='error') {
                for(const preset of savedPresets) {
                    const item=button('',event=>{
                        // Rendering can remove the click target before the outside-click handler runs.
                        event.stopPropagation();
                        try {
                            if(!applyPreset(preset)) return;
                            picker.open=false;
                            picker.querySelector('summary')?.focus();
                        } catch(error) {
                            presetError=error;
                            renderPresetOptions();
                            const alert=presetOptions.querySelector('[role="alert"]');
                            alert?.focus({preventScroll:true});
                            alert?.scrollIntoView({block:'nearest'});
                        }
                    });
                    item.className='tab-row-icon-btn workspace-preset-btn';
                    item.dataset.workspacePresetId=preset.id;
                    item.disabled=presetState==='loading';
                    const icon=el('span','view_quilt','material-icons');icon.setAttribute('aria-hidden','true');
                    item.append(icon,el('span',preset.name,'workspace-preset-name'));
                    presetOptions.append(item);
                }
            }
            if(presetState==='loading' || (presetState==='ready' && !savedPresets.length)) {
                const status=el('p',t(presetState==='loading'?'loading':'noSavedPresets'),'workspace-layout-hint');
                status.role='status';presetOptions.append(status);
            }
            if(presetError) {
                const alert=el('p',presetError.message,'workspace-layout-hint');
                alert.role='alert';alert.tabIndex=-1;presetOptions.append(alert);
            }
            if(presetState==='error') {
                const retry=button(t('retry'),async event=>{
                    event.stopPropagation();
                    try { await loadPresets(); } catch { /* The menu displays the load error. */ }
                    if(picker.open) (presetOptions.querySelector('button:not(:disabled)') || document.getElementById('workspacePresetsBtn'))?.focus();
                });
                retry.className='tab-row-icon-btn';presetOptions.append(retry);
            }
        }
        function loadPresets() {
            if(presetLoad) return presetLoad;
            const revision=presetRevision;
            presetState='loading';presetError=null;renderPresetOptions();
            presetLoad=(async()=>{
                try {
                    const data=await api('workspace-presets');
                    // A completed save takes precedence over an older pending read.
                    if(revision===presetRevision) {savedPresets=data.presets;presetState='ready';}
                    return savedPresets;
                } catch(error) {
                    if(revision!==presetRevision) return savedPresets;
                    presetState='error';presetError=error;throw error;
                } finally {
                    presetLoad=null;
                    if(revision===presetRevision) renderPresetOptions();
                }
            })();
            return presetLoad;
        }
        picker?.addEventListener('toggle',()=>{
            if(picker.open) loadPresets().catch(()=>{ /* The built-in layouts remain available. */ });
        });
        async function openPresets() {
            if(picker?.open){picker.open=false;picker.querySelector('summary')?.focus();}
            const modal=dialog(t('presetsTitle'));modal.body.append(el('p',t('presetsHint'),'customer-intro'));
            const loading=el('p',t('loading'),'customer-muted');loading.role='status';modal.body.append(loading);
            let presets;
            try {presets=await loadPresets();}catch(error){loading.remove();if(modal.isConnected)report(modal,error);return;}
            loading.remove();
            if(!modal.isConnected) return;
            const saved=el('div','','customer-presets');modal.body.append(saved);
            async function save(next) {
                const data=await api('workspace-presets',{presets:next});
                presetRevision++;
                presets=data.presets;savedPresets=presets;presetState='ready';presetError=null;
                renderPresetOptions();render();
            }
            function render() {
                saved.replaceChildren();if(!presets.length)saved.append(el('p',t('noPresets'),'customer-empty'));
                for(const preset of presets) {
                    const row=el('section','', 'customer-row');const info=el('div','','customer-preset-info');info.append(el('h3',preset.name),el('p',t('layout')+': '+preset.layout,'customer-muted'));row.append(info);const actions=el('div','','customer-row-actions');
                    const choices=el('div','','customer-preset-connections'); choices.hidden=true;
                    const apply=button(t('applyLayout'),()=>{
                        try { if(!applyPreset(preset))return; }
                        catch(error) {report(modal,error);return;}
                        choices.hidden=false;apply.setAttribute('aria-expanded','true');
                    });apply.setAttribute('aria-expanded','false');actions.append(apply);
                    for(const id of preset.profile_ids) {
                        const profile=root.ProfileManager?.profiles.find(item=>item.id===id);
                        const connect=button(profile ? t('connect')+' '+profile.name : t('missingHost'),()=>{
                            modal.close(); const manager=sessions;
                            const free=manager?.paneAssignments?.findIndex(item=>!item);
                            root.launchProfileForPane?.(id,free>=0?free:undefined);
                        });connect.disabled=!profile;choices.append(connect);
                    }
                    const remove=button(t('removePreset'),async()=>{remove.disabled=true;try{await save(presets.filter(item=>item.id!==preset.id));}catch(error){remove.disabled=false;report(modal,error);}});remove.classList.add('customer-remove');actions.append(remove);row.append(actions,choices);
                    saved.append(row);
                }
            }
            render();
            const form=el('form','','customer-preset-form');form.id='workspacePresetForm';form.append(el('h3',t('newPreset')));const name=el('input');name.required=true;name.maxLength=80;name.id='workspacePresetName';
            const label=el('label',t('presetName'));label.htmlFor=name.id;
            const layout=el('select');layout.id='workspacePresetLayout';const layoutLabel=el('label',t('layout'));layoutLabel.htmlFor=layout.id;
            for(const count of [1,2,4]){const option=el('option',String(count));option.value=String(count);layout.append(option);}layout.value=String([1,2,4].includes(sessions?.layout) ? sessions.layout : [1,2,4].find(count=>count>=(sessions?.paneAssignments?.filter(Boolean).length || 1)) || 4);
            const fields=el('div','','customer-form-fields');const nameField=el('div');nameField.append(label,name);const layoutField=el('div');layoutField.append(layoutLabel,layout);fields.append(nameField,layoutField);form.append(fields);
            const hosts=el('fieldset');hosts.append(el('legend',t('chooseHosts')));
            const current=new Set(sessions?.getAllSessions?.().map(item=>item.profileId));
            for(const profile of root.ProfileManager?.profiles || []) { const label=el('label','', 'customer-choice');const check=el('input');check.type='checkbox';check.value=profile.id;check.checked=current.has(profile.id);label.append(check,document.createTextNode(profile.name));hosts.append(label); }
            if(!hosts.querySelector('input'))hosts.append(el('p',t('noHosts'),'customer-muted'));form.append(hosts);const submit=el('button',t('savePreset'),'btn btn-primary');submit.type='submit';submit.setAttribute('form',form.id);modal.footer.append(submit);modal.body.append(form);
            form.addEventListener('submit',async event=>{
                event.preventDefault();submit.disabled=true;modal.querySelector('[role=alert]')?.remove();
                try {
                    const ids=[...hosts.querySelectorAll('input:checked')].map(item=>item.value);
                    if(ids.length>Number(layout.value))throw Error(t('tooManyHosts'));
                    if(presets.length>=12)throw Error(t('presetLimit'));
                    await save([...presets,{id:presetId(root.crypto),name:name.value.trim(),layout:Number(layout.value),profile_ids:ids}]);name.value='';let feedback=modal.body.querySelector('.customer-saved');if(!feedback){feedback=el('p','','customer-saved');feedback.role='status';saved.after(feedback);}feedback.textContent=t('presetSaved');
                }catch(error){report(modal,error);}finally{submit.disabled=false;}
            });
        }
        document.querySelectorAll('[data-workspace-presets]').forEach(item=>item.addEventListener('click',openPresets));
        document.querySelectorAll('[data-recovery-check]').forEach(item=>item.addEventListener('click',openRecovery));
        refreshRecoveryNotice();
    }
    return {layoutAssignments, presetId, adviceKey, init};
}));
