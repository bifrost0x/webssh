(function () {
    'use strict';
    // Calendar controls translate to cron; the server remains the authority for due times and DST.
    const scheduleBuilder = {
        cron({frequency, time = '09:00', minute = '0', weekday = '1', monthday = '1', custom = ''}) {
            const integer = (value, min, max) => /^\d+$/.test(String(value)) && Number(value) >= min && Number(value) <= max;
            if (frequency === 'custom') return custom;
            if (frequency === 'hourly') return integer(minute, 0, 59) ? `${Number(minute)} * * * *` : null;
            if (!/^\d{2}:\d{2}$/.test(time)) return null;
            const [hour, min] = time.split(':');
            if (!integer(hour, 0, 23) || !integer(min, 0, 59)) return null;
            const clock = `${Number(min)} ${Number(hour)}`;
            if (frequency === 'daily') return clock + ' * * *';
            if (frequency === 'weekdays') return clock + ' * * 1-5';
            if (frequency === 'weekly' && integer(weekday, 0, 6)) return clock + ' * * ' + Number(weekday);
            if (frequency === 'monthly' && integer(monthday, 1, 31)) return clock + ' ' + Number(monthday) + ' * *';
            return null;
        },
        parse(expression) {
            const custom = {frequency:'custom', custom:expression};
            const fields = expression.trim().split(/\s+/);
            if (fields.length !== 5) return custom;
            const [minute, hour, day, month, weekday] = fields;
            const time = hour.padStart(2,'0') + ':' + minute.padStart(2,'0');
            const candidate = {time, minute, weekday, monthday:day};
            if (hour === '*' && day === '*' && month === '*' && weekday === '*') candidate.frequency = 'hourly';
            else if (day === '*' && month === '*' && weekday === '*') candidate.frequency = 'daily';
            else if (day === '*' && month === '*' && weekday === '1-5') candidate.frequency = 'weekdays';
            else if (day === '*' && month === '*') candidate.frequency = 'weekly';
            else if (month === '*' && weekday === '*') candidate.frequency = 'monthly';
            // Recognize only exact canonical expressions, leaving all advanced semantics untouched.
            return this.cron(candidate) === expression ? candidate : custom;
        }
    };
    window.AutomationSchedule = scheduleBuilder;
    const $ = id => document.getElementById(id);
    if (!document.getElementById('automationApp')) return;
    const nativeCredentials = !!document.querySelector('main[data-native-automation]');
    const stepDetails = new WeakMap();
    const tr = (key, values) => window.AutomationText.t(key, values);
    const node = (tag, text, className) => {
        const element = document.createElement(tag);
        if (text !== undefined) element.textContent = text;
        if (className) element.className = className;
        return element;
    };
    let model = {runbooks: [], profiles: [], vault: {exists: false, unlocked: false, credentials: []}};
    let selectedId = null;
    let dirty = false;
    let editRevision = 0;
    let lastStateRefresh = 0;
    let preview = null;
    let busy = false;
    let polling = false;
    let historySignature = '';
    let runsStale = false;
    let knownRuns = [];
    let knownSchedules = [];
    let runsLoaded = false;
    let runsEnabled = document.querySelector('main[data-native-automation]')?.dataset.automationEnabled === 'true'
        || document.body.dataset.automationEnabled === 'true';
    function getRunSnapshot() {
        return {enabled: runsEnabled, loaded: runsLoaded, stale: runsStale, runs: knownRuns.map(run => {
            const steps = run.targets.flatMap(target => target.steps || []);
            const confirmed = run.status === 'succeeded' && run.targets.length > 0 && steps.length > 0
                && run.targets.every(target => target.status === 'succeeded' && target.steps?.length > 0)
                && steps.every(step => step.status === 'succeeded' && step.exit_code === 0);
            const outcome = confirmed ? 'succeeded' : run.status === 'failed' ? 'failed'
                : ['unknown', 'succeeded'].includes(run.status) ? 'unknown' : 'other';
            return {id: run.id, name: run.name, created_at: run.created_at, status: run.status,
                outcome, targetIds: run.targets.map(target => target.id).filter(Boolean)};
        }), schedules: knownSchedules.map(schedule => ({id: schedule.id, name: schedule.name, enabled: schedule.enabled === true,
            last_status: schedule.last_status || null, next_due: schedule.next_due || null}))};
    }
    function publishRunSnapshot() {
        window.dispatchEvent(new CustomEvent('automation-runs-updated', {detail: getRunSnapshot()}));
    }
    let promptResolve = null;
    let selectedTab = 'runbooks';
    let fieldSequence = 0;
    let authorizationGeneration = 0;
    let stateRequestSequence = 0;
    let currentAuthorization = null;
    function assertAuthorizationCurrent(generation) {
        if (generation !== authorizationGeneration) throw new DOMException('Cancelled', 'AbortError');
    }
    const errors = new Set(['disabled', 'https_required', 'authentication_required', 'busy', 'vault_locked',
        'vault_missing', 'vault_unlock_failed', 'vault_exists', 'vault_unreadable', 'credential_missing',
        'invalid_passphrase', 'invalid_runbook', 'invalid_request', 'invalid_targets', 'unsupported_target',
        'key_unavailable', 'preview_changed', 'invalid_intent', 'confirmation_required', 'step_up_required',
        'invalid_schedule', 'storage_limit', 'storage_unavailable', 'not_found', 'acknowledgement_required', 'unavailable',
        'credentials_disabled', 'credential_target_changed', 'host_key_required', 'cancelled', 'run_active']);
    function notify(message, error = false) {
        const target = $(error ? 'automationError' : 'automationNotice');
        target.textContent = message;
        target.hidden = !message;
    }
    let scheduleHome;
    function availability(enabled) {
        $('automationApp').hidden = !enabled;
        $('automationDisabled').hidden = enabled;
        const schedules = $('auto-schedules');
        if (schedules) {
            if (!scheduleHome) { scheduleHome = document.createComment('schedule section'); schedules.before(scheduleHome); }
            if (enabled) { scheduleHome.after(schedules); schedules.hidden = selectedTab !== 'schedules'; }
            else { $('automationDisabled').append(schedules); schedules.hidden = false; }
        }
    }
    async function api(path, options = {}) {
        const root = document.querySelector('meta[name="app-root"]')?.content || '';
        const response = await fetch(root + path, {credentials: 'same-origin', cache: 'no-store', ...options,
            headers: {'Content-Type': 'application/json',
                'X-CSRFToken': document.querySelector('meta[name="csrf-token"]')?.content || '', ...options.headers},
            ...(options.body ? {body: JSON.stringify(options.body)} : {})});
        let data;
        try { data = await response.json(); } catch { throw new Error(tr('requestFailed')); }
        if (!response.ok) {
            if (data.code === 'disabled') availability(false);
            if (['disabled', 'authentication_required'].includes(data.code)) {
                authorizationGeneration += 1;
                stateRequestSequence += 1;
                currentAuthorization?.controller.abort();
                currentAuthorization?.popup?.close();
                preview = null;
                schedulePreview = null;
                model = {...model, profiles: [], vault: {credentials: [], unlocked: false}};
                renderTargets();
                $('runPreview').close();
                $('scheduleReview')?.close();
            }
            // Never fall back to an unexplained message: an unmapped code is
            // still shown so the user or an administrator can act on it.
            const hosts = Array.isArray(data.hosts) ? data.hosts.filter(name => typeof name === 'string').slice(0, 5).join(', ') : '';
            const message = errors.has(data.code) ? tr(`error.${data.code}`, {hosts: hosts || tr('hostsSelected')})
                : typeof data.code === 'string' && /^[a-z_]{1,64}$/.test(data.code) ? tr('requestFailedCode', {code: data.code})
                    : tr('requestFailed');
            const error = new Error(message);
            error.code = data.code;
            throw error;
        }
        return data;
    }
    async function action(task, {automationPreviewError = false} = {}) {
        if (busy) return;
        busy = true;
        notify('', true);
        notify('');
        const controls = [...document.querySelectorAll('#automationApp button[type="submit"], .automation-dialog button[type="submit"], #previewRun, #reviewWorkspace, #scheduleList button, #openSchedule, #runbookList button, #newRunbook, #inventoryTemplate, #useWorkflowTemplate')];
        controls.forEach(button => { button.disabled = true; });
        document.body.setAttribute('aria-busy', 'true');
        try { await task(); } catch (error) {
            if (error.name !== 'AbortError') {
                if (automationPreviewError && $('runPreview').open) {
                    $('automationPreviewError').textContent = error.message;
                    $('automationPreviewError').hidden = false;
                } else notify(error.message, true);
            }
        } finally {
            busy = false;
            controls.forEach(button => { button.disabled = false; });
            document.body.removeAttribute('aria-busy');
        }
    }
    function translate() {
        document.querySelectorAll('[data-auto-i18n]').forEach(element => { element.textContent = tr(element.dataset.autoI18n); });
        document.querySelectorAll('[data-auto-placeholder]').forEach(element => { element.placeholder = tr(element.dataset.autoPlaceholder); });
        const language = window.i18n?.getLanguage() === 'de' ? 'de' : 'en';
        document.querySelectorAll('main[data-native-automation], .automation-dialog').forEach(element => {
            element.lang = language;
        });
        updateSectionHint();
        renderTemplates();
    }
    function selectedTemplate(value = $('workflowTemplate')?.value || '') {
        if (!value.startsWith('set:')) return window.AutomationTemplates?.create(value);
        const set = window.CommandSetManager?.commandSets.find(item => item.id === value.slice(4));
        if (!set) return null;
        return {title:{en:set.name,de:set.name}, requires:{en:set.description || '',de:set.description || ''}, writes:true, commandSet:set,
            steps:[{name:set.name, command:set.resolved_command || '', timeout:30, sudo:false}]};
    }
    function renderTemplates() {
        const select = $('workflowTemplate');
        if (!select || !window.AutomationTemplates) return;
        const previous = select.value;
        const language = window.i18n?.getLanguage() === 'de' ? 'de' : 'en';
        select.replaceChildren();
        const groups = {};
        window.AutomationTemplates.list().forEach(template => {
            if (!groups[template.group]) {
                const group = node('optgroup');
                const labelKey = 'templateGroup' + template.group[0].toUpperCase() + template.group.slice(1);
                group.label = tr(labelKey);
                groups[template.group] = group; select.append(group);
            }
            const option = node('option', template.title[language]); option.value = template.id;
            groups[template.group].append(option);
        });
        const sets = window.CommandSetManager?.commandSets || [];
        if (sets.length) {
            const group = node('optgroup'); group.label = tr('ownCommandSets');
            sets.forEach(set => { const option = node('option', set.name); option.value = 'set:' + set.id; group.append(option); });
            select.append(group);
        }
        if (previous && ![...select.options].some(option => option.value === previous)) {
            const missing=node('option',tr('commandSetUnavailable')); missing.value=previous; missing.disabled=true; select.append(missing);
        }
        if (previous) select.value = previous;
        previewTemplate();
        renderEditorSources();
    }
    function previewTemplate() {
        const template = selectedTemplate();
        if (!template) { $('workflowTemplateEffect').textContent=tr('commandSetUnavailable'); $('workflowTemplateRequirements').textContent=''; $('workflowTemplateSteps').replaceChildren(); return; }
        const language = window.i18n?.getLanguage() === 'de' ? 'de' : 'en';
        $('workflowTemplateEffect').textContent = tr(template.commandSet ? 'commandSetCopy' : template.writes ? 'templateChanges' : 'templateReadOnly');
        $('workflowTemplateEffect').dataset.writes = String(template.writes);
        $('workflowTemplateRequirements').textContent = template.commandSet ? tr('commandSetCopyHint') + ' ' + template.requires[language] : template.requires[language];
        $('workflowTemplateSteps').replaceChildren(...template.steps.map(step => node('li', step.name)));
    }
    async function resolveSource(template) {
        if (template.commandSet) {
            const set = template.commandSet;
            let command = set.resolved_command;
            if (set.parameters?.length) {
                const values = {};
                for (const parameter of set.parameters) {
                    const value = await question(parameter.name, tr('commandSetParameterHint'));
                    if (value === null) return false;
                    values[parameter.name] = value;
                }
                const response = await new Promise(resolve => {
                    if (!window.socket?.connected) return resolve(null);
                    window.socket.timeout(10000).emit('resolve_command_set_parameters', {command_set_id:set.id,values,use_sudo:set.use_sudo === true}, (error, result) => resolve(error ? null : result));
                });
                if (!response?.success) throw new Error(tr('commandSetUnavailable'));
                command = response.resolved_command;
            } else if (set.resolution_error) throw new Error(tr('commandSetUnavailable'));
            if (typeof command !== 'string' || !command.trim() || new TextEncoder().encode(command).length > 8192) throw new Error(tr('commandSetUnavailable'));
            template.steps[0].command = command;
        }
        return true;
    }
    function editorSource() {
        const value = $('editorSource')?.value || '';
        if (!value) return null;
        if (!value.startsWith('command:')) return selectedTemplate(value);
        const command = window.CommandLibrary?.commands.find(item => String(item.id) === value.slice(8));
        if (!command) return null;
        return {steps:[{name:command.name, command:command.command + (command.parameters ? ' ' + command.parameters : ''), timeout:30, sudo:false}], libraryCommand:command, requires:{en:command.description || '',de:command.description || ''}};
    }
    function previewEditorSource() {
        const mount = $('editorSourcePreview');
        if (!mount) return;
        const source = editorSource();
        mount.replaceChildren();
        $('addEditorSource').disabled = !source;
        if (!source) return;
        const language = window.i18n?.getLanguage() === 'de' ? 'de' : 'en';
        mount.append(node('p',source.commandSet ? tr('commandSetCopyHint') : source.requires?.[language] || tr('commandCopyHint'),'automation-hint'));
        const list=node('ol');
        source.steps.forEach(step=>{const item=node('li');item.append(node('strong',step.name),node('code',step.command));list.append(item);});
        mount.append(list);motion(mount);
    }
    function renderEditorSources() {
        const select=$('editorSource');if(!select)return;
        const previous=select.value, language=window.i18n?.getLanguage()==='de'?'de':'en';
        const placeholder=node('option',tr('editorSourceChoose'));placeholder.value='';select.replaceChildren(placeholder);
        const groups=[
            [tr('editorSourceCommands'),(window.CommandLibrary?.commands || []).map(c=>({id:'command:'+c.id,name:c.name}))],
            [tr('ownCommandSets'),(window.CommandSetManager?.commandSets || []).map(c=>({id:'set:'+c.id,name:c.name}))],
            [tr('editorSourceTemplates'),(window.AutomationTemplates?.list() || []).map(c=>({id:c.id,name:c.title[language]}))]
        ];
        groups.forEach(([label,items])=>{if(!items.length)return;const group=node('optgroup');group.label=label;items.forEach(item=>{const option=node('option',item.name);option.value=item.id;group.append(option);});select.append(group);});
        if([...select.options].some(option=>option.value===previous))select.value=previous;
        previewEditorSource();
    }
    function updateSectionHint() {
        if ($('automationSectionHint')) $('automationSectionHint').textContent = tr(`sectionHint.${['library', 'runs', 'schedules'].includes(selectedTab) ? selectedTab : 'runbooks'}`);
    }
    function tab(name) {
        if (!['library', 'runbooks', 'runs', 'schedules', 'credentials'].includes(name)) name = $('auto-library') ? 'library' : 'runbooks';
        if (nativeCredentials && name === 'credentials') { window.dispatchEvent(new CustomEvent('webssh:credentials')); return; }
        selectedTab = name;
        updateSectionHint();
        $('workspaceViews').hidden = name !== 'runbooks';
        document.querySelectorAll('[data-auto-tab]').forEach(button => {
            if (button.dataset.autoTab === name) button.setAttribute('aria-current', 'page');
            else button.removeAttribute('aria-current');
        });
        ['library', 'runbooks', 'runs', 'schedules', 'credentials'].forEach(key => { if ($(`auto-${key}`)) $(`auto-${key}`).hidden = key !== name; });
        const panel = $(`auto-${name}`);
        if (panel && !window.matchMedia('(prefers-reduced-motion: reduce)').matches) {
            panel.getAnimations?.().forEach(animation => animation.cancel());
            panel.animate?.([{opacity:.5,transform:'translateY(10px)'},{opacity:1,transform:'translateY(0)'}],{duration:220,easing:'cubic-bezier(.16,1,.3,1)'});
        }
        if (!document.getElementById('automationNativeView')) history.replaceState(null, '', `#${name}`);
        if (name === 'runs') action(loadRuns);
        if (name === 'schedules') action(loadSchedules);
    }
    function iconButton(icon, label, callback) {
        const button = node('button', undefined, 'automation-icon-button');
        button.type = 'button';
        button.title = label;
        button.setAttribute('aria-label', label);
        const glyph = node('span', icon, 'material-icons');
        glyph.setAttribute('aria-hidden', 'true');
        button.append(glyph);
        button.addEventListener('click', callback);
        return button;
    }
    function motion(row, direction = 1) {
        if (!window.matchMedia('(prefers-reduced-motion: reduce)').matches && row.animate) {
            row.animate([{transform: `translateY(${direction * 12}px)`, opacity: .65}, {transform: 'translateY(0)', opacity: 1}], {duration:260, easing:'cubic-bezier(.16,1,.3,1)'});
        }
    }
    function setStage(name, {focus = false, animate = true} = {}) {
        const workspace = $('auto-runbooks'), stages = ['editor', 'targets', 'schedule'];
        const previous = workspace.dataset.view || 'editor';
        const panels = [document.querySelector('.automation-editor'), document.querySelector('.automation-target-section'), $('automationScheduleInspector')];
        workspace.dataset.view = name;
        workspace.dataset.inspector = name === 'editor' ? 'step' : name;
        if (nativeCredentials) panels.forEach((panel, index) => {
            panel.getAnimations?.().forEach(animation => animation.cancel());
            panel.hidden = stages[index] !== name;
            panel.inert = panel.hidden;
        });
        document.querySelectorAll('[data-workspace-view]').forEach(button => button.setAttribute('aria-pressed', String(button.dataset.workspaceView === name)));
        $('openSchedule')?.setAttribute('aria-pressed', String(name === 'schedule'));
        if ($('automationStageHint')) {
            $('automationStageHint').textContent = tr(`stageHint.${name}`);
            $('previousStage').hidden = name === 'editor';
            $('nextStage').hidden = name === 'schedule';
            $('nextStage').textContent = tr(name === 'editor' ? 'nextTargets' : 'nextSchedule');
            $('reviewWorkspace').hidden = name !== 'targets';
        }
        updateReviewAction();
        const panel = panels[stages.indexOf(name)];
        if (nativeCredentials && animate && previous !== name && panel.animate) {
            const reduced = window.matchMedia('(prefers-reduced-motion: reduce)').matches;
            const direction = stages.indexOf(name) > stages.indexOf(previous) ? 1 : -1;
            panel.animate(reduced ? [{opacity:.7}, {opacity:1}] : [
                {transform:'translateX(' + direction * 28 + 'px)', opacity:.65, filter:'blur(2px)'},
                {transform:'translateX(0)', opacity:1, filter:'blur(0)'}
            ], {duration:reduced ? 0 : 360, easing:'cubic-bezier(.16,1,.3,1)'});
        }
        if (focus || panels.some(item => item?.hidden && item.contains(document.activeElement))) {
            (name === 'editor' ? $('runbookName') : name === 'targets' ? $('targetSearch') : $('scheduleFrequency') || $('scheduleCron')).focus({preventScroll:true});
        }
    }
    function updateReviewAction() {
        const button = $('reviewWorkspace');
        if (!button) return;
        const key = $('auto-runbooks').dataset.inspector === 'schedule' ? 'reviewSchedule' : 'review';
        button.dataset.autoI18n = key;
        button.textContent = tr(key);
    }
    function selectStep(row, focus = false) {
        if (nativeCredentials) {
            setStage('editor');
            document.querySelectorAll('.automation-step-detail').forEach(detail => detail.removeAttribute('id'));
            stepDetails.get(row).id = 'automationStepDetail';
        }
        document.querySelectorAll('.automation-step').forEach(step => {
            const active = step === row;
            step.classList.toggle('is-active', active);
            stepDetails.get(step).hidden = !active;
            if ($('activeStepEditor') && !active) step.append(stepDetails.get(step));
            step.querySelector('.automation-step-toggle').setAttribute('aria-expanded', String(active));
            step.querySelector('.automation-step-preview').hidden = active;
        });
        if ($('activeStepEditor')) {
            $('activeStepEditor').replaceChildren(stepDetails.get(row));
            updateActiveStepTitle();
        }
        motion(stepDetails.get(row));
        if (focus) row.querySelector('[data-field="name"]').focus();
    }
    function updateWorkflowName() {
        if ($('automationCurrentWorkflow')) $('automationCurrentWorkflow').textContent = $('runbookName').value.trim() || tr('newRunbook');
    }
    function updateActiveStepTitle() {
        const row = $('runbookSteps').querySelector('.is-active');
        if ($('activeStepTitle') && row) $('activeStepTitle').textContent = row.querySelector('.automation-step-number').textContent + ' · ' + (row.querySelector('[data-field="name"]').value.trim() || tr('stepName'));
    }
    function changed() { updateWorkflowName(); updateActiveStepTitle(); editRevision += 1; dirty = true; $('saveState').textContent = tr('unsaved'); }
    function stepElement(step = {}) {
        const row = node('section', undefined, 'automation-step');
        const index = $('runbookSteps').children.length + 1;
        const heading = node('div', undefined, 'automation-step-heading');
        const number = node('span', String(index), 'automation-step-number');
        number.setAttribute('aria-hidden', 'true');
        const name = node('input');
        name.className = 'form-control'; name.required = true; name.maxLength = 128;
        name.value = step.name || ''; name.placeholder = tr('stepName'); name.dataset.field = 'name';
        name.setAttribute('aria-label', tr('stepName'));
        const tools = node('div', undefined, 'automation-step-tools');
        tools.append(iconButton('arrow_upward', tr('moveUp'), () => {
            const focus = row.contains(document.activeElement) ? document.activeElement : null;
            if (row.previousElementSibling) row.previousElementSibling.before(row);
            renumber(); changed();
            focus?.focus({preventScroll:true});
        }), iconButton('arrow_downward', tr('moveDown'), () => {
            const focus = row.contains(document.activeElement) ? document.activeElement : null;
            if (row.nextElementSibling) row.nextElementSibling.after(row);
            renumber(); changed();
            focus?.focus({preventScroll:true});
        }), iconButton('delete_outline', tr('removeStep'), () => {
            if ($('runbookSteps').children.length > 1) { const next = row.nextElementSibling || row.previousElementSibling; row.remove(); renumber(); changed(); selectStep(next, true); }
        }));
        const toggle = iconButton('unfold_more', tr('editStep'), () => selectStep(row, true));
        toggle.classList.add('automation-step-toggle'); toggle.setAttribute('aria-expanded', 'true');
        heading.append(number, name, toggle, tools);
        name.addEventListener('focus', () => { if (!row.classList.contains('is-active')) selectStep(row); });
        const commandLabel = node('label', tr('command'));
        const command = node('textarea');
        command.className = 'form-control'; command.required = true; command.maxLength = 8192;
        command.value = step.command || ''; command.spellcheck = false; command.dataset.field = 'command';
        command.id = `command-${++fieldSequence}`; commandLabel.htmlFor = command.id;
        const options = node('div', undefined, 'automation-step-options');
        const timeoutGroup = node('div', undefined, 'automation-timeout');
        const timeout = node('input');
        timeout.type = 'number'; timeout.min = '1'; timeout.max = '300'; timeout.required = true;
        timeout.value = String(step.timeout || 30); timeout.dataset.field = 'timeout'; timeout.className = 'form-control';
        timeout.id = `timeout-${++fieldSequence}`;
        const timeoutLabel = node('label', tr('timeout')); timeoutLabel.htmlFor = timeout.id;
        timeoutGroup.append(timeoutLabel, timeout);
        const sudoLabel = node('label', undefined, 'automation-check');
        const sudo = node('input'); sudo.type = 'checkbox'; sudo.checked = step.sudo === true; sudo.dataset.field = 'sudo';
        sudoLabel.append(sudo, node('span', tr('sudo')));
        options.append(timeoutGroup, sudoLabel);
        const detail = node('div', undefined, 'automation-step-detail'); detail.append(commandLabel, command, options);
        const guidance = node('div', undefined, 'automation-step-guidance');
        guidance.setAttribute('aria-live', 'polite'); detail.append(guidance);
        const updateGuidance = () => {
            const hints = window.AutomationGuidance?.stepHints({command:command.value, timeout:Number(timeout.value), sudo:sudo.checked}) || [];
            guidance.replaceChildren(...hints.map(key => node('p', tr(key), 'automation-hint')));
            guidance.hidden = !hints.length;
        };
        [command, timeout, sudo].forEach(field => field.addEventListener('input', updateGuidance));
        updateGuidance();
        const snippet = node('button', step.command || tr('command'), 'automation-step-preview'); snippet.type = 'button';
        snippet.addEventListener('click', () => { selectStep(row); command.focus(); });
        command.addEventListener('input', () => { snippet.textContent = command.value || tr('command'); });
        stepDetails.set(row, detail);
        if (nativeCredentials) detail.querySelectorAll('input,textarea').forEach(field => field.setAttribute('form', 'runbookForm'));
        row.append(heading, snippet);
        row.append(detail);
        return row;
    }
    function renumber() {
        [...$('runbookSteps').children].forEach((row, index) => { row.querySelector('.automation-step-number').textContent = String(index + 1); });
        $('addStep').disabled = $('runbookSteps').children.length >= 20;
        if ($('copyLibraryCommand')) $('copyLibraryCommand').disabled = $('runbookSteps').children.length >= 20;
    }
    function draft() {
        return { ...(selectedId ? {id: selectedId} : {}), name: $('runbookName').value.trim(),
            stop_on_error: $('stopOnError').checked,
            steps: [...$('runbookSteps').children].map(row => ({
                name: row.querySelector('[data-field="name"]').value.trim(),
                command: stepDetails.get(row).querySelector('[data-field="command"]').value,
                timeout: Number(stepDetails.get(row).querySelector('[data-field="timeout"]').value),
                sudo: stepDetails.get(row).querySelector('[data-field="sudo"]').checked
            }))};
    }
    function edit(book, {preserveSchedule = false} = {}) {
        if (!preserveSchedule) {
            scheduleDraftInitialized = false; editingScheduleId = null;
            document.querySelectorAll('#targetHosts input, #targetGroups input').forEach(input => { input.checked = false; });
            updateTargetCount();
        }
        selectedId = book?.id || null;
        $('runbookName').value = book?.name || '';
        updateWorkflowName();
        $('stopOnError').checked = book?.stop_on_error !== false;
        $('runbookSteps').replaceChildren();
        $('activeStepEditor')?.replaceChildren();
        (book?.steps || [{}]).forEach(step => { $('runbookSteps').append(stepElement(step)); });
        $('editorTitle').textContent = book ? tr('editRunbook') : tr('newRunbook');
        $('deleteRunbook').hidden = !selectedId;
        dirty = false; $('saveState').textContent = '';
        renumber(); renderBooks(); selectStep($('runbookSteps').firstElementChild);
    }
    function renderBooks() {
        $('runbookList').replaceChildren();
        if (!model.runbooks.length) $('runbookList').append(node('p', tr('noRunbooks'), 'automation-hint'));
        const search = $('runbookSearch').value.toLowerCase();
        if (model.runbooks.length && !model.runbooks.some(book => book.name.toLowerCase().includes(search))) $('runbookList').append(node('p', tr('noMatches'), 'automation-hint'));
        model.runbooks.filter(book => book.name.toLowerCase().includes(search)).forEach(book => {
            const button = node('button', book.name, 'automation-library-entry'); button.type = 'button';
            if (book.id === selectedId) button.setAttribute('aria-current', 'true');
            button.append(node('small', tr(book.steps.length === 1 ? 'oneStep' : 'stepCount', {count: book.steps.length})));
            const sequence = node('span', book.steps.slice(0,3).map(step => step.name).join(' → ') + (book.steps.length > 3 ? ' …' : ''), 'automation-workflow-sequence');
            button.append(sequence);
            const lastRun = knownRuns.find(run => run.runbook_id === book.id);
            if (lastRun) { const status = node('small', tr(`state.${lastRun.status}`), 'automation-state'); status.dataset.state = lastRun.status; button.append(status); }
            button.addEventListener('click', () => action(async () => {
                if (await discardChanges()) { edit(book); tab('runbooks'); $('runbookName').focus(); }
            }));
            const entry = node('div', undefined, 'automation-library-item');
            entry.setAttribute('role', 'group');
            entry.setAttribute('aria-label', book.name);
            const execute = node('button', tr('executeNow'), 'btn btn-primary'); execute.type = 'button';
            execute.addEventListener('click', () => action(async () => {
                if (!await discardChanges()) return;
                const retained = selectedId === book.id ? selectedTargets() : null;
                edit(book); tab('runbooks');
                if (retained) {
                    document.querySelectorAll('#targetHosts input').forEach(input => { input.checked = !input.disabled && retained.ids.includes(input.value); });
                    document.querySelectorAll('#targetGroups input').forEach(input => { input.checked = retained.groups.includes(input.value); });
                    updateTargetCount();
                }
                setStage('targets', {focus:true});
                if (selectedTargets().targets.length) await review();
                else notify(tr('chooseRunTargets'));
            }));
            const actions = node('div', undefined, 'automation-workflow-actions');
            const editButton = node('button', tr('editWorkflow'), 'btn btn-secondary'); editButton.type = 'button';
            editButton.addEventListener('click', () => button.click());
            const remove = node('button', tr('delete'), 'btn btn-secondary danger'); remove.type = 'button';
            remove.addEventListener('click', () => action(() => deleteBook(book)));
            actions.append(execute, editButton, remove);
            entry.append(button, actions); $('runbookList').append(entry);
        });
    }
    async function discardChanges() {
        return !dirty || await question(tr('unsavedTitle'), tr('discardHint'), {confirm: true}) === '';
    }
    async function saveBook() {
        if (nativeCredentials) {
            for (const row of $('runbookSteps').children) {
                const invalid = [...stepDetails.get(row).querySelectorAll('input,textarea')].find(field => !field.checkValidity());
                if (invalid) { selectStep(row); invalid.reportValidity(); throw new DOMException('Invalid form', 'AbortError'); }
            }
        }
        if (!$('runbookForm').checkValidity()) { setStage('editor'); $('runbookForm').reportValidity(); throw new DOMException('Invalid form', 'AbortError'); }
        const revision = editRevision;
        const result = await api('/api/automation/runbooks', {method: 'POST', body: draft()});
        selectedId = result.runbook.id;
        model.runbooks = model.runbooks.filter(book => book.id !== selectedId).concat(result.runbook);
        dirty = editRevision !== revision; $('saveState').textContent = tr(dirty ? 'unsaved' : 'saved'); $('deleteRunbook').hidden = false;
        $('editorTitle').textContent = tr('editRunbook'); renderBooks();
        return result.runbook;
    }
    function selectedTargets() {
        const ids = [...document.querySelectorAll('#targetHosts input:checked')].map(input => input.value);
        const groups = [...document.querySelectorAll('#targetGroups input:checked')].map(input => input.value);
        const targets = model.profiles.filter(profile => ids.includes(profile.id) || groups.includes(profile.group));
        return {ids, groups, targets};
    }
    function updateTargetCount() {
        $('mobileTargetCount').textContent = String(selectedTargets().targets.length);
        $('targetCount').textContent = tr('hostCount', {count: selectedTargets().targets.length});
        const selectedIds = new Set(selectedTargets().targets.map(profile => profile.id));
        document.querySelectorAll('#targetGroups input').forEach(input => {
            const members = model.profiles.filter(profile => profile.group === input.value);
            const selected = members.filter(profile => selectedIds.has(profile.id)).length;
            input.indeterminate = selected > 0 && selected < members.length;
        });
    }
    function hopCredentialStatus(id, authType, status, available) {
        if (authType === 'key') return 'sshKey';
        if (status === 'ready' || available === true) return 'storedUnverified';
        if (status === 'changed') return 'credentialChanged';
        const stored = model.vault.credentials.find(item => item.profile_id === id);
        return stored?.valid ? 'storedUnverified' : 'missingPassword';
    }
    function targetCredentialStatus(profile) {
        if (!profile.supported) return 'unsupported';
        const own = hopCredentialStatus(profile.id, profile.auth_type, profile.credential_status, profile.credential_available);
        if (!profile.route_id || ['missingPassword', 'credentialChanged'].includes(own)) return own;
        // A run needs both hops; name the jump host when only its password is missing.
        const route = hopCredentialStatus(profile.route_id, profile.route_auth_type, profile.route_credential_status);
        return route === 'missingPassword' ? 'jumpPasswordMissing' : route === 'credentialChanged' ? 'jumpCredentialChanged' : own;
    }

    function openCredential(profileId) {
        window.dispatchEvent(new CustomEvent('webssh:credentials', {detail:{resourceId:profileId}}));
    }
    function renderTargets() {
        const previous = selectedTargets();
        $('targetHosts').replaceChildren(); $('targetGroups').replaceChildren();
        const groupNames = [...new Set(model.profiles.map(profile => profile.group).filter(Boolean))];
        groupNames.forEach(group => {
            const members = model.profiles.filter(profile => profile.group === group);
            const label = node('label', undefined, 'automation-check');
            const input = node('input'); input.type = 'checkbox'; input.value = group;
            input.disabled = members.some(profile => !profile.supported); input.checked = !input.disabled && previous.groups.includes(group);
            label.append(input, node('span', `${group} (${members.length})${input.disabled ? ` · ${tr('unsupported')}` : ''}`));
            input.addEventListener('change', updateTargetCount); $('targetGroups').append(label);
        });
        model.profiles.forEach(profile => {
            const row = node('div', undefined, 'automation-host');
            row.dataset.search = `${profile.name} ${profile.host} ${profile.group || ''}`.toLowerCase();
            const input = node('input'); input.type = 'checkbox'; input.value = profile.id;
            input.id = `target-${profile.id}`; input.disabled = !profile.supported; input.checked = !input.disabled && previous.ids.includes(profile.id);
            const label = node('label'); label.htmlFor = input.id;
            label.append(node('strong', profile.name || profile.host), node('small', `${profile.username}@${profile.host}:${profile.port || 22}${profile.via ? ` · ${tr('viaJump', {name: profile.via})}` : ''}${profile.group ? ` · ${profile.group}` : ''}`));
            const marker = node('span', 'dns', 'material-icons automation-host-icon'); marker.setAttribute('aria-hidden', 'true');
            const statusKey = targetCredentialStatus(profile);
            const status = node('span', tr(statusKey), 'automation-state'); status.dataset.credentialStatus = profile.id;
            label.append(status); row.append(input, marker, label);
            const jumpCredential = ['jumpPasswordMissing', 'jumpCredentialChanged'].includes(statusKey);
            if (profile.supported && (profile.auth_type !== 'key' || jumpCredential)) {
                const resourceId = jumpCredential ? profile.route_id : profile.id;
                const button = iconButton('key', tr(['credentialChanged', 'jumpCredentialChanged'].includes(statusKey) ? 'replacePassword' : 'credentials'), () => openCredential(resourceId));
                button.dataset.credentialAction = profile.id; row.append(button);
            }
            input.addEventListener('change', updateTargetCount); $('targetHosts').append(row);
        });
        $('noHosts').hidden = model.profiles.length > 0;
        filterTargets();
        updateTargetCount();
    }
    async function loadState({initial = false} = {}) {
        const generation = authorizationGeneration;
        const sequence = ++stateRequestSequence;
        const result = await api('/api/automation/state');
        if (generation !== authorizationGeneration || sequence !== stateRequestSequence) return;
        availability(true);
        const targetsChanged = JSON.stringify(model.profiles) !== JSON.stringify(result.profiles);
        const booksChanged = JSON.stringify(model.runbooks) !== JSON.stringify(result.runbooks);
        model = {...result, runbooks: result.runbooks || [], vault:result.vault || {credentials:[],unlocked:false}};
        lastStateRefresh = Date.now();
        if (initial || targetsChanged) renderTargets();
        if (initial) edit(model.runbooks[0]);
        else if (booksChanged) renderBooks();
    }
    function settlePrompt(value) {
        $('promptInput').value = '';
        $('automationPrompt').close();
        const resolve = promptResolve; promptResolve = null;
        if (resolve) resolve(value);
    }
    function question(title, hint, {secret = false, choices = null, confirm = false, numeric = false, initialValue = '', allowEmpty = false} = {}) {
        if (promptResolve) settlePrompt(null);
        $('promptTitle').textContent = title; $('promptHint').textContent = hint;
        $('promptInput').value = initialValue; $('promptInput').hidden = Boolean(choices) || confirm;
        $('promptInput').required = !choices && !confirm && !allowEmpty;
        $('promptInput').type = secret ? 'password' : 'text';
        $('promptInput').inputMode = numeric ? 'numeric' : 'text';
        $('promptLabel').textContent = title; $('promptLabel').hidden = Boolean(choices) || confirm;
        $('promptSelect').hidden = !choices; $('promptSelectLabel').hidden = !choices; $('promptSelectLabel').textContent = title;
        $('promptSelect').replaceChildren();
        if (choices) choices.forEach(method => {
            const option = node('option', typeof method === 'object' ? method.label : tr(`method.${method}`)); option.value = typeof method === 'object' ? method.value : method; $('promptSelect').append(option);
        });
        $('promptForm').querySelector('button[type="submit"]').disabled = false;
        $('automationPrompt').showModal();
        (choices ? $('promptSelect') : confirm ? $('promptCancel') : $('promptInput')).focus();
        return new Promise(resolve => { promptResolve = resolve; });
    }
    const decode = value => Uint8Array.from(atob(value.replace(/-/g, '+').replace(/_/g, '/')), c => c.charCodeAt(0));
    const encode = value => btoa(String.fromCharCode(...new Uint8Array(value))).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
    async function authorize(actionName, token, generation = authorizationGeneration) {
        assertAuthorizationCurrent(generation);
        const context = {controller: new AbortController(), popup: null};
        currentAuthorization = context;
        const guarded = callback => async (...args) => {
            assertAuthorizationCurrent(generation);
            const result = await callback(...args);
            assertAuthorizationCurrent(generation);
            return result;
        };
        const stepUp = window.WebSSHSecurityUI.createAccountStepUpClient({api: guarded(api),
        chooseMethod: guarded(methods => question(tr('authMethod'), tr('authHint'), {choices: methods})),
        requestSecret: guarded(method => question(tr(method === 'totp' ? 'authCode' : method === 'bootstrap' ? 'bootstrapCode' : 'accountPassword'), tr('authHint'), {secret: true, numeric: method === 'totp'})),
        getPasskeyAssertion: guarded(options => navigator.credentials.get({signal: context.controller.signal, publicKey: {...options,
            challenge: decode(options.challenge), allowCredentials: (options.allowCredentials || []).map(item => ({...item, id: decode(item.id)}))}})),
        serializeCredential: credential => ({id: credential.id, rawId: encode(credential.rawId), type: credential.type,
            authenticatorAttachment: credential.authenticatorAttachment, clientExtensionResults: credential.getClientExtensionResults(),
            response: {clientDataJSON: encode(credential.response.clientDataJSON), authenticatorData: encode(credential.response.authenticatorData),
                signature: encode(credential.response.signature), userHandle: credential.response.userHandle ? encode(credential.response.userHandle) : null}}),
        openAuthorization: url => {
            assertAuthorizationCurrent(generation);
            const popup = window.open(url, 'webssh-automation-auth', 'popup,width=720,height=760');
            if (!popup) throw new Error(tr('popupHint'));
            context.popup = popup;
        }
        });
        try {
            const grant = await stepUp.authorize(actionName, token);
            assertAuthorizationCurrent(generation);
            if (!grant) throw new DOMException('Cancelled', 'AbortError');
            return stepUp.header(grant);
        } finally {
            context.popup?.close();
            if (currentAuthorization === context) currentAuthorization = null;
        }
    }
    function reviewContext(scheduled = false) {
        const selected = selectedTargets();
        return JSON.stringify({revision:editRevision, tab:selectedTab,
            view:window.primaryWorkspaceController?.getActiveView(), stage:$('auto-runbooks').dataset.view,
            targets:selected.ids, groups:selected.groups,
            ...(scheduled ? {schedule:editingScheduleId, cron:$('scheduleCron').value, timezone:$('scheduleTimezone').value} : {})});
    }
    function assertReviewCurrent(context, scheduled = false) {
        if (context !== reviewContext(scheduled)) throw new Error(tr('reviewChanged'));
    }
    async function review() {
        const generation = authorizationGeneration;
        const context = reviewContext();
        if (!selectedTargets().targets.length) throw new Error(tr('error.invalid_targets'));
        const book = await saveBook();
        assertAuthorizationCurrent(generation);
        assertReviewCurrent(context);
        const selected = selectedTargets();
        const result = await api('/api/automation/preview', {method: 'POST', body: {runbook_id: book.id, profile_ids: selected.ids, groups: selected.groups}});
        assertAuthorizationCurrent(generation);
        assertReviewCurrent(context);
        showRunPreview(result);
    }
    function showRunPreview(result) {
        preview = result;
        const content = $('automationPreviewContent'); content.replaceChildren(node('h3', preview.runbook.name));
        content.append(node('h3', tr('hostCount', {count: preview.targets.length})));
        const targets = node('ul');
        preview.targets.forEach(target => { targets.append(node('li', `${target.name} · ${target.username}@${target.host}:${target.port || 22}`)); });
        content.append(targets);
        preview.runbook.steps.forEach((step, index) => {
            content.append(node('h3', `${index+1}. ${step.name} · ${step.timeout}s${step.sudo ? ' · sudo -n' : ''}`), node('pre', step.command));
        });
        content.append(node('p', tr('resultsHint'), 'automation-hint'));
        content.append(node('p', tr(preview.runbook.stop_on_error ? 'stopOnError' : 'continueOnError'), 'automation-hint'));
        $('runConfirmationLabel').textContent = tr('typeCount', {count: preview.confirmation});
        $('runConfirmation').value = ''; $('automationPreviewError').hidden = true;
        $('runPreview').showModal(); $('runConfirmation').focus();
    }
    // Preserve disclosure, focus, selection and output scroll during polling.
    function runPart(parent, key, tag, className) {
        let child = [...parent.children].find(item => item.dataset.resultKey === key);
        if (!child) { child = node(tag, undefined, className); child.dataset.resultKey = key; parent.append(child); }
        return child;
    }
    function runText(parent, key, tag, text, className) {
        const child = runPart(parent, key, tag, className);
        if (child.textContent !== text) child.textContent = text;
        return child;
    }
    const diagnosticReasons = new Set(['nonzero_exit','timeout','cancelled','output_limit','channel_lost','acknowledgement_lost','dispatch_failed','run_interrupted']);
    const runIcons = {succeeded:'check_circle', failed:'error', unknown:'help', running:'sync', queued:'schedule', cancelled:'cancel', skipped:'remove_circle_outline'};
    function runDuration(run) {
        if (!run.finished_at) return '';
        const seconds = Math.max(0, Math.round((Date.parse(run.finished_at) - Date.parse(run.created_at)) / 1000));
        if (!Number.isFinite(seconds)) return '';
        return seconds < 60 ? tr('durationSeconds', {seconds}) : tr('durationMinutes', {minutes: Math.floor(seconds / 60), seconds: seconds % 60});
    }
    async function deleteRun(run) {
        if (await question(tr('deleteRun'), run.name + '\n\n' + tr('deleteRunHint'), {confirm:true}) !== '') return;
        await api('/api/automation/runs/' + encodeURIComponent(run.id), {method:'DELETE'});
        notify(tr('runDeleted')); await loadRuns();
    }
    async function clearRuns() {
        const finished = knownRuns.filter(run => !['queued','running'].includes(run.status)).length;
        if (!finished) { notify(tr('noFinishedRuns')); return; }
        if (await question(tr('clearRuns'), tr('clearRunsHint', {count: finished}), {confirm:true}) !== '') return;
        const result = await api('/api/automation/runs/clear', {method:'POST', body:{}});
        notify(tr('runsDeleted', {count: result.deleted})); await loadRuns();
    }
    let runsRequest = 0;
    async function loadRuns() {
        const request = ++runsRequest;
        let result;
        try { result = await api('/api/automation/runs'); }
        catch (error) {
            if (request === runsRequest) {
                if (['disabled','authentication_required'].includes(error.code)) { runsEnabled=false; knownRuns=[]; historySignature=''; }
                setRunsStale(true);
            }
            throw error;
        }
        if (request !== runsRequest) return;
        runsLoaded = true;
        runsEnabled = true;
        setRunsStale(false);
        const signature = JSON.stringify(result.runs);
        if (signature === historySignature) return;
        historySignature = signature;
        knownRuns = result.runs; renderBooks();
        publishRunSnapshot();
        const history = $('runHistory');
        const retained = new Set(result.runs.map(run => run.id));
        [...history.children].forEach(child => { if (!retained.has(child.dataset.resultKey)) child.remove(); });
        if (!result.runs.length) runText(history, 'empty', 'p', tr('noRuns'), 'automation-hint');
        result.runs.forEach((run, index) => {
            const exists = [...history.children].some(item => item.dataset.resultKey === run.id);
            const details = runPart(history, run.id, 'details', 'automation-run'); details.dataset.runId = run.id;
            const active = ['queued','running'].includes(run.status);
            // Older cards start collapsed so a long history stays scannable; the newest and running work stay open.
            if (!exists) { details.open = index === 0 || active; history.insertBefore(details, history.children[index] || null); }
            details.dataset.state = run.status;
            const steps = run.targets.flatMap(target => target.steps);
            const confirmed = steps.filter(step => step.status === 'succeeded' && step.exit_code === 0).length;
            const summary = runPart(details, 'summary', 'summary', 'automation-run-summary');
            const badge = runText(summary, 'badge', 'span', runIcons[run.status] || 'radio_button_unchecked', 'material-icons automation-run-badge');
            badge.setAttribute('aria-hidden', 'true');
            const heading = runPart(summary, 'heading', 'span', 'automation-run-heading');
            runText(heading, 'name', 'strong', run.name);
            runText(heading, 'meta', 'span', [tr(run.schedule_id ? 'scheduledRun' : 'manualRun'),
                tr('runTotals', {hosts:run.targets.length, confirmed, total:steps.length}), runDuration(run)].filter(Boolean).join(' · '), 'automation-run-meta');
            const hosts = runPart(summary, 'hosts', 'span', 'automation-run-hosts');
            const shown = run.targets.slice(0, 4);
            [...hosts.children].forEach(child => { if (!shown.some((_target, i) => child.dataset.resultKey === 'host-' + i) && child.dataset.resultKey !== 'more') child.remove(); });
            shown.forEach((target, i) => { runText(hosts, 'host-' + i, 'span', target.name, 'automation-run-host').dataset.state = target.status; });
            const more = runText(hosts, 'more', 'span', run.targets.length > 4 ? '+' + (run.targets.length - 4) : '', 'automation-run-host');
            more.hidden = run.targets.length <= 4;
            const date = runText(summary, 'date', 'time', new Date(run.created_at).toLocaleString()); date.dateTime = run.created_at;
            runText(summary, 'status', 'span', tr(`state.${run.status}`), 'automation-state automation-run-status').dataset.state = run.status;
            const remove = runPart(summary, 'delete', 'button', 'automation-icon-button automation-run-delete');
            if (!remove.firstChild) {
                remove.type = 'button';
                const glyph = node('span', 'delete', 'material-icons'); glyph.setAttribute('aria-hidden', 'true'); remove.append(glyph);
                remove.addEventListener('click', event => {
                    // A button inside <summary> would otherwise also toggle the card.
                    event.preventDefault(); event.stopPropagation();
                    action(() => deleteRun(run));
                });
            }
            remove.title = tr('deleteRun'); remove.setAttribute('aria-label', tr('deleteRunLabel', {name: run.name}));
            remove.hidden = active;
            const cancel = runPart(details, 'cancel', 'button', 'btn btn-secondary');
            cancel.type = 'button'; cancel.textContent = tr('cancelRun'); cancel.hidden = !active;
            if (!exists) cancel.addEventListener('click', () => action(async () => {
                await api('/api/automation/runs/' + encodeURIComponent(run.id) + '/cancel', {method:'POST',body:{}});
                notify(tr('cancellationRequested')); await loadRuns();
            }));
            // Identical results across hosts, grouped per step; differences stand out.
            const comparison = runPart(details, 'compare', 'details', 'automation-run-compare');
            comparison.hidden = run.targets.length < 2 || active || !window.AutomationTools;
            if (!comparison.hidden) {
                const result = window.AutomationTools.compareRun(run);
                const differing = result.steps.filter(step => !step.uniform).length;
                runText(comparison, 'summary', 'summary', differing ? tr(differing === 1 ? 'compareDiffersOne' : 'compareDiffers', {count: differing}) : tr('compareUniform'), 'automation-run-compare-summary');
                // Long workflows: show only the steps that differ, unless all agree.
                const filter = runPart(comparison, 'filter', 'label', 'automation-check automation-compare-filter');
                if (!filter.firstChild) {
                    const toggle = node('input'); toggle.type = 'checkbox'; toggle.checked = true;
                    toggle.addEventListener('change', () => { comparison.dataset.onlyDiffering = String(toggle.checked); });
                    filter.append(toggle, node('span', tr('compareOnlyDiffering')));
                    comparison.dataset.onlyDiffering = 'true';
                }
                filter.hidden = !differing || differing === result.steps.length;
                comparison.dataset.filterActive = String(!filter.hidden);
                const steps = runPart(comparison, 'steps', 'div', 'automation-compare-steps');
                steps.replaceChildren(...result.steps.map(step => {
                    const section = node('section', undefined, 'automation-compare-step');
                    section.dataset.uniform = String(step.uniform);
                    section.append(node('h5', step.name));
                    step.groups.forEach(group => {
                        const entry = node('div', undefined, 'automation-compare-group');
                        entry.dataset.state = group.status;
                        entry.append(node('p', tr(group.hosts.length === 1 ? 'compareGroupOne' : 'compareGroup', {count: group.hosts.length, hosts: group.hosts.join(', '),
                            exit: group.exitCode ?? '—', state: tr(`state.${group.status}`)}), 'automation-compare-hosts'));
                        if (group.output !== null) {
                            const pre = node('pre', group.output.length > 2000 ? group.output.slice(0, 2000) + '…' : group.output || tr('diagnostic.empty'));
                            pre.tabIndex = 0;
                            entry.append(pre);
                        }
                        if (group.errors) {
                            const errors = node('pre', group.errors.length > 2000 ? group.errors.slice(0, 2000) + '…' : group.errors, 'automation-compare-stderr');
                            errors.tabIndex = 0; errors.setAttribute('aria-label', 'stderr');
                            entry.append(errors);
                        }
                        if (group.truncated) entry.append(node('p', tr('diagnostic.truncated'), 'automation-warning'));
                        section.append(entry);
                    });
                    return section;
                }));
            }
            run.targets.forEach((target, targetIndex) => {
                const section = runPart(details, 'target-' + targetIndex, 'section', 'automation-run-target');
                section.dataset.state = target.status;
                const title = runPart(section, 'title', 'h4', 'automation-run-target-title');
                runText(title, 'name', 'span', target.name, 'automation-run-target-name');
                runText(title, 'address', 'span', target.username + '@' + target.host, 'automation-run-target-address');
                runText(title, 'status', 'span', tr(`state.${target.status}`), 'automation-state').dataset.state = target.status;
                runText(section, 'reason', 'p', target.reason ? tr(errors.has(target.reason) ? 'error.' + target.reason : 'result.' + target.reason) : '', 'automation-hint').hidden = !target.reason;
                target.steps.forEach((step, stepIndex) => {
                    const state = step.status === 'succeeded' && step.exit_code !== 0 ? 'unknown' : step.status;
                    const item = runPart(section, 'step-' + stepIndex, 'details', 'automation-run-diagnostic');
                    const row = runPart(item, 'summary', 'summary', 'automation-run-step'); row.dataset.state = state;
                    const symbol = runText(row, 'icon', 'span', ({succeeded:'check_circle',failed:'error',unknown:'help',running:'sync',cancelled:'cancel'})[state] || 'radio_button_unchecked', 'material-icons automation-run-symbol'); symbol.setAttribute('aria-hidden','true');
                    runText(row, 'name', 'span', step.name, 'automation-run-step-name');
                    runText(row, 'status', 'span', tr(`state.${state}`));
                    runText(row, 'metrics', 'span', tr('stepMetrics', {exit:step.exit_code ?? '—', duration:step.duration ?? '—'}), 'automation-run-metrics');
                    const chevron = runText(row, 'chevron', 'span', 'expand_more', 'material-icons automation-run-chevron'); chevron.setAttribute('aria-hidden','true');
                    const body = runPart(item, 'body', 'div', 'automation-run-output');
                    const specificReason = window.AutomationGuidance?.resultHint(step);
                    const reason = specificReason ? tr(specificReason) : diagnosticReasons.has(step.reason) ? tr(`diagnostic.${step.reason}`) : state === 'succeeded' ? tr('diagnostic.confirmed') : tr('diagnostic.unconfirmed');
                    runText(body, 'reason', 'p', reason, 'automation-hint');
                    const captured = typeof step.stdout === 'string' && typeof step.stderr === 'string';
                    runText(body, 'legacy', 'p', tr('diagnostic.legacy'), 'automation-hint').hidden = captured;
                    runText(body, 'truncated', 'p', tr('diagnostic.truncated'), 'automation-warning').hidden = !step.output_truncated;
                    ['stdout','stderr'].forEach(stream => {
                        const output = runPart(body, stream, 'section', 'automation-output-stream'); output.hidden = !captured;
                        runText(output, 'label', 'h5', stream);
                        const pre = runText(output, 'text', 'pre', captured ? step[stream] || tr(['queued','running'].includes(state) ? 'diagnostic.pending' : 'diagnostic.empty') : '');
                        pre.tabIndex = 0; pre.setAttribute('aria-label', step.name + ': ' + stream);
                    });
                });
            });
        });
        filterRuns();
    }
    function setRunsStale(value) {
        runsStale = value;
        publishRunSnapshot();
    }
    function openRun(runId, targetProfileId) {
        return action(async()=>{
            window.primaryWorkspaceController?.open('automation',$('automationNativeView'));
            $('runSearch').value=''; $('runStatusFilter').value=''; tab('runs'); await loadRuns(); filterRuns();
            const detail=[...$('runHistory').children].find(item=>item.dataset.runId===runId);
            if (!detail) {notify(tr('runUnavailable'),true);return;}
            detail.open=true;
            const run=knownRuns.find(item=>item.id===runId);
            const targetIndex=targetProfileId ? run?.targets.findIndex(target=>target.id===targetProfileId) : -1;
            const target=targetIndex >= 0 ? [...detail.children].find(item=>item.dataset.resultKey==='target-'+targetIndex) : detail;
            (target || detail).querySelectorAll('.automation-run-diagnostic').forEach(item=>item.open=true);
            (target || detail).scrollIntoView({block:'start'});
            detail.querySelector('summary')?.focus({preventScroll:true});
        });
    }
    function filterRuns() {
        const query = ($('runSearch')?.value || '').trim().toLocaleLowerCase();
        const status = $('runStatusFilter')?.value || '';
        let matches = 0;
        for (const item of document.querySelectorAll('#runHistory > .automation-run')) {
            const run = knownRuns.find(entry => entry.id === item.dataset.runId);
            const names = run ? [run.name, ...run.targets.map(target => target.name + ' ' + target.host)].join(' ').toLocaleLowerCase() : '';
            item.hidden = !run || Boolean(status && (status === 'attention' ? !['failed','unknown'].includes(run.status) : run.status !== status)) || !names.includes(query);
            if (!item.hidden) matches++;
        }
        if ($('runFilterEmpty')) $('runFilterEmpty').hidden = !knownRuns.length || matches > 0;
    }
    $('runSearch')?.addEventListener('input', filterRuns);
    $('runStatusFilter')?.addEventListener('change', filterRuns);
    let schedulePreview = null;
    let editingScheduleId = null;
    let scheduleDraftInitialized = false;
    const scheduleTime = (value, timezone) => {
        try { return new Intl.DateTimeFormat(document.documentElement.lang, {dateStyle:'medium',timeStyle:'short',timeZone:timezone || undefined}).format(new Date(value)); }
        catch { return String(value || '—'); }
    };
    function updateScheduleBuilder({preserveCron = false} = {}) {
        if (!$('scheduleFrequency')) return;
        const frequency = $('scheduleFrequency').value;
        const fields = {Time: !['hourly','custom'].includes(frequency), Minute: frequency === 'hourly', Weekday: frequency === 'weekly', Monthday: frequency === 'monthly', Custom: frequency === 'custom'};
        Object.entries(fields).forEach(([name, visible]) => {
            $(`schedule${name}Field`).hidden = !visible;
            $(`schedule${name}Field`).querySelectorAll('input,select').forEach(input => { input.disabled = !visible; });
        });
        const options = {frequency, time:$('scheduleTime').value, minute:$('scheduleMinute').value, weekday:$('scheduleWeekday').value, monthday:$('scheduleMonthday').value, custom:$('scheduleCron').value};
        const cron = scheduleBuilder.cron(options);
        if (!preserveCron && cron !== null) $('scheduleCron').value = cron;
        let summary = '';
        if (cron !== null) summary = tr(`summary.${frequency}`, {...options, day: tr(`weekday.${options.weekday}`), cron:options.custom});
        $('scheduleSummary').textContent = summary ? summary + ' · ' + $('scheduleTimezone').value : tr('scheduleChooseTime');
    }
    function setScheduleBuilder(expression) {
        const values = scheduleBuilder.parse(expression);
        $('scheduleFrequency').value = values.frequency;
        $('scheduleTime').value = values.time && /^\d{2}:\d{2}$/.test(values.time) ? values.time : '09:00';
        $('scheduleMinute').value = values.frequency === 'hourly' ? values.minute : '0';
        $('scheduleWeekday').value = values.frequency === 'weekly' ? values.weekday : '1';
        $('scheduleMonthday').value = values.frequency === 'monthly' ? values.monthday : '1';
        updateScheduleBuilder({preserveCron:true});
    }
    $('scheduleForm')?.addEventListener('input', () => updateScheduleBuilder());
    $('scheduleFrequency')?.addEventListener('change', () => updateScheduleBuilder());
    function openSchedule(schedule) {
        if (busy) return;
        if (schedule) {
            const book = model.runbooks.find(item => item.id === schedule.runbook_id);
            if (!book) { notify(tr('scheduleReloadRequired'),true); return; }
            if (dirty) { notify(tr('scheduleSaveDraft'),true); return; }
            edit(book);
            const ids = new Set(schedule.profile_ids || []);
            document.querySelectorAll('#targetHosts input').forEach(input => { input.checked = !input.disabled && ids.has(input.value); });
            document.querySelectorAll('#targetGroups input').forEach(input => { input.checked = (schedule.groups || []).includes(input.value); });
            updateTargetCount();
        }
        if (schedule || !scheduleDraftInitialized) {
            editingScheduleId = schedule?.id || null;
            $('scheduleCron').value = schedule?.cron || '0 9 * * 1-5';
            $('scheduleTimezone').value = schedule?.timezone || Intl.DateTimeFormat().resolvedOptions().timeZone || 'UTC';
            if ($('scheduleFrequency')) setScheduleBuilder($('scheduleCron').value);
            scheduleDraftInitialized = true;
        }
        tab('runbooks');
        setStage('schedule');
        if ($('scheduleFrequency')) $('scheduleFrequency').focus(); else $('scheduleCron').focus();
    }
    let schedulesRequest = 0;
    async function loadSchedules() {
        if (!$('scheduleList')) return;
        const request = ++schedulesRequest;
        const result = await api('/api/automation/schedules');
        // An older answer must not bring back a schedule that was just paused or deleted.
        if (request !== schedulesRequest) return;
        knownSchedules = Array.isArray(result.schedules) ? result.schedules : [];
        publishRunSnapshot();
        $('scheduleList').replaceChildren();
        if (!result.schedules.length) $('scheduleList').append(node('p',tr('noSchedules'),'automation-hint'));
        result.schedules.forEach(schedule => {
            const row = node('section',undefined,'automation-run');
            const heading = node('div',undefined,'automation-section-heading');
            heading.append(node('h3',schedule.name));
            const state = !schedule.enabled ? 'paused' : schedule.last_status || 'waiting';
            heading.append(node('span',tr(`scheduleState.${state}`),'automation-state'));
            const pattern = scheduleBuilder.parse(schedule.cron);
            const description = pattern.frequency === 'custom' ? schedule.cron : tr(`summary.${pattern.frequency}`, {...pattern, day: tr(`weekday.${pattern.weekday}`)});
            row.append(heading,node('p',description + ' · ' + schedule.timezone,'automation-hint'));
            if (schedule.next_due && schedule.enabled) row.append(node('p',tr('nextRun') + ': ' + scheduleTime(schedule.next_due,schedule.timezone) + ' · ' + schedule.timezone,'automation-hint'));
            if (schedule.last_status && state !== schedule.last_status) row.append(node('p',tr('lastResult') + ': ' + tr(`scheduleState.${schedule.last_status}`),'automation-hint'));
            const tools=node('div',undefined,'automation-actions');
            if (schedule.enabled || schedule.running) {
                const pause=node('button',tr('pauseSchedule'),'btn btn-secondary');pause.type='button';
                pause.addEventListener('click',()=>action(async()=>{await api('/api/automation/schedules/'+encodeURIComponent(schedule.id)+'/pause',{method:'POST',body:{}});await loadSchedules();}));tools.append(pause);
            }
            const execute = node('button', tr('executeNow'), 'btn btn-primary'); execute.type = 'button';
            execute.addEventListener('click', () => action(async () => {
                const generation = authorizationGeneration;
                const result = await api('/api/automation/schedules/' + encodeURIComponent(schedule.id) + '/preview-run', {method:'POST', body:{}});
                assertAuthorizationCurrent(generation); showRunPreview(result);
            })); execute.disabled = $('automationApp').hidden; tools.append(execute);
            const review=node('button',tr('reviewSchedule'),'btn btn-secondary');review.type='button';
            review.addEventListener('click',()=>openSchedule(schedule));review.disabled=$('automationApp').hidden;tools.append(review);
            const remove=node('button',tr('delete'),'automation-text-button danger');remove.type='button';
            remove.addEventListener('click',()=>action(async()=>{if(await question(tr('deleteSchedule'),tr('deleteScheduleHint'),{confirm:true})!== '')return;await api('/api/automation/schedules/'+encodeURIComponent(schedule.id),{method:'DELETE'});await loadSchedules();}));tools.append(remove);
            row.append(tools);$('scheduleList').append(row);
        });
    }
    async function reviewSchedule() {
        const context = reviewContext(true);
        if (!selectedTargets().targets.length) throw new Error(tr('error.invalid_targets'));
        const book=await saveBook();
        assertReviewCurrent(context, true);
        const selected=selectedTargets();
        const cron = $('scheduleCron').value.trim(), timezone = $('scheduleTimezone').value.trim();
        const result=await api('/api/automation/schedules/preview',{method:'POST',body:{runbook_id:book.id,profile_ids:selected.ids,groups:selected.groups,cron,timezone,...(editingScheduleId?{schedule_id:editingScheduleId}:{})}});
        assertReviewCurrent(context, true);
        schedulePreview=result;
        const content=$('scheduleReviewContent');content.replaceChildren(node('h3',schedulePreview.runbook.name));
        const pattern = scheduleBuilder.parse(cron);
        const summary = pattern.frequency === 'custom' ? cron : tr(`summary.${pattern.frequency}`, {...pattern,day:tr(`weekday.${pattern.weekday}`)});
        content.append(node('p',summary+' · '+timezone));
        const hosts=node('ul');schedulePreview.targets.forEach(target=>hosts.append(node('li',target.name+' · '+target.username+'@'+target.host+':'+(target.port||22))));content.append(hosts);
        schedulePreview.runbook.steps.forEach(step=>{content.append(node('h3',step.name),node('pre',(step.sudo?'sudo -n ':'')+step.command),node('p',tr('timeout')+': '+step.timeout));});
        content.append(node('p',tr('stopOnError')+': '+tr(schedulePreview.runbook.stop_on_error!==false ? 'yes' : 'no')));
        content.append(node('p',tr('resultsHint'),'automation-hint'));
        content.append(node('h3',tr('nextRuns')));const times=node('ul');schedulePreview.next_runs.forEach(value=>times.append(node('li',scheduleTime(value,timezone)+' · '+timezone)));content.append(times);
        content.append(node('p',tr('previewExpires',{minutes:Math.ceil((schedulePreview.expires_in||300)/60)}),'automation-hint'));
        $('scheduleConfirmationLabel').textContent=tr('typeCount',{count:schedulePreview.targets.length});$('scheduleConfirmation').value='';$('scheduleReviewError').hidden=true;$('scheduleReview').showModal();
    }
    $('openSchedule')?.addEventListener('click',()=>openSchedule());
    $('refreshSchedules')?.addEventListener('click',()=>action(loadSchedules));
    $('scheduleForm')?.addEventListener('submit',event=>{event.preventDefault();action(reviewSchedule);});
    $('closeScheduleReview')?.addEventListener('click',()=>{if(!busy){$('scheduleReview').close();schedulePreview=null;}});
    $('scheduleReview')?.addEventListener('cancel',event=>{if(busy)event.preventDefault();else schedulePreview=null;});
    $('scheduleStartForm')?.addEventListener('submit',event=>{event.preventDefault();action(async()=>{
        try {
            if(!schedulePreview||$('scheduleConfirmation').value!==schedulePreview.confirmation)throw new Error(tr('error.confirmation_required'));
            const generation=authorizationGeneration;const intent=schedulePreview.intent;
            const headers=await authorize('automation.schedule',intent,generation);assertAuthorizationCurrent(generation);
            await api('/api/automation/schedules',{method:'POST',headers,body:{intent,confirmation:$('scheduleConfirmation').value}});assertAuthorizationCurrent(generation);
            schedulePreview=null;editingScheduleId=null;scheduleDraftInitialized=false;$('scheduleReview').close();tab('schedules');await loadSchedules();notify(tr('scheduleEnabled'));
        }catch(error){if(error.name==='AbortError')return;$('scheduleReviewError').textContent=error.message;$('scheduleReviewError').hidden=false;}
    });});
    document.querySelectorAll('[data-auto-tab]').forEach(button => { button.addEventListener('click', () => tab(button.dataset.autoTab)); });
    $('runbookForm').addEventListener('input', event => { if (!event.target.closest('.automation-source-picker')) changed(); });

    $('runbookForm').addEventListener('invalid', event => { const row = event.target.closest('.automation-step'); if (row) selectStep(row); }, true);
    $('runbookForm').addEventListener('submit', event => { event.preventDefault(); action(saveBook); });
    $('addStep').addEventListener('click', () => { if ($('runbookSteps').children.length < 20) { const row = stepElement(); $('runbookSteps').append(row); renumber(); changed(); selectStep(row, true); } });
    $('editorSource')?.addEventListener('change',previewEditorSource);
    $('addEditorSource')?.addEventListener('click',()=>action(async()=>{
        const source=editorSource();if(!source)return;
        const revision=editRevision,generation=authorizationGeneration,selection=$('editorSource').value;
        const first=$('runbookSteps').firstElementChild, detail=first&&stepDetails.get(first);
        const emptyStarter=$('runbookSteps').children.length===1 && !first.querySelector('[data-field="name"]').value
            && !detail.querySelector('[data-field="command"]').value && detail.querySelector('[data-field="timeout"]').value==='30'
            && !detail.querySelector('[data-field="sudo"]').checked;
        if($('runbookSteps').children.length-(emptyStarter?1:0)+source.steps.length>20)throw new Error(tr('editorSourceLimit'));
        if(source.libraryCommand?.parameters){
            const parameters=await question(tr('commandParameters'),tr('commandParametersHint'),{initialValue:source.libraryCommand.parameters,allowEmpty:true});
            if(parameters===null)return;
            source.steps[0].command=source.libraryCommand.command+(parameters?' '+parameters:'');
        }
        if(!await resolveSource(source))return;
        assertAuthorizationCurrent(generation);
        if(editRevision!==revision || $('editorSource').value!==selection || selectedTab!=='runbooks' || $('auto-runbooks').dataset.view!=='editor')throw new Error(tr('importChanged'));
        const rows=source.steps.map(step=>stepElement(step));
        if(emptyStarter)first.remove();
        $('runbookSteps').append(...rows);renumber();changed();selectStep(rows[0],true);
        notify(tr('editorSourceAdded',{count:rows.length}));
    }));
    $('newRunbook').addEventListener('click', () => action(async () => { if (await discardChanges()) { edit(); tab('runbooks'); $('runbookName').focus(); } }));
    $('workflowTemplate')?.addEventListener('change', previewTemplate);
    $('useWorkflowTemplate')?.addEventListener('click', () => action(async () => {
        const template = selectedTemplate();
        if (!template || !await discardChanges()) return;
        const importRevision = editRevision, importSelection = $('workflowTemplate').value;
        const importGeneration = authorizationGeneration;
        if (!await resolveSource(template)) return;
        assertAuthorizationCurrent(importGeneration);
        if (editRevision !== importRevision || $('workflowTemplate').value !== importSelection || selectedTab !== 'library') throw new Error(tr('importChanged'));
        const language = window.i18n?.getLanguage() === 'de' ? 'de' : 'en';
        edit({name:template.title[language],steps:template.steps,stop_on_error:true});
        $('editorTitle').textContent = tr('newRunbook'); changed(); tab('runbooks'); $('runbookName').focus();
    }));
    $('inventoryTemplate').addEventListener('click', () => action(async () => {
        if (await discardChanges()) { edit({name: tr('inventoryName'), steps: [{name:tr('inventoryStep'),command:'uname -a && uptime && df -hP',timeout:30,sudo:false}],stop_on_error:true}); changed(); tab('runbooks'); }
    }));
    async function deleteBook(book) {
        if (!book || (book.id === selectedId && !await discardChanges())) return;
        if (await question(tr('deleteRunbook'), book.name + '\n\n' + tr('deleteRunbookHint'), {confirm:true}) !== '') return;
        await api(`/api/automation/runbooks/${encodeURIComponent(book.id)}`, {method:'DELETE'});
        model.runbooks = model.runbooks.filter(item => item.id !== book.id);
        if (book.id === selectedId) edit(); else renderBooks();
        if ($('auto-library')) { tab('library'); $('runbookSearch').focus(); }
        notify(tr('deleted'));
    }
    $('deleteRunbook').addEventListener('click', () => action(() => deleteBook(model.runbooks.find(book => book.id === selectedId))));
    function filterTargets() {
        const search = $('targetSearch').value.toLowerCase();
        document.querySelectorAll('.automation-host[data-search]').forEach(row => { row.hidden = !row.dataset.search.includes(search); });
    }
    $('backToWorkflows')?.addEventListener('click', () => { tab('library'); $('runbookSearch').focus(); });
    $('toggleLibrary')?.addEventListener('click', () => {
        const open = $('toggleLibrary').getAttribute('aria-expanded') !== 'true';
        $('toggleLibrary').setAttribute('aria-expanded', String(open));
        document.querySelector('.automation-library').classList.toggle('is-open', open);
        if (open) $('runbookSearch').focus();
    });
    $('runbookSearch').addEventListener('input', renderBooks);
    document.querySelectorAll('[data-workspace-view]').forEach(button => button.addEventListener('click', () => {
        setStage(button.dataset.workspaceView, {focus:true});
    }));
    $('previousStage')?.addEventListener('click', () => setStage($('auto-runbooks').dataset.view === 'schedule' ? 'targets' : 'editor', {focus:true}));
    $('nextStage')?.addEventListener('click', () => {
        if ($('auto-runbooks').dataset.view === 'editor') setStage('targets', {focus:true});
        else openSchedule();
    });
    $('targetSearch').addEventListener('input', filterTargets);
    $('previewRun').addEventListener('click', () => action(review));
    $('reviewWorkspace')?.addEventListener('click', () => {
        if ($('auto-runbooks').dataset.inspector === 'schedule') $('scheduleForm').requestSubmit();
        else action(review);
    });
    $('closePreview').addEventListener('click', () => { if (!busy) { $('runPreview').close(); preview = null; } });
    $('runPreview').addEventListener('cancel', event => { if (busy) event.preventDefault(); else preview = null; });
    $('startRunForm').addEventListener('submit', event => {
        event.preventDefault(); action(async () => {
            if (!preview || $('runConfirmation').value !== preview.confirmation) throw new Error(tr('error.confirmation_required'));
            const generation = authorizationGeneration;
            const payload = {intent: preview.intent, confirmation: $('runConfirmation').value};
            const headers = await authorize('automation.run', payload.intent, generation);
            assertAuthorizationCurrent(generation);
            await api('/api/automation/start', {method:'POST',headers,body:payload});
            assertAuthorizationCurrent(generation);
            preview = null; $('runPreview').close(); tab('runs'); await loadRuns();
            assertAuthorizationCurrent(generation); notify(tr('runStarted'));
        }, {automationPreviewError:true});
    });
    $('promptForm').addEventListener('submit', event => { event.preventDefault(); settlePrompt($('promptSelect').hidden ? $('promptInput').value : $('promptSelect').value); });
    $('promptCancel').addEventListener('click', () => settlePrompt(null));
    $('automationPrompt').addEventListener('cancel', event => { event.preventDefault(); settlePrompt(null); });
    $('refreshRuns').addEventListener('click', () => action(loadRuns));
    $('clearRuns')?.addEventListener('click', () => action(clearRuns));
    window.addEventListener('pagehide', () => {
        document.querySelectorAll('input[type="password"]').forEach(input => { input.value = ''; });
    });
    window.addEventListener('beforeunload', event => { if (dirty) { event.preventDefault(); event.returnValue = ''; } });
    window.addEventListener('languageChanged', () => {
        const currentDraft = draft(); const wasDirty = dirty; const currentStage = $('auto-runbooks').dataset.view;
        translate(); if ($('scheduleFrequency')) updateScheduleBuilder({preserveCron:true}); edit(currentDraft, {preserveSchedule:true}); dirty = wasDirty; renderTargets(); setStage(currentStage, {animate:false});
        historySignature = ''; if (selectedTab === 'runs') action(loadRuns);
    });
    // Open a built-in template as an unsaved draft with the given hosts selected.
    // Used by the overview; nothing is saved or run without the usual review.
    function openTemplate(templateId, hostIds = []) {
        return action(async () => {
            window.primaryWorkspaceController?.open('automation', $('automationNativeView'));
            const template = window.AutomationTemplates?.create(templateId);
            if (!template || !await discardChanges()) return;
            if (!model.profiles.length) await loadState();
            const language = window.i18n?.getLanguage() === 'de' ? 'de' : 'en';
            edit({name: template.title[language], steps: template.steps, stop_on_error: true});
            changed(); tab('runbooks');
            const wanted = new Set(hostIds);
            document.querySelectorAll('#targetHosts input').forEach(input => { input.checked = !input.disabled && wanted.has(input.value); });
            updateTargetCount();
            notify(tr('templateOpenedFor', {count: [...document.querySelectorAll('#targetHosts input:checked')].length}));
        });
    }
    window.WebSSHAutomation = {openRun, openTemplate, getRunSnapshot, activate: () => action(async () => { try { await loadState(); } catch(error) { if(error.code !== 'disabled')throw error; availability(false); await loadSchedules(); return; } await loadSchedules(); if (selectedTab === 'runs') await loadRuns(); })};
    window.addEventListener('load',()=>{window.socket?.on('command_sets_list',()=>setTimeout(renderTemplates,0));window.socket?.on('commands_list',()=>setTimeout(renderEditorSources,0));renderTemplates();});
    translate(); edit();
    if (document.body.dataset.automationEnabled === 'true' || document.querySelector('main[data-native-automation]')?.dataset.automationEnabled === 'true' || nativeCredentials) {
        $('automationApp').inert = true;
        action(async () => {
            try {
                try { await loadState({initial:true}); tab(location.hash.slice(1)); await loadRuns(); await loadSchedules(); }
                catch(error) { if(error.code !== 'disabled' || !nativeCredentials)throw error; availability(false); await loadSchedules(); return; }
            }
            finally { $('automationApp').inert = false; }
        });
        setInterval(async () => {
            if (polling || busy || document.hidden) return;
            polling = true;
            try {
                if (!$('automationApp').hidden && (selectedTab === 'runs' || window.primaryWorkspaceController?.getActiveView() === 'overview')) await loadRuns();
                if (Date.now() - lastStateRefresh >= 15000) await loadState();
            } catch (error) { if (['disabled','authentication_required'].includes(error.code)) { knownRuns=[]; historySignature=''; runsEnabled=false; publishRunSnapshot(); } if(error.code !== 'disabled')notify(error.message,true); else if(nativeCredentials)$('automationDisabled').hidden=false; } finally { polling = false; }
        }, 3000);
    }
}());
