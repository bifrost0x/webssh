(function (root, factory) {
    const api = factory(root);
    if (typeof module === 'object' && module.exports) module.exports = api;
    if (root.document) root.HostContext = api;
}(typeof globalThis !== 'undefined' ? globalThis : this, function (root) {
    'use strict';

    function copy(value) { return JSON.parse(JSON.stringify(value)); }

    function createController(deps) {
        const drafts = new Map();
        let epoch = 0;
        const state = {profileId: null, sessionId: null, content: null, loading: false, dirty: false, error: null};
        const changed = () => deps.changed?.(state);
        function currentTarget() {
            const session = deps.getActiveSession?.();
            return session?.connected && session.id === state.sessionId
                && session.profileId === state.profileId ? session : null;
        }
        const controller = {
            state,
            currentTarget,
            async open(profileId, sessionId = null, reload = false) {
                const token = ++epoch;
                Object.assign(state, {profileId, sessionId, content: null, loading: Boolean(profileId), dirty: false, error: null});
                if (!profileId) { changed(); return; }
                if (drafts.has(profileId) && !reload) {
                    Object.assign(state, drafts.get(profileId), {loading: false});
                    changed();
                    return;
                }
                changed();
                try {
                    const content = await deps.request(profileId);
                    if (token !== epoch) return;
                    Object.assign(state, {content, loading: false});
                    drafts.set(profileId, {content, dirty: false, error: null});
                } catch (error) {
                    if (token !== epoch) return;
                    Object.assign(state, {loading: false, error: error.code || 'load_failed'});
                }
                changed();
            },
            update(patch) {
                if (!state.content) return;
                state.content = {...state.content, ...copy(patch)};
                state.dirty = true;
                drafts.set(state.profileId, {content: state.content, dirty: true, error: state.error});
                // Keep typing stable; the view only needs status changes here.
                deps.updated?.(state);
            },
            async save() {
                if (!state.content || state.loading || state.saving) return false;
                const profileId = state.profileId;
                const snapshot = copy(state.content);
                state.saving = true;
                changed();
                try {
                    const result = await deps.request(profileId, snapshot);
                    const draft = drafts.get(profileId);
                    const unchanged = JSON.stringify(draft?.content) === JSON.stringify(snapshot);
                    const content = unchanged ? result : {...draft.content, revision: result.revision};
                    const saved = {content, dirty: !unchanged, error: null};
                    drafts.set(profileId, saved);
                    if (state.profileId === profileId) Object.assign(state, saved);
                    return true;
                } catch (error) {
                    const draft = drafts.get(profileId);
                    if (draft) draft.error = error.code || 'save_failed';
                    if (state.profileId === profileId) state.error = error.code || 'save_failed';
                    return false;
                } finally {
                    state.saving = false;
                    changed();
                }
            },
            async directory(path) {
                const target = currentTarget();
                if (!target || !state.content?.directories.includes(path)) return false;
                const actionEpoch = epoch;
                return await deps.directory(target.id, path, () => epoch === actionEpoch && Boolean(currentTarget())) !== false;
            },
            async commandSet(id) {
                const target = currentTarget();
                if (!target || !state.content?.command_sets.includes(id)) return false;
                return await deps.commandSet(target.id, id) !== false;
            },
        };
        return controller;
    }

    const text = (key, fallback) => {
        const value = root.i18n?.t(`hostContext.${key}`);
        return value && value !== `hostContext.${key}` ? value : fallback;
    };
    let controller;
    let modal;
    let heading;
    const node = id => root.document.getElementById(id);
    const manager = () => typeof SessionManager !== 'undefined' ? SessionManager : root.SessionManager;
    const active = () => { const m = manager(); return m?.getSession(m.getActiveSession()); };
    const sets = () => root.CommandSetManager?.commandSets || [];

    function status(state) {
        node('hostContextStatus').textContent = !state.profileId ? '' : state.loading ? text('loading', 'Loading...')
            : state.saving ? text('saving', 'Saving...')
                : state.error ? text(state.error === 'conflict' ? 'conflict' : 'failed', state.error === 'conflict'
                    ? 'This host context changed elsewhere. Your draft is preserved. Copy your changes or discard and reload before saving again.'
                    : 'Host context could not be loaded or saved. Your draft is preserved. Check directory limits and assigned command sets, then retry.')
                    : state.dirty ? text('unsaved', 'Unsaved changes') : text('saved', 'Saved');
        node('hostContextSave').disabled = !state.content || state.loading || state.saving || !state.dirty;
        node('hostContextReload').disabled = !state.profileId || state.loading || state.saving;
    }

    function render(state) {
        status(state);
        const content = state.content;
        node('hostContextFields').hidden = !content;
        node('hostContextEmpty').hidden = Boolean(state.profileId);
        node('hostContextTarget').textContent = heading || text('title', 'Host context');
        node('hostContextNotes').value = content?.notes || '';
        node('hostContextDirectories').value = (content?.directories || []).join('\n');
        const launchers = node('hostContextLaunchers');
        const choices = node('hostContextSets');
        launchers.replaceChildren();
        choices.replaceChildren();
        const canAct = Boolean(controller.currentTarget());
        node('hostContextSessionHint').hidden = canAct;
        if (!content) return;
        for (const path of content.directories) {
            const button = root.document.createElement('button');
            button.type = 'button'; button.className = 'btn btn-secondary btn-sm';
            button.textContent = path;
            button.disabled = !canAct;
            button.addEventListener('click', async () => {
                if (!await controller.directory(path)) actionError();
            });
            launchers.appendChild(button);
        }
        const available = sets();
        const ids = new Set([...available.map(item => item.id), ...content.command_sets]);
        for (const id of ids) {
            const set = available.find(item => item.id === id);
            const row = root.document.createElement('div'); row.className = 'host-context-set';
            const label = root.document.createElement('label');
            const checkbox = root.document.createElement('input'); checkbox.type = 'checkbox';
            checkbox.checked = content.command_sets.includes(id);
            checkbox.addEventListener('change', () => {
                const selected = new Set(controller.state.content.command_sets);
                if (checkbox.checked) selected.add(id); else selected.delete(id);
                controller.update({command_sets: [...selected]});
                render(controller.state);
            });
            const name = root.document.createElement('span');
            name.textContent = set?.name || text('unavailableSet', 'Unavailable command set');
            label.append(checkbox, name); row.appendChild(label);
            if (content.command_sets.includes(id)) {
                const insert = root.document.createElement('button');
                insert.type = 'button'; insert.className = 'btn btn-secondary btn-sm';
                insert.textContent = text('insert', 'Open command set');
                insert.disabled = !set || !canAct;
                insert.addEventListener('click', async () => { if (!await controller.commandSet(id)) actionError(); });
                row.appendChild(insert);
            }
            choices.appendChild(row);
        }
    }

    function actionError() {
        node('hostContextStatus').textContent = text('targetChanged', 'The active SSH session changed or this action is unavailable. Open host context again for the intended session.');
    }

    async function request(profileId, body) {
        const appRoot = root.document.querySelector('meta[name="app-root"]')?.content || '';
        const response = await root.fetch(`${appRoot}/api/profiles/${encodeURIComponent(profileId)}/context`, {
            method: body ? 'PUT' : 'GET', credentials: 'same-origin',
            headers: body ? {'Content-Type': 'application/json', 'X-CSRFToken': root.document.querySelector('meta[name="csrf-token"]')?.content || ''} : {},
            ...(body ? {body: JSON.stringify(body)} : {}),
        });
        const data = await response.json();
        if (!response.ok) throw Object.assign(new Error(), {code: data.code});
        return data;
    }

    function init() {
        modal = node('hostContextModal');
        if (!modal || controller) return;
        controller = createController({request, changed: render, updated: status, getActiveSession: active,
            directory: async (sessionId, path, valid) => {
                const fm = root.getSFTPFileManager?.();
                if (!fm || !valid()) return false;
                root.ModalManager.close(modal);
                fm.open();
                await fm.onSourceChange('left', `sftp-session:${sessionId}`);
                if (!valid() || fm.getPaneSourceId('left') !== `sftp-session:${sessionId}`) return false;
                // A favorite navigates files only; terminal folder sync is an independent choice.
                await fm.navigatePaneTo('left', path, {directorySync: true});
                return true;
            },
            commandSet: (sessionId, id) => {
                const launcher = root.SessionCommandLauncher;
                if (!sets().some(set => set.id === id) || !launcher) return false;
                root.ModalManager.close(modal);
                root.primaryWorkspaceController?.showWorkspaces?.();
                root.workspaceLayoutController?.openContext('commands', 'user');
                launcher.open(sessionId);
                launcher.searchQuery = sets().find(set => set.id === id).name;
                launcher.render();
                return true;
            },
        });
        node('hostContextClose').addEventListener('click', () => root.ModalManager.close(modal));
        node('hostContextSave').addEventListener('click', () => controller.save());
        node('hostContextReload').addEventListener('click', () => controller.open(controller.state.profileId, controller.state.sessionId, true));
        node('hostContextNotes').addEventListener('input', event => controller.update({notes: event.target.value}));
        node('hostContextDirectories').addEventListener('input', event => controller.update({directories: event.target.value.split('\n').filter(Boolean)}));
        node('activeHostContextBtn')?.addEventListener('click', () => openActive());
    }

    function open(profileId, label) {
        init();
        const session = active();
        heading = label || text('title', 'Host context');
        root.ModalManager.open(modal);
        controller.open(profileId, session?.profileId === profileId ? session.id : null);
    }

    function openActive() {
        const session = active();
        open(session?.profileId || null, session ? `${session.username}@${session.host}:${session.port}` : null);
    }

    return {createController, init, open, openActive};
}));
