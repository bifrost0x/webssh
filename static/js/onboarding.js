/* First-login orientation uses the same navigation and account settings as the app. */
(() => {
    'use strict';
    // English text is the fallback when the translator or a key is missing.
    const t = (key, fallback) => { const value = window.i18n?.t?.(key); return value && value !== key ? value : fallback; };
    // [anchor element, wiki page, English title, English body]; keys are tour.stepNTitle / tour.stepNBody.
    const steps = [
        ['overviewNavBtn', 'Home', 'Your WebSSH', 'Eight steps introduce the workspaces and enabled features of this instance. The tour does not connect to servers or change configuration.'],
        ['manageProfilesBtn', 'Profiles-Jump-Hosts-and-Commands', 'Hosts and credentials', 'Save servers, groups and jump hosts here. Associate SSH keys or saved passwords with a connection. Password storage must first be enabled by an administrator.'],
        ['workspaceNavBtn', 'Terminal-and-Persistent-tmux-Sessions', 'Your terminal at the center', 'Open a host to work in a workspace. Files, notes and diagnostics on the right belong to the selected session. SSH permissions are granted by the destination server, not WebSSH.'],
        ['fileTransferBtn', 'SFTP-File-Workspace-and-Transfers', 'Files in the right context', 'Choose a connected session before editing or transferring files. SFTP uses its SSH permissions. SMB is a separate, optional source.'],
        ['commandLibraryBtn', 'Profiles-Jump-Hosts-and-Commands', 'Reuse commands', 'The library contains commands and your command sets. Review the destination and parameters before execution. Saving a command does not execute it.'],
        ['automationNavBtn', 'Administration-Audit-and-Diagnostics', 'Automate workflows', 'Build a workflow from templates, commands or command sets. Select hosts, then run it explicitly or create a schedule. Find results and logs under Runs. Automation remains disabled until an administrator enables it.'],
        ['overviewNavBtn', 'Configuration-Reference', 'What is enabled here?', 'These are the effective values. Deployment options come from the environment, often Compose. Passwords, automation and registration are managed in Administration. The Compose file itself is not inspected.'],
        ['overviewNavBtn', 'Security-Model-and-Hardening', 'Permissions and security boundaries', 'WebSSH knows your role and active authentication features. Host mounts, Docker privileges and remote sudo rights cannot reliably be inferred from these values. Verify them in your deployment and on the destination. Backup exports omit saved passwords and SSH keys.'],
    ];
    const wiki = 'https://github.com/bifrost0x/webssh/wiki/';
    const featureDocs = {SMB_ENABLED:'SFTP-File-Workspace-and-Transfers', SFTP_CHMOD_ENABLED:'SFTP-File-Workspace-and-Transfers#unix-permissions', SERVER_OPERATIONS_ENABLED:'Administration-Audit-and-Diagnostics', TMUX_ENABLED:'Terminal-and-Persistent-tmux-Sessions', TAILSCALE_SSH_ENABLED:'Tailscale-SSH', credentials_enabled:'Profiles-Jump-Hosts-and-Commands', automation_enabled:'Administration-Audit-and-Diagnostics', registration_enabled:'Users-and-Account-Management', OIDC_ENABLED:'OpenID-Connect', LDAP_ENABLED:'LDAP-and-Active-Directory', TOTP_ENABLED:'Authentication-Overview', WEBAUTHN_ENABLED:'Passkeys-and-Recovery-Codes', SESSION_COOKIE_SECURE:'Production-Deployment', BOOTSTRAP_REGISTRATION_ENABLED:'Quick-Start'};
    // Same prefix source as the other modules: document.baseURI breaks under a
    // URL prefix opened without a trailing slash.
    const appRoot = (document.querySelector('meta[name="app-root"]')?.content || '').replace(/\/$/, '');
    const api = new URL(appRoot + '/api/account/tour', window.location.origin);
    let state, index = 0, dialog, target;
    const node = (tag, text, className) => { const el = document.createElement(tag); if (text) el.textContent = text; if (className) el.className = className; return el; };
    const button = (text, handler, primary = false) => { const el = node('button', text, `btn ${primary ? 'btn-primary' : 'btn-secondary'}`); el.type = 'button'; el.addEventListener('click', handler); return el; };
    async function load() { const r = await fetch(api, {credentials: 'same-origin'}); if (!r.ok) throw Error('tour'); return r.json(); }
    async function finish(value) {
        const buttons = [...dialog.querySelectorAll('button')]; buttons.forEach(b => { b.disabled = true; });
        try {
            const r = await fetch(api, {method: 'POST', headers: {'Content-Type': 'application/json', 'X-CSRFToken': document.querySelector('meta[name="csrf-token"]').content}, body: JSON.stringify({state: value, acknowledged: value === 'completed' && dialog.querySelector('#introAcknowledge')?.checked === true})});
            if (!r.ok) throw Error('save');
            target?.classList.remove('intro-target'); dialog.close(); dialog.remove(); dialog = null;
            const next = [document.getElementById('overviewNavBtn'), document.getElementById('overviewTitle')].find(element => element?.offsetParent);
            next?.focus();
        } catch {
            buttons.forEach(b => { b.disabled = false; });
            if (!dialog.querySelector('.intro-error')) { const error = node('p', t('tour.saveError', 'Could not save progress. Please try again.'), 'intro-error'); error.role = 'alert'; dialog.append(error); }
        }
    }
    // A language switch redraws the open dialog without re-clicking the anchor or losing the acknowledgement.
    function render(refresh = false) {
        const acknowledged = dialog.querySelector('#introAcknowledge')?.checked === true;
        target?.classList.remove('intro-target');
        const [id, docPage, titleFallback, bodyFallback] = steps[index];
        const doc = docPage;
        const title = t(`tour.step${index + 1}Title`, titleFallback);
        const body = t(`tour.step${index + 1}Body`, bodyFallback);
        target = document.getElementById(id);
        // The disabled feature is still explained without pretending it is available.
        if (!refresh) target?.click();
        target?.classList.add('intro-target');
        dialog.replaceChildren();
        const header = node('header'); header.append(node('span', `${index + 1} / ${steps.length}`), button(t('tour.skip', 'Skip tour'), () => finish('dismissed')));
        const progress = node('progress'); progress.max = steps.length; progress.value = index + 1; progress.setAttribute('aria-label', t('tour.progress', 'Progress'));
        const heading = node('h2', title); heading.id = 'introTitle'; heading.tabIndex = -1;
        dialog.append(header, progress, heading, node('p', body));
        if (index >= 6) {
            if (index === 7) dialog.append(node('p', `${t('tour.role', 'Your role')}: ${state.administrator ? t('tour.roleAdministrator', 'Administrator') : t('tour.roleUser', 'User')}.${state.administrator ? ` ${t('tour.processRoot', 'WebSSH process as root')}: ${state.process_root === null ? t('tour.unknown', 'Unknown') : state.process_root ? t('tour.yes', 'Yes') : t('tour.no', 'No')}.` : ''}`));
            const auth = ['OIDC_ENABLED', 'LDAP_ENABLED', 'TOTP_ENABLED', 'WEBAUTHN_ENABLED', 'SESSION_COOKIE_SECURE', 'BOOTSTRAP_REGISTRATION_ENABLED'];
            const names = {
                SMB_ENABLED: t('tour.feature.smb', 'SMB file sources'), SFTP_CHMOD_ENABLED: t('tour.feature.chmod', 'Change file permissions'),
                SERVER_OPERATIONS_ENABLED: t('tour.feature.serverOperations', 'Server operations'), TMUX_ENABLED: t('tour.feature.tmux', 'Persistent terminals'),
                TAILSCALE_SSH_ENABLED: 'Tailscale SSH', credentials_enabled: t('tour.feature.credentials', 'Saved passwords'),
                automation_enabled: 'Automation', registration_enabled: t('tour.feature.registration', 'Further registrations'),
                OIDC_ENABLED: 'OpenID Connect', LDAP_ENABLED: 'LDAP', TOTP_ENABLED: 'TOTP', WEBAUTHN_ENABLED: 'Passkeys',
                SESSION_COOKIE_SECURE: t('tour.feature.secureCookies', 'HTTPS session cookies'), BOOTSTRAP_REGISTRATION_ENABLED: t('tour.feature.bootstrapRegistration', 'First-account registration'),
            };
            const list = node('dl');
            state.facts.filter(f => (index === 7) === auth.includes(f.key)).forEach(f => {
                const row = node('div'); const term = node('dt'); const link = node('a', names[f.key] || f.key);
                link.href = wiki + (featureDocs[f.key] || doc); link.target = '_blank'; link.rel = 'noopener noreferrer'; term.append(link, node('small', f.key));
                row.append(term, node('dd', f.enabled ? t('tour.enabled', 'Enabled') : f.configured ? t('tour.availableNotEnabled', 'Available, not enabled') : t('tour.disabled', 'Disabled'))); list.append(row);
            }); dialog.append(list);
        }
        const links = node('div', '', 'intro-links'); const help = node('a', t('tour.openDocs', 'Open documentation')); help.href = wiki + doc; help.target = '_blank'; help.rel = 'noopener noreferrer'; links.append(help);
        if (state.admin_url && index >= 6) { const admin = node('a', t('tour.openAdmin', 'Open Administration')); admin.href = state.admin_url; admin.target = '_blank'; admin.rel = 'noopener noreferrer'; links.append(admin); }
        const footer = node('footer'); const back = button(t('tour.back', 'Back'), () => { index--; render(); }); back.disabled = index === 0;
        footer.append(back, button(index === 7 ? t('tour.getStarted', 'Get started') : t('tour.next', 'Next'), () => { if (index === 7) finish('completed'); else { index++; render(); } }, true));
        dialog.append(links);
        if (index === 7) {
            const label = node('label'); const check = node('input'); check.type = 'checkbox'; check.id = 'introAcknowledge'; check.checked = acknowledged;
            label.append(check, document.createTextNode(` ${t('tour.acknowledge', 'I have read the introduction and reviewed the settings shown.')}`));
            // The acknowledgement sits in the sticky footer next to the button it unlocks, so it is visible on small screens.
            label.className = 'intro-acknowledge'; const done = footer.lastElementChild; done.disabled = !check.checked; check.addEventListener('change', () => { done.disabled = !check.checked; }); footer.prepend(label);
        }
        dialog.append(footer); heading.focus(); dialog.scrollTop = 0;
    }
    function start() {
        if (dialog) return;
        index = 0; dialog = node('dialog', '', 'intro-tour'); dialog.setAttribute('aria-labelledby', 'introTitle');
        dialog.addEventListener('cancel', event => { event.preventDefault(); finish('dismissed'); });
        document.body.append(dialog); dialog.showModal(); render();
    }
    async function init() {
        const restart = document.getElementById('restartTour'); if (!restart) return;
        const label = () => { restart.lastElementChild.textContent = t('tour.productTour', 'Product tour'); };
        label();
        window.addEventListener('languageChanged', () => { label(); if (dialog && state) render(true); });
        restart.addEventListener('click', async () => { try { state = await load(); start(); } catch { window.alert(t('tour.loadError', 'Could not load tour. Please try again.')); } });
        try { state = await load(); if (state.state === 'new') start(); } catch { /* A failed optional tour must not block normal work. The menu allows retry. */ }
    }
    if (document.readyState === 'complete') init(); else window.addEventListener('load', init, {once: true});
})();
