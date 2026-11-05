/* First-login orientation uses the same navigation and account settings as the app. */
(() => {
    'use strict';
    const de = window.i18n?.getLanguage?.() === 'de';
    const t = (german, english) => de ? german : english;
    const steps = [
        ['overviewNavBtn', t('Dein WebSSH', 'Your WebSSH'), t('In acht Schritten lernst du die Arbeitsbereiche und die aktiven Funktionen dieser Instanz kennen. Die Tour verbindet sich mit keinem Server und ändert keine Einstellungen.', 'Eight steps introduce the workspaces and enabled features of this instance. The tour does not connect to servers or change configuration.'), 'Home'],
        ['manageProfilesBtn', t('Hosts und Zugänge', 'Hosts and credentials'), t('Speichere Server, Gruppen und Jump Hosts hier. SSH-Schlüssel und gespeicherte Kennwörter werden einem Zugang zugeordnet. Kennwortspeicherung muss zuvor im Adminbereich aktiviert werden.', 'Save servers, groups and jump hosts here. Associate SSH keys or saved passwords with a connection. Password storage must first be enabled by an administrator.'), 'Profiles-Jump-Hosts-and-Commands'],
        ['workspaceNavBtn', t('Dein Terminal im Mittelpunkt', 'Your terminal at the center'), t('Öffne einen Host, um im Workspace zu arbeiten. Rechts findest du Dateien, Notizen und Diagnose für die gewählte Sitzung. SSH-Rechte werden vom Zielserver vergeben, nicht von WebSSH.', 'Open a host to work in a workspace. Files, notes and diagnostics on the right belong to the selected session. SSH permissions are granted by the destination server, not WebSSH.'), 'Terminal-and-Persistent-tmux-Sessions'],
        ['fileTransferBtn', t('Dateien im richtigen Kontext', 'Files in the right context'), t('Wähle eine verbundene Sitzung, bevor du Dateien bearbeitest oder überträgst. SFTP verwendet deren SSH-Rechte. SMB ist eine getrennte, optionale Quelle.', 'Choose a connected session before editing or transferring files. SFTP uses its SSH permissions. SMB is a separate, optional source.'), 'SFTP-File-Workspace-and-Transfers'],
        ['commandLibraryBtn', t('Befehle wiederverwenden', 'Reuse commands'), t('Die Bibliothek enthält Befehle und eigene Command Sets. Prüfe Ziel und Parameter vor dem Ausführen. Ein gespeicherter Befehl wird nicht automatisch ausgeführt.', 'The library contains commands and your command sets. Review the destination and parameters before execution. Saving a command does not execute it.'), 'Profiles-Jump-Hosts-and-Commands'],
        ['automationNavBtn', t('Abläufe automatisieren', 'Automate workflows'), t('Baue einen Workflow aus Vorlagen, Befehlen oder Command Sets. Wähle Hosts und starte ihn bewusst oder lege einen Zeitplan an. Ergebnisse und Logs findest du unter Runs. Ohne Admin-Freigabe bleibt Automation deaktiviert.', 'Build a workflow from templates, commands or command sets. Select hosts, then run it explicitly or create a schedule. Find results and logs under Runs. Automation remains disabled until an administrator enables it.'), 'Administration-Audit-and-Diagnostics'],
        ['overviewNavBtn', t('Was ist hier aktiviert?', 'What is enabled here?'), t('Dies sind die aktuell wirksamen Werte. Deployment-Optionen werden über die Umgebung, häufig Compose, gesetzt. Kennwörter, Automation und Registrierung werden im Adminbereich verwaltet. Die Compose-Datei selbst wird nicht gelesen.', 'These are the effective values. Deployment options come from the environment, often Compose. Passwords, automation and registration are managed in Administration. The Compose file itself is not inspected.'), 'Configuration-Reference'],
        ['overviewNavBtn', t('Rechte und Sicherheitsgrenzen', 'Permissions and security boundaries'), t('WebSSH kennt deine Rolle und die aktiven Anmeldefunktionen. Host-Mounts, Docker-Rechte und entfernte sudo-Rechte lassen sich daraus nicht verlässlich ableiten. Prüfe sie in deiner Bereitstellung und auf dem Zielserver. Backup-Exporte enthalten keine gespeicherten Kennwörter oder SSH-Schlüssel.', 'WebSSH knows your role and active authentication features. Host mounts, Docker privileges and remote sudo rights cannot reliably be inferred from these values. Verify them in your deployment and on the destination. Backup exports omit saved passwords and SSH keys.'), 'Security-Model-and-Hardening'],
    ];
    const wiki = 'https://github.com/bifrost0x/webssh/wiki/';
    const featureDocs = {SMB_ENABLED:'SFTP-File-Workspace-and-Transfers', SFTP_CHMOD_ENABLED:'SFTP-File-Workspace-and-Transfers#unix-permissions', SERVER_OPERATIONS_ENABLED:'Administration-Audit-and-Diagnostics', TMUX_ENABLED:'Terminal-and-Persistent-tmux-Sessions', TAILSCALE_SSH_ENABLED:'Tailscale-SSH', credentials_enabled:'Profiles-Jump-Hosts-and-Commands', automation_enabled:'Administration-Audit-and-Diagnostics', registration_enabled:'Users-and-Account-Management', OIDC_ENABLED:'OpenID-Connect', LDAP_ENABLED:'LDAP-and-Active-Directory', TOTP_ENABLED:'Authentication-Overview', WEBAUTHN_ENABLED:'Passkeys-and-Recovery-Codes', SESSION_COOKIE_SECURE:'Production-Deployment', BOOTSTRAP_REGISTRATION_ENABLED:'Quick-Start'};
    const api = new URL('api/account/tour', document.baseURI);
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
            document.getElementById('overviewNavBtn')?.focus();
        } catch {
            buttons.forEach(b => { b.disabled = false; });
            if (!dialog.querySelector('.intro-error')) { const error = node('p', t('Fortschritt konnte nicht gespeichert werden. Bitte erneut versuchen.', 'Could not save progress. Please try again.'), 'intro-error'); error.role = 'alert'; dialog.append(error); }
        }
    }
    function render() {
        target?.classList.remove('intro-target');
        const [id, title, body, doc] = steps[index];
        target = document.getElementById(id);
        // The disabled feature is still explained without pretending it is available.
        target?.click();
        target?.classList.add('intro-target');
        dialog.replaceChildren();
        const header = node('header'); header.append(node('span', `${index + 1} / ${steps.length}`), button(t('Tour beenden', 'Skip tour'), () => finish('dismissed')));
        const progress = node('progress'); progress.max = steps.length; progress.value = index + 1; progress.setAttribute('aria-label', t('Fortschritt', 'Progress'));
        const heading = node('h2', title); heading.id = 'introTitle'; heading.tabIndex = -1;
        dialog.append(header, progress, heading, node('p', body));
        if (index >= 6) {
            if (index === 7) dialog.append(node('p', `${t('Deine Rolle', 'Your role')}: ${state.administrator ? t('Administrator', 'Administrator') : t('Benutzer', 'User')}. ${t('WebSSH-Prozess als root', 'WebSSH process as root')}: ${state.process_root === null ? t('Unbekannt', 'Unknown') : state.process_root ? t('Ja', 'Yes') : t('Nein', 'No')}.`));
            const auth = ['OIDC_ENABLED', 'LDAP_ENABLED', 'TOTP_ENABLED', 'WEBAUTHN_ENABLED', 'SESSION_COOKIE_SECURE', 'BOOTSTRAP_REGISTRATION_ENABLED'];
            const names = {
                SMB_ENABLED: t('SMB-Dateiquellen', 'SMB file sources'), SFTP_CHMOD_ENABLED: t('Dateirechte ändern', 'Change file permissions'),
                SERVER_OPERATIONS_ENABLED: t('Serveraktionen', 'Server operations'), TMUX_ENABLED: t('Persistente Terminals', 'Persistent terminals'),
                TAILSCALE_SSH_ENABLED: 'Tailscale SSH', credentials_enabled: t('Kennwörter speichern', 'Saved passwords'),
                automation_enabled: 'Automation', registration_enabled: t('Weitere Registrierungen', 'Further registrations'),
                OIDC_ENABLED: 'OpenID Connect', LDAP_ENABLED: 'LDAP', TOTP_ENABLED: 'TOTP', WEBAUTHN_ENABLED: 'Passkeys',
                SESSION_COOKIE_SECURE: t('HTTPS-Sitzungscookies', 'HTTPS session cookies'), BOOTSTRAP_REGISTRATION_ENABLED: t('Erstes Konto registrieren', 'First-account registration'),
            };
            const list = node('dl');
            state.facts.filter(f => (index === 7) === auth.includes(f.key)).forEach(f => {
                const row = node('div'); const term = node('dt'); const link = node('a', names[f.key] || f.key);
                link.href = wiki + (featureDocs[f.key] || doc); link.target = '_blank'; link.rel = 'noopener noreferrer'; term.append(link, node('small', f.key));
                row.append(term, node('dd', f.enabled ? t('Aktiviert', 'Enabled') : f.configured ? t('Bereit, nicht freigegeben', 'Available, not enabled') : t('Deaktiviert', 'Disabled'))); list.append(row);
            }); dialog.append(list);
        }
        const links = node('div', '', 'intro-links'); const help = node('a', t('Dokumentation öffnen', 'Open documentation')); help.href = wiki + doc; help.target = '_blank'; help.rel = 'noopener noreferrer'; links.append(help);
        if (state.admin_url && index >= 6) { const admin = node('a', t('Adminbereich öffnen', 'Open Administration')); admin.href = state.admin_url; admin.target = '_blank'; admin.rel = 'noopener noreferrer'; links.append(admin); }
        const footer = node('footer'); const back = button(t('Zurück', 'Back'), () => { index--; render(); }); back.disabled = index === 0;
        footer.append(back, button(index === 7 ? t('Loslegen', 'Get started') : t('Weiter', 'Next'), () => { if (index === 7) finish('completed'); else { index++; render(); } }, true));
        dialog.append(links);
        if (index === 7) {
            const label = node('label'); const check = node('input'); check.type = 'checkbox'; check.id = 'introAcknowledge';
            label.append(check, document.createTextNode(t(' Ich habe die Einführung und die angezeigten Einstellungen zur Kenntnis genommen.', ' I have read the introduction and reviewed the settings shown.')));
            const done = footer.lastElementChild; done.disabled = true; check.addEventListener('change', () => { done.disabled = !check.checked; }); dialog.append(label);
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
        restart.lastElementChild.textContent = t('Produkttour', 'Product tour');
        restart.addEventListener('click', async () => { try { state = await load(); start(); } catch { window.alert(t('Tour konnte nicht geladen werden. Bitte erneut versuchen.', 'Could not load tour. Please try again.')); } });
        try { state = await load(); if (state.state === 'new') start(); } catch { /* A failed optional tour must not block normal work. The menu allows retry. */ }
    }
    if (document.readyState === 'complete') init(); else window.addEventListener('load', init, {once: true});
})();
