(function (root, factory) {
    'use strict';
    const api = factory();
    if (typeof module === 'object' && module.exports) { module.exports = api; }
    if (root?.document) {
        root.WebSSHAccountControls = api;
        if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', api.init);
        else api.init();
    }
})(typeof window === 'undefined' ? null : window, function () {
    'use strict';
    const defaultT = (_key, fallback) => fallback;
    const translate = (key, fallback) => {
        const value = window.i18n?.t(key);
        return value && value !== key ? value : fallback;
    };
    function format(text, values) {
        return text.replace(/\{(\w+)\}/g, (match, name) => values[name] ?? match);
    }
    function methodLabel(method, t = defaultT) {
        const labels = {password:'Password', passkey:'Passkey', totp:'Authenticator app', recovery:'Recovery codes',
            recovery_code:'Recovery code', oidc:'Identity provider', ldap:'LDAP', github:'GitHub'};
        return t(`accountControls.method.${method}`, labels[method] || method);
    }
    function featureImpactLines(impact, t = defaultT) {
        const counts = values => Object.entries(values || {}).map(([name, count]) => `${methodLabel(name, t)}: ${count}`).join(', ')
            || t('accountControls.none', 'None');
        return [
            format(t('accountControls.affected', 'Affected accounts: {accounts}; administrators: {admins}; already locked: {locked}.'),
                {accounts:impact.affected_accounts, admins:impact.affected_admins, locked:impact.locked_affected_accounts}),
            t('accountControls.primary', 'Remaining configured primary sign-in paths (unlocked affected accounts): ') + counts(impact.remaining_primary),
            t('accountControls.factors', 'Remaining configured local factors / recovery paths: ') + counts(impact.remaining_factors),
            format(t('accountControls.noPrimary', 'Without a configured primary path: {accounts}; administrators: {admins}.'),
                {accounts:impact.accounts_without_primary, admins:impact.admins_without_primary}),
            format(t('accountControls.noMfa', 'MFA required but no remaining local Passkey/TOTP: {accounts}; administrators: {admins}.'),
                {accounts:impact.mfa_required_without_local_factor, admins:impact.admins_without_local_factor}),
            t('accountControls.unverified', 'These paths are configured, not tested. An identity provider may supply MFA; its availability and assurance have not been verified. Recovery codes allow restricted repair only. Test an alternative sign-in before disabling a method.'),
            t('accountControls.featureEffect', 'Existing browser, SSH and tmux sessions are not terminated. New sign-ins and factor setup use the changed rule immediately.'),
        ];
    }
    function deletionConfirmation(username, t = defaultT) {
        return format(t('accountControls.delete', 'Delete account "{user}"? Its access will be revoked and its account removed. User files are retained in quarantine until an operator explicitly removes them.'), {user:username});
    }
    function confirmFeatureImpact(preview, label, t = translate) {
        return new Promise(resolve => {
            const previous = document.activeElement;
            const dialog = document.createElement('dialog');
            dialog.className = 'account-impact-dialog';
            const title = document.createElement('h2');
            title.id = 'accountImpactTitle';
            title.textContent = format(t('accountControls.disableTitle', 'Disable {feature}?'), {feature:label});
            dialog.setAttribute('aria-labelledby', title.id);
            dialog.append(title);
            const body = document.createElement('div');
            body.className = 'account-impact-body';
            const counts = document.createElement('dl');
            counts.className = 'account-impact-counts';
            for (const [key, fallback, count] of [
                ['affectedAccounts', 'Accounts affected', preview.impact.affected_accounts],
                ['affectedAdmins', 'Administrators', preview.impact.affected_admins],
                ['withoutPrimary', 'Without primary path', preview.impact.accounts_without_primary],
            ]) {
                const group = document.createElement('div');
                const term = document.createElement('dt'); term.textContent = t(`accountControls.${key}`, fallback);
                const value = document.createElement('dd'); value.textContent = count;
                group.append(term, value); counts.append(group);
            }
            body.append(counts);
            if (preview.impact.mfa_required_without_local_factor > 0) {
                const warning = document.createElement('p');
                warning.className = 'account-impact-warning';
                warning.textContent = format(t('accountControls.noMfa', 'MFA required but no remaining local Passkey/TOTP: {accounts}; administrators: {admins}.'),
                    {accounts:preview.impact.mfa_required_without_local_factor, admins:preview.impact.admins_without_local_factor});
                body.append(warning);
            }
            const unverified = document.createElement('p');
            unverified.textContent = t('accountControls.configuredOnly', 'Configured, not tested. Test an alternative sign-in first; provider availability and MFA have not been verified.');
            const effect = document.createElement('p');
            effect.textContent = t('accountControls.featureEffect', 'Existing browser, SSH and tmux sessions are not terminated. New sign-ins and factor setup use the changed rule immediately.');
            body.append(unverified, effect);
            const details = document.createElement('details');
            const summary = document.createElement('summary');
            summary.textContent = t('accountControls.affectedList', 'Review affected accounts');
            details.append(summary);
            for (const line of featureImpactLines(preview.impact, t).slice(0, 6)) {
                const paragraph = document.createElement('p'); paragraph.textContent = line; details.append(paragraph);
            }
            if (preview.impact.accounts?.length) {
                const list = document.createElement('ul');
                list.className = 'account-impact-accounts';
                preview.impact.accounts.forEach(account => {
                    const item = document.createElement('li');
                    const name = document.createElement('strong');
                    name.textContent = account.username;
                    if (account.admin) name.textContent += ` · ${t('accountControls.admin', 'Administrator')}`;
                    if (account.locked) name.textContent += ` · ${t('accountControls.locked', 'Locked')}`;
                    if (account.mfa_required) name.textContent += ' · MFA';
                    const paths = document.createElement('p');
                    const describe = methods => methods.map(method => methodLabel(method, t)).join(', ') || t('accountControls.none', 'None');
                    paths.textContent = format(t('accountControls.accountPaths', 'Primary: {primary} · Factors / recovery: {factors}'),
                        {primary:describe(account.remaining_primary), factors:describe(account.remaining_factors)});
                    item.append(name, paths); list.append(item);
                });
                details.append(list);
            }
            body.append(details); dialog.append(body);
            const actions = document.createElement('div');
            actions.className = 'account-controls-actions';
            const cancel = document.createElement('button');
            cancel.className = 'btn btn-secondary';
            cancel.textContent = t('common.cancel', 'Cancel');
            const confirm = document.createElement('button');
            confirm.className = 'btn btn-danger';
            confirm.textContent = t('accountControls.continue', 'Continue to authentication');
            const finish = approved => {
                dialog.close(); dialog.remove(); previous?.focus(); resolve(approved);
            };
            cancel.addEventListener('click', () => finish(false));
            confirm.addEventListener('click', () => finish(true));
            dialog.addEventListener('cancel', event => { event.preventDefault(); finish(false); });
            actions.append(cancel, confirm); dialog.append(actions); document.body.append(dialog);
            dialog.showModal(); cancel.focus();
        });
    }
    function init() {
        const list = document.getElementById('accountLoginList');
        if (!list) return;
        const status = document.getElementById('accountLoginStatus');
        const others = document.getElementById('accountRevokeOthers');
        const refresh = document.getElementById('accountRefreshLogins');
        const appRoot = (document.querySelector('meta[name="app-root"]')?.content || '').replace(/\/$/, '');
        const csrf = document.querySelector('meta[name="csrf-token"]')?.content || '';
        let busy = false;
        let rows = [];
        async function api(path, body) {
            const response = await fetch(appRoot + path, {method:body ? 'POST' : 'GET',
                headers:{Accept:'application/json', 'Content-Type':'application/json', 'X-CSRFToken':csrf},
                ...(body ? {body:JSON.stringify(body)} : {})});
            const data = await response.json();
            if (!response.ok) throw new Error(translate('accountControls.failed', 'Could not update logins. Refresh and try again.'));
            return data;
        }
        const timestamp = value => new Date(value).toLocaleString(document.documentElement.lang || undefined);
        function render() {
            list.replaceChildren();
            rows.forEach(row => {
                const item = document.createElement('li'); item.className = 'account-login-row';
                const details = document.createElement('div');
                const heading = document.createElement('strong');
                heading.textContent = row.methods.map(method => methodLabel(method, translate)).join(' + ');
                if (row.current) heading.textContent += ` · ${translate('accountControls.current', 'This login')}`;
                const dates = document.createElement('p'); dates.className = 'admin-muted';
                dates.textContent = format(translate('accountControls.dates', 'Started: {start} · Expires: {expiry}'),
                    {start:timestamp(row.started_at), expiry:timestamp(row.expires_at)});
                details.append(heading, dates); item.append(details);
                if (!row.current) {
                    const button = document.createElement('button'); button.className = 'btn btn-danger';
                    button.textContent = translate('accountControls.revoke', 'Revoke login');
                    button.setAttribute('aria-label', `${button.textContent}: ${heading.textContent}, ${timestamp(row.started_at)}`);
                    button.addEventListener('click', () => revoke({session:row.handle}, dates.textContent));
                    item.append(button);
                }
                list.append(item);
            });
            others.disabled = busy || !rows.some(row => !row.current);
        }
        async function load() {
            if (busy) return;
            busy = true; refresh.disabled = true; others.disabled = true;
            try { rows = (await api('/api/account/sessions')).sessions; status.textContent = ''; render(); }
            catch (error) { status.textContent = error.message; }
            finally { busy = false; refresh.disabled = false; others.disabled = !rows.some(row => !row.current); }
        }
        async function revoke(body, details) {
            if (busy) return;
            const warning = translate('accountControls.confirmRevoke', 'Revoke this access? The selected browser connections, their transfers and login-bound jobs will stop. Shared SSH/tmux sessions remain available to valid logins.');
            if (!window.confirm(`${details || translate('accountControls.others', 'All other logins')}\n\n${warning}`)) return;
            busy = true; refresh.disabled = true; others.disabled = true;
            list.querySelectorAll('button').forEach(button => { button.disabled = true; });
            let message = '';
            try {
                const result = await api('/api/account/sessions/revoke', body);
                message = result.cleanup_incomplete
                    ? translate('accountControls.cleanupWarning', 'Login access was revoked, but some live resources could not be closed. Contact the operator.')
                    : translate('accountControls.revoked', 'Selected login access revoked.');
            } catch (error) { message = error.message; }
            finally { busy = false; await load(); status.textContent = message; }
        }
        refresh.addEventListener('click', load);
        others.addEventListener('click', () => revoke({others:true}));
        window.addEventListener('languageChanged', render);
        load();
    }
    return {init, methodLabel, featureImpactLines, deletionConfirmation, confirmFeatureImpact};
});
