(function () {
    'use strict';

    const APP_ROOT = (document.querySelector('meta[name="app-root"]')?.content || '')
        .replace(/\/$/, '');
    const CSRF = document.querySelector('meta[name="csrf-token"]')?.content || '';

    function setPreferenceStatus(message, isError) {
        const status = document.getElementById('settingsPreferenceStatus');
        if (!status) { return; }
        status.textContent = message || '';
        status.classList.toggle('text-error', Boolean(isError));
    }

    async function savePreference(payload) {
        const response = await fetch(`${APP_ROOT}/api/account/preferences`, {
            method: 'POST',
            headers: {
                'Accept': 'application/json',
                'Content-Type': 'application/json',
                'X-CSRFToken': CSRF,
            },
            body: JSON.stringify(payload),
        });
        const data = await response.json().catch(() => ({}));
        if (!response.ok) {
            throw new Error(data.error || `Request failed (${response.status})`);
        }
        return data.settings || {};
    }

    function initNavigation() {
        const buttons = Array.from(document.querySelectorAll('[data-account-section]'));
        const panels = Array.from(document.querySelectorAll('[data-account-panel]'));
        const adminTabs = Array.from(document.querySelectorAll('.admin-tab[data-tab]'));
        const mobileSelect = document.getElementById('settingsMobileSection');
        if (!buttons.length || !panels.length) { return; }

        const recoveryMode = document.body.dataset.recoveryMode === 'true';
        const fallback = recoveryMode ? 'factors' : 'security-overview';

        const adminTabFor = requested => adminTabs.find(tab => (
            tab.dataset.settingsSection === requested || tab.dataset.tab === requested
        ));
        const hideAccountPanels = () => {
            buttons.forEach(button => {
                button.classList.remove('active');
                button.setAttribute('aria-current', 'false');
            });
            panels.forEach(panel => panel.classList.add('hidden'));
        };
        const hideAdminPanels = () => {
            adminTabs.forEach(tab => tab.classList.remove('active'));
            ['users', 'audit', 'settings', 'backup'].forEach(name => {
                document.getElementById(`tab-${name}`)?.classList.add('hidden');
            });
            document.querySelectorAll('[data-settings-panel]').forEach(panel => {
                panel.classList.add('hidden');
            });
        };
        const valueForAdminTab = tab => tab.dataset.settingsSection || tab.dataset.tab;
        const updateMobileSelect = value => {
            if (mobileSelect && mobileSelect.value !== value) {
                mobileSelect.value = value;
            }
        };

        if (mobileSelect) {
            mobileSelect.replaceChildren();
            let currentGroup = null;
            Array.from(document.querySelector('.settings-center-navigation')?.children || [])
                .forEach(item => {
                    if (item.classList.contains('admin-nav-group')) {
                        const label = item.querySelector('span')?.textContent
                            || item.childNodes[0]?.textContent
                            || item.textContent;
                        currentGroup = document.createElement('optgroup');
                        currentGroup.label = String(label || '').trim();
                        mobileSelect.appendChild(currentGroup);
                        return;
                    }
                    if (!item.matches('.admin-tab')) { return; }
                    const option = document.createElement('option');
                    option.value = item.dataset.accountSection || valueForAdminTab(item);
                    option.textContent = item.querySelector('span:last-child')?.textContent
                        || item.textContent.trim();
                    (currentGroup || mobileSelect).appendChild(option);
                });
        }

        const show = (requested, updateHistory) => {
            const requestedAdminTab = adminTabFor(requested);
            if (requestedAdminTab) {
                hideAccountPanels();
                updateMobileSelect(valueForAdminTab(requestedAdminTab));
                if (updateHistory) {
                    requestedAdminTab.click();
                } else {
                    setTimeout(() => requestedAdminTab.click(), 0);
                }
                return;
            }
            const available = buttons.find(button => button.dataset.accountSection === requested);
            const section = available ? requested : fallback;
            hideAdminPanels();
            buttons.forEach(button => {
                const active = button.dataset.accountSection === section;
                button.classList.toggle('active', active);
                button.setAttribute('aria-current', active ? 'page' : 'false');
            });
            panels.forEach(panel => {
                panel.classList.toggle('hidden', panel.dataset.accountPanel !== section);
            });
            updateMobileSelect(section);
            if (updateHistory) {
                history.replaceState(null, '', `#${section}`);
            }
        };

        buttons.forEach(button => {
            button.addEventListener('click', () => {
                show(button.dataset.accountSection, true);
            });
        });
        adminTabs.forEach(tab => {
            tab.addEventListener('click', hideAccountPanels);
        });
        mobileSelect?.addEventListener('change', () => {
            show(mobileSelect.value, true);
        });
        document.querySelectorAll('[data-account-jump]').forEach(button => {
            button.addEventListener('click', () => {
                show(button.dataset.accountJump, true);
                document.querySelector('.settings-center-content')?.scrollTo({
                    top: 0,
                    behavior: 'smooth',
                });
            });
        });
        document.querySelectorAll('[data-admin-jump]').forEach(button => {
            button.addEventListener('click', () => {
                const target = adminTabFor(button.dataset.adminJump);
                target?.click();
                document.querySelector('.settings-center-main')?.scrollTo({
                    top: 0,
                    behavior: 'smooth',
                });
            });
        });
        show(String(location.hash || '').slice(1), false);
        window.addEventListener('hashchange', () => {
            show(String(location.hash || '').slice(1), false);
        });
    }

    function initLanguage() {
        const select = document.getElementById('settingsLanguageSelect');
        if (!select || !window.i18n) { return; }
        select.replaceChildren();
        i18n.getLanguages().forEach(language => {
            const option = document.createElement('option');
            option.value = language.code;
            option.textContent = `${language.flag} ${language.name}`;
            select.appendChild(option);
        });
        select.value = i18n.getLanguage();
        select.addEventListener('change', () => {
            i18n.setLanguage(select.value);
            setPreferenceStatus('Language updated.');
        });
    }

    function initTheme() {
        const select = document.getElementById('settingsThemeSelect');
        if (!select) { return; }
        select.value = document.body.dataset.theme || 'glass';
        select.addEventListener('change', async () => {
            const previous = document.body.dataset.theme || 'glass';
            const requested = select.value;
            select.disabled = true;
            document.body.dataset.theme = requested;
            window.ThemePreference?.store(requested);
            setPreferenceStatus('Saving theme…');
            try {
                await savePreference({theme: requested});
                setPreferenceStatus('Theme saved.');
            } catch (error) {
                document.body.dataset.theme = previous;
                select.value = previous;
                window.ThemePreference?.store(previous);
                setPreferenceStatus(error.message, true);
            } finally {
                select.disabled = false;
            }
        });
    }

    function initScrollback() {
        const input = document.getElementById('scrollbackInput');
        if (!input) { return; }
        input.value = localStorage.getItem('terminalScrollback') || '500';
        input.addEventListener('change', () => {
            let value = Number.parseInt(input.value, 10);
            if (!Number.isFinite(value) || value < 50) { value = 50; }
            if (value > 10000) { value = 10000; }
            input.value = String(value);
            localStorage.setItem('terminalScrollback', String(value));
            setPreferenceStatus('Scrollback saved in this browser.');
        });
    }

    function initBooleanPreference(id, datasetKey, payloadKey) {
        const input = document.getElementById(id);
        if (!input) { return; }
        input.checked = document.body.dataset[datasetKey] === 'true';
        input.addEventListener('change', async () => {
            const previous = document.body.dataset[datasetKey] === 'true';
            const requested = input.checked;
            input.disabled = true;
            setPreferenceStatus('Saving setting…');
            try {
                await savePreference({[payloadKey]: requested});
                document.body.dataset[datasetKey] = String(requested);
                setPreferenceStatus('Setting saved.');
            } catch (error) {
                input.checked = previous;
                setPreferenceStatus(error.message, true);
            } finally {
                input.disabled = false;
            }
        });
    }

    function initDisconnectAction() {
        const select = document.getElementById('disconnectSessionActionSelect');
        if (!select) { return; }
        select.value = document.body.dataset.disconnectSessionAction || 'retry';
        select.addEventListener('change', async () => {
            const previous = document.body.dataset.disconnectSessionAction || 'retry';
            const requested = select.value;
            select.disabled = true;
            setPreferenceStatus('Saving setting…');
            try {
                await savePreference({disconnect_session_action: requested});
                document.body.dataset.disconnectSessionAction = requested;
                setPreferenceStatus('Setting saved.');
            } catch (error) {
                select.value = previous;
                setPreferenceStatus(error.message, true);
            } finally {
                select.disabled = false;
            }
        });
    }

    document.addEventListener('DOMContentLoaded', () => {
        initNavigation();
        initLanguage();
        initTheme();
        initScrollback();
        initBooleanPreference(
            'confirmSessionCloseInput',
            'confirmSessionClose',
            'confirm_session_close',
        );
        initDisconnectAction();
    });
})();
