/* Theme, language and account menu wiring for the main page. Function
 * declarations stay global: other scripts and tests call applyTheme() and
 * closeAccountDropdownHeader(); header-actions.js calls toggleAccountDropdownHeader(). */
/* exported applyTheme, toggleAccountDropdownHeader */
function initThemeSelectorHeader() {
    const currentTheme = document.body.getAttribute('data-theme') || 'glass';
    window.ThemePreference?.store(currentTheme);
    window.addEventListener('storage', event => {
        if (event.key !== 'websshTheme' || !window.ThemePreference?.isValid(event.newValue)) return;
        if (document.body.dataset.theme === event.newValue) return;
        document.body.dataset.theme = event.newValue;
        window.TerminalManager?.applyThemeToAll();
        window.dispatchEvent(new CustomEvent('themeChanged', {detail: {theme: event.newValue}}));
    });
    const select = document.getElementById('settingsThemeSelect');

    if (select) {
        select.value = currentTheme;
        select.addEventListener('change', () => {
            applyTheme(select.value);
        });
    }
}

function applyTheme(themeId) {
    if (!window.ThemePreference?.isValid(themeId)) {
        return;
    }
    document.body.setAttribute('data-theme', themeId);
    window.ThemePreference.store(themeId);
    if (window.socket) {
        window.socket.emit('set_theme', { theme: themeId });
    }
    const select = document.getElementById('settingsThemeSelect');
    if (select) select.value = themeId;
    if (window.TerminalManager && typeof TerminalManager.applyThemeToAll === 'function') {
        TerminalManager.applyThemeToAll();
    }
}

function initLanguageSelectorHeader() {
    const select = document.getElementById('settingsLanguageSelect');
    const languages = i18n.getLanguages();
    const currentLang = i18n.getLanguage();

    if (!select) return;
    select.replaceChildren();
    languages.forEach(lang => {
        const option = document.createElement('option');
        option.value = lang.code;
        option.textContent = `${lang.flag} ${lang.name}`;
        select.appendChild(option);
    });
    select.value = currentLang;
    select.addEventListener('change', () => {
        i18n.setLanguage(select.value);
    });
}

function closeAccountDropdownHeader() {
    document.getElementById('accountDropdownHeader')?.classList.remove('show');
    document.getElementById('accountBtnHeader')?.setAttribute('aria-expanded', 'false');
}

function toggleAccountDropdownHeader(event) {
    if (event) {
        event.stopPropagation();
    }
    const dropdown = document.getElementById('accountDropdownHeader');
    if (!dropdown) {
        return;
    }
    if (dropdown.classList.contains('show')) {
        closeAccountDropdownHeader();
        return;
    }
    dropdown.classList.add('show');
    document.getElementById('accountBtnHeader')?.setAttribute('aria-expanded', 'true');
}

document.getElementById('accountDropdownHeader')?.addEventListener('click', (e) => {
    if (e.target.closest('.account-action')) {
        closeAccountDropdownHeader();
    }
});

window.addEventListener('click', (e) => {
    if (!e.target.closest('.account-selector')) {
        closeAccountDropdownHeader();
    }
});

document.addEventListener('DOMContentLoaded', () => {
    initThemeSelectorHeader();
    initLanguageSelectorHeader();
    window.webssh2Shell = window.WebSSH2Shell?.init({
        sessionManager: SessionManager,
        document,
    });
    window.accountWorkspacePulse = window.AccountWorkspacePulseModule?.createAccountWorkspacePulse({
        sessionManager: SessionManager,
        document,
        window,
        translate: key => window.i18n ? i18n.t(key) : key,
    });
    window.accountWorkspacePulse?.init();
});
