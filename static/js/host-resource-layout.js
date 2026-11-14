/* Shared list-first layout for connection resources. Existing managers own writes. */
(function () {
    'use strict';
    const t = (key, fallback) => window.i18n?.t(key) || fallback;
    function install(id, kind, formId, listId, titleKey, fallback) {
        const root = document.getElementById(id);
        const layout = root?.querySelector('.connection-asset-layout');
        if (!layout) return;
        const form = document.getElementById(formId);
        const editor = form.closest('section');
        const list = document.getElementById(listId);
        const library = list.closest('section');
        root.classList.add('host-resource-view');
        library.classList.add('host-resource-library');
        editor.classList.add('host-resource-editor');
        layout.prepend(library);
        const toolbar = document.createElement('div');
        toolbar.className = 'host-resource-toolbar management-panel-toolbar';
        const searchLabel = document.createElement('label');
        searchLabel.className = 'management-search-control';
        const icon = document.createElement('span'); icon.className = 'material-icons'; icon.textContent = 'search'; icon.setAttribute('aria-hidden', 'true');
        const search = document.createElement('input'); search.type = 'search'; search.className = 'form-control';
        search.dataset.i18nPlaceholder = 'connectionAssets.search'; search.dataset.i18nAriaLabel = 'connectionAssets.search';
        search.placeholder = t('connectionAssets.search', 'Search saved entries'); search.setAttribute('aria-label', search.placeholder);
        search.id = kind + 'ResourceSearch';
        searchLabel.append(icon, search);
        const add = document.createElement('button'); add.type = 'button'; add.className = 'btn btn-primary';
        add.id = kind + 'ResourceNew'; add.dataset.i18n = titleKey; add.textContent = t(titleKey, fallback);
        toolbar.append(searchLabel, add); layout.before(toolbar);
        const close = document.createElement('button'); close.type = 'button'; close.className = 'btn btn-secondary resource-editor-back';
        close.dataset.i18n = 'common.backToList'; close.textContent = t('common.backToList', 'Back to list');
        editor.prepend(close);
        const show = () => { root.classList.add('has-resource-editor'); form.querySelector('input')?.focus(); };
        root.showResourceEditor = show;
        const hide = () => { root.classList.remove('has-resource-editor'); add.focus(); };
        add.addEventListener('click', () => {
            if (kind === 'socks') {
                if (!window.SocksProxyManager.canDiscard()) return;
                window.SocksProxyManager.resetEditor();
            } else if (kind === 'jump') {
                if (!window.JumpHostManager.canDiscard()) return;
                window.JumpHostManager.resetEditor();
            }
            show();
        });
        close.addEventListener('click', () => {
            if (kind === 'socks') {
                if (!window.SocksProxyManager.canDiscard()) return;
                window.SocksProxyManager.resetEditor();
            } else if (kind === 'jump') {
                if (!window.JumpHostManager.canDiscard()) return;
                window.JumpHostManager.resetEditor();
            } else {
                const dirty = [...form.querySelectorAll('input,textarea')].some(input => input.value);
                if (dirty && !window.confirm(t('editor.unsavedConfirm', 'Discard unsaved changes?'))) return;
                form.reset();
            }
            hide();
        });
        form.addEventListener('reset', () => root.classList.remove('has-resource-editor'));
        const noResults = document.createElement('p'); noResults.className = 'no-items';
        noResults.dataset.i18n = 'sessionCommands.noResults'; noResults.textContent = t('sessionCommands.noResults', 'No matching entries.');
        noResults.hidden = true; library.append(noResults);
        const filter = () => {
            const query = search.value.trim().toLocaleLowerCase();
            for (const row of list.querySelectorAll('.key-item')) {
                row.hidden = Boolean(query && !row.querySelector('.key-info')?.textContent.toLocaleLowerCase().includes(query));
            }
            noResults.hidden = !query || !list.querySelector('.key-item') || Boolean(list.querySelector('.key-item:not([hidden])'));
        };
        search.addEventListener('input', filter);
        new MutationObserver(filter).observe(list, {childList: true});
    }
    document.addEventListener('DOMContentLoaded', () => {
        install('jumpHostManagementModal', 'jump', 'jumpHostForm', 'jumpHostsList', 'jumphosts.addNew', 'Add Jump Host');
        install('socksProxyManagementModal', 'socks', 'socksProxyForm', 'socksProxiesList', 'socksproxies.addNew', 'Add SOCKS5 Proxy');
        install('keyManagementModal', 'key', 'keyUploadForm', 'keysList', 'keys.uploadNewKey', 'Upload New Key');
    });
})();
