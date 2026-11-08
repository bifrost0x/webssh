/* Click actions for header buttons. This script loads right after the header
 * markup, so its listeners run before listeners added by later scripts, as the
 * former inline handlers did. The called functions are resolved on click. */
(function () {
    'use strict';
    const actions = {
        fileTransferBtn: () => window.openFileManager(),
        mobileQuickConnectAction: () => {
            window.openDefaultConnectionModal?.();
            window.mobileAppShell?.closeMoreMenu();
        },
        mobileToolsAction: () => {
            window.primaryWorkspaceController?.showWorkspaces();
            window.workspaceLayoutController?.setNotesOpen(true, 'user');
            window.mobileAppShell?.closeMoreMenu();
        },
        mobileBroadcastAction: () => {
            window.primaryWorkspaceController?.showWorkspaces();
            window.BroadcastInput?.toggle();
            window.mobileAppShell?.closeMoreMenu();
        },
        mobileTranscriptAction: () => {
            window.primaryWorkspaceController?.showWorkspaces();
            document.getElementById('saveTranscriptBtn').click();
            window.mobileAppShell?.closeMoreMenu();
        },
        accountBtnHeader: event => window.toggleAccountDropdownHeader(event),
    };
    Object.entries(actions).forEach(([id, action]) => {
        document.getElementById(id)?.addEventListener('click', action);
    });
})();
