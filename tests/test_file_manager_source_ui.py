from pathlib import Path


APP_JS = Path('static/js/app.js')
FILE_MANAGER_JS = Path('static/js/sftp-file-manager.js')
INDEX_TEMPLATE = Path('templates/index.html')


def test_file_preview_uses_canonical_source_id_contract():
    source = APP_JS.read_text(encoding='utf-8')
    preview = source[source.index('const FilePreview = {'):source.index(
        'window.FilePreview = FilePreview;'
    )]

    assert 'currentSourceId: null' in preview
    assert 'currentSessionId' not in preview
    assert 'source_id: this.currentSourceId' in preview
    assert 'session_id:' not in preview


def test_file_manager_pane_state_has_no_legacy_connection_identity():
    source = FILE_MANAGER_JS.read_text(encoding='utf-8')
    factory = source[source.index('createEmptyPaneState()'):source.index(
        'normalizeSourceDescriptor('
    )]

    assert 'source: null' in factory
    assert 'sessionId' not in factory
    assert 'connectionId' not in factory
    assert 'type:' not in factory
    assert 'state.type' not in source
    assert 'paneState?.type' not in source


def test_file_manager_trusts_only_server_supplied_source_capabilities():
    source = FILE_MANAGER_JS.read_text(encoding='utf-8')

    assert 'defaultSftpCapabilities()' not in source
    assert 'session.file_source || session.fileSource || {' not in source
    assert 'connection.file_source || connection.fileSource || {' not in source
    assert "source?.security?.hostKeyVerified || source?.kind === 'sftp'" not in source


def test_file_manager_empty_source_uses_one_action_icon():
    source = FILE_MANAGER_JS.read_text(encoding='utf-8')
    empty_state = source[source.index("if (!this.getPaneSourceId(state))"):
                         source.index("const sortedFiles =", source.index(
                             "if (!this.getPaneSourceId(state))"
                         ))]

    assert empty_state.count('folder_open') == 1
    assert 'fm-empty-icon-shell' not in empty_state


def test_file_manager_does_not_open_source_launcher_implicitly():
    source = FILE_MANAGER_JS.read_text(encoding='utf-8')
    open_block = source[source.index('    open() {'):source.index(
        '    close(options = {})'
    )]
    layout_block = source[source.index('    setWorkspaceLayout(layout) {'):
                          source.index('    buildSourceCatalog()')]

    assert 'openSourceLauncher' not in open_block
    assert 'openSourceLauncher' not in layout_block


def test_file_manager_exposes_folder_drop_move_and_concise_smb_help():
    source = FILE_MANAGER_JS.read_text(encoding='utf-8')
    template = INDEX_TEMPLATE.read_text(encoding='utf-8')

    assert 'data-pane-action="move"' not in source
    assert 'setupDirectoryDropTarget(item, pane, index)' in source
    assert 'moveSelectedToDirectory(pane, targetIndex, selectedItems)' in source
    assert source.count('id="fmTransferBetween"') == 1
    assert 'id="fmTransferRight"' not in source
    assert 'id="fmTransferLeft"' not in source
    assert 'canStartSamePaneMove(pane)' in source
    assert 'SFTP-File-Workspace-and-Transfers' in template
    assert 'target="_blank" rel="noopener noreferrer"' in template
    assert 'For Active Directory or TrueNAS, try DNS domain' not in template


def test_image_preview_keeps_listener_until_the_correlated_response_arrives():
    source = APP_JS.read_text(encoding='utf-8')
    handler = source[source.index('const handleBinaryDownload = (data) => {'):
                     source.index('this._pendingImageHandler = handleBinaryDownload;')]

    assert handler.index('this.matchesResponse(data, requestId)') < handler.index(
        "socket.off('file_download_ready_binary', handleBinaryDownload)"
    )
