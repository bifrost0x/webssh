# WebSSH screenshots

[Back to the project overview](../README.md).

Captured from the current interface with synthetic hosts and example data.

### Focused session workspace

<p align="center">
  <img src="../assets/workspace-overview.png" alt="Connected WebSSH terminal with active-session controls and a notes workspace" width="1100">
</p>

The active session stays central while contextual tools remain close at hand.

### Multiple live sessions

<p align="center">
  <img src="../assets/multi-session.png" alt="WebSSH desktop workspace with two live terminal panes and four session tabs" width="1100">
</p>

Split panes make side-by-side observation and coordinated work visible without
mixing session ownership or terminal state.

### Commands, favorites, and reusable sequences

<p align="center">
  <img src="../assets/commandlibrary.png" alt="WebSSH Command Library with searchable command cards, operating-system filters, and separate Favorites and Command Sets tabs" width="1100">
</p>

Browse the library, keep frequently used entries in Favorites, and build
reusable Command Sets. Each has its own label, icon, and color.

<p align="center">
  <img src="../assets/command-set-builder.png" alt="WebSSH Command Set editor with a searchable library, ordered steps, and per-step parameter controls" width="1100">
</p>

Arrange steps, review parameters, and assign a saved sequence to a connection.

### File workspace

<p align="center">
  <img src="../assets/sftp-workspace.png" alt="WebSSH dual-pane file workspace with trusted sources and a transfer queue" width="1100">
</p>

Each pane has an explicit source, endpoint, path, trust state, and selection.

Empty-file creation is available for SFTP and SMB. The SFTP Unix permission
editor is opt-in: uncomment `SFTP_CHMOD_ENABLED=true` under `environment` in
`docker-compose.yml`, then run `docker compose up -d --force-recreate webssh`.
It requires a compatible SFTP server and normal remote permissions. The file
manager shows setup help while disabled. Choose separate file and folder modes, optionally include folder contents,
and review a bounded server-side preview before applying. Progress and partial
changes remain visible; jobs stop on the first detected conflict or error.
See the [chmod manual](https://github.com/bifrost0x/webssh/wiki/SFTP-File-Workspace-and-Transfers#unix-permissions)
for production-overlay instructions and security boundaries.

### Review file changes before saving

<p align="center">
  <img src="../assets/file-edit-review.png" alt="WebSSH file editor showing the destination, a colored line diff, original-file backup, and explicit save confirmation" width="1100">
</p>

Check the target and changed lines, optionally download the original, then
explicitly save the reviewed content.

<details>
  <summary>Preview the file editing workflow</summary>

<p align="center">
  <img src="../assets/file-editing.gif" alt="WebSSH file workflow from dual-pane browsing through preview, editing, save confirmation, and transfer completion" width="1100">
</p>

</details>

### Security Center

<p align="center">
  <img src="../assets/security-center.png" alt="WebSSH Security Center showing sign-in assurance, SSH host trust, Passkeys, TOTP, and Recovery Codes" width="1100">
</p>

The Security Center explains how the current sign-in confirms protected
changes and keeps factors and SSH trust in one account-owned view.

### Mobile workspace

<p align="center">
  <img src="../assets/mobile-workspace.png" alt="WebSSH mobile terminal workspace with responsive session controls and connection status" width="360">
</p>


## Product tour

[![Watch the full WebSSH tour](../site/assets/webssh-youtube-tour.jpg)](https://www.youtube.com/watch?v=mw_qXUnYYVs)

![Animated workspace tour](../assets/webssh-demo.gif)
