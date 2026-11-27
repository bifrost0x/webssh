# Warpgate SSH connections

The integration is **disabled by default**. An administrator must enable
**Settings → Administration → Integrations → Warpgate / SSH gateway** first.
This global setting applies to all WebSSH users and is saved in the existing
application settings store. Changing it requires the normal admin step-up
verification. Reload open workspaces after changing the setting.

Disabling blocks new gateway terminal and Quick SFTP connections, gateway
profile changes, and unfinished gateway authentication. Existing profiles are
retained and established sessions are not disconnected. The server enforces
the setting even when an older browser tab still shows the enabled UI.

Once enabled, connect to an existing Warpgate SSH endpoint using an ordinary WebSSH profile:

1. Enter the gateway hostname and SSH port.
2. Enter the exact Warpgate selector, for example `alice@example.com:production`, as the username.
3. Choose **Password** or an existing **SSH key**. With Password, leave the password empty to start interactive authentication.
4. Respond to additional authentication prompts. Browser approval links open only when clicked. Return to WebSSH and continue after approval.
5. Review any target host-key or access-approval prompt in the temporary gateway terminal.

No additional service, Compose setting, database migration, or dependency is required. Ordinary SSH and jump hosts also support interactive MFA prompts without enabling the gateway integration. Tailscale keeps its dedicated authentication path. A normal SSH jump host may precede a gateway terminal connection; Quick SFTP does not add jump-host or Tailscale support.

When globally enabled, the integration is selected by a validated `user:target` username.
Ordinary SSH terminals share the bounded MFA interaction lifecycle, while
gateway target setup remains exclusive to gateway selectors. Ordinary Quick
SFTP remains synchronous.

## Security and compatibility boundaries

- Selectors opt in to a separate authentication path. They do not identify a server as trustworthy; existing per-user gateway host-key checks and network restrictions still apply.
- The gateway controls access to its targets. WebSSH's network policy checks the gateway endpoint, not the destination hidden behind it.
- Passwords, additional factors and approval responses are transient. They are never stored in profiles. Additional factors are explicitly answered; the original password is never reused as an OTP.
- Each interaction belongs to one WebSSH user, socket and request. Challenges are one-shot, deadlines and byte limits are enforced, and pending gateway attempts count against the SSH session quota, with at most 64 waiting attempts per server.
- Warpgate target host-key checks and approval policies remain enabled. There is no automatic target host-key acceptance.
- Terminal setup requires a target supporting a PTY and a bounded `printf` exec probe. Only after the nonce response and successful exit does WebSSH run normal terminal/tmux setup or configured startup commands.
- Quick SFTP uses a temporary PTY for gateway prompts and a separate SFTP channel. Targets must permit those two channels during setup; PTY-disabled or single-channel targets are not supported by this path.
- Existing profile auth types remain unchanged. Older WebSSH versions can read the profile document, but cannot connect using the new selector syntax.
- Ticket secrets, `#` selectors, automatic target discovery, gateway administration and non-SSH protocols are not supported.

The Go client is tested against Warpgate 0.30.6. It always tries the `none` method first, which shows only in the gateway's log. Prompts carry the server's echo flag, but the page masks every answer. Output of the temporary gateway terminal keeps characters that span two 4 KiB frames. A gateway that asks for a password and then a one-time code asks for both in the browser; with a Warpgate user whose policy asks for the code first, a login without a saved password is refused, as in 3.3, and works with a saved password. Switching the gateway off ends pending gateway logins within a second.

Cancel closes an unfinished gateway attempt. Once the existing startup/session commit boundary has been crossed, the ordinary WebSSH cancellation contract applies.
