# SSH Connections and Host Keys

WebSSH opens SSH connections from the server process to the target. The browser
does not connect directly to the SSH server.

## Connection methods

Open **Quick Connect** or launch a saved profile. A connection includes:

- hostname or IP address;
- SSH port, normally `22`;
- remote operating-system username;
- password, stored SSH key, or authorized Tailscale SSH mode;
- optional jump host;
- optional persistent tmux selection;
- optional post-connect command or command set.

Connection passwords are not stored in profiles or audit logs. Stored private
keys are encrypted at rest and decrypted only when needed for authentication.

## Stored SSH keys

WebSSH accepts RSA, Ed25519, and ECDSA private keys supported by the installed
Paramiko runtime. Each user's keys are isolated below their own data directory.

Private-key content is encrypted with Fernet. A per-user key is derived from
`SECRET_KEY:user_id` through PBKDF2-HMAC-SHA256 with 600,000 iterations. Key
directories use mode `0700` and files use `0600` on POSIX systems.

`SECRET_KEY` is the root of this protection. Anyone with both the application
secret and encrypted files can decrypt the keys. Preserve the secret during
updates and protect backups accordingly.

The key manager supports upload/import, rename, replacement, and deletion. Key
paths are validated against the owning user's key directory, and writes are
atomic.

## Host-key trust

WebSSH uses persistent trust on first use (TOFU):

1. On the first connection to a host identity, the server key fingerprint is
   stored and logged.
2. Later connections require the stored key to match.
3. A changed key is rejected instead of being silently accepted.

Trust is scoped to the relevant user or administrator-managed global store.
Users can inspect and revoke their own trust records in the Security Center;
administrators can manage global trust.

## Add global host trust

Administrators can add a verified OpenSSH `known_hosts` record under **Admin →
Settings → Global SSH host trust**. The import accepts exactly one bounded
record, validates the hostname pattern and public key, requires action-bound
administrator Step-up, and returns only fingerprint metadata to the browser.

One way to collect a candidate record is:

```bash
ssh-keyscan -p 22 server.example
```

`ssh-keyscan` collects a key but does **not** prove its identity. Verify the
fingerprint through a separate trusted channel, for example with the server
owner, console, or configuration management, before importing it. You can
inspect a collected record with:

```bash
ssh-keygen -lf candidate_known_hosts
```

Paste one verified `hostname key-type base64-key` line into the Admin field.
Hashed hostnames, non-default-port tokens such as `[server.example]:2222`,
multi-host records, and `@revoked` records are supported. Duplicate records are
rejected. A different key for the same host token and algorithm must be
verified and the old record explicitly removed first.

Removing a global record also requires Step-up and affects every user who
depends on that global trust record. Per-user trust can still take precedence
for the same effective host identity.

## SSH authentication banners

An SSH server can send `SSH_MSG_USERAUTH_BANNER` during authentication. The SSH
protocol does not make this a true pre-authentication message; Paramiko exposes
it after authentication completes. WebSSH therefore pauses immediately after
authentication and before it opens a target shell, jump-host forwarding
channel, tmux probe, or post-connect command.

The browser displays the bounded, control-character-sanitized text and requires
**Continue** or **Cancel connection**. Cancellation, browser disconnect, or a
60-second timeout closes the transport. The audit log records the user, target,
target/jump-host context, and accepted/declined/timed-out result. It deliberately
does not record the banner text, which is controlled by the remote server.

## Respond to a changed host key

Do not immediately delete the record and retry. A change may indicate:

- a legitimate server rebuild or SSH host-key rotation;
- DNS or IP reassignment;
- a load balancer reaching a different host;
- interception.

Verify the new fingerprint out of band with the system owner. Only then revoke
the old record and reconnect.

## Network and SSRF policy

`BLOCK_INTERNAL_SSH=true` blocks loopback, link-local, private, reserved, and
other unsafe destinations after DNS resolution. The production profile requires
this protection.

The homelab profile defaults to false because private addresses are often the
intended targets. If untrusted users can access the instance, private-target
access turns WebSSH into a powerful network pivot. Isolate the instance or
enforce a reviewed target policy.

DNS results are validated. ProxyJump normally uses locally validated target
resolution. `PROXY_JUMP_REMOTE_DNS_ALLOWLIST` permits only exact hostnames that a
trusted bastion must resolve remotely; wildcards and IP literals are rejected.

## Jump hosts

Save a jump host once and reference it from profiles. A jump host can have its
own hostname, port, remote username, and authentication method.

WebSSH opens the target through Paramiko's existing bounded channel helpers.
The UI marks a connection as routed through the selected bastion. Deleting or
changing a referenced jump host can affect saved profiles, so verify dependents
before removal.

## Connection ownership

Every live SSH session is owned by one WebSSH user. Socket.IO input, resize,
disconnect, SFTP, diagnostics, and transfer operations authenticate the browser
session and verify resource ownership.

Terminal output is emitted to the owning user's private room. Lock, deletion,
logout, and LDAP revalidation close tracked resources.

## Capacity and rate limits

Defaults:

- 10 concurrent SSH sessions globally;
- 5 per user;
- 10 SSH or quick-connect attempts per minute per user;
- 12 temporary SSH/SFTP connections globally;
- 3 temporary connections per user.

All counters are process-local and rely on the mandatory single-worker model.

## Troubleshooting

### Connection times out

Check DNS, routing, firewall rules, target port, jump-host reachability, and the
container network. Confirm the target is not blocked by network policy.

### Authentication fails

Verify the remote username and selected method. For keys, check the public key
is installed for that remote user and the private-key format is supported. For
a jump host, distinguish bastion authentication from target authentication.

### The authentication banner closes the connection

Choose **Continue** within 60 seconds only after reviewing the remote policy.
Cancelling, closing the browser connection, or leaving the prompt unanswered
fails closed before a shell or startup command is opened.

### Host key is rejected

Review the trust record and verify the new fingerprint. Do not disable host-key
verification.

### Connection closes while idle

`SESSION_TIMEOUT` defaults to 1800 seconds and closes idle SSH sessions. A tmux
session may keep the remote shell alive for later reattachment even though the
WebSSH transport closed.

## Related pages

- [Profiles, Jump Hosts and Commands](Profiles-Jump-Hosts-and-Commands)
- [Terminal and Persistent tmux Sessions](Terminal-and-Persistent-tmux-Sessions)
- [Security Model and Hardening](Security-Model-and-Hardening)
