# GitHub Authentication

WebSSH can use a GitHub App as an optional sign-in provider. The integration
verifies identity only: it does not browse repositories, run Git operations,
read issues, use Actions, synchronize SSH keys, or retain GitHub access tokens.

GitHub authentication is configured entirely at runtime under **Settings →
Administration → Authentication → GitHub authentication**. There are no
`GITHUB_*` environment variables, Compose overlays, Docker secrets, or extra
mounts to add. Existing deployments remain unchanged until an administrator
saves a complete configuration and enables the provider.

## Create the GitHub App

Create a GitHub App in the GitHub organization or account that owns the sign-in
policy:

1. Set the callback URL to the exact value shown in the WebSSH Admin Panel,
   for example `https://ssh.example.com/auth/github/callback`.
2. Disable webhook delivery; WebSSH does not use webhooks.
3. Do not grant repository permissions.
4. For basic identity-only login, no additional repository or organization
   permission is required.
5. If an organization allowlist is configured, grant the organization
   permission **Members: read**. This lets the authenticated user's temporary
   GitHub App token prove private as well as public membership.
6. Generate a client secret and copy the client ID and secret into WebSSH.

Avoid wildcard callback URLs. When WebSSH runs below `APPLICATION_ROOT`, include
that prefix before `/auth/github/callback` in both GitHub and the Admin Panel.

## Configure WebSSH

Keep a tested local break-glass administrator, then open the GitHub section in
the Admin Panel. Enter:

- GitHub App client ID
- client secret
- exact public HTTPS callback URL
- optional comma-separated organization allowlist
- whether unknown GitHub identities may be auto-provisioned

The client secret field is write-only. Leaving it blank preserves the existing
secret; entering a value replaces it. WebSSH encrypts it at rest with a
domain-separated key derived from the existing persistent `SECRET_KEY`.
Backups therefore remain sensitive, and the supported secret-rotation command
also re-encrypts the stored GitHub secret.

Saving configuration requires administrator Step-up. Provider changes
invalidate outstanding GitHub OAuth states. Incomplete or undecryptable
configuration fails closed for GitHub while local WebSSH login remains
available.

## Login and account binding

GitHub OAuth uses authorization code flow, PKCE S256, a random session-bound
single-use state, a five-minute server-side state record, an exact callback,
and bounded local continuations. WebSSH uses the immutable numeric GitHub user
ID as the identity key; login, display name, and email are never durable keys.

Existing users connect GitHub from their Security settings after a WebSSH
Step-up check and a successful GitHub authorization. A GitHub identity can be
linked to only one WebSSH account, and each WebSSH account can have only one
GitHub identity. Changing the GitHub username does not break the binding.

Disconnecting also requires Step-up. A GitHub-provisioned account must first
add and test a Passkey so removing GitHub does not remove its only usable
primary authentication method.

## Auto-provisioning

Auto-provisioning is disabled by default. When disabled, an unknown GitHub
identity is rejected without matching by username or email. When enabled,
WebSSH creates a new non-admin account and its identity binding atomically.
GitHub metadata can never create or promote an administrator.

## Organization policy

With an empty allowlist, WebSSH performs no organization check. With one or
more organizations configured, the temporary user access token must prove an
active membership in at least one entry. A non-member is rejected. Timeouts,
permission failures, malformed responses, and GitHub API outages fail closed.

The user access token exists only long enough to retrieve `/user` and, when
configured, membership. WebSSH never persists the access token, refresh token,
authorization code, or OAuth response and never writes them to audit logs.

## Troubleshooting

- **Login button missing:** the provider is disabled or required configuration
  is incomplete. Review the status beside the Admin save button.
- **Invalid or expired login:** restart the flow. OAuth state is intentionally
  one-use, browser-bound, configuration-generation-bound, and short-lived.
- **Organization rejected:** confirm the exact organization name, active
  membership, and **Members: read** permission on the GitHub App.
- **Callback rejected by GitHub:** make the GitHub App callback and the Admin
  Panel callback identical, including scheme, host, port, and application root.
- **Provider unavailable:** use the local break-glass administrator and check
  outbound HTTPS connectivity to `github.com` and `api.github.com`.
