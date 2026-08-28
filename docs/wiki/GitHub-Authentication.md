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

### 1. Decide who owns the app

Use an organization-owned GitHub App when an organization membership allowlist
will control WebSSH access. A personal app is sufficient for a private test or
identity-only login without organization policy.

Only organization owners can create and install organization-owned apps by
default. A designated GitHub App manager can create and edit an app, but that
role alone does not grant permission to install it.

### 2. Open the GitHub App registration page

For a personal app:

1. In GitHub, select the profile picture in the upper-right corner.
2. Open **Settings**.
3. In the left sidebar, open **Developer settings**.
4. Open **GitHub Apps**.
5. Select **New GitHub App**.

The direct personal registration URL is
<https://github.com/settings/apps/new>.

For an organization-owned app:

1. In GitHub, select the profile picture and open **Your organizations**.
2. Beside the owning organization, select **Settings**.
3. In the left sidebar, open **Developer settings**.
4. Open **GitHub Apps**.
5. Select **New GitHub App**.

The organization registration URL has the form
`https://github.com/organizations/ORGANIZATION/settings/apps/new`.

### 3. Complete Basic information

Use the following values on GitHub's registration form:

| GitHub field | Value for WebSSH |
|---|---|
| **GitHub App name** | A unique descriptive name, for example `WebSSH – Example Org` |
| **Homepage URL** | The public WebSSH base URL, for example `https://ssh.example.com/` |
| **Callback URL** | The exact WebSSH callback, for example `https://ssh.example.com/auth/github/callback` |
| **Request user authorization (OAuth) during installation** | Leave cleared; WebSSH starts the authorization flow when a user signs in or links an account |
| **Setup URL** | Leave empty |
| **Webhook → Active** | Clear this option; WebSSH does not receive webhooks |

Avoid wildcard callback matching. WebSSH always sends the configured exact
callback URL. When WebSSH runs below `APPLICATION_ROOT`, include that prefix
before `/auth/github/callback` in both GitHub and the Admin Panel. Production
callbacks must use HTTPS; plain HTTP is accepted only for a loopback host in
the homelab profile.

### 4. Select the minimum permissions

Keep every **Repository permission** and **Account permission** at **No
access**. WebSSH does not read repositories, email addresses, SSH keys, issues,
Actions, or other account data.

For identity-only login with an empty organization allowlist, keep every
**Organization permission** at **No access** as well.

When **Allowed organizations** will contain one or more organization logins:

1. On the GitHub App registration form, find **Permissions & events**.
2. Under **Organization permissions**, find **Members**.
3. Select **Read-only**. GitHub describes this effective permission as
   **Members: read**.
4. Leave every other permission at **No access**.

This is the permission required by GitHub's organization-membership endpoint
to prove private as well as public membership. The signed-in user must also be
an active member of the allowed organization.

### 5. Create and install the app

1. Under **Where can this GitHub App be installed?**, prefer **Only on this
   account** for a private, owner-scoped deployment. Choose a broader option
   only when the app must be installed outside its owning account.
2. Select **Create GitHub App**.
3. On the new app's settings page, open **Install App**.
4. Select **Install** beside the personal account or organization whose
   resources and membership policy the app should use.
5. Review that the installation requests no repository access and, when an
   organization allowlist is used, only read access to members.

GitHub distinguishes installation from user authorization. Installation grants
the app access to the selected account or organization under its declared
permissions. Each WebSSH user separately authorizes the app during login or
account linking. An organization owner must approve an installation that
requests an organization permission.

### 6. Copy Client ID and create a client secret

Return to **Developer settings → GitHub Apps** and select **Edit** beside the
app. On its **General** page:

1. Copy **Client ID**. Do not copy **App ID**; they are different values.
2. Scroll to **Client secrets**.
3. Select **Generate a new client secret**.
4. Copy the generated secret immediately and paste it into WebSSH. Treat it as
   a password and never place it in Compose, source control, screenshots, or
   issue text.

WebSSH does not need a private key, PEM download, webhook secret, or OAuth App
client credentials. It needs only the GitHub App **Client ID** and one generated
**Client secret**.

## Configure WebSSH

Keep a tested local break-glass administrator, then open the GitHub section in
the Admin Panel. Enter:

- GitHub App client ID
- client secret
- exact public HTTPS callback URL
- optional comma-separated organization allowlist
- whether unknown GitHub identities may be auto-provisioned

Then select **Enable GitHub sign-in** and **Save GitHub configuration**. WebSSH
will request administrator reauthentication for this protected change. The
status beside the buttons must report **GitHub sign-in is active** before users
will see the GitHub login option.

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
  membership, **Members: read** permission, approved installation on that
  organization, and approval of any changed permissions.
- **Callback rejected by GitHub:** make the GitHub App callback and the Admin
  Panel callback identical, including scheme, host, port, and application root.
- **Client ID rejected:** copy **Client ID** from the app's General page, not
  **App ID**, OAuth App credentials, or an installation ID.
- **Client secret rejected:** generate a new value under **Client secrets** on
  the GitHub App's General page. Do not use a webhook secret or private key.
- **Private organization membership is never accepted:** install the app on the
  organization, grant **Organization permissions → Members → Read-only**, and
  have an organization owner approve the permission or installation request.
- **Provider unavailable:** use the local break-glass administrator and check
  outbound HTTPS connectivity to `github.com` and `api.github.com`.

## GitHub references

- [Registering a GitHub App](https://docs.github.com/en/apps/creating-github-apps/registering-a-github-app)
- [About the user authorization callback URL](https://docs.github.com/en/apps/creating-github-apps/registering-a-github-app/about-the-user-authorization-callback-url)
- [Choosing permissions for a GitHub App](https://docs.github.com/en/apps/creating-github-apps/registering-a-github-app/choosing-permissions-for-a-github-app)
- [Installing a GitHub App](https://docs.github.com/en/apps/using-github-apps/installing-a-github-app-from-a-third-party)
- [Organization member API permissions](https://docs.github.com/en/rest/orgs/members)
