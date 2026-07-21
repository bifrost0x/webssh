"""Authorization policy for the optional shared-identity Tailscale SSH mode."""

import config


def user_can_use_tailscale_ssh(user):
    """Return whether a WebSSH user may use the node's Tailscale identity."""
    if not config.TAILSCALE_SSH_ENABLED or not user:
        return False
    return bool(
        getattr(user, 'is_admin', False)
        or getattr(user, 'username', None) in config.TAILSCALE_SSH_ALLOWED_WEBSSH_USERS
    )


def validate_tailscale_ssh_access(user, host, remote_username):
    """Return an error message when the shared Tailscale identity is denied."""
    if not user_can_use_tailscale_ssh(user):
        return 'Tailscale SSH is not enabled for this account'

    allowed_targets = config.TAILSCALE_SSH_ALLOWED_TARGETS
    if allowed_targets and (host or '').strip().lower() not in allowed_targets:
        return 'Tailscale SSH target is not allowed'

    allowed_remote_users = config.TAILSCALE_SSH_ALLOWED_REMOTE_USERS
    if allowed_remote_users and (remote_username or '').strip() not in allowed_remote_users:
        return 'Tailscale SSH remote username is not allowed'

    return None
