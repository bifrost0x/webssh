"""Authorization policy for the optional shared-identity Tailscale SSH mode."""

from dataclasses import dataclass

import config

from .network_policy import canonicalize_hostname


@dataclass(frozen=True)
class TailscaleSSHAuthorization:
    """Attempt-scoped authority for one exact shared-identity connection."""

    user_id: int
    host: str
    remote_username: str

    def matches(self, user_id, host, remote_username):
        try:
            canonical_host = canonicalize_hostname(host)
            clean_user_id = int(user_id)
        except (TypeError, ValueError):
            return False
        return (
            clean_user_id == self.user_id
            and canonical_host == self.host
            and str(remote_username or '').strip() == self.remote_username
        )


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

    try:
        canonical_host = canonicalize_hostname(host)
    except ValueError:
        return 'Tailscale SSH target is not allowed'

    try:
        allowed_targets = {
            canonicalize_hostname(target)
            for target in config.TAILSCALE_SSH_ALLOWED_TARGETS
        }
    except (TypeError, ValueError):
        return 'Tailscale SSH target is not allowed'
    if allowed_targets and canonical_host not in allowed_targets:
        return 'Tailscale SSH target is not allowed'

    clean_remote_username = str(remote_username or '').strip()
    allowed_remote_users = config.TAILSCALE_SSH_ALLOWED_REMOTE_USERS
    if allowed_remote_users and clean_remote_username not in allowed_remote_users:
        return 'Tailscale SSH remote username is not allowed'

    return None


def authorize_tailscale_ssh_access(user, host, remote_username):
    """Return an exact internal authorization object or a safe error."""
    error = validate_tailscale_ssh_access(user, host, remote_username)
    if error:
        return None, error
    try:
        user_id = int(getattr(user, 'id'))
        canonical_host = canonicalize_hostname(host)
    except (TypeError, ValueError):
        return None, 'Tailscale SSH is not enabled for this account'
    return TailscaleSSHAuthorization(
        user_id=user_id,
        host=canonical_host,
        remote_username=str(remote_username or '').strip(),
    ), None


def profile_is_authorized_for_launch(user, profile):
    """Return whether a saved profile is still allowed by current policy."""
    if not isinstance(profile, dict) or profile.get('auth_type') != 'tailscale':
        return True
    return validate_tailscale_ssh_access(
        user,
        profile.get('host'),
        profile.get('username'),
    ) is None
