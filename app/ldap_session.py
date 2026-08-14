"""Periodic validation for authenticated LDAP-managed sessions."""

import logging

from . import user_lifecycle
from .audit_logger import log_security_event
from .ldap_service import LDAPDirectory, LDAPLookupRejected, LDAPUnavailable
from .models import LDAPIdentity, User, db


def revalidate_user(user):
    mapping = user.ldap_identity
    if mapping is None or user.is_locked or user.is_admin:
        raise LDAPLookupRejected('LDAP account is not eligible')
    resolved = LDAPDirectory().lookup(mapping.directory_username)
    if resolved.provider != mapping.provider or resolved.subject != mapping.subject:
        raise LDAPLookupRejected('Stable LDAP identity no longer matches')
    return resolved


def revalidate_all_linked_users(app, socketio_instance=None):
    """Revoke live access for mappings that no longer validate."""
    with app.app_context():
        user_ids = [
            user_id
            for (user_id,) in (
                db.session.query(LDAPIdentity.user_id)
                .order_by(LDAPIdentity.user_id)
                .all()
            )
        ]
        for user_id in user_ids:
            user = db.session.get(User, user_id)
            if user is None:
                continue
            try:
                revalidate_user(user)
            except (LDAPLookupRejected, LDAPUnavailable) as exc:
                log_security_event(
                    'LDAP_BACKGROUND_REVALIDATION_REJECTED',
                    level=logging.WARNING,
                    user=user.username,
                    error=type(exc).__name__,
                )
                user_lifecycle.revoke_user_access(
                    user.id,
                    socketio_instance,
                )
