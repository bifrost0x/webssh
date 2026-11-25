"""Set up saved-password assignments through the confirmed native intent flow."""


def _apply_native(service, uid, aid, mutation):
    token = service.prepare_vault(uid, aid, dict(operation='native', mutation=mutation))['intent']
    service.apply_native_assignment(uid, aid, token, mutation)


def assign_credential(service, uid, aid, resource_id, credential_id):
    """Assign an existing saved password to an owned resource."""
    _apply_native(service, uid, aid, dict(
        method='assign', resource_id=resource_id, credential_id=credential_id, confirm_target=True))


def create_assigned_credential(service, uid, aid, resource_id, data):
    """Save a new password for an unassigned resource and return its public record."""
    _apply_native(service, uid, aid, dict(method='create', resource_id=resource_id, confirm_target=True, **data))
    document = service.named.read(uid)
    record_id = document['assignments'][resource_id]['credential_id']
    return service.named.public(document, document['credentials'][record_id])
