"""Opt-in, one-shot attention signals to an administrator-owned HTTPS endpoint."""
import http.client
import json
import os
import ssl
import threading
from urllib.parse import urlsplit

from flask import current_app
from .automation_store import notification_preferences, incarnation


_job_slot = threading.BoundedSemaphore(1)
_network_slot = threading.BoundedSemaphore(1)
_pending = set()


def endpoint():
    value = current_app.config.get('AUTOMATION_NOTIFICATION_WEBHOOK_URL', os.environ.get('AUTOMATION_NOTIFICATION_WEBHOOK_URL', ''))
    try:
        parsed = urlsplit(value)
        if (not isinstance(value, str) or len(value) > 2048 or any(ord(c) < 33 for c in value)
                or parsed.scheme != 'https' or not parsed.hostname or parsed.username is not None
                or parsed.password is not None or parsed.fragment or (parsed.port is not None and not 1 <= parsed.port <= 65535)):
            return None
        return value
    except (ValueError, TypeError):
        return None


def status(user_id):
    preferences = notification_preferences(user_id)
    delivery = preferences['delivery']
    if delivery == 'pending' and (id(current_app._get_current_object()), int(user_id)) not in _pending:
        delivery = 'failed'  # A restart cannot prove the last delivery completed.
    return dict(enabled=preferences['enabled'], available=endpoint() is not None, delivery=delivery)


def _post(url, payload):
    # Direct standard-library connection: no proxy environment, redirects or retry.
    parsed = urlsplit(url)
    connection = http.client.HTTPSConnection(parsed.hostname, parsed.port or 443, timeout=3, context=ssl.create_default_context())
    try:
        connection.request('POST', (parsed.path or '/') + ('?' + parsed.query if parsed.query else ''),
                           body=json.dumps(payload).encode('utf-8'),
                           headers={'Content-Type': 'application/json', 'User-Agent': 'WebSSH-Workflow'})
        response = connection.getresponse()
        if not 200 <= response.status < 300:
            raise ValueError('delivery_failed')
        # No response body is needed or retained.
    finally:
        connection.close()


def _deliver(url, payload):
    # A wall-clock bound also covers DNS and a peer sending headers very slowly.
    # At most one daemon request may outlive the deadline; no queue or replay.
    if not _network_slot.acquire(blocking=False):
        raise TimeoutError('delivery_busy')
    completed = threading.Event()
    outcome = []
    def request_once():
        try:
            _post(url, payload)
            outcome.append(True)
        except Exception:
            pass
        finally:
            _network_slot.release()
            completed.set()
    worker = threading.Thread(target=request_once, name='workflow-notification-http', daemon=True)
    try:
        worker.start()
    except Exception:
        _network_slot.release()
        raise
    if not completed.wait(3) or not outcome:
        raise TimeoutError('delivery_failed')


def notify(user_id, event):
    """Queue at most one best-effort delivery without delaying workflow work."""
    if event not in {'failed', 'unknown', 'needs_review'}:
        return
    acquired = False
    pending_key = None
    try:
        preferences = notification_preferences(user_id)
        if not preferences['enabled']:
            return
        url = endpoint()
        if url is None:
            notification_preferences(user_id, delivery='unavailable')
            return
        acquired = _job_slot.acquire(blocking=False)
        if not acquired:
            notification_preferences(user_id, delivery='failed')
            return
        app = current_app._get_current_object()
        from .automation_schedule import _account, _policy
        account = _account(user_id)
        policy = _policy()
        pending_key = (id(app), int(user_id))
        _pending.add(pending_key)
        notification_preferences(user_id, delivery='pending')
        def deliver(cancelled):
            try:
                with app.app_context():
                    if incarnation(user_id) != account[0]:
                        return
                    delivery = 'failed'
                    try:
                        if (not cancelled.is_set() and endpoint() == url
                                and _account(user_id) == account and _policy() == policy
                                and notification_preferences(user_id)['enabled']):
                            _deliver(url, {'event': 'workflow_attention', 'status': event})
                            delivery = 'sent'
                    except Exception:
                        pass
                    if incarnation(user_id) == account[0]:
                        notification_preferences(user_id, delivery=delivery)
            except Exception:
                pass
            finally:
                _pending.discard(pending_key)
                _job_slot.release()
        app.extensions['runtime_lifecycle'].start_job('workflow-notification', deliver, owner_id=user_id)
        acquired = False  # Job now owns the admission slot.
    except Exception:
        if acquired:
            _pending.discard(pending_key)
            _job_slot.release()
        try:
            notification_preferences(user_id, delivery='failed')
        except Exception:
            pass
