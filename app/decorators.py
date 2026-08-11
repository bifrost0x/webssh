from functools import wraps
from flask_socketio import disconnect, emit
from flask import request, abort
from flask_login import current_user
import config
from .auth import get_user_from_socket, login_manager
from .audit_logger import log_warning


def admin_required(f):
    """Require an enabled panel and authenticated admin (place above @login_required)."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not config.ADMIN_PANEL_ENABLED:
            abort(404)
        if not current_user.is_authenticated:
            return login_manager.unauthorized()
        if not getattr(current_user, 'is_admin', False):
            log_warning("Unauthorized admin access attempt",
                        user=getattr(current_user, 'username', None),
                        path=getattr(request, 'path', None))
            abort(403)
        return f(*args, **kwargs)
    return decorated_function

def socket_login_required(f):
    """
    Decorator to require authentication for socket events.

    This decorator:
    1. Gets the SocketIO session ID from the request
    2. Looks up the authenticated user for this socket
    3. Disconnects if no authenticated user found
    4. Injects 'current_user' parameter into the decorated function

    Usage:
        @socketio.on('some_event')
        @socket_login_required
        def handle_event(data, current_user=None):
            # current_user is automatically injected
            print(f"User {current_user.username} triggered event")
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        from .maintenance_mode import is_active
        if is_active():
            payload = {
                'success': False,
                'error': 'WebSSH is in restore maintenance mode',
                'code': 'maintenance',
            }
            emit('error', payload)
            return payload
        socket_sid = request.sid
        user = get_user_from_socket(socket_sid)
        if not user:
            log_warning("Unauthorized socket event attempt", event=f.__name__, sid=socket_sid)
            disconnect()
            return
        kwargs['current_user'] = user
        return f(*args, **kwargs)

    return decorated_function
