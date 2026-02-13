from functools import wraps
from flask_socketio import disconnect
from flask import request
from .auth import get_user_from_socket
from .audit_logger import log_warning

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
        socket_sid = request.sid
        user = get_user_from_socket(socket_sid)
        if not user:
            log_warning(f"Unauthorized socket event attempt", event=f.__name__, sid=socket_sid)
            disconnect()
            return
        kwargs['current_user'] = user
        return f(*args, **kwargs)

    return decorated_function
