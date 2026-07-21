from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, session
from flask_socketio import SocketIO
from flask_login import login_user, logout_user, login_required, current_user
from flask_wtf.csrf import CSRFProtect
from werkzeug.middleware.proxy_fix import ProxyFix
import config
import os
from .models import db
from .auth import (login_manager, init_auth, authenticate_user, register_user,
                   check_rate_limit, password_exceeds_bcrypt_limit)
from .audit_logger import (log_rate_limit_exceeded, log_info, log_warning, log_error,
                              log_login_attempt, log_logout, log_registration, log_password_change)
from .user_settings import get_user_settings
from .app_settings import is_registration_enabled, set_registration_enabled
from . import sftp_handler
from .tailscale_ssh import user_can_use_tailscale_ssh

socketio = SocketIO()
csrf = CSRFProtect()

def get_client_ip():
    """
    Get the real client IP address.

    SECURITY: When behind a reverse proxy (e.g., Traefik, nginx), the real
    client IP is in X-Forwarded-For header. ProxyFix middleware handles this
    when TRUSTED_PROXIES is configured.

    Returns the IP address that should be used for rate limiting.
    """
    return request.remote_addr or 'unknown'

def create_app():
    base_dir = os.path.dirname(os.path.dirname(__file__))
    template_dir = os.path.join(base_dir, 'templates')
    static_dir = os.path.join(base_dir, 'static')
    app = Flask(__name__, template_folder=template_dir, static_folder=static_dir)
    app.config.from_object(config)

    url_prefix = getattr(config, 'APPLICATION_ROOT', '')
    if url_prefix:
        app.config['SESSION_COOKIE_PATH'] = url_prefix
        app.config['REMEMBER_COOKIE_PATH'] = url_prefix

    @app.context_processor
    def inject_url_prefix():
        return {
            'url_prefix': url_prefix,
            'registration_enabled': is_registration_enabled(),
            'tmux_enabled': config.TMUX_ENABLED,
            'tmux_default': config.TMUX_DEFAULT,
            'tailscale_ssh_allowed': user_can_use_tailscale_ssh(current_user)
        }

    trusted_proxies = int(os.environ.get('TRUSTED_PROXIES', '0'))
    if trusted_proxies > 0:
        app.wsgi_app = ProxyFix(
            app.wsgi_app,
            x_for=trusted_proxies,
            x_proto=trusted_proxies,
            x_host=trusted_proxies,
            x_prefix=trusted_proxies
        )
        log_info("ProxyFix enabled")

    if not config.DEBUG:
        if not os.environ.get('SECRET_KEY'):
            log_error("CRITICAL: SECRET_KEY not set in environment variables! "
                      "Using auto-generated SECRET_KEY will break sessions after restart. "
                      "Set SECRET_KEY environment variable for production deployment!")

        if config.CORS_ORIGINS == '*' and not os.environ.get('ALLOW_CORS_WILDCARD', '').lower() == 'true':
            log_warning("CORS_ORIGINS set to wildcard (*) in production mode! "
                        "This allows any domain to access your API - significant security risk. "
                        "Set CORS_ORIGINS to specific allowed origins.")

    config.DATA_DIR.mkdir(parents=True, exist_ok=True)
    app.config['SQLALCHEMY_DATABASE_URI'] = f'sqlite:///{config.DATA_DIR / "app.db"}'
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
    db.init_app(app)
    init_auth(app)
    csrf.init_app(app)

    with app.app_context():
        db.create_all()
        from .models import ensure_user_columns, ensure_ssh_session_columns
        ensure_user_columns()
        ensure_ssh_session_columns()
        from .auth import sync_admin_users
        sync_admin_users()
    cors_origins = config.CORS_ORIGINS
    if isinstance(cors_origins, str):
        cors_origins = [origin.strip() for origin in cors_origins.split(',') if origin.strip()]
    if cors_origins == ['*']:
        cors_origins = '*'

    socketio.init_app(
        app,
        cors_allowed_origins=cors_origins,
        async_mode=config.SOCKETIO_ASYNC_MODE,
        ping_timeout=config.SOCKETIO_PING_TIMEOUT,
        ping_interval=config.SOCKETIO_PING_INTERVAL,
        max_http_buffer_size=110 * 1024 * 1024,
        logger=False,
        engineio_logger=False
    )

    @app.after_request
    def add_security_headers(response):
        """Add comprehensive security headers to all responses."""
        response.headers['Content-Security-Policy'] = (
            "default-src 'self'; "
            "script-src 'self' 'unsafe-inline'; "
            "style-src 'self' 'unsafe-inline'; "
            "img-src 'self' data: https:; "
            "font-src 'self' data:; "
            "media-src 'self' data:; "
            "connect-src 'self' ws: wss:; "
            "frame-ancestors 'none';"
        )

        response.headers['X-Frame-Options'] = 'DENY'

        response.headers['X-Content-Type-Options'] = 'nosniff'

        response.headers['X-XSS-Protection'] = '1; mode=block'

        response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'

        response.headers['Permissions-Policy'] = 'geolocation=(), microphone=(), camera=()'

        if not config.DEBUG:
            response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'

        return response

    from . import socket_events, command_manager

    def setup_background_tasks():
        """Setup background tasks like session cleanup."""
        import threading
        from .auth import cleanup_inactive_socket_sessions
        from .ssh_manager import cleanup_idle_sessions

        def db_cleanup_task():
            while True:
                import time
                time.sleep(1800)
                try:
                    with app.app_context():
                        deleted = cleanup_inactive_socket_sessions(timeout_minutes=30)
                        if deleted > 0:
                            log_info(f"Cleaned up {deleted} inactive sessions")
                except Exception as e:
                    log_error(f"Session cleanup error", error=str(e))

        def ssh_cleanup_task():
            while True:
                import time
                time.sleep(60)
                try:
                    cleanup_idle_sessions()
                except Exception as e:
                    log_error(f"SSH cleanup error", error=str(e))

        cleanup_thread = threading.Thread(target=db_cleanup_task, daemon=True)
        cleanup_thread.start()
        ssh_cleanup_thread = threading.Thread(target=ssh_cleanup_task, daemon=True)
        ssh_cleanup_thread.start()
        log_info("Background session cleanup tasks started")

    setup_background_tasks()

    @app.route('/')
    @login_required
    def index():
        settings = get_user_settings(current_user.id)
        theme = settings.get('theme', 'glass')
        return render_template('index.html', username=current_user.username, theme=theme,
                               max_editor_file_size=config.MAX_EDITOR_FILE_SIZE)

    @app.route('/login', methods=['GET', 'POST'])
    def login():
        if current_user.is_authenticated:
            return redirect(url_for('index'))
        if request.method == 'POST':
            client_ip = get_client_ip()
            if config.RATELIMIT_ENABLED and check_rate_limit(
                client_ip,
                'login',
                config.RATELIMIT_LOGIN_LIMIT
            ):
                log_rate_limit_exceeded('login', client_ip)
                flash('Too many login attempts. Please try again later.', 'error')
                return render_template('login.html')

            username = request.form.get('username')
            password = request.form.get('password')
            user, error = authenticate_user(username, password)
            if user:
                session.clear()
                remember_me = request.form.get('remember') == 'on'
                login_user(user, remember=remember_me)
                log_login_attempt(username, True, client_ip, request.user_agent.string)
                return redirect(url_for('index'))
            else:
                log_login_attempt(username, False, client_ip, request.user_agent.string)
                flash(error, 'error')
        return render_template('login.html')

    @app.route('/register', methods=['GET', 'POST'])
    def register():
        if not is_registration_enabled():
            flash('Registration is currently disabled.', 'error')
            return redirect(url_for('login'))
        if current_user.is_authenticated:
            return redirect(url_for('index'))

        if request.method == 'POST':
            client_ip = get_client_ip()
            if config.RATELIMIT_ENABLED and check_rate_limit(
                client_ip,
                'register',
                config.RATELIMIT_DEFAULT
            ):
                log_rate_limit_exceeded('register', client_ip)
                flash('Too many registration attempts. Please try again later.', 'error')
                return render_template('register.html')

            username = request.form.get('username')
            password = request.form.get('password')
            confirm_password = request.form.get('confirm_password')
            if password != confirm_password:
                flash('Passwords do not match', 'error')
            else:
                user, error = register_user(username, password)
                if user:
                    session.clear()
                    login_user(user)
                    log_registration(username, True, client_ip)
                    flash('Account created successfully!', 'success')
                    return redirect(url_for('index'))
                else:
                    log_registration(username, False, client_ip)
                    flash(error, 'error')
        return render_template('register.html')

    @app.route('/logout', methods=['POST'])
    @login_required
    def logout():
        from . import user_lifecycle

        user_id = current_user.id
        log_logout(current_user.username, get_client_ip())
        user_lifecycle.revoke_user_access(user_id, socketio)
        logout_user()
        return redirect(url_for('login'))

    @app.route('/change-password', methods=['GET', 'POST'])
    @login_required
    def change_password():
        if request.method == 'POST':
            client_ip = get_client_ip()
            if config.RATELIMIT_ENABLED and check_rate_limit(
                client_ip,
                'change_password',
                config.RATELIMIT_LOGIN_LIMIT
            ):
                log_rate_limit_exceeded('change_password', client_ip, user=current_user.username)
                flash('Too many attempts. Please try again later.', 'error')
                settings = get_user_settings(current_user.id)
                theme = settings.get('theme', 'glass')
                return render_template('change_password.html', theme=theme)

            current_password = request.form.get('current_password', '')
            new_password = request.form.get('new_password', '')
            confirm_password = request.form.get('confirm_password', '')

            if not current_user.check_password(current_password):
                flash('Current password is incorrect', 'error')
            elif new_password != confirm_password:
                flash('New passwords do not match', 'error')
            elif len(new_password) < config.MIN_PASSWORD_LENGTH:
                flash(
                    f'New password must be at least {config.MIN_PASSWORD_LENGTH} characters',
                    'error'
                )
            elif password_exceeds_bcrypt_limit(new_password):
                flash(
                    f'New password must not exceed {config.MAX_PASSWORD_LENGTH} bytes when encoded as UTF-8',
                    'error'
                )
            elif current_user.check_password(new_password):
                flash('New password must be different from current password', 'error')
            else:
                current_user.set_password(new_password)
                db.session.commit()
                log_password_change(current_user.username, True, get_client_ip())
                flash('Password updated successfully', 'success')
                return redirect(url_for('index'))
        settings = get_user_settings(current_user.id)
        theme = settings.get('theme', 'glass')
        return render_template('change_password.html', theme=theme)

    from .decorators import admin_required
    from .models import User
    from .audit_logger import read_audit_logs

    def _user_to_dict(u):
        return {
            'id': u.id,
            'username': u.username,
            'is_admin': bool(u.is_admin),
            'is_locked': bool(u.is_locked),
            'created_at': u.created_at.isoformat() if u.created_at else None,
            'last_login': u.last_login.isoformat() if u.last_login else None,
        }

    @app.route('/admin')
    @login_required
    @admin_required
    def admin_page():
        settings = get_user_settings(current_user.id)
        theme = settings.get('theme', 'glass')
        return render_template('admin.html', username=current_user.username, theme=theme)

    @app.route('/admin/api/users', methods=['GET'])
    @login_required
    @admin_required
    def admin_list_users():
        users = User.query.order_by(User.id.asc()).all()
        return jsonify({'users': [_user_to_dict(u) for u in users]})

    @app.route('/admin/api/users', methods=['POST'])
    @login_required
    @admin_required
    def admin_create_user():
        data = request.get_json(silent=True) or {}
        username = (data.get('username') or '').strip()
        password = data.get('password') or ''
        make_admin = bool(data.get('is_admin'))
        user, error = register_user(username, password)
        if error:
            return jsonify({'error': error}), 400
        if make_admin:
            user.is_admin = True
            db.session.commit()
        log_info("Admin created user", admin=current_user.username,
                 user=user.username, is_admin=make_admin)
        return jsonify({'user': _user_to_dict(user)}), 201

    @app.route('/admin/api/users/<int:user_id>/<action>', methods=['POST'])
    @login_required
    @admin_required
    def admin_user_action(user_id, action):
        from . import user_lifecycle

        target = db.session.get(User, user_id)
        if not target:
            return jsonify({'error': 'User not found'}), 404
        is_self = (target.id == current_user.id)

        def _is_last_admin():
            return target.is_admin and User.query.filter_by(is_admin=True).count() <= 1

        revoke_after_commit = False
        if action == 'lock':
            if is_self:
                return jsonify({'error': 'You cannot lock your own account'}), 400
            target.is_locked = True
            revoke_after_commit = True
        elif action == 'unlock':
            target.is_locked = False
        elif action == 'promote':
            target.is_admin = True
        elif action == 'demote':
            if is_self:
                return jsonify({'error': 'You cannot remove your own admin rights'}), 400
            if _is_last_admin():
                return jsonify({'error': 'Cannot demote the last administrator'}), 400
            target.is_admin = False
        elif action == 'delete':
            if is_self:
                return jsonify({'error': 'You cannot delete your own account'}), 400
            if _is_last_admin():
                return jsonify({'error': 'Cannot delete the last administrator'}), 400
            username = target.username
            target.is_locked = True
            db.session.commit()
            try:
                user_lifecycle.delete_user_account(target, socketio)
            except Exception as exc:
                log_error(
                    "Admin user deletion failed",
                    admin=current_user.username,
                    user=username,
                    error=str(exc),
                )
                return jsonify({
                    'error': 'User deletion failed; the account remains locked'
                }), 500
            log_warning("Admin deleted user", admin=current_user.username, user=username)
            return jsonify({'ok': True})
        else:
            return jsonify({'error': 'Unknown action'}), 400

        db.session.commit()
        if revoke_after_commit:
            user_lifecycle.revoke_user_access(target.id, socketio)
        log_info("Admin user action", admin=current_user.username,
                 user=target.username, action=action)
        return jsonify({'user': _user_to_dict(target)})

    @app.route('/admin/api/audit', methods=['GET'])
    @login_required
    @admin_required
    def admin_audit():
        try:
            offset = int(request.args.get('offset', 0))
            limit = int(request.args.get('limit', 100))
        except (ValueError, TypeError):
            offset, limit = 0, 100
        level = request.args.get('level') or None
        q = request.args.get('q') or None
        result = read_audit_logs(offset=offset, limit=limit, level=level, q=q)
        return jsonify(result)

    @app.route('/admin/api/settings', methods=['GET'])
    @login_required
    @admin_required
    def admin_get_settings():
        return jsonify({'registration_enabled': is_registration_enabled()})

    @app.route('/admin/api/settings', methods=['POST'])
    @login_required
    @admin_required
    def admin_set_settings():
        data = request.get_json(silent=True) or {}
        if 'registration_enabled' in data:
            val = set_registration_enabled(bool(data['registration_enabled']))
            log_info("Admin changed registration setting",
                     admin=current_user.username, registration_enabled=val)
        return jsonify({'registration_enabled': is_registration_enabled()})

    @app.route('/api/upload', methods=['POST'])
    @login_required
    def api_upload():
        """HTTP file upload endpoint for SFTP."""
        try:
            file = request.files.get('file')
            session_id = request.form.get('session_id')
            remote_path = request.form.get('remote_path')

            if not all([file, session_id, remote_path]):
                return jsonify({'error': 'Missing required fields'}), 400

            max_mb = config.MAX_UPLOAD_SIZE // (1024 * 1024)

            # Reject oversized uploads from the Content-Length header BEFORE
            # buffering anything, so a large request cannot exhaust memory.
            if request.content_length and request.content_length > config.MAX_UPLOAD_SIZE:
                return jsonify({'error': f'File too large. Maximum: {max_mb}MB'}), 413

            from .socket_events import verify_session_ownership
            from . import connection_pool
            if not verify_session_ownership(session_id, current_user.id):
                conn_info = connection_pool.temp_connection_pool.get_connection_info(session_id)
                if not conn_info or conn_info['user_id'] != str(current_user.id):
                    return jsonify({'error': 'Unauthorized'}), 403

            # Read incrementally with a hard cap instead of file.read() into one
            # buffer plus a second full copy. This also guards against a missing
            # or dishonest Content-Length (e.g. chunked transfer-encoding).
            chunk_size = config.CHUNK_SIZE
            chunks = []
            total = 0
            while True:
                chunk = file.read(chunk_size)
                if not chunk:
                    break
                total += len(chunk)
                if total > config.MAX_UPLOAD_SIZE:
                    return jsonify({'error': f'File too large. Maximum: {max_mb}MB'}), 413
                chunks.append(chunk)

            success, error = sftp_handler.upload_file_chunked(
                session_id=session_id,
                filename=file.filename,
                chunks=chunks,
                remote_path=remote_path,
                socketio_instance=None
            )

            if error:
                log_error("Upload failed in SFTP handler", error=str(error), user=current_user.username, path=remote_path)
                return jsonify({'error': 'Upload failed'}), 500

            log_info(f"File uploaded via HTTP: {file.filename}", user=current_user.username, path=remote_path)
            return jsonify({'success': True, 'filename': file.filename}), 200

        except Exception as e:
            log_error(f"Upload failed", error=str(e))
            return jsonify({'error': 'Upload failed'}), 500

    return app
