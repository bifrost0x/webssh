from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, session
from flask_socketio import SocketIO
from flask_login import login_user, logout_user, login_required, current_user
from flask_wtf.csrf import CSRFProtect
from werkzeug.middleware.proxy_fix import ProxyFix
import config
import os
from .models import db
from flask_migrate import Migrate
from .auth import login_manager, init_auth, authenticate_user, register_user, check_rate_limit
from .audit_logger import (log_rate_limit_exceeded, log_info, log_warning, log_error,
                              log_login_attempt, log_logout, log_registration, log_password_change)
from .user_settings import get_user_settings
from . import sftp_handler

socketio = SocketIO()
csrf = CSRFProtect()
migrate = Migrate()

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

    trusted_proxies = int(os.environ.get('TRUSTED_PROXIES', '0'))
    if trusted_proxies > 0:
        app.wsgi_app = ProxyFix(
            app.wsgi_app,
            x_for=trusted_proxies,
            x_proto=trusted_proxies,
            x_host=trusted_proxies,
            x_prefix=trusted_proxies
        )
        log_info(f"ProxyFix enabled with {trusted_proxies} trusted proxy level(s)")

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
    migrate.init_app(app, db)
    init_auth(app)
    csrf.init_app(app)

    with app.app_context():
        db.create_all()
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
            "script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net https://cdn.socket.io; "
            "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net https://fonts.googleapis.com; "
            "img-src 'self' data: https:; "
            "font-src 'self' data: https://fonts.gstatic.com; "
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
            import time
            consecutive_errors = 0
            while True:
                time.sleep(1800)
                try:
                    with app.app_context():
                        deleted = cleanup_inactive_socket_sessions(timeout_minutes=30)
                        if deleted > 0:
                            log_info(f"Cleaned up {deleted} inactive sessions")
                    consecutive_errors = 0
                except Exception as e:
                    consecutive_errors += 1
                    log_error("Session cleanup error", error=str(e))
                    if consecutive_errors >= 5:
                        backoff = min(300, 60 * consecutive_errors)
                        log_warning(f"Session cleanup backing off {backoff}s after {consecutive_errors} consecutive errors")
                        time.sleep(backoff)

        def ssh_cleanup_task():
            import time
            consecutive_errors = 0
            while True:
                time.sleep(60)
                try:
                    cleanup_idle_sessions()
                    consecutive_errors = 0
                except Exception as e:
                    consecutive_errors += 1
                    log_error("SSH cleanup error", error=str(e))
                    if consecutive_errors >= 5:
                        backoff = min(300, 60 * consecutive_errors)
                        log_warning(f"SSH cleanup backing off {backoff}s after {consecutive_errors} consecutive errors")
                        time.sleep(backoff)

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
        return render_template('index.html', username=current_user.username, theme=theme)

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
        if not config.REGISTRATION_ENABLED:
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
        log_logout(current_user.username, get_client_ip())
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
            elif len(new_password) > config.MAX_PASSWORD_LENGTH:
                flash(
                    f'New password must not exceed {config.MAX_PASSWORD_LENGTH} characters',
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

            file_data = file.read()
            if len(file_data) > config.MAX_UPLOAD_SIZE:
                max_mb = config.MAX_UPLOAD_SIZE // (1024 * 1024)
                return jsonify({'error': f'File too large. Maximum: {max_mb}MB'}), 413

            from .socket_events import verify_session_ownership
            from . import connection_pool
            if not verify_session_ownership(session_id, current_user.id):
                conn_info = connection_pool.temp_connection_pool.get_connection_info(session_id)
                if not conn_info or conn_info['user_id'] != str(current_user.id):
                    return jsonify({'error': 'Unauthorized'}), 403

            chunk_size = 65536
            chunks = [file_data[i:i+chunk_size] for i in range(0, len(file_data), chunk_size)]

            success, error = sftp_handler.upload_file_chunked(
                session_id=session_id,
                filename=file.filename,
                chunks=chunks,
                remote_path=remote_path,
                socketio_instance=None
            )

            if error:
                return jsonify({'error': f'Upload failed: {error}'}), 500

            log_info(f"File uploaded via HTTP: {file.filename}", user=current_user.username, path=remote_path)
            return jsonify({'success': True, 'filename': file.filename}), 200

        except Exception as e:
            log_error("Upload failed", error=str(e))
            return jsonify({'error': 'Upload failed'}), 500

    return app
