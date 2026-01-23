from flask import Flask, render_template, request, redirect, url_for, flash
from flask_socketio import SocketIO
from flask_login import login_user, logout_user, login_required, current_user
from flask_wtf.csrf import CSRFProtect
from werkzeug.middleware.proxy_fix import ProxyFix
import config
import os
from .models import db
from .auth import login_manager, init_auth, authenticate_user, register_user, check_rate_limit
from .audit_logger import log_rate_limit_exceeded, log_info, log_warning, log_error
from .user_settings import get_user_settings

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
    # ProxyFix middleware sets request.remote_addr to the real client IP
    return request.remote_addr or 'unknown'


def create_app():
    base_dir = os.path.dirname(os.path.dirname(__file__))
    template_dir = os.path.join(base_dir, 'templates')
    static_dir = os.path.join(base_dir, 'static')
    app = Flask(__name__, template_folder=template_dir, static_folder=static_dir)
    app.config.from_object(config)

    # SECURITY: Enable ProxyFix for trusted reverse proxy deployments
    # This ensures X-Forwarded-For header is respected for rate limiting
    # Set TRUSTED_PROXIES=1 (or number of proxies) when behind a reverse proxy
    trusted_proxies = int(os.environ.get('TRUSTED_PROXIES', '0'))
    if trusted_proxies > 0:
        app.wsgi_app = ProxyFix(
            app.wsgi_app,
            x_for=trusted_proxies,  # Trust X-Forwarded-For
            x_proto=trusted_proxies,  # Trust X-Forwarded-Proto
            x_host=trusted_proxies,  # Trust X-Forwarded-Host
            x_prefix=trusted_proxies  # Trust X-Forwarded-Prefix
        )
        log_info(f"ProxyFix enabled with {trusted_proxies} trusted proxy level(s)")

    # SECURITY: Production readiness checks
    if not config.DEBUG:
        # Check SECRET_KEY is not default/weak
        if not os.environ.get('SECRET_KEY'):
            log_error("CRITICAL: SECRET_KEY not set in environment variables! "
                      "Using auto-generated SECRET_KEY will break sessions after restart. "
                      "Set SECRET_KEY environment variable for production deployment!")

        # Check CORS is not wildcard
        if config.CORS_ORIGINS == '*':
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
        logger=False,
        engineio_logger=False
    )

    # Security Headers Middleware
    @app.after_request
    def add_security_headers(response):
        """Add comprehensive security headers to all responses."""
        # Content Security Policy
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

        # Prevent clickjacking
        response.headers['X-Frame-Options'] = 'DENY'

        # Prevent MIME type sniffing
        response.headers['X-Content-Type-Options'] = 'nosniff'

        # XSS Protection
        response.headers['X-XSS-Protection'] = '1; mode=block'

        # Referrer Policy
        response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'

        # Permissions Policy
        response.headers['Permissions-Policy'] = 'geolocation=(), microphone=(), camera=()'

        # HSTS (only if not in debug mode)
        if not config.DEBUG:
            response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'

        return response

    from . import socket_events, command_manager

    # Background session cleanup (runs every 30 minutes)
    def setup_background_tasks():
        """Setup background tasks like session cleanup."""
        import threading
        from .auth import cleanup_inactive_socket_sessions

        def cleanup_task():
            while True:
                import time
                time.sleep(1800)  # 30 minutes
                try:
                    with app.app_context():
                        deleted = cleanup_inactive_socket_sessions(timeout_minutes=30)
                        if deleted > 0:
                            log_info(f"Cleaned up {deleted} inactive sessions")
                except Exception as e:
                    log_error(f"Session cleanup error", error=str(e))

        cleanup_thread = threading.Thread(target=cleanup_task, daemon=True)
        cleanup_thread.start()
        log_info("Background session cleanup task started")

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
                login_user(user, remember=True)
                return redirect(url_for('index'))
            else:
                flash(error, 'error')
        return render_template('login.html')

    @app.route('/register', methods=['GET', 'POST'])
    def register():
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
                    login_user(user)
                    flash('Account created successfully!', 'success')
                    return redirect(url_for('index'))
                else:
                    flash(error, 'error')
        return render_template('register.html')

    @app.route('/logout')
    @login_required
    def logout():
        logout_user()
        return redirect(url_for('login'))

    @app.route('/change-password', methods=['GET', 'POST'])
    @login_required
    def change_password():
        if request.method == 'POST':
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
            elif current_user.check_password(new_password):
                flash('New password must be different from current password', 'error')
            else:
                current_user.set_password(new_password)
                db.session.commit()
                flash('Password updated successfully', 'success')
                return redirect(url_for('index'))
        return render_template('change_password.html')
    return app
