from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, session, abort
from flask_socketio import SocketIO
from flask_login import login_required, current_user
from flask_wtf.csrf import CSRFProtect
from werkzeug.middleware.proxy_fix import ProxyFix
import config
import os
import time
from .models import db
from .auth import (init_auth, authenticate_user, register_user,
                   check_rate_limit, is_bootstrap_registration_available,
                   password_exceeds_bcrypt_limit)
from .audit_logger import (log_rate_limit_exceeded, log_info, log_warning, log_error,
                              log_login_attempt, log_logout, log_registration, log_password_change)
from .user_settings import get_user_settings, save_user_settings
from .app_settings import is_registration_enabled, set_registration_enabled
from .storage_errors import StorageCorruptionError
from .tailscale_ssh import user_can_use_tailscale_ssh
from .runtime_lifecycle import RuntimeLifecycle
from .browser_identity import connection_history_scope
from .auth_assurance import clear_browser_authentication

socketio = SocketIO(
    async_mode=config.SOCKETIO_ASYNC_MODE,
    async_handlers=config.SOCKETIO_ASYNC_HANDLERS,
)
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

def _initialize_persistent_storage(app):
    """Initialize storage and schema for serving or explicit CLI mutation."""
    if app.extensions.get('persistent_storage_initialized'):
        return

    config.DATA_DIR.mkdir(parents=True, exist_ok=True)
    from .session_epoch import current_epoch
    current_epoch()
    from .audit_logger import initialize_file_logging
    initialize_file_logging(config.DATA_DIR)
    with app.app_context():
        db.create_all()
        from .models import ensure_security_columns, ensure_ssh_session_columns
        ensure_security_columns()
        ensure_ssh_session_columns()
        from .auth import ensure_initial_admin, sync_admin_users
        ensure_initial_admin()
        sync_admin_users()
        from .cli import warn_if_no_admin
        warn_if_no_admin()
        from .audit_logger import apply_audit_backup_count
        apply_audit_backup_count()
    app.extensions['persistent_storage_initialized'] = True


def create_app(
    *,
    initialize_storage=True,
    start_runtime=True,
    initialize_oidc=True,
):
    base_dir = os.path.dirname(os.path.dirname(__file__))
    template_dir = os.path.join(base_dir, 'templates')
    static_dir = os.path.join(base_dir, 'static')
    app = Flask(__name__, template_folder=template_dir, static_folder=static_dir)
    app.config.from_object(config)
    app.extensions['runtime_lifecycle'] = RuntimeLifecycle(
        max_workers=config.BACKGROUND_WORKERS
    )

    from .maintenance_mode import is_active, recover_interrupted_restore
    if initialize_storage:
        recover_interrupted_restore()

    for warning in config.SECURITY_CONFIG_WARNINGS:
        log_warning('Deployment security warning', warning=warning)

    @app.errorhandler(StorageCorruptionError)
    def handle_storage_corruption(error):
        """Return a safe response without rendering another template."""
        log_error(
            'Storage corruption detected',
            store=error.path.name,
            path=str(error.path),
            reason=error.reason,
        )
        message = 'Stored data is unreadable. Please restore or remove it.'
        if request.path.startswith('/api/') or request.path.startswith('/admin/api/'):
            return jsonify({
                'success': False,
                'error': message,
                'code': 'storage_error',
            }), 503
        body = (
            '<!doctype html><html lang="en"><head><meta charset="utf-8">'
            '<title>Stored data unavailable</title></head><body>'
            f'<main><h1>Stored data unavailable</h1><p>{message}</p></main>'
            '</body></html>'
        )
        return app.response_class(body, status=503, mimetype='text/html')

    url_prefix = getattr(config, 'APPLICATION_ROOT', '')
    if url_prefix:
        app.config['SESSION_COOKIE_PATH'] = url_prefix
        app.config['REMEMBER_COOKIE_PATH'] = url_prefix

    @app.context_processor
    def inject_url_prefix():
        from .security_features import feature_is_active

        registration_available = (
            is_registration_enabled()
            or is_bootstrap_registration_available()
        )
        return {
            'url_prefix': url_prefix,
            'registration_enabled': registration_available,
            'tmux_enabled': config.TMUX_ENABLED,
            'tmux_default': config.TMUX_DEFAULT,
            'admin_panel_enabled': config.ADMIN_PANEL_ENABLED,
            'webauthn_enabled': feature_is_active('passkey'),
            'webauthn_origin': config.WEBAUTHN_ORIGIN,
            'webauthn_rp_id': config.WEBAUTHN_RP_ID,
            'totp_enabled': feature_is_active('totp'),
            'oidc_enabled': feature_is_active('oidc'),
            'ldap_enabled': feature_is_active('ldap'),
            'ldap_provider_id': config.LDAP_PROVIDER_ID,
            'ldap_managed': bool(
                current_user.is_authenticated
                and current_user.is_ldap_managed
            ),
            'recovery_codes_enabled': feature_is_active('recovery'),
            'host_key_management_enabled': (
                config.HOST_KEY_MANAGEMENT_ENABLED
            ),
            'audit_export_enabled': config.AUDIT_EXPORT_ENABLED,
            'tailscale_ssh_allowed': user_can_use_tailscale_ssh(current_user)
        }

    @app.before_request
    def hide_disabled_admin_panel():
        if not config.ADMIN_PANEL_ENABLED and (
            request.path == '/admin' or request.path.startswith('/admin/')
        ):
            abort(404)

    @app.before_request
    def enforce_restore_maintenance_and_session_epoch():
        if is_active() and request.path not in {
            '/health',
            '/ready',
            '/admin/api/backups/restore/status',
        }:
            return jsonify({
                'error': 'WebSSH is in restore maintenance mode',
                'code': 'maintenance',
            }), 503
        if (
            current_user.is_authenticated
            and current_user.is_ldap_managed
            and not config.LDAP_ENABLED
        ):
            from . import user_lifecycle

            user_id = current_user.id
            user_lifecycle.revoke_user_access(user_id, socketio)
            clear_browser_authentication()
            return redirect(url_for('login'))
        if (
            current_user.is_authenticated
            and current_user.is_ldap_managed
            and config.LDAP_ENABLED
            and int(time.time()) - int(session.get('_ldap_verified_at', 0))
            >= config.LDAP_SESSION_REVALIDATION_SECONDS
        ):
            from . import user_lifecycle
            from .ldap_service import LDAPLookupRejected, LDAPUnavailable
            from .ldap_session import revalidate_user

            try:
                revalidate_user(current_user)
            except (LDAPLookupRejected, LDAPUnavailable) as exc:
                user_id = current_user.id
                log_warning(
                    'LDAP session revalidation rejected',
                    user=current_user.username,
                    error=type(exc).__name__,
                )
                user_lifecycle.revoke_user_access(user_id, socketio)
                clear_browser_authentication()
                return redirect(url_for('login'))
            session['_ldap_verified_at'] = int(time.time())
        if initialize_storage and current_user.is_authenticated:
            from .session_epoch import current_epoch
            epoch = current_epoch()
            stored_epoch = session.get('_auth_epoch')
            if stored_epoch is None:
                session['_auth_epoch'] = epoch
            elif stored_epoch != epoch:
                clear_browser_authentication()
                return redirect(url_for('login', next=request.path))
        if initialize_storage and current_user.is_authenticated:
            from .auth_assurance import current_authentication_session

            auth_session = current_authentication_session()
            if auth_session is None:
                username = current_user.username
                clear_browser_authentication()
                log_warning(
                    'Authentication session rejected',
                    user=username,
                )
                return redirect(url_for('login', next=request.path))
            from .auth_assurance import (
                recovery_route_allowed,
                recovery_session_required,
            )
            if (
                recovery_session_required(auth_session)
                and not recovery_route_allowed(request.path, request.method)
            ):
                if request.path.startswith('/api/'):
                    return jsonify({
                        'error': 'A replacement factor or explicit MFA disable is required',
                        'code': 'recovery_required',
                    }), 403
                abort(403)

    trusted_proxies = config.TRUSTED_PROXIES
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

    app.config['SQLALCHEMY_DATABASE_URI'] = f'sqlite:///{config.DATA_DIR / "app.db"}'
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
    db.init_app(app)
    from .backup_coordination import install_sqlalchemy_coordination
    install_sqlalchemy_coordination()
    init_auth(app)
    from .request_limits import init_request_limits
    from .webauthn_routes import webauthn_blueprint
    init_request_limits(app)

    @app.before_request
    def enforce_security_feature_gate():
        from .security_features import feature_is_active, request_feature_name

        feature_name = request_feature_name(request.path)
        if feature_name is not None and not feature_is_active(feature_name):
            abort(404)

    csrf.init_app(app)
    from .cli import register_cli
    from .audit_export import audit_export_blueprint
    from .admin_backup import admin_backup_blueprint
    from .account_step_up_routes import account_step_up_blueprint
    from .health import health_blueprint
    from .host_key_routes import host_key_blueprint
    from .oidc_routes import init_oidc, oidc_blueprint
    from .recovery_routes import recovery_blueprint
    from .step_up_routes import step_up_blueprint
    from .totp_routes import totp_blueprint
    from .transfer_routes import transfer_blueprint, transfer_manager
    register_cli(app)
    oidc_ready = not config.OIDC_ENABLED
    if initialize_oidc:
        init_oidc(app)
        if config.OIDC_ENABLED:
            oidc_ready = True
    app.register_blueprint(audit_export_blueprint)
    app.register_blueprint(account_step_up_blueprint)
    app.register_blueprint(admin_backup_blueprint)
    app.register_blueprint(health_blueprint)
    app.register_blueprint(host_key_blueprint)
    app.register_blueprint(oidc_blueprint)
    app.register_blueprint(recovery_blueprint)
    app.register_blueprint(step_up_blueprint)
    app.register_blueprint(totp_blueprint)
    app.register_blueprint(transfer_blueprint)
    app.register_blueprint(webauthn_blueprint)
    ldap_ready = not config.LDAP_ENABLED
    if config.LDAP_ENABLED:
        from .ldap_routes import ldap_blueprint
        from .ldap_service import validate_runtime_files
        validate_runtime_files()
        app.register_blueprint(ldap_blueprint)
        ldap_ready = True
    from .security_features import initialize_feature_readiness
    initialize_feature_readiness(
        app,
        oidc_ready=oidc_ready,
        ldap_ready=ldap_ready,
    )
    if initialize_storage:
        _initialize_persistent_storage(app)
    if start_runtime:
        from .backup_operations import backup_operations
        backup_operations.cleanup_orphans()
        app.extensions['runtime_lifecycle'].start_job(
            'backup-operation-cleanup',
            backup_operations.cleanup_loop,
        )
        transfer_runtime_binding = transfer_manager.bind_runtime()
        app.extensions['runtime_lifecycle'].start_job(
            'transfer-token-cleanup',
            transfer_manager.cleanup_loop,
        )
        app.extensions['runtime_lifecycle'].register_shutdown_callback(
            'active_transfers',
            lambda _deadline: transfer_manager.close_and_cancel(
                transfer_runtime_binding
            ),
        )
    cors_origins = config.CORS_ORIGINS
    if isinstance(cors_origins, str):
        cors_origins = [origin.strip() for origin in cors_origins.split(',') if origin.strip()]
    if cors_origins == ['*']:
        cors_origins = '*'

    socketio.init_app(
        app,
        cors_allowed_origins=cors_origins,
        async_mode=config.SOCKETIO_ASYNC_MODE,
        async_handlers=config.SOCKETIO_ASYNC_HANDLERS,
        ping_timeout=config.SOCKETIO_PING_TIMEOUT,
        ping_interval=config.SOCKETIO_PING_INTERVAL,
        max_http_buffer_size=config.SOCKETIO_MAX_MESSAGE_SIZE,
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

        if initialize_storage and session.get('_user_id') is not None:
            from .session_epoch import current_epoch
            session['_auth_epoch'] = current_epoch()
        return response

    from . import socket_events as _socket_events  # noqa: F401
    from . import connection_pool

    def setup_background_tasks():
        """Setup background tasks like session cleanup."""
        from .auth import cleanup_inactive_socket_sessions
        from .models import cleanup_expired_security_rows
        from .ssh_manager import cleanup_idle_sessions
        lifecycle = app.extensions['runtime_lifecycle']

        def db_cleanup_task(cancel_event):
            while not cancel_event.wait(1800):
                try:
                    with app.app_context():
                        deleted = cleanup_inactive_socket_sessions(timeout_minutes=30)
                        security_deleted = cleanup_expired_security_rows()
                        if deleted > 0:
                            log_info(f"Cleaned up {deleted} inactive sessions")
                        if security_deleted > 0:
                            log_info(
                                "Cleaned up expired authentication state",
                                count=security_deleted,
                            )
                except Exception as e:
                    log_error("Session cleanup error", error=str(e))

        def ssh_cleanup_task(cancel_event):
            while not cancel_event.wait(60):
                try:
                    cleanup_idle_sessions()
                except Exception as e:
                    log_error("SSH cleanup error", error=str(e))

        def ldap_revalidation_task(cancel_event):
            from .ldap_session import revalidate_all_linked_users

            while not cancel_event.wait(
                config.LDAP_SESSION_REVALIDATION_SECONDS
            ):
                try:
                    revalidate_all_linked_users(app, socketio)
                except Exception as e:
                    log_error(
                        "LDAP background revalidation error",
                        error=type(e).__name__,
                    )

        try:
            lifecycle.start_job(
                'inactive_socket_session_cleanup', db_cleanup_task
            )
            lifecycle.start_job('idle_ssh_session_cleanup', ssh_cleanup_task)
            if config.LDAP_ENABLED:
                lifecycle.start_job(
                    'ldap_session_revalidation',
                    ldap_revalidation_task,
                )
            connection_pool.bind_temp_connection_pool(lifecycle)
            if config.SMB_ENABLED:
                from . import smb_pool

                smb_pool.bind_smb_connection_pool(lifecycle)
        except Exception:
            lifecycle.begin_shutdown(config.RUNTIME_SHUTDOWN_GRACE_SECONDS)
            raise
        log_info("Background session cleanup tasks started")

    if start_runtime:
        setup_background_tasks()

    @app.route('/')
    @login_required
    def index():
        settings = get_user_settings(current_user.id)
        theme = settings.get('theme', 'glass')
        return render_template(
            'index.html',
            username=current_user.username,
            theme=theme,
            connection_history_scope=connection_history_scope(
                current_user,
                app.config['SECRET_KEY'],
            ),
            confirm_session_close=settings.get('confirm_session_close', False),
            disconnect_session_action=settings.get(
                'disconnect_session_action',
                'retry',
            ),
            max_editor_file_size=config.MAX_EDITOR_FILE_SIZE,
            smb_enabled=config.SMB_ENABLED,
            transfer_limits={
                'uploadBytes': config.MAX_UPLOAD_SIZE,
                'downloadBytes': config.MAX_DOWNLOAD_SIZE,
                'archiveBytes': config.MAX_ZIP_DOWNLOAD_SIZE,
                'remoteTransferBytes': config.MAX_ZIP_DOWNLOAD_SIZE,
            },
        )

    @app.route('/login', methods=['GET', 'POST'])
    def login():
        if current_user.is_authenticated:
            return redirect(url_for('index'))
        if (
            request.method == 'GET'
            and is_bootstrap_registration_available()
        ):
            return redirect(url_for('register'))
        if request.method == 'POST':
            client_ip = get_client_ip()
            if config.RATELIMIT_ENABLED and check_rate_limit(
                client_ip,
                'login',
                config.RATELIMIT_LOGIN_LIMIT
            ):
                log_rate_limit_exceeded('login', client_ip)
                flash('Too many login attempts. Please try again later.', 'error')
                return render_template('login.html', auth_source='local')

            username = request.form.get('username')
            password = request.form.get('password')
            user, error = authenticate_user(username, password)
            if user:
                from .auth_assurance import (
                    AssuranceLevel,
                    available_mfa_methods,
                    begin_authentication,
                    browser_session_binding,
                    consume_pending,
                    finalize_login,
                )

                session.clear()
                remember_me = request.form.get('remember') == 'on'
                binding = browser_session_binding()
                token = begin_authentication(
                    user,
                    'password',
                    assurance=AssuranceLevel.BASIC,
                    session_binding=binding,
                    remember=remember_me,
                    continuation=request.args.get('next', '/'),
                )
                if user.mfa_enabled:
                    methods = available_mfa_methods(user)
                    session['_pending_authentication'] = token
                    return render_template(
                        'login.html',
                        auth_source='local',
                        mfa_required=True,
                        pending_token=token,
                        mfa_methods=methods,
                    )
                pending = consume_pending(token, binding)
                finalize_login(pending, methods=['password'])
                return redirect(pending.continuation)
            else:
                log_login_attempt(username, False, client_ip, request.user_agent.string)
                flash(error, 'error')
        return render_template(
            'login.html',
            auth_source='local' if request.method == 'POST' else None,
        )

    @app.route('/register', methods=['GET', 'POST'])
    def register():
        ongoing_registration = is_registration_enabled()
        bootstrap_registration = is_bootstrap_registration_available()
        if not ongoing_registration and not bootstrap_registration:
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
                user, error = register_user(
                    username,
                    password,
                    first_user_only=not ongoing_registration,
                )
                if user:
                    from .auth_assurance import (
                        AssuranceLevel,
                        begin_authentication,
                        browser_session_binding,
                        consume_pending,
                        finalize_login,
                    )

                    session.clear()
                    binding = browser_session_binding()
                    token = begin_authentication(
                        user,
                        'password',
                        assurance=AssuranceLevel.BASIC,
                        session_binding=binding,
                        remember=False,
                        continuation='/',
                    )
                    pending = consume_pending(token, binding)
                    finalize_login(pending, methods=['password'])
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
        from .auth_assurance import delete_current_authentication_session

        user_id = current_user.id
        log_logout(current_user.username, get_client_ip())
        try:
            delete_current_authentication_session()
        except Exception as exc:
            db.session.rollback()
            log_warning(
                'Authentication session deletion failed during logout',
                user_id=user_id,
                error=type(exc).__name__,
            )
        user_lifecycle.revoke_user_access(user_id, socketio)
        clear_browser_authentication()
        return redirect(url_for('login'))

    @app.route('/change-password', methods=['GET', 'POST'])
    @login_required
    def change_password():
        if current_user.is_ldap_managed:
            abort(403)
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

            if (password_exceeds_bcrypt_limit(current_password)
                    or not current_user.check_password(current_password)):
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

    @app.route('/security')
    @app.route('/settings')
    @login_required
    def security_center():
        from .auth_assurance import (
            authentication_methods,
            current_authentication_session,
            recovery_session_required,
        )

        settings = get_user_settings(current_user.id)
        auth_session = current_authentication_session()
        method_labels = {
            'password': 'WebSSH password',
            'ldap': 'LDAP directory',
            'oidc': 'Identity provider (OIDC)',
            'passkey': 'Passkey',
            'totp': 'Authenticator app',
            'recovery_code': 'Recovery code',
        }
        method_i18n_keys = {
            'password': 'security.methodPassword',
            'ldap': 'security.methodLdap',
            'oidc': 'security.methodOidc',
            'passkey': 'security.methodPasskey',
            'totp': 'security.methodTotp',
            'recovery_code': 'security.methodRecoveryCode',
        }
        methods = authentication_methods(auth_session)
        primary_method = methods[0] if methods else 'password'
        return render_template(
            'security.html',
            username=current_user.username,
            theme=settings.get('theme', 'glass'),
            recovery_mode=recovery_session_required(auth_session),
            authentication_methods=tuple(
                {
                    'id': method,
                    'label': method_labels.get(method, method),
                    'i18n_key': method_i18n_keys.get(
                        method,
                        'security.methodUnknown',
                    ),
                }
                for method in (methods or ('password',))
            ),
            authentication_primary_method=primary_method,
            account_mfa_enabled=bool(current_user.mfa_enabled),
            confirm_session_close=settings.get(
                'confirm_session_close',
                False,
            ),
            disconnect_session_action=settings.get(
                'disconnect_session_action',
                'retry',
            ),
            is_admin=bool(current_user.is_admin),
        )

    @app.route('/api/account/preferences', methods=['POST'])
    @login_required
    def account_preferences():
        data = request.get_json(silent=True)
        if not isinstance(data, dict):
            return jsonify({'error': 'Invalid settings payload'}), 400
        allowed = {
            'theme',
            'confirm_session_close',
            'disconnect_session_action',
        }
        if not data or set(data) - allowed:
            return jsonify({'error': 'Invalid settings payload'}), 400

        updates = {}
        if 'theme' in data:
            valid_themes = {
                'glass', 'retro', 'solar', 'paper', 'noir',
                'arctic-ice', 'rose-gold', 'cyberpunk-neon',
                'emerald-matrix', 'obsidian',
            }
            if (
                not isinstance(data['theme'], str)
                or data['theme'] not in valid_themes
            ):
                return jsonify({'error': 'Invalid theme'}), 400
            updates['theme'] = data['theme']
        if 'confirm_session_close' in data:
            if not isinstance(data['confirm_session_close'], bool):
                return jsonify({
                    'error': 'Invalid close confirmation setting',
                }), 400
            updates['confirm_session_close'] = data[
                'confirm_session_close'
            ]
        if 'disconnect_session_action' in data:
            action = data['disconnect_session_action']
            if (
                not isinstance(action, str)
                or action not in {'retry', 'close'}
            ):
                return jsonify({
                    'error': 'Invalid disconnect session action',
                }), 400
            updates['disconnect_session_action'] = action

        if not save_user_settings(current_user.id, updates):
            return jsonify({'error': 'Failed to save settings'}), 500
        return jsonify({'settings': get_user_settings(current_user.id)})

    from .decorators import admin_required, step_up_required
    from .models import User
    from .audit_logger import read_audit_logs

    def _user_to_dict(u):
        return {
            'id': u.id,
            'username': u.username,
            'is_admin': bool(u.is_admin),
            'is_locked': bool(u.is_locked),
            'mfa_enabled': bool(u.mfa_enabled),
            'ldap_managed': bool(u.is_ldap_managed),
            'created_at': u.created_at.isoformat() if u.created_at else None,
            'last_login': u.last_login.isoformat() if u.last_login else None,
        }

    @app.route('/admin')
    @admin_required
    @login_required
    def admin_page():
        return redirect(f"{url_for('security_center')}#users")

    @app.route('/admin/api/users', methods=['GET'])
    @admin_required
    @login_required
    def admin_list_users():
        users = User.query.order_by(User.id.asc()).all()
        return jsonify({'users': [_user_to_dict(u) for u in users]})

    @app.route('/admin/api/users', methods=['POST'])
    @admin_required
    @login_required
    @step_up_required(
        'user.create',
        lambda: str((request.get_json(silent=True) or {}).get('username') or ''),
    )
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
    @admin_required
    @login_required
    @step_up_required(
        'user.manage',
        lambda user_id, action: f'{user_id}:{action}',
    )
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
            if target.is_ldap_managed:
                return jsonify({
                    'error': (
                        'LDAP accounts cannot be administrators; keep a '
                        'local break-glass administrator'
                    )
                }), 400
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

    @app.route('/admin/api/users/<int:user_id>/mfa', methods=['DELETE'])
    @admin_required
    @login_required
    @step_up_required('user.mfa_reset', lambda user_id: user_id)
    def admin_reset_user_mfa(user_id):
        from . import user_lifecycle
        from .models import (
            RecoveryCode,
            TOTPAuthenticator,
            TOTPEnrollment,
            WebAuthnChallenge,
            WebAuthnCredential,
        )

        data = request.get_json(silent=True) or {}
        target = db.session.get(User, user_id)
        if target is None:
            return jsonify({'error': 'User not found'}), 404
        if data.get('confirm_username') != target.username:
            return jsonify({'error': 'Target confirmation does not match'}), 400
        WebAuthnCredential.query.filter_by(user_id=target.id).delete()
        WebAuthnChallenge.query.filter_by(user_id=target.id).delete()
        TOTPAuthenticator.query.filter_by(user_id=target.id).delete()
        TOTPEnrollment.query.filter_by(user_id=target.id).delete()
        RecoveryCode.query.filter_by(user_id=target.id).delete()
        target.mfa_enabled = False
        target.auth_generation = int(target.auth_generation or 0) + 1
        db.session.commit()
        user_lifecycle.revoke_user_access(target.id, socketio)
        log_warning(
            'Admin reset user MFA',
            admin=current_user.username,
            user=target.username,
        )
        return jsonify({'ok': True})

    @app.route('/admin/api/audit', methods=['GET'])
    @admin_required
    @login_required
    def admin_audit():
        if not config.AUDIT_EXPORT_ENABLED:
            abort(404)
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
    @admin_required
    @login_required
    def admin_get_settings():
        return jsonify({'registration_enabled': is_registration_enabled()})

    @app.route('/admin/api/settings', methods=['POST'])
    @admin_required
    @login_required
    @step_up_required('settings.update', 'global')
    def admin_set_settings():
        data = request.get_json(silent=True) or {}
        if 'registration_enabled' in data:
            if type(data['registration_enabled']) is not bool:
                return jsonify({
                    'error': 'registration_enabled must be a boolean'
                }), 400
            if (
                config.DEPLOYMENT_PROFILE == 'production'
                and data['registration_enabled']
            ):
                return jsonify({
                    'error': (
                        'Registration cannot be enabled in the production '
                        'profile'
                    )
                }), 400
            val = set_registration_enabled(data['registration_enabled'])
            log_info("Admin changed registration setting",
                     admin=current_user.username, registration_enabled=val)
        return jsonify({'registration_enabled': is_registration_enabled()})

    @app.route('/admin/api/security-features', methods=['GET'])
    @admin_required
    @login_required
    def admin_get_security_features():
        from .security_features import all_feature_statuses

        return jsonify({
            'features': [
                status.to_dict() for status in all_feature_statuses()
            ],
        })

    @app.route(
        '/admin/api/security-features/<feature_name>',
        methods=['POST'],
    )
    @admin_required
    @login_required
    @step_up_required(
        'security_feature.update',
        lambda feature_name: feature_name,
    )
    def admin_set_security_feature(feature_name):
        from .security_features import (
            FeatureUnavailable,
            UnknownSecurityFeature,
            feature_status,
            set_feature_active,
        )

        data = request.get_json(silent=True)
        if not isinstance(data, dict) or type(data.get('enabled')) is not bool:
            return jsonify({'error': 'enabled must be a boolean'}), 400
        try:
            current_status = feature_status(feature_name)
            if (
                current_status.active
                and data['enabled'] is False
                and data.get('confirm_session_fallback') is not True
            ):
                log_warning(
                    'Security feature change needs fallback confirmation',
                    admin=current_user.username,
                    feature=feature_name,
                )
                return jsonify({
                    'error': 'Explicit confirmation is required',
                    'code': 'session_fallback_confirmation_required',
                    'message': (
                        'Existing browser, SSH, and tmux sessions will not be '
                        'terminated. New logins and factor ceremonies will '
                        'follow the disabled rule immediately.'
                    ),
                    'feature': current_status.to_dict(),
                }), 409
            status = set_feature_active(
                feature_name,
                data['enabled'],
                current_user.id,
            )
        except UnknownSecurityFeature:
            abort(404)
        except FeatureUnavailable as exc:
            return jsonify({
                'error': exc.status.reason,
                'feature': exc.status.to_dict(),
            }), 409
        return jsonify({'feature': status.to_dict()})

    return app
