import os
import tempfile
import pytest

os.environ.setdefault('SECRET_KEY', 'test-secret-key-for-unit-tests-only')
os.environ['DEBUG'] = 'True'


@pytest.fixture
def app():
    """Create Flask test application."""
    # ignore_cleanup_errors: on Windows the SQLite file can still be locked at
    # teardown; disposing the engine below handles the normal case, this is a
    # belt-and-suspenders guard so a stray handle never fails the test.
    with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmpdir:
        os.environ['DATA_DIR'] = tmpdir
        # Re-import config to pick up test DATA_DIR
        import importlib
        import config
        importlib.reload(config)

        from app import create_app
        app = create_app()
        app.config['TESTING'] = True
        app.config['WTF_CSRF_ENABLED'] = False

        from app.models import db
        with app.app_context():
            db.create_all()
            yield app
            # Close all DB connections so the SQLite file is released before
            # the temp dir is removed (required on Windows, harmless on POSIX).
            db.session.remove()
            db.engine.dispose()


@pytest.fixture
def client(app):
    """Flask test client."""
    return app.test_client()


@pytest.fixture
def db_session(app):
    """Database session for direct DB operations."""
    from app.models import db
    with app.app_context():
        yield db.session
