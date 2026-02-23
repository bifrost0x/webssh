import os
import tempfile
import pytest

os.environ.setdefault('SECRET_KEY', 'test-secret-key-for-unit-tests-only')
os.environ['DEBUG'] = 'True'

@pytest.fixture
def app():
    """Create Flask test application."""
    with tempfile.TemporaryDirectory() as tmpdir:
        os.environ['DATA_DIR'] = tmpdir
        # Re-import config to pick up test DATA_DIR
        import importlib
        import config
        importlib.reload(config)

        from app import create_app
        app = create_app()
        app.config['TESTING'] = True
        app.config['WTF_CSRF_ENABLED'] = False

        with app.app_context():
            from app.models import db
            db.create_all()
            yield app


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
