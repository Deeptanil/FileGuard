import os
import sys
import shutil
import tempfile
import pytest
from pathlib import Path

# Add project root to sys.path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from werkzeug.security import generate_password_hash
from app import create_app
from app.config import TestingConfig
from app.extensions import db
from app.models import Administrator, FileRecord, SecurityEvent, IntegrityCheck, BlockedHash, AbuseReport

@pytest.fixture(scope="session")
def app():
    """Create test application instance with isolated temporary storage."""
    temp_storage = tempfile.mkdtemp(prefix="fg_test_storage_")
    
    class TestAppConfig(TestingConfig):
        STORAGE_DIR = Path(temp_storage)
        WTF_CSRF_ENABLED = False
        RATELIMIT_ENABLED = False

    app = create_app(TestAppConfig)

    with app.app_context():
        db.create_all()
        # Create test administrator
        admin = Administrator(
            username="admin",
            password_hash=generate_password_hash("TestAdminPass123!", method="scrypt"),
            active_status=True
        )
        db.session.add(admin)
        db.session.commit()

    yield app

    # Cleanup temp storage
    shutil.rmtree(temp_storage, ignore_errors=True)


@pytest.fixture(scope="function")
def client(app):
    """Flask test client."""
    return app.test_client()


@pytest.fixture(scope="function")
def db_session(app):
    """Isolated database session per test function."""
    with app.app_context():
        yield db.session
        db.session.rollback()
        # Clean records between tests
        AbuseReport.query.delete()
        BlockedHash.query.delete()
        SecurityEvent.query.delete()
        IntegrityCheck.query.delete()
        FileRecord.query.delete()
        db.session.commit()


@pytest.fixture(scope="function")
def authenticated_admin_client(app, client):
    """Test client logged in with active administrative session."""
    with client.session_transaction() as sess:
        sess["admin_logged_in"] = True
        sess["admin_username"] = "admin"
        sess["admin_user_id"] = 1
        sess["_csrf_token"] = "test-csrf-token-abc123xyz"
    return client
