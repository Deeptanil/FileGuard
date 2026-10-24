import io
from app.models import FileRecord
from app.security import hash_token

def test_25_unauthenticated_cannot_access_dashboard(client):
    """Test 25: Unauthenticated visitors cannot access the administrative dashboard."""
    response = client.get("/admin/dashboard")
    # Redirects to login page (302)
    assert response.status_code == 302
    assert "/admin/login" in response.headers.get("Location", "")


def test_26_unauthenticated_cannot_access_forensics(client):
    """Test 26: Unauthenticated visitors cannot access forensic reports."""
    response = client.get("/admin/forensics/")
    assert response.status_code == 302
    assert "/admin/login" in response.headers.get("Location", "")


def test_27_invalid_admin_credentials_rejected(client):
    """Test 27: Invalid administrator credentials are rejected."""
    with client.session_transaction() as sess:
        sess["_csrf_token"] = "admin_csrf_val"

    response = client.post("/admin/login", data={
        "username": "admin",
        "password": "WrongPassword123!",
        "csrf_token": "admin_csrf_val"
    }, follow_redirects=True)

    assert response.status_code == 200
    assert b"Invalid administrative credentials" in response.data


def test_28_admin_login_success(client):
    """Test 28: Valid administrator credentials successfully authenticate."""
    with client.session_transaction() as sess:
        sess["_csrf_token"] = "admin_csrf_val"

    response = client.post("/admin/login", data={
        "username": "admin",
        "password": "TestAdminPass123!",
        "csrf_token": "admin_csrf_val"
    }, follow_redirects=False)

    assert response.status_code == 302
    assert "/admin/dashboard" in response.headers.get("Location", "")

    # Follow redirect to dashboard
    dash_response = client.get("/admin/dashboard")
    assert dash_response.status_code == 200
    assert b"Security Operations Center" in dash_response.data


def test_29_csrf_protection_on_state_changing_requests(authenticated_admin_client):
    """Test 29: State-changing administrative requests enforce CSRF protection."""
    # Attempt cleanup with invalid CSRF token
    response = authenticated_admin_client.post("/admin/cleanup", headers={
        "X-CSRFToken": "invalid_forged_csrf_token"
    })
    assert response.status_code == 403


def test_30_public_routes_do_not_expose_storage_paths(client, db_session):
    """Test 30: Public routes do not expose internal storage paths or sensitive tokens."""
    with client.session_transaction() as sess:
        sess["_csrf_token"] = "csrf_path_check"

    data = {
        "file": (io.BytesIO(b"Path Leak Check Content"), "leak_check.txt"),
        "csrf_token": "csrf_path_check"
    }
    res = client.post("/api/files", data=data, content_type="multipart/form-data")
    token = res.get_json()["token"]

    # Check recipient share page
    share_page = client.get(f"/share/{token}").get_data(as_text=True)
    assert "storage" not in share_page.lower() or "fg_" not in share_page
    assert "/var" not in share_page and "c:\\" not in share_page.lower()

    # Check public status JSON
    status_res = client.get(f"/api/files/{token}/status").get_json()
    assert "storage_id" not in status_res
    assert "sha256_reference" not in status_res
    assert "share_token_hash" not in status_res

