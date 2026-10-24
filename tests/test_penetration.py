import io
import re
from app.models import FileRecord
from app.security import hash_token
from app.storage import get_storage_path

def test_pen_path_traversal_prevention(client, db_session):
    """
    PEN-TEST 01: Path Traversal Vulnerability Assessment
    Target: Upload filename sanitization & storage resolution
    Vector: Malicious relative path ../../../../etc/passwd
    Expected: Path traversal sequences stripped; file stored safely inside STORAGE_DIR.
    """
    with client.session_transaction() as sess:
        sess["_csrf_token"] = "pen_csrf_token"

    traversal_filenames = [
        "../../../../etc/passwd.txt",
        "..\\..\\..\\windows\\win.ini.txt",
        "nested/../../traversal.txt"
    ]

    for fname in traversal_filenames:
        data = {
            "file": (io.BytesIO(b"Path traversal attack payload test"), fname),
            "csrf_token": "pen_csrf_token"
        }
        res = client.post("/api/files", data=data, content_type="multipart/form-data")
        assert res.status_code == 201
        saved_name = res.get_json()["filename"]
        # Ensure path separators are stripped
        assert "/" not in saved_name
        assert "\\" not in saved_name
        assert ".." not in saved_name


def test_pen_stored_xss_prevention(client, db_session):
    """
    PEN-TEST 02: Stored Cross-Site Scripting (XSS) Assessment
    Target: Filename rendering on recipient and admin pages
    Vector: <script>alert('XSS_POC')</script>.txt
    Expected: HTML characters entity-encoded; script tag not executed raw.
    """
    with client.session_transaction() as sess:
        sess["_csrf_token"] = "pen_csrf_token"

    xss_payload = "<script>alert('XSS_POC')</script>.txt"
    data = {
        "file": (io.BytesIO(b"Harmless XSS test bytes"), xss_payload),
        "csrf_token": "pen_csrf_token"
    }
    res = client.post("/api/files", data=data, content_type="multipart/form-data")
    assert res.status_code == 201
    token = res.get_json()["token"]

    # Retrieve sharing view page
    view_res = client.get(f"/share/{token}").get_data(as_text=True)
    # Must NOT contain raw unescaped script tag or alert execution payload
    assert "<script>alert('XSS_POC')</script>" not in view_res
    assert "alert('XSS_POC')" not in view_res
    assert "XSS_POC" not in view_res
    # Filename must be sanitized to safe basename (script.txt)
    assert "script.txt" in view_res


def test_pen_csrf_enforcement(client, db_session):
    """
    PEN-TEST 03: Cross-Site Request Forgery (CSRF) Assessment
    Target: Upload and administrative state-changing endpoints
    Vector: Submitting POST without valid CSRF token
    Expected: Rejected with HTTP 403 Forbidden.
    """
    # 1. Unauthenticated / No token upload
    data = {
        "file": (io.BytesIO(b"Data without CSRF"), "nocsrf.txt")
    }
    res = client.post("/api/files", data=data, content_type="multipart/form-data")
    assert res.status_code == 403

    # 2. Forged token upload
    with client.session_transaction() as sess:
        sess["_csrf_token"] = "legitimate_session_token"

    data_forged = {
        "file": (io.BytesIO(b"Data with forged CSRF"), "forged.txt"),
        "csrf_token": "attacker_guessed_token"
    }
    res_forged = client.post("/api/files", data=data_forged, content_type="multipart/form-data")
    assert res_forged.status_code == 403


def test_pen_sql_injection_defense(client, db_session):
    """
    PEN-TEST 04: SQL Injection Assessment
    Target: Administrative login form & token resolution
    Vector: Classic SQLi payloads (' OR '1'='1, 1' UNION SELECT)
    Expected: Parameterized query blocks injection; no auth bypass or 500 error.
    """
    with client.session_transaction() as sess:
        sess["_csrf_token"] = "sqli_csrf"

    sqli_payloads = [
        "' OR '1'='1",
        "admin' --",
        "' OR 1=1 #",
        "' UNION SELECT 1, 'admin', 'hash', datetime('now'), datetime('now'), 1 --"
    ]

    for payload in sqli_payloads:
        res = client.post("/admin/login", data={
            "username": payload,
            "password": "Password123!",
            "csrf_token": "sqli_csrf"
        }, follow_redirects=True)
        # Authentication must fail
        assert res.status_code == 200
        assert b"Invalid administrative credentials" in res.data
        # Session must not be granted admin access
        dash = client.get("/admin/dashboard")
        assert dash.status_code == 302


def test_pen_idor_and_enumeration_resistance(client, db_session):
    """
    PEN-TEST 05: Insecure Direct Object Reference (IDOR) & Token Enumeration
    Target: File retrieval via predictable IDs
    Vector: Attempting sequential numeric IDs (/api/files/1, /api/files/2)
    Expected: Rejected with 404; download requires 256-bit CSPRNG token.
    """
    # Upload one valid file to ensure database has ID #1
    with client.session_transaction() as sess:
        sess["_csrf_token"] = "idor_csrf"
    data = {
        "file": (io.BytesIO(b"IDOR target file content"), "target.txt"),
        "csrf_token": "idor_csrf"
    }
    res = client.post("/api/files", data=data, content_type="multipart/form-data")
    assert res.status_code == 201

    # Attempt numeric enumeration
    for test_id in ["1", "2", "0", "100"]:
        res_enum = client.get(f"/api/files/{test_id}/download")
        assert res_enum.status_code == 404


def test_pen_security_headers_verification(client):
    """
    PEN-TEST 06: HTTP Security Headers Audit
    Target: Response headers across public and admin pages
    Expected: X-Content-Type-Options, X-Frame-Options, Content-Security-Policy set.
    """
    response = client.get("/")
    assert response.headers.get("X-Content-Type-Options") == "nosniff"
    assert response.headers.get("X-Frame-Options") == "SAMEORIGIN"
    assert "default-src 'self'" in response.headers.get("Content-Security-Policy", "")
    assert response.headers.get("Referrer-Policy") == "strict-origin-when-cross-origin"


def test_pen_cookie_security_flags(client):
    """
    PEN-TEST 07: Session Cookie Hardening
    Target: Flask session cookie configuration
    Expected: HttpOnly and SameSite=Lax enabled.
    """
    with client.session_transaction() as sess:
        sess["test_marker"] = "security_flag_check"

    res = client.get("/")
    cookies = res.headers.getlist("Set-Cookie")
    for cookie in cookies:
        if "session=" in cookie:
            assert "HttpOnly" in cookie
            assert "SameSite=Lax" in cookie

