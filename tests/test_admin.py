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


def test_admin_blocked_ips_management(authenticated_admin_client, app):
    """Verify administrator can list, ban, and unban IPs with cascade purge."""
    from app.models import BlockedIp, BlockedHash, FileRecord
    test_ip = "198.51.100.77"

    # 1. Upload a file from test_ip
    with app.app_context():
        rec = FileRecord(
            storage_id="fg_test_admin_ban_1",
            original_filename="malicious_tool.exe",
            file_size=1024,
            file_extension="exe",
            detected_mime_type="application/x-dosexec",
            sha256_reference="a" * 64,
            share_token_hash=hash_token("9999-1111"),
            uploader_ip=test_ip,
            status="active",
            expires_at=FileRecord.query.first().expires_at if FileRecord.query.first() else None
        )
        if not rec.expires_at:
            from app.models import utc_now
            from datetime import timedelta
            rec.expires_at = utc_now() + timedelta(hours=12)
        from app.extensions import db
        db.session.add(rec)
        db.session.commit()

    # 2. View blocked IPs page
    res_list = authenticated_admin_client.get("/admin/blocked-ips")
    assert res_list.status_code == 200
    assert b"Blocked IPs &amp; Devices" in res_list.data or b"Blocked IPs & Devices" in res_list.data

    # 3. Ban the IP with cascade file purge
    with authenticated_admin_client.session_transaction() as sess:
        sess["_csrf_token"] = "valid_admin_csrf"

    res_ban = authenticated_admin_client.post(
        "/admin/blocked-ips/ban",
        data={
            "csrf_token": "valid_admin_csrf",
            "ip_address": test_ip,
            "reason": "MALWARE_UPLOAD",
            "notes": "Verified threat in test",
            "purge_files": "true"
        },
        follow_redirects=True
    )
    assert res_ban.status_code == 200

    with app.app_context():
        entry = BlockedIp.query.filter_by(ip_address=test_ip).first()
        assert entry is not None
        assert entry.reason == "MALWARE_UPLOAD"

        # File must be deleted
        file_rec = FileRecord.query.filter_by(uploader_ip=test_ip).first()
        assert file_rec.status == "deleted"

        # Hash quarantined
        assert BlockedHash.query.filter_by(sha256_hash="a" * 64).first() is not None

    # 4. Unban the IP
    with authenticated_admin_client.session_transaction() as sess:
        sess["_csrf_token"] = "valid_admin_csrf_2"

    res_unban = authenticated_admin_client.post(
        "/admin/blocked-ips/unban",
        data={
            "csrf_token": "valid_admin_csrf_2",
            "ip_address": test_ip
        },
        follow_redirects=True
    )
    assert res_unban.status_code == 200

    with app.app_context():
        assert BlockedIp.query.filter_by(ip_address=test_ip).first() is None


def test_admin_abuse_reports_management(authenticated_admin_client, app):
    """Verify administrator can inspect, resolve, and reject abuse reports."""
    from app.models import AbuseReport, db
    with app.app_context():
        rep = AbuseReport(
            token_or_url="4444-2222",
            category="copyright",
            description="Pirated material detected",
            reporter_email="rights@example.org",
            reporter_ip="203.0.113.88",
            status="pending"
        )
        db.session.add(rep)
        db.session.commit()
        rep_id = rep.id

    # View reports page
    res_page = authenticated_admin_client.get("/admin/abuse-reports")
    assert res_page.status_code == 200
    assert b"Abuse &amp; DMCA Takedown Reports" in res_page.data or b"Abuse & DMCA Takedown Reports" in res_page.data
    assert b"Pirated material detected" in res_page.data

    # Reject report
    with authenticated_admin_client.session_transaction() as sess:
        sess["_csrf_token"] = "admin_csrf_reject"

    res_reject = authenticated_admin_client.post(
        f"/admin/abuse-reports/{rep_id}/reject",
        data={
            "csrf_token": "admin_csrf_reject",
            "notes": "Insufficient proof"
        },
        follow_redirects=True
    )
    assert res_reject.status_code == 200

    with app.app_context():
        updated_rep = AbuseReport.query.get(rep_id)
        assert updated_rep.status == "rejected"


def test_admin_malware_dashboard_and_rescan(authenticated_admin_client, app):
    """Verify malware telemetry view and re-scan triggering."""
    from app.models import FileRecord, db
    with app.app_context():
        rec = FileRecord(
            storage_id="fg_test_admin_malware_1",
            original_filename="invoice_receipt.pdf",
            file_size=2048,
            file_extension="pdf",
            detected_mime_type="application/pdf",
            sha256_reference="b" * 64,
            share_token_hash=hash_token("7777-3333"),
            uploader_ip="198.51.100.44",
            status="active",
            malware_status="clean",
            malware_positives=0,
            malware_scan_details="Clean across 72 engines"
        )
        from app.models import utc_now
        from datetime import timedelta
        rec.expires_at = utc_now() + timedelta(hours=12)
        db.session.add(rec)
        db.session.commit()
        f_id = rec.id

    # View malware dashboard
    res_malware = authenticated_admin_client.get("/admin/malware")
    assert res_malware.status_code == 200
    assert b"VirusTotal &amp; Antivirus Scans" in res_malware.data or b"VirusTotal & Antivirus Scans" in res_malware.data
    assert b"invoice_receipt.pdf" in res_malware.data

    # Trigger re-scan
    with authenticated_admin_client.session_transaction() as sess:
        sess["_csrf_token"] = "admin_csrf_rescan"

    res_rescan = authenticated_admin_client.post(
        f"/admin/files/{f_id}/rescan",
        data={"csrf_token": "admin_csrf_rescan"},
        follow_redirects=True
    )
    assert res_rescan.status_code == 200


def test_admin_user_profile_view(authenticated_admin_client, app):
    """Verify admin user 360-degree forensic profile view."""
    test_user_ip = "192.0.2.199"
    res_user = authenticated_admin_client.get(f"/admin/user/{test_user_ip}")
    assert res_user.status_code == 200
    assert test_user_ip.encode() in res_user.data
    assert b"Client Device Forensics" in res_user.data


