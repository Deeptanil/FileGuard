import io
import hashlib
import pytest
from app.models import BlockedHash, AbuseReport, FileRecord
from app.security import generate_share_token, hash_token, generate_csrf_token

def test_report_abuse_page_loads(client):
    """GET /report renders successfully with CSRF token."""
    res = client.get("/report")
    assert res.status_code == 200
    assert b"REPORT CONTENT ABUSE" in res.data
    assert b"csrf_token" in res.data


def test_report_abuse_with_prefill_token(client):
    """GET /report?token=1234-5678 prefills the token input."""
    res = client.get("/report?token=1234-5678")
    assert res.status_code == 200
    assert b"1234-5678" in res.data


def test_submit_abuse_report_success(client, app):
    """POST /report submits an abuse report successfully with CSRF validation."""
    with client.session_transaction() as sess:
        sess["_csrf_token"] = "valid-csrf-token"

    res = client.post(
        "/report",
        data={
            "csrf_token": "valid-csrf-token",
            "token_or_url": "1234-5678",
            "category": "malware",
            "reporter_email": "security@example.com",
            "description": "This file contains a malicious dropper payload."
        }
    )
    assert res.status_code == 200
    assert b"REPORT RECEIVED" in res.data

    with app.app_context():
        report = AbuseReport.query.filter_by(token_or_url="1234-5678").first()
        assert report is not None
        assert report.category == "malware"
        assert report.status == "pending"


def test_submit_abuse_report_invalid_csrf(client):
    """POST /report rejects requests with missing or invalid CSRF."""
    res = client.post(
        "/report",
        data={
            "csrf_token": "invalid-token",
            "token_or_url": "1234-5678",
            "category": "csam",
            "description": "Exploitation content"
        }
    )
    assert res.status_code == 403


def test_blocked_hash_quarantine_rejects_upload(client, app):
    """Uploading a file whose SHA-256 matches a quarantined hash must return HTTP 403."""
    file_bytes = b"Quarantined malware content sample string 12345"
    malicious_sha256 = hashlib.sha256(file_bytes).hexdigest()

    with app.app_context():
        from app.extensions import db
        block = BlockedHash(
            sha256_hash=malicious_sha256,
            reason="MALWARE",
            notes="Known Trojan Dropper Signature"
        )
        db.session.add(block)
        db.session.commit()

    with client.session_transaction() as sess:
        sess["_csrf_token"] = "valid-csrf"

    res = client.post(
        "/api/files",
        data={
            "file": (io.BytesIO(file_bytes), "sample.txt")
        },
        headers={
            "X-CSRFToken": "valid-csrf"
        },
        content_type="multipart/form-data"
    )

    assert res.status_code == 403
    json_data = res.get_json()
    assert "prohibited content signature" in json_data["error"]
    assert "MALWARE" in json_data["error"]

    with app.app_context():
        # Ensure file record was NOT persisted
        rec = FileRecord.query.filter_by(sha256_reference=malicious_sha256).first()
        assert rec is None


def test_executable_warning_strip_on_share_page(client, app):
    """Share page displays the executable warning banner when an executable file is shared."""
    raw_token, token_hash = generate_share_token()
    
    with app.app_context():
        from datetime import datetime, timedelta, timezone
        from app.extensions import db
        now = datetime.now(timezone.utc).replace(tzinfo=None)
        rec = FileRecord(
            storage_id="test_exe_storage_id",
            original_filename="payload_installer.exe",
            display_title="Payload Installer",
            file_size=1024,
            file_extension="exe",
            detected_mime_type="application/x-msdownload",
            sha256_reference="a" * 64,
            share_token_hash=token_hash,
            uploaded_at=now,
            expires_at=now + timedelta(hours=12),
            status="active"
        )
        db.session.add(rec)
        db.session.commit()

    res = client.get(f"/{raw_token}")
    assert res.status_code == 200
    assert b"EXECUTABLE APPLICATION / SCRIPT" in res.data
    assert b"Report Content Abuse" in res.data


def test_admin_resolve_and_purge_abuse_report(authenticated_admin_client, app):
    """Admin can resolve an abuse report and trigger an instant purge & hash block."""
    raw_token, token_hash = generate_share_token()
    sample_sha = "b" * 64

    with app.app_context():
        from datetime import datetime, timedelta, timezone
        from app.extensions import db
        now = datetime.now(timezone.utc).replace(tzinfo=None)
        rec = FileRecord(
            storage_id="abusive_storage_id",
            original_filename="abusive_image.jpg",
            file_size=2048,
            file_extension="jpg",
            detected_mime_type="image/jpeg",
            sha256_reference=sample_sha,
            share_token_hash=token_hash,
            uploaded_at=now,
            expires_at=now + timedelta(hours=12),
            status="active"
        )
        report = AbuseReport(
            token_or_url=raw_token,
            category="csam",
            description="Illegal exploitation material",
            status="pending"
        )
        db.session.add(rec)
        db.session.add(report)
        db.session.commit()
        report_id = report.id

    res = authenticated_admin_client.post(
        f"/admin/abuse-reports/{report_id}/resolve",
        data={
            "action": "purge_and_block",
            "notes": "Verified CSAM violation - purged and quarantined"
        },
        headers={"X-CSRFToken": "test-csrf-token-abc123xyz"}
    )
    assert res.status_code == 200
    assert res.get_json()["status"] == "resolved"

    with app.app_context():
        blocked = BlockedHash.query.filter_by(sha256_hash=sample_sha).first()
        assert blocked is not None
        assert "CSAM" in blocked.reason

        file_rec = FileRecord.query.filter_by(sha256_reference=sample_sha).first()
        assert file_rec.status == "deleted"
