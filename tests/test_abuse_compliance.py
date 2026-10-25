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


def test_automated_consensus_takedown_and_cascade_ip_ban(client, app):
    """When a file receives >2 reports, it is auto-takedown, cascades to IP siblings, and bans IP."""
    raw_token_a, token_hash_a = generate_share_token()
    raw_token_b, token_hash_b = generate_share_token()
    uploader_ip = "198.51.100.99"

    with app.app_context():
        from datetime import datetime, timedelta, timezone
        from app.extensions import db
        now = datetime.now(timezone.utc).replace(tzinfo=None)
        
        # File A
        rec_a = FileRecord(
            storage_id="target_abuse_file_a",
            original_filename="infringing_movie.mp4",
            file_size=1024,
            file_extension="mp4",
            detected_mime_type="video/mp4",
            sha256_reference="1" * 64,
            share_token_hash=token_hash_a,
            uploaded_at=now,
            expires_at=now + timedelta(hours=12),
            status="active",
            uploader_ip=uploader_ip
        )
        # Sibling File B from same uploader IP
        rec_b = FileRecord(
            storage_id="sibling_abuse_file_b",
            original_filename="infringing_doc.pdf",
            file_size=512,
            file_extension="pdf",
            detected_mime_type="application/pdf",
            sha256_reference="2" * 64,
            share_token_hash=token_hash_b,
            uploaded_at=now,
            expires_at=now + timedelta(hours=12),
            status="active",
            uploader_ip=uploader_ip
        )
        db.session.add(rec_a)
        db.session.add(rec_b)
        db.session.commit()

    with client.session_transaction() as sess:
        sess["_csrf_token"] = "valid-csrf"

    # Report 1: File A
    res1 = client.post(
        "/report",
        data={
            "csrf_token": "valid-csrf",
            "token_or_url": raw_token_a,
            "category": "copyright",
            "description": "Report 1 for copyright"
        },
        headers={"X-Forwarded-For": "203.0.113.1"}
    )
    assert res1.status_code == 200

    # Ensure both files are still active after 1 report
    with app.app_context():
        assert FileRecord.query.filter_by(share_token_hash=token_hash_a).first().status == "active"
        assert FileRecord.query.filter_by(share_token_hash=token_hash_b).first().status == "active"

    # Report 2: File A
    res2 = client.post(
        "/report",
        data={
            "csrf_token": "valid-csrf",
            "token_or_url": raw_token_a,
            "category": "copyright",
            "description": "Report 2 for copyright"
        },
        headers={"X-Forwarded-For": "203.0.113.2"}
    )
    assert res2.status_code == 200

    # Ensure both files are still active after 2 reports
    with app.app_context():
        assert FileRecord.query.filter_by(share_token_hash=token_hash_a).first().status == "active"
        assert FileRecord.query.filter_by(share_token_hash=token_hash_b).first().status == "active"

    # Report 3: File A (> 2 reports threshold reached!)
    res3 = client.post(
        "/report",
        data={
            "csrf_token": "valid-csrf",
            "token_or_url": raw_token_a,
            "category": "copyright",
            "description": "Report 3 for copyright"
        },
        headers={"X-Forwarded-For": "203.0.113.3"}
    )
    assert res3.status_code == 200

    with app.app_context():
        from app.models import BlockedIp, BlockedHash
        # File A must be deleted
        file_a = FileRecord.query.filter_by(share_token_hash=token_hash_a).first()
        assert file_a.status == "deleted"

        # Sibling File B from same IP must also be cascaded to deleted!
        file_b = FileRecord.query.filter_by(share_token_hash=token_hash_b).first()
        assert file_b.status == "deleted"

        # Both hashes must be in BlockedHash quarantine
        assert BlockedHash.query.filter_by(sha256_hash="1" * 64).first() is not None
        assert BlockedHash.query.filter_by(sha256_hash="2" * 64).first() is not None

        # Uploader IP must now be banned in BlockedIp table!
        blocked_ip_record = BlockedIp.query.filter_by(ip_address=uploader_ip).first()
        assert blocked_ip_record is not None
        assert blocked_ip_record.violation_count >= 2

    # Verify that future upload attempts from this banned IP are rejected with 403 Forbidden
    upload_res = client.post(
        "/api/files",
        data={
            "file": (io.BytesIO(b"Blocked uploader new payload"), "clean.txt"),
            "csrf_token": "valid-csrf"
        },
        headers={
            "X-Forwarded-For": uploader_ip,
            "X-CSRFToken": "valid-csrf"
        },
        content_type="multipart/form-data"
    )
    assert upload_res.status_code == 403
    assert "blocked" in upload_res.get_json()["error"].lower()

