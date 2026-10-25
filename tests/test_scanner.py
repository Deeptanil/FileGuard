import io
import json
import urllib.error
from unittest.mock import patch, MagicMock
import pytest
from app.models import FileRecord, BlockedHash, utc_now
from app.scanner import check_virustotal_hash, execute_scan_for_file_record, dispatch_background_malware_scan
from app.security import generate_share_token
from datetime import datetime, timedelta, timezone


def test_check_virustotal_hash_no_key():
    """Without an API key, scanner safely reports unscanned status with heuristic note."""
    result = check_virustotal_hash("a" * 64, api_key="")
    assert result["status"] == "unscanned"
    assert "heuristic" in result["details"].lower()


@patch("urllib.request.urlopen")
def test_check_virustotal_hash_clean(mock_urlopen):
    """When VirusTotal reports 0 detections, scanner marks file clean."""
    mock_resp = MagicMock()
    mock_resp.status = 200
    sample_data = {
        "data": {
            "attributes": {
                "last_analysis_stats": {
                    "malicious": 0,
                    "suspicious": 0,
                    "undetected": 68,
                    "harmless": 2
                }
            }
        }
    }
    mock_resp.read.return_value = json.dumps(sample_data).encode("utf-8")
    mock_urlopen.return_value.__enter__.return_value = mock_resp

    result = check_virustotal_hash("b" * 64, api_key="dummy-key", min_positives=4)
    assert result["status"] == "clean"
    assert result["positives"] == 0


@patch("urllib.request.urlopen")
def test_check_virustotal_hash_suspicious_below_threshold(mock_urlopen):
    """When only 1 or 2 engines flag a threat, it is marked suspicious (not malicious) to prevent false-positive purges."""
    mock_resp = MagicMock()
    mock_resp.status = 200
    sample_data = {
        "data": {
            "attributes": {
                "last_analysis_stats": {
                    "malicious": 1,
                    "suspicious": 1,
                    "undetected": 66,
                    "harmless": 0
                }
            }
        }
    }
    mock_resp.read.return_value = json.dumps(sample_data).encode("utf-8")
    mock_urlopen.return_value.__enter__.return_value = mock_resp

    result = check_virustotal_hash("c" * 64, api_key="dummy-key", min_positives=4)
    assert result["status"] == "suspicious"
    assert result["positives"] == 2
    assert "Unconfirmed heuristic flag" in result["details"]


@patch("urllib.request.urlopen")
def test_check_virustotal_hash_confirmed_malicious(mock_urlopen):
    """When 4 or more engines flag a threat, consensus confirms malicious malware."""
    mock_resp = MagicMock()
    mock_resp.status = 200
    sample_data = {
        "data": {
            "attributes": {
                "last_analysis_stats": {
                    "malicious": 5,
                    "suspicious": 1,
                    "undetected": 62,
                    "harmless": 0
                }
            }
        }
    }
    mock_resp.read.return_value = json.dumps(sample_data).encode("utf-8")
    mock_urlopen.return_value.__enter__.return_value = mock_resp

    result = check_virustotal_hash("d" * 64, api_key="dummy-key", min_positives=4)
    assert result["status"] == "malicious"
    assert result["positives"] == 6
    assert "Confirmed threat" in result["details"]


@patch("urllib.request.urlopen")
def test_check_virustotal_hash_404_novel_file(mock_urlopen):
    """A 404 from VirusTotal means novel/uncataloged file with zero known threats."""
    mock_err = urllib.error.HTTPError("https://virustotal.com", 404, "Not Found", {}, None)
    mock_urlopen.side_effect = mock_err

    result = check_virustotal_hash("e" * 64, api_key="dummy-key")
    assert result["status"] == "clean"
    assert result["positives"] == 0


@patch("app.scanner.check_virustotal_hash")
def test_execute_scan_suspicious_does_not_purge(mock_check, app, client):
    """Suspicious files below threshold are NOT purged; recipient can still download with warning."""
    sample_sha = "f" * 64
    raw_token, token_hash = generate_share_token()

    mock_check.return_value = {
        "status": "suspicious",
        "positives": 2,
        "details": "Unconfirmed heuristic flag: 2 engine(s) flagged"
    }

    with app.app_context():
        from app.extensions import db
        now = datetime.now(timezone.utc).replace(tzinfo=None)
        rec = FileRecord(
            storage_id="suspicious_sample_storage",
            original_filename="sample_script.py",
            file_size=1024,
            file_extension="txt",
            detected_mime_type="text/plain",
            sha256_reference=sample_sha,
            share_token_hash=token_hash,
            uploaded_at=now,
            expires_at=now + timedelta(hours=12),
            status="active",
            malware_status="pending"
        )
        db.session.add(rec)
        db.session.commit()
        rec_id = rec.id

    execute_scan_for_file_record(app, rec_id)

    with app.app_context():
        updated_rec = FileRecord.query.get(rec_id)
        # File must remain active!
        assert updated_rec.status == "active"
        assert updated_rec.malware_status == "suspicious"
        assert updated_rec.malware_positives == 2

        # Quarantine table must NOT have this hash
        blocked = BlockedHash.query.filter_by(sha256_hash=sample_sha).first()
        assert blocked is None

    # Share view renders with caution warning but download remains permitted
    share_res = client.get(f"/{raw_token}")
    assert share_res.status_code == 200
    assert b"POTENTIAL HEURISTIC WARNING" in share_res.data
    assert b"DOWNLOAD NOW" in share_res.data


@patch("app.scanner.check_virustotal_hash")
def test_execute_scan_purges_malicious_file(mock_check, app, client):
    """When consensus confirms malware, file is purged from disk, deleted in DB, and quarantined."""
    sample_sha = "9" * 64
    raw_token, token_hash = generate_share_token()

    mock_check.return_value = {
        "status": "malicious",
        "positives": 8,
        "details": "Confirmed threat: Flagged by 8 security engines on VirusTotal"
    }

    with app.app_context():
        from app.extensions import db
        now = datetime.now(timezone.utc).replace(tzinfo=None)
        rec = FileRecord(
            storage_id="malware_sample_storage_2",
            original_filename="trojan.exe",
            file_size=1024,
            file_extension="exe",
            detected_mime_type="application/octet-stream",
            sha256_reference=sample_sha,
            share_token_hash=token_hash,
            uploaded_at=now,
            expires_at=now + timedelta(hours=12),
            status="active",
            malware_status="pending"
        )
        db.session.add(rec)
        db.session.commit()
        rec_id = rec.id

    execute_scan_for_file_record(app, rec_id)

    with app.app_context():
        updated_rec = FileRecord.query.get(rec_id)
        assert updated_rec.status == "deleted"
        assert updated_rec.malware_status == "malicious"
        assert updated_rec.malware_positives == 8

        # Quarantine table has SHA-256
        blocked = BlockedHash.query.filter_by(sha256_hash=sample_sha).first()
        assert blocked is not None
        assert blocked.reason == "VIRUSTOTAL_MALWARE"

    # Download blocked with 410 Gone
    dl_res = client.get(f"/api/files/{raw_token}/download")
    assert dl_res.status_code == 410

    # Share page renders 403 with MALWARE DETECTED
    share_res = client.get(f"/{raw_token}")
    assert share_res.status_code == 403
    assert b"MALWARE DETECTED" in share_res.data
