import io
from datetime import timedelta
from app.models import FileRecord, utc_now
from app.security import hash_token
from app.storage import get_storage_path


def test_encryption_at_rest_and_tamper_detection(client, db_session):
    """Verify stored file on disk is encrypted with AES-256-GCM and detects disk tampering."""
    with client.session_transaction() as sess:
        sess["_csrf_token"] = "csrf_test_enc"

    plain_content = b"Top secret confidential payload that must not be readable on disk!"
    data = {
        "file": (io.BytesIO(plain_content), "confidential.txt"),
        "csrf_token": "csrf_test_enc"
    }
    res = client.post("/api/files", data=data, content_type="multipart/form-data")
    assert res.status_code == 201
    token = res.get_json()["token"]

    record = FileRecord.query.filter_by(share_token_hash=hash_token(token)).first()
    assert record is not None
    assert record.is_encrypted_at_rest is True

    # Inspect physical file on disk
    file_path = get_storage_path(record.storage_id)
    assert file_path.exists()
    disk_bytes = file_path.read_bytes()

    # Must start with FG_ENC_V1 envelope header
    assert disk_bytes.startswith(b"FG_ENC_V1")
    # Must NOT contain plain payload on physical storage
    assert plain_content not in disk_bytes

    # Successful download decrypts transparently on the fly
    res_down = client.get(f"/api/files/{token}/download")
    assert res_down.status_code == 200
    assert res_down.data == plain_content

    # Simulate bit-rot or physical disk tampering: flip one byte in the ciphertext
    tampered_bytes = bytearray(disk_bytes)
    tampered_bytes[25] ^= 0xFF
    file_path.write_bytes(bytes(tampered_bytes))

    # GCM tag authentication must immediately fail and trigger HTTP 409 Anti-Tamper Block
    res_tampered = client.get(f"/api/files/{token}/download")
    assert res_tampered.status_code == 409


def test_password_protection_and_unlock_flow(app, db_session):
    """Verify password protection gates downloads and recipient page until unlocked."""
    uploader_client = app.test_client()
    with uploader_client.session_transaction() as sess:
        sess["_csrf_token"] = "csrf_test_pwd"

    data = {
        "file": (io.BytesIO(b"Secret Document Protected by PIN"), "secret.txt"),
        "csrf_token": "csrf_test_pwd",
        "password": "VaultPass2026!",
        "display_title": "Project Classified"
    }
    res = uploader_client.post("/api/files", data=data, content_type="multipart/form-data")
    assert res.status_code == 201
    token = res.get_json()["token"]

    record = FileRecord.query.filter_by(share_token_hash=hash_token(token)).first()
    assert record.has_password is True
    assert record.display_name == "Project Classified"

    # Separate recipient client (not the uploader)
    recipient_client = app.test_client()

    # 1. Direct download without password returns HTTP 403 Forbidden
    res_locked_down = recipient_client.get(f"/api/files/{token}/download")
    assert res_locked_down.status_code == 403

    # 2. Recipient page presents password unlock prompt
    res_page = recipient_client.get(f"/share/{token}")
    assert res_page.status_code == 200
    html = res_page.get_data(as_text=True)
    assert "Password-Protected Transfer" in html or "Enter PIN or Password" in html

    # 3. Submitting incorrect password fails
    with recipient_client.session_transaction() as sess:
        sess["_csrf_token"] = "recip_csrf_1"
    res_wrong = recipient_client.post(
        f"/share/{token}/unlock",
        data={"password": "WrongPassword", "csrf_token": "recip_csrf_1"},
        follow_redirects=True
    )
    assert res_wrong.status_code == 200
    assert "Incorrect PIN or password" in res_wrong.get_data(as_text=True)

    # 4. Submitting correct password unlocks session
    with recipient_client.session_transaction() as sess:
        sess["_csrf_token"] = "recip_csrf_2"
    res_correct = recipient_client.post(
        f"/share/{token}/unlock",
        data={"password": "VaultPass2026!", "csrf_token": "recip_csrf_2"},
        follow_redirects=True
    )
    assert res_correct.status_code == 200

    # Once unlocked, download succeeds
    res_unlocked_down = recipient_client.get(f"/api/files/{token}/download")
    assert res_unlocked_down.status_code == 200
    assert res_unlocked_down.data == b"Secret Document Protected by PIN"

    # 5. Third recipient with query param or header unlocks directly
    third_client = app.test_client()
    res_param_down = third_client.get(f"/api/files/{token}/download?password=VaultPass2026!")
    assert res_param_down.status_code == 200
    assert res_param_down.data == b"Secret Document Protected by PIN"


def test_custom_expiration_and_post_upload_settings(app, db_session):
    """Verify custom expiration and post-upload settings update endpoint."""
    client = app.test_client()
    with client.session_transaction() as sess:
        sess["_csrf_token"] = "csrf_exp_test"

    # Upload with 3-hour expiration and custom title
    data = {
        "file": (io.BytesIO(b"Data expiring in 3 hours"), "expiring.txt"),
        "csrf_token": "csrf_exp_test",
        "expiration_hours": "3",
        "display_title": "Quarterly Earnings Deck"
    }
    res = client.post("/api/files", data=data, content_type="multipart/form-data")
    assert res.status_code == 201
    token = res.get_json()["token"]

    record = FileRecord.query.filter_by(share_token_hash=hash_token(token)).first()
    assert record.display_name == "Quarterly Earnings Deck"
    diff_hours = (record.expires_at - record.uploaded_at).total_seconds() / 3600.0
    assert 2.9 <= diff_hours <= 3.1

    # Uploader updates settings: change title, add password, and shorten expiration to 1 hour
    settings_payload = {
        "display_title": "Final Revised Deck",
        "password": "NewSecretPIN123",
        "expiration_hours": 1
    }
    res_settings = client.post(f"/api/files/{token}/settings", json=settings_payload)
    assert res_settings.status_code == 200
    resp_data = res_settings.get_json()
    assert resp_data["success"] is True
    assert resp_data["display_title"] == "Final Revised Deck"
    assert resp_data["has_password"] is True

    # Verify updated in database
    db_session.refresh(record)
    assert record.display_title == "Final Revised Deck"
    assert record.has_password is True
    diff_hours_new = (record.expires_at - record.uploaded_at).total_seconds() / 3600.0
    assert 0.9 <= diff_hours_new <= 1.1

    # Now remove password protection
    res_remove_pwd = client.post(f"/api/files/{token}/settings", json={"remove_password": True})
    assert res_remove_pwd.status_code == 200
    db_session.refresh(record)
    assert record.has_password is False

    # Another client cannot edit settings (owner check)
    other_client = app.test_client()
    res_unauth = other_client.post(f"/api/files/{token}/settings", json={"display_title": "Hacked"})
    assert res_unauth.status_code == 403


def test_multi_file_bundle_upload_with_name_and_pin(client, db_session):
    """Verify uploading 2 files with custom display title and PIN succeeds."""
    with client.session_transaction() as sess:
        sess["_csrf_token"] = "csrf_bundle_pin"

    data = {
        "file": [
            (io.BytesIO(b"First bundle item"), "file1.txt"),
            (io.BytesIO(b"Second bundle item"), "file2.txt")
        ],
        "display_title": "Project Deliverables Bundle",
        "password": "4321",
        "csrf_token": "csrf_bundle_pin"
    }
    res = client.post("/api/files", data=data, content_type="multipart/form-data")
    assert res.status_code == 201
    resp_json = res.get_json()
    assert resp_json["success"] is True
    assert resp_json["display_title"] == "Project Deliverables Bundle"
    assert resp_json["has_password"] is True
    assert resp_json["filename"].endswith(".zip")


def test_legal_pages_and_e2ee_transparency(client):
    """Verify terms, privacy, cookies, and dmca legal pages load successfully with E2EE notices."""
    for path, expected_text in [
        ("/terms", "TERMS OF SERVICE"),
        ("/privacy", "PRIVACY POLICY"),
        ("/cookies", "COOKIE &amp; STORAGE POLICY"),
        ("/dmca", "DMCA &amp; ABUSE POLICY")
    ]:
        res = client.get(path)
        assert res.status_code == 200
        assert expected_text.encode("utf-8") in res.data
        assert b"End-to-End Encrypted" in res.data or b"end-to-end encryption" in res.data or b"END-TO-END" in res.data

    # Verify home page renders E2EE and cookie banner markup
    home_res = client.get("/")
    assert home_res.status_code == 200
    assert b"End-to-End Encrypted" in home_res.data
    assert b"cookie-banner" in home_res.data


