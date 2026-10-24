import io
from datetime import timedelta
from app.models import FileRecord, utc_now
from app.security import hash_token

def upload_sample_file(client, filename="sample.txt", content=b"Sample content for download tests"):
    """Helper to upload a sample file and return (token, raw_content, filename)."""
    with client.session_transaction() as sess:
        sess["_csrf_token"] = "sample_csrf_123"

    data = {
        "file": (io.BytesIO(content), filename),
        "csrf_token": "sample_csrf_123"
    }
    res = client.post("/api/files", data=data, content_type="multipart/form-data")
    assert res.status_code == 201
    token = res.get_json()["token"]
    return token, content, filename


def test_8_valid_share_link_displays_file_info(client, db_session):
    """Test 8: A valid sharing link displays correct file information."""
    token, _, filename = upload_sample_file(client, "document.pdf", b"%PDF-1.4 sample content")
    # Verify standard hyphenated link (e.g. 4829-1047)
    response = client.get(f"/share/{token}")
    assert response.status_code == 200
    assert filename in response.get_data(as_text=True)

    # Verify unhyphenated version (e.g. 48291047) also resolves seamlessly
    unhyphenated = token.replace("-", "")
    res_unhyphenated = client.get(f"/share/{unhyphenated}")
    assert res_unhyphenated.status_code == 200
    assert filename in res_unhyphenated.get_data(as_text=True)


def test_9_valid_share_link_permits_download(client, db_session):
    """Test 9: A valid sharing link permits download before expiration."""
    token, content, filename = upload_sample_file(client, "report.txt", b"Confidential Report Content")
    response = client.get(f"/api/files/{token}/download")
    assert response.status_code == 200
    assert response.data == content
    disposition = response.headers.get("Content-Disposition", "")
    assert f"filename={filename}" in disposition or f'filename="{filename}"' in disposition


def test_10_invalid_token_does_not_return_file(client, db_session):
    """Test 10: An invalid token does not return a file."""
    response = client.get("/api/files/completely-invalid-nonexistent-token/download")
    assert response.status_code == 404


def test_11_token_isolation(client, db_session):
    """Test 11: One file's token cannot retrieve another file."""
    token1, content1, _ = upload_sample_file(client, "file1.txt", b"First file payload")
    token2, content2, _ = upload_sample_file(client, "file2.txt", b"Second file payload")

    res1 = client.get(f"/api/files/{token1}/download")
    res2 = client.get(f"/api/files/{token2}/download")

    assert res1.data == content1
    assert res2.data == content2
    assert res1.data != res2.data


def test_12_file_cannot_be_downloaded_after_expiration(client, db_session):
    """Test 12: A file cannot be downloaded after expiration."""
    token, _, _ = upload_sample_file(client, "expire_now.txt", b"Soon to expire payload")

    # Fast forward expiration into the past
    token_h = hash_token(token)
    record = FileRecord.query.filter_by(share_token_hash=token_h).first()
    record.expires_at = utc_now() - timedelta(minutes=5)
    db_session.commit()

    # Attempt download
    res = client.get(f"/api/files/{token}/download")
    assert res.status_code == 410  # Gone / Expired
    assert b"expired" in res.data.lower()


def test_13_expiration_enforced_without_cleanup_worker(client, db_session):
    """Test 13: Expiration check works even when the cleanup worker has not run."""
    token, _, _ = upload_sample_file(client, "uncleaned.txt", b"File still on disk but past deadline")

    # Simulate past expiration while file is still physically on disk
    token_h = hash_token(token)
    record = FileRecord.query.filter_by(share_token_hash=token_h).first()
    record.expires_at = utc_now() - timedelta(hours=1)
    record.status = "active"  # Not yet marked deleted by background cleanup
    db_session.commit()

    # The download endpoint must block access dynamically
    res = client.get(f"/api/files/{token}/download")
    assert res.status_code == 410

