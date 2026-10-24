import io
import qrcode
from flask import (
    Blueprint,
    render_template,
    send_file,
    jsonify,
    current_app,
    make_response,
    request
)
from app.extensions import db, limiter
from app.models import FileRecord
from app.storage import get_storage_path
from app.security import hash_token, compute_sha256
from app.expiration import is_file_expired
from app.integrity import verify_file_integrity
from app.audit import (
    log_security_event,
    EVENT_DOWNLOAD_SUCCESS,
    EVENT_DOWNLOAD_BLOCKED_EXP,
    EVENT_DOWNLOAD_BLOCKED_INT,
    EVENT_INVALID_TOKEN,
    EVENT_FILE_MISSING
)

downloads_bp = Blueprint("downloads", __name__)


@downloads_bp.route("/share/<token>")
def view_shared_file(token: str):
    """Recipient view page for inspecting shared file metadata and remaining time."""
    token_h = hash_token(token)
    record = FileRecord.query.filter_by(share_token_hash=token_h).first()

    if not record:
        log_security_event(
            event_type=EVENT_INVALID_TOKEN,
            outcome="BLOCKED",
            severity="LOW",
            details="Attempted access with unrecognized share token"
        )
        return render_template("errors/invalid_share.html"), 404

    if is_file_expired(record):
        log_security_event(
            event_type=EVENT_DOWNLOAD_BLOCKED_EXP,
            outcome="BLOCKED",
            severity="LOW",
            file_record_id=record.id,
            details="User visited expired file share link"
        )
        return render_template("expired.html", file=record), 410

    from app.routes.uploads import generate_qr_base64
    canonical_base = current_app.config["CANONICAL_URL"]
    share_url = f"{canonical_base}/share/{token}"
    qr_data = generate_qr_base64(share_url)

    return render_template(
        "share.html",
        file=record,
        token=token,
        share_url=share_url,
        qr_code_base64=qr_data,
        just_uploaded=(request.args.get("just_uploaded") == "true")
    )


@downloads_bp.route("/api/files/<token>/status")
@limiter.limit("60 per minute")
def file_status(token: str):
    """Public endpoint to check countdown and file availability."""
    token_h = hash_token(token)
    record = FileRecord.query.filter_by(share_token_hash=token_h).first()

    if not record:
        return jsonify({"error": "File not found or invalid token"}), 404

    expired = is_file_expired(record)
    return jsonify({
        "filename": record.original_filename,
        "file_size": record.file_size,
        "extension": record.file_extension,
        "mime_type": record.detected_mime_type,
        "uploaded_at": record.uploaded_at.isoformat() + "Z",
        "expires_at": record.expires_at.isoformat() + "Z",
        "remaining_seconds": record.remaining_seconds,
        "is_expired": expired,
        "status": "expired" if expired else record.status
    })


@downloads_bp.route("/api/files/<token>/qr")
def download_qr(token: str):
    """Stream raw PNG image of the QR code for sharing link."""
    token_h = hash_token(token)
    record = FileRecord.query.filter_by(share_token_hash=token_h).first()
    if not record:
        return jsonify({"error": "File not found"}), 404

    canonical_base = current_app.config["CANONICAL_URL"]
    share_url = f"{canonical_base}/share/{token}"

    qr = qrcode.QRCode(version=1, box_size=10, border=3)
    qr.add_data(share_url)
    qr.make(fit=True)
    img = qr.make_image(fill_color="#0F172A", back_color="#FFFFFF")

    buf = io.BytesIO()
    img.save(buf, format="PNG")
    buf.seek(0)

    return send_file(
        buf,
        mimetype="image/png",
        as_attachment=False,
        download_name=f"fileguard_qr_{record.id}.png"
    )


@downloads_bp.route("/api/files/<token>/download")
@limiter.limit("30 per minute")
def download_file(token: str):
    """
    Secure file download pipeline enforcing all 5 mandatory checks:
    1. Token exists in database
    2. File record is valid & not marked deleted
    3. Expiration verification (server clock authoritative)
    4. Storage file existence on physical disk
    5. SHA-256 cryptographic integrity verification before serving
    """
    # Check 1: Token resolution
    token_h = hash_token(token)
    record = FileRecord.query.filter_by(share_token_hash=token_h).first()

    if not record:
        log_security_event(
            event_type=EVENT_INVALID_TOKEN,
            outcome="BLOCKED",
            severity="LOW",
            details="Download requested with invalid sharing token"
        )
        return render_template("errors/invalid_share.html"), 404

    # Check 2 & 3: Expiration & Status Verification
    if is_file_expired(record):
        log_security_event(
            event_type=EVENT_DOWNLOAD_BLOCKED_EXP,
            outcome="BLOCKED",
            severity="LOW",
            file_record_id=record.id,
            details="Download rejected: 12-hour expiration deadline exceeded"
        )
        return render_template("expired.html", file=record), 410

    # Check 4: Storage file existence
    path = get_storage_path(record.storage_id)
    if not path.exists():
        log_security_event(
            event_type=EVENT_FILE_MISSING,
            outcome="FAILURE",
            severity="HIGH",
            file_record_id=record.id,
            details={"storage_id": record.storage_id, "error": "File not on disk during download"}
        )
        return render_template("errors/missing_file.html"), 404

    # Check 5: SHA-256 Cryptographic Integrity Verification
    try:
        current_sha256 = compute_sha256(path)
    except Exception as e:
        return render_template("errors/server_error.html", message="Integrity check failed"), 500

    if current_sha256 != record.sha256_reference:
        # Tampering detected!
        record.status = "tampered"
        db.session.commit()

        log_security_event(
            event_type=EVENT_DOWNLOAD_BLOCKED_INT,
            outcome="BLOCKED",
            severity="CRITICAL",
            file_record_id=record.id,
            details={
                "alert": "Download blocked due to SHA-256 integrity mismatch",
                "expected": record.sha256_reference,
                "observed": current_sha256
            }
        )
        return render_template(
            "errors/integrity_error.html",
            expected=record.sha256_reference,
            observed=current_sha256
        ), 409

    # All 5 security checks passed: Serve the file safely
    log_security_event(
        event_type=EVENT_DOWNLOAD_SUCCESS,
        outcome="SUCCESS",
        severity="INFO",
        file_record_id=record.id,
        details={"filename": record.original_filename, "bytes": record.file_size}
    )

    response = make_response(
        send_file(
            path,
            as_attachment=True,
            download_name=record.original_filename,
            mimetype=record.detected_mime_type
        )
    )
    # Apply security headers to prevent content sniffing and drive-by execution
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Content-Security-Policy"] = "default-src 'none'"
    response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
    return response

