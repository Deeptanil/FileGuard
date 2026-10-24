import io
import base64
from datetime import timedelta
import qrcode
from flask import Blueprint, request, jsonify, render_template, current_app, redirect, url_for
from app.extensions import db, limiter
from app.models import FileRecord, utc_now
from app.storage import save_upload_stream, StorageError, delete_stored_file
from app.security import (
    inspect_file_type,
    sanitize_filename,
    generate_share_token,
    hash_token,
    validate_csrf
)
from app.audit import log_security_event, EVENT_UPLOAD_SUCCESS, EVENT_UPLOAD_REJECTED

uploads_bp = Blueprint("uploads", __name__)


def generate_qr_base64(url: str) -> str:
    """Generate QR code PNG as base64 data URI."""
    qr = qrcode.QRCode(
        version=1,
        error_correction=qrcode.constants.ERROR_CORRECT_M,
        box_size=8,
        border=2,
    )
    qr.add_data(url)
    qr.make(fit=True)
    img = qr.make_image(fill_color="#0F172A", back_color="#FFFFFF")
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    buf.seek(0)
    return f"data:image/png;base64,{base64.b64encode(buf.getvalue()).decode('utf-8')}"


@uploads_bp.route("/api/files", methods=["POST"])
@limiter.limit("20 per minute")
def upload_file():
    """
    Handle secure file upload.
    Validates CSRF, size, extension, MIME signature, computes SHA-256 reference hash,
    and returns unique sharing link and QR code.
    """
    # 1. CSRF validation
    csrf_token = request.headers.get("X-CSRFToken") or request.form.get("csrf_token")
    if not validate_csrf(csrf_token):
        log_security_event(
            event_type=EVENT_UPLOAD_REJECTED,
            outcome="BLOCKED",
            severity="MEDIUM",
            details="Upload rejected due to missing or invalid CSRF token"
        )
        return jsonify({"error": "Invalid or missing CSRF token"}), 403

    # 2. File presence validation
    if "file" not in request.files:
        return jsonify({"error": "No file part in upload request"}), 400

    file = request.files["file"]
    if not file or not file.filename:
        return jsonify({"error": "No file selected for upload"}), 400

    # 3. Filename and extension inspection
    clean_name, ext = sanitize_filename(file.filename)
    is_allowed, ext, detected_mime = inspect_file_type(file.stream, file.filename)

    if not is_allowed:
        log_security_event(
            event_type=EVENT_UPLOAD_REJECTED,
            outcome="BLOCKED",
            severity="MEDIUM",
            details={
                "reason": "Disallowed file extension or magic signature mismatch",
                "filename": clean_name,
                "extension": ext
            }
        )
        return jsonify({
            "error": f"Disallowed file type '.{ext}'. Allowed types: {', '.join(sorted(current_app.config['ALLOWED_EXTENSIONS']))}"
        }), 400

    # 4. Save file to isolated storage & compute SHA-256
    try:
        storage_id, byte_size, sha256_hash = save_upload_stream(file.stream)
    except StorageError as e:
        log_security_event(
            event_type=EVENT_UPLOAD_REJECTED,
            outcome="BLOCKED",
            severity="LOW",
            details=str(e)
        )
        return jsonify({"error": str(e)}), 413
    except Exception as e:
        log_security_event(
            event_type=EVENT_UPLOAD_REJECTED,
            outcome="FAILURE",
            severity="HIGH",
            details=f"Unexpected storage error: {str(e)}"
        )
        return jsonify({"error": "Failed to process file storage"}), 500

    if byte_size == 0:
        delete_stored_file(storage_id)
        return jsonify({"error": "Empty file uploads are not permitted"}), 400

    # 5. Generate sharing token & calculate strict 12-hour expiration
    raw_token, token_hash = generate_share_token()
    upload_time = utc_now()
    expiration_hours = current_app.config["EXPIRATION_HOURS"]
    expires_time = upload_time + timedelta(hours=expiration_hours)

    # 6. Save metadata record to database
    try:
        record = FileRecord(
            storage_id=storage_id,
            original_filename=clean_name,
            file_size=byte_size,
            file_extension=ext,
            detected_mime_type=detected_mime,
            sha256_reference=sha256_hash,
            share_token_hash=token_hash,
            uploaded_at=upload_time,
            expires_at=expires_time,
            status="active"
        )
        db.session.add(record)
        db.session.commit()
    except Exception as e:
        db.session.rollback()
        delete_stored_file(storage_id)
        return jsonify({"error": "Failed to record file metadata"}), 500

    # 7. Construct canonical URLs and QR Code
    canonical_base = current_app.config.get("CANONICAL_URL")
    if not canonical_base or "localhost" in canonical_base:
        # Use request's actual host URL if available (e.g. https://fileguard.onrender.com)
        canonical_base = request.host_url.rstrip("/")
    share_url = f"{canonical_base}/share/{raw_token}"
    qr_data = generate_qr_base64(share_url)

    # 8. Log success audit event
    log_security_event(
        event_type=EVENT_UPLOAD_SUCCESS,
        outcome="SUCCESS",
        severity="INFO",
        file_record_id=record.id,
        details={
            "filename": clean_name,
            "size": byte_size,
            "sha256": sha256_hash,
            "expires_at": expires_time.isoformat() + "Z"
        }
    )

    return jsonify({
        "success": True,
        "token": raw_token,
        "share_url": share_url,
        "qr_code_base64": qr_data,
        "filename": clean_name,
        "file_size": byte_size,
        "sha256_reference": sha256_hash,
        "uploaded_at": upload_time.isoformat() + "Z",
        "expires_at": expires_time.isoformat() + "Z",
        "remaining_seconds": int((expires_time - upload_time).total_seconds())
    }), 201


@uploads_bp.route("/upload-success/<token>")
def upload_success(token: str):
    """Render upload completion page with sharing link and QR code."""
    token_h = hash_token(token)
    record = FileRecord.query.filter_by(share_token_hash=token_h).first()
    if not record or record.status in ("deleted", "expired") or record.is_expired:
        return render_template("expired.html", reason="The requested upload session has expired or does not exist."), 404

    canonical_base = current_app.config["CANONICAL_URL"]
    share_url = f"{canonical_base}/share/{token}"
    qr_data = generate_qr_base64(share_url)

    return render_template(
        "upload_success.html",
        file=record,
        token=token,
        share_url=share_url,
        qr_code_base64=qr_data
    )

