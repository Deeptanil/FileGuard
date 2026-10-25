import io
import qrcode
from flask import (
    Blueprint,
    render_template,
    send_file,
    jsonify,
    current_app,
    make_response,
    request,
    session,
    flash,
    redirect,
    url_for
)
from werkzeug.security import check_password_hash
from app.extensions import db, limiter
from app.models import FileRecord
from app.storage import get_storage_path, delete_stored_file, get_decrypted_stream
from app.security import hash_token, compute_sha256, validate_csrf
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

RESERVED_ROOT_PATHS = {
    "upload", "history", "admin", "forensics", "static", "api",
    "robots.txt", "sitemap.xml", "llms.txt", "health", "favicon.ico", "favicon.png", "favicon.svg"
}


@downloads_bp.route("/<token>")
@downloads_bp.route("/share/<token>")
def view_shared_file(token: str):
    """Recipient view page for inspecting shared file metadata and remaining time."""
    if token.lower() in RESERVED_ROOT_PATHS:
        return render_template("errors/404.html"), 404

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

    # Malware check: if flagged, render malware alert on share view
    if record.malware_status == "malicious":
        canonical_base = current_app.config.get("CANONICAL_URL") or request.host_url.rstrip("/")
        return render_template(
            "share.html",
            file=record,
            token=token,
            is_malicious=True,
            is_locked=False,
            is_unlocked=False,
            is_owner=False,
            just_uploaded=False,
            share_url=f"{canonical_base}/{token}",
            qr_code_base64=""
        ), 403

    if is_file_expired(record):
        log_security_event(
            event_type=EVENT_DOWNLOAD_BLOCKED_EXP,
            outcome="BLOCKED",
            severity="LOW",
            file_record_id=record.id,
            details="User visited expired file share link"
        )
        return render_template("expired.html", file=record), 410

    # Check password lock status
    is_owner = bool(session.get(f"uploader_{token}"))
    is_unlocked = bool(session.get(f"unlocked_{record.id}"))
    is_locked = bool(record.has_password and not is_unlocked and not is_owner)

    from app.routes.uploads import generate_qr_base64
    canonical_base = current_app.config.get("CANONICAL_URL")
    if not canonical_base or "localhost" in canonical_base:
        canonical_base = request.host_url.rstrip("/")
    share_url = f"{canonical_base}/{token}"
    qr_data = generate_qr_base64(share_url)

    return render_template(
        "share.html",
        file=record,
        token=token,
        share_url=share_url,
        qr_code_base64=qr_data,
        is_locked=is_locked,
        is_unlocked=is_unlocked,
        is_owner=is_owner,
        just_uploaded=(request.args.get("just_uploaded") == "true")
    )


@downloads_bp.route("/<token>/unlock", methods=["POST"])
@downloads_bp.route("/share/<token>/unlock", methods=["POST"])
@limiter.limit("15 per minute")
def unlock_shared_file(token: str):
    """Verify submitted PIN or password and unlock recipient session."""
    token_h = hash_token(token)
    record = FileRecord.query.filter_by(share_token_hash=token_h).first()
    if not record or is_file_expired(record):
        if request.is_json:
            return jsonify({"error": "File not found or expired."}), 404
        return redirect(url_for("downloads.view_shared_file", token=token))

    json_body = request.get_json(silent=True) or {}
    csrf_token = request.headers.get("X-CSRFToken") or request.form.get("csrf_token") or json_body.get("csrf_token")
    if not validate_csrf(csrf_token):
        if request.is_json:
            return jsonify({"error": "Session expired or invalid security token. Please refresh."}), 403
        flash("Session expired or invalid form token. Please try again.", "danger")
        return redirect(url_for("downloads.view_shared_file", token=token))

    password_attempt = (request.form.get("password") or json_body.get("password") or "").strip()
    if record.password_hash and check_password_hash(record.password_hash, password_attempt):
        session[f"unlocked_{record.id}"] = True
        if request.is_json:
            return jsonify({
                "success": True,
                "download_url": url_for("downloads.download_file", token=token)
            }), 200
        return redirect(url_for("downloads.view_shared_file", token=token))
    else:
        if request.is_json:
            return jsonify({"error": "Incorrect PIN or password."}), 403
        flash("Incorrect PIN or password. Access to this transfer is restricted.", "danger")
        return redirect(url_for("downloads.view_shared_file", token=token))


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
    share_url = f"{canonical_base}/{token}"

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

    # Malware quarantine check: block delivery immediately
    if record.malware_status == "malicious" or record.status == "deleted":
        log_security_event(
            event_type="DOWNLOAD_BLOCKED_MALWARE",
            outcome="BLOCKED",
            severity="CRITICAL",
            file_record_id=record.id,
            details=f"Download blocked: File flagged as malware ({record.malware_scan_details})"
        )
        if request.is_json:
            return jsonify({"error": "Download blocked: File flagged as malicious and permanently purged."}), 410
        return render_template("expired.html", file=record), 410

    # Password authorization check if file is protected
    if record.has_password:
        is_unlocked = bool(session.get(f"unlocked_{record.id}"))
        provided_pwd = request.args.get("password") or request.headers.get("X-File-Password")
        if provided_pwd and check_password_hash(record.password_hash, provided_pwd.strip()):
            is_unlocked = True
            session[f"unlocked_{record.id}"] = True

        if not is_unlocked:
            return jsonify({"error": "Password required to access this file"}), 403

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

    # All 5 security checks passed: Serve the file safely (decrypting if stored under AES-256-GCM)
    log_security_event(
        event_type=EVENT_DOWNLOAD_SUCCESS,
        outcome="SUCCESS",
        severity="INFO",
        file_record_id=record.id,
        details={"filename": record.original_filename, "display_title": record.display_name, "bytes": record.file_size}
    )

    try:
        stream = get_decrypted_stream(record.storage_id)
    except Exception as e:
        return render_template("errors/server_error.html", message="Failed to decrypt file stream"), 500

    response = make_response(
        send_file(
            stream,
            as_attachment=True,
            download_name=record.download_filename,
            mimetype=record.detected_mime_type
        )
    )
    # Apply security headers to prevent content sniffing and drive-by execution
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Content-Security-Policy"] = "default-src 'none'"
    response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
    return response


@downloads_bp.route("/api/files/batch-status", methods=["POST"])
@limiter.limit("60 per minute")
def batch_file_status():
    """Check live status and remaining seconds for multiple share tokens."""
    data = request.get_json(silent=True) or {}
    tokens = data.get("tokens", [])
    if not isinstance(tokens, list):
        return jsonify({"error": "Invalid tokens array"}), 400

    tokens = [t for t in tokens if isinstance(t, str) and t.strip()][:50]
    results = {}

    for token in tokens:
        token_h = hash_token(token)
        record = FileRecord.query.filter_by(share_token_hash=token_h).first()
        if not record:
            results[token] = {
                "status": "not_found",
                "is_expired": True,
                "remaining_seconds": 0
            }
        else:
            if record.status in ("deleted", "tampered"):
                effective_status = record.status
                expired = is_file_expired(record)
            else:
                expired = is_file_expired(record)
                effective_status = "expired" if expired else record.status

            results[token] = {
                "status": effective_status,
                "is_expired": expired,
                "remaining_seconds": record.remaining_seconds if (not expired and record.status == "active") else 0,
                "filename": record.original_filename,
                "file_size": record.file_size,
                "is_bundle": getattr(record, "is_bundle", False),
                "expires_at": record.expires_at.isoformat() + "Z"
            }

    return jsonify({"statuses": results}), 200


@downloads_bp.route("/api/files/<token>/revoke", methods=["POST"])
@limiter.limit("20 per minute")
def revoke_file(token: str):
    """Allow immediate deletion and revocation of a file by token bearer."""
    token_h = hash_token(token)
    record = FileRecord.query.filter_by(share_token_hash=token_h).first()
    if not record:
        return jsonify({"error": "File not found or invalid token"}), 404

    if record.status == "deleted":
        return jsonify({"message": "File is already revoked", "status": "deleted"}), 200

    try:
        delete_stored_file(record.storage_id)
    except Exception as e:
        current_app.logger.warning(f"Error purging storage during revocation: {e}")

    record.status = "deleted"
    db.session.commit()

    log_security_event(
        event_type="FILE_REVOKED_BY_USER",
        outcome="SUCCESS",
        severity="INFO",
        file_record_id=record.id,
        details=f"File '{record.original_filename}' immediately revoked and deleted by token bearer."
    )

    return jsonify({
        "success": True,
        "message": f"File '{record.original_filename}' has been revoked and purged immediately.",
        "status": "deleted"
    }), 200


