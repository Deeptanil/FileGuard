import io
import os
import zipfile
import base64
from datetime import timedelta
import qrcode
from flask import Blueprint, request, jsonify, render_template, current_app, redirect, url_for, session
from werkzeug.security import generate_password_hash, check_password_hash
from sqlalchemy import func
from app.extensions import db, limiter
from app.models import FileRecord, utc_now
from app.storage import save_upload_stream, StorageError, delete_stored_file
from app.security import (
    inspect_file_type,
    sanitize_filename,
    generate_share_token,
    hash_token,
    validate_csrf,
    get_client_ip
)
from app.audit import log_security_event, EVENT_UPLOAD_SUCCESS, EVENT_UPLOAD_REJECTED

uploads_bp = Blueprint("uploads", __name__)


def check_ip_upload_quota(client_ip: str, incoming_bytes: int) -> tuple[bool, str, int]:
    """
    Check if the client IP has exceeded the 12-hour upload limit (default 100 MB).
    Returns (is_allowed, error_message, remaining_bytes).
    """
    quota_hours = current_app.config.get("IP_QUOTA_HOURS", 12)
    quota_mb = current_app.config.get("IP_QUOTA_MB", 100)
    quota_bytes = quota_mb * 1024 * 1024

    since_time = utc_now() - timedelta(hours=quota_hours)

    used_bytes = db.session.query(func.sum(FileRecord.file_size)).filter(
        FileRecord.uploader_ip == client_ip,
        FileRecord.uploaded_at >= since_time
    ).scalar() or 0

    remaining = max(0, quota_bytes - used_bytes)

    if (used_bytes + incoming_bytes) > quota_bytes:
        used_mb = round(used_bytes / (1024 * 1024), 1)
        inc_mb = round(incoming_bytes / (1024 * 1024), 1)
        msg = (
            f"12-Hour upload quota exceeded for your device. "
            f"You have uploaded {used_mb} MB in the last {quota_hours} hours. "
            f"This upload ({inc_mb} MB) exceeds your remaining allowance of {round(remaining / (1024 * 1024), 1)} MB. "
            f"Quota resets continuously over 12 hours."
        )
        return False, msg, remaining

    return True, "", remaining


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
    Handle secure file upload (single file or multiple files / folder bundled into a zip archive).
    Validates CSRF, 12-hour per-IP quota (100 MB), individual and aggregate size,
    extension whitelist, and MIME signatures before saving with SHA-256 integrity hash.
    """
    client_ip = get_client_ip()

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
    files = request.files.getlist("file") or request.files.getlist("files[]")
    if not files or all(not f.filename for f in files):
        return jsonify({"error": "No file or folder selected for upload"}), 400

    # Filter out empty files
    valid_files = [f for f in files if f and f.filename]
    if not valid_files:
        return jsonify({"error": "No valid files received"}), 400

    max_mb = current_app.config.get("MAX_CONTENT_LENGTH_MB", 100)
    max_bytes = max_mb * 1024 * 1024
    allowed_exts = current_app.config["ALLOWED_EXTENSIONS"]

    # 3. Handle Single File vs Multiple Files / Folder Bundle
    is_folder_request = request.form.get("is_folder") == "true"
    if len(valid_files) == 1 and not is_folder_request:
        file = valid_files[0]
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
                "error": f"Disallowed file type '.{ext}'. Allowed types: {', '.join(sorted(allowed_exts))}"
            }), 400

        # Pre-check IP Quota
        content_length = request.content_length or 0
        quota_ok, quota_err, _ = check_ip_upload_quota(client_ip, content_length)
        if not quota_ok:
            log_security_event(
                event_type=EVENT_UPLOAD_REJECTED,
                outcome="BLOCKED",
                severity="LOW",
                details=quota_err
            )
            return jsonify({"error": quota_err}), 429

        try:
            storage_id, byte_size, sha256_hash = save_upload_stream(file.stream)
        except StorageError as e:
            return jsonify({"error": str(e)}), 413
        except Exception as e:
            return jsonify({"error": "Failed to process file storage"}), 500

        is_bundle = False
    else:
        # Multiple files or folder upload -> automatically bundle into a clean ZIP archive
        bundle_buffer = io.BytesIO()
        total_bundle_size = 0
        bundle_name = request.form.get("bundle_name", "").strip()
        if not bundle_name:
            # Derive sensible bundle name from first file or folder path
            first_path = valid_files[0].filename.replace("\\", "/")
            if "/" in first_path:
                top_folder = first_path.split("/")[0]
                bundle_name = f"{top_folder}.zip"
            else:
                bundle_name = f"FileGuard_Bundle_{len(valid_files)}_files.zip"
        
        clean_name, ext = sanitize_filename(bundle_name)
        if not clean_name.endswith(".zip"):
            clean_name += ".zip"
        ext = "zip"
        detected_mime = "application/zip"

        try:
            with zipfile.ZipFile(bundle_buffer, mode="w", compression=zipfile.ZIP_DEFLATED) as zf:
                for f in valid_files:
                    f_clean_name, f_ext = sanitize_filename(f.filename)
                    # Verify individual file extension
                    if f_ext not in allowed_exts and f_ext != "":
                        return jsonify({
                            "error": f"File '{f.filename}' has disallowed type '.{f_ext}'. Allowed types: {', '.join(sorted(allowed_exts))}"
                        }), 400

                    file_data = f.read()
                    total_bundle_size += len(file_data)
                    if total_bundle_size > max_bytes:
                        return jsonify({"error": f"Total bundle size exceeds {max_mb} MB limit."}), 413

                    # Preserve relative path within ZIP if uploading a folder
                    rel_arcname = f.filename.replace("\\", "/").lstrip("/")
                    zf.writestr(rel_arcname, file_data)
        except Exception as e:
            return jsonify({"error": f"Failed to create folder bundle archive: {str(e)}"}), 500

        bundle_buffer.seek(0)
        bundle_size = len(bundle_buffer.getvalue())

        # Pre-check IP Quota for the entire bundle
        quota_ok, quota_err, _ = check_ip_upload_quota(client_ip, bundle_size)
        if not quota_ok:
            log_security_event(
                event_type=EVENT_UPLOAD_REJECTED,
                outcome="BLOCKED",
                severity="LOW",
                details=quota_err
            )
            return jsonify({"error": quota_err}), 429

        try:
            storage_id, byte_size, sha256_hash = save_upload_stream(bundle_buffer)
        except StorageError as e:
            return jsonify({"error": str(e)}), 413
        except Exception as e:
            return jsonify({"error": "Failed to process storage"}), 500

        is_bundle = True

    if byte_size == 0:
        delete_stored_file(storage_id)
        return jsonify({"error": "Empty file uploads are not permitted"}), 400

    # 4. Strict IP Quota Post-Check (Authoritative byte size comparison)
    quota_ok, quota_err, _ = check_ip_upload_quota(client_ip, byte_size)
    if not quota_ok:
        delete_stored_file(storage_id)
        log_security_event(
            event_type=EVENT_UPLOAD_REJECTED,
            outcome="BLOCKED",
            severity="LOW",
            details=quota_err
        )
        return jsonify({"error": quota_err}), 429

    # 5. Generate sharing token & calculate expiration
    raw_token, token_hash = generate_share_token()
    upload_time = utc_now()
    default_exp_hours = current_app.config.get("EXPIRATION_HOURS", 12)
    try:
        req_exp_hours = int(request.form.get("expiration_hours", default_exp_hours))
        expiration_hours = max(1, min(12, req_exp_hours))
    except (ValueError, TypeError):
        expiration_hours = default_exp_hours
    expires_time = upload_time + timedelta(hours=expiration_hours)

    # Optional custom title & PIN/password protection
    display_title = (request.form.get("display_title") or "").strip() or None
    raw_password = (request.form.get("password") or "").strip()
    password_hash = generate_password_hash(raw_password, method="scrypt") if raw_password else None
    is_e2ee = (request.form.get("is_e2ee") == "true")

    # 6. Save metadata record to database
    try:
        record = FileRecord(
            storage_id=storage_id,
            original_filename=clean_name,
            display_title=display_title,
            file_size=byte_size,
            file_extension=ext,
            detected_mime_type=detected_mime,
            sha256_reference=sha256_hash,
            share_token_hash=token_hash,
            password_hash=password_hash,
            is_e2ee=is_e2ee,
            is_encrypted_at_rest=True,
            uploaded_at=upload_time,
            expires_at=expires_time,
            status="active",
            uploader_ip=client_ip,
            is_bundle=is_bundle
        )
        db.session.add(record)
        db.session.commit()
    except Exception as e:
        current_app.logger.error(f"Failed to record file metadata: {e}")
        db.session.rollback()
        delete_stored_file(storage_id)
        return jsonify({"error": "Failed to record file metadata"}), 500

    # Mark uploader session as owner (require PIN unlock if password is set)
    session[f"uploader_{raw_token}"] = True
    session[f"unlocked_{record.id}"] = not bool(password_hash)

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
            "display_title": record.display_name,
            "size": byte_size,
            "sha256": sha256_hash,
            "has_password": bool(password_hash),
            "is_e2ee": is_e2ee,
            "expires_at": expires_time.isoformat() + "Z"
        }
    )

    return jsonify({
        "success": True,
        "token": raw_token,
        "share_url": share_url,
        "qr_code_base64": qr_data,
        "filename": clean_name,
        "display_title": record.display_name,
        "file_size": byte_size,
        "has_password": bool(password_hash),
        "is_e2ee": is_e2ee,
        "sha256_reference": sha256_hash,
        "uploaded_at": upload_time.isoformat() + "Z",
        "expires_at": expires_time.isoformat() + "Z",
        "remaining_seconds": int((expires_time - upload_time).total_seconds())
    }), 201


@uploads_bp.route("/api/files/<token>/settings", methods=["POST"])
@limiter.limit("20 per minute")
def update_file_settings(token: str):
    """
    Allow uploader to adjust title, password, or shorten expiration post-upload.
    """
    token_h = hash_token(token)
    record = FileRecord.query.filter_by(share_token_hash=token_h).first()
    if not record or record.status in ("deleted", "tampered") or record.is_expired:
        return jsonify({"error": "File not found or inactive"}), 404

    is_owner = bool(session.get(f"uploader_{token}"))
    if not is_owner:
        return jsonify({"error": "Unauthorized. Only the uploader can modify transfer settings."}), 403

    csrf_token = request.headers.get("X-CSRFToken") or request.form.get("csrf_token") or (request.get_json(silent=True) or {}).get("csrf_token")
    if csrf_token and not validate_csrf(csrf_token):
        return jsonify({"error": "Invalid CSRF token"}), 403

    data = request.get_json(silent=True) or request.form.to_dict()

    # 1. Update Display Title
    if "display_title" in data:
        new_title = str(data.get("display_title", "")).strip()
        record.display_title = new_title[:200] if new_title else None

    # 2. Update / Remove Password
    if data.get("remove_password") in (True, "true", "1"):
        record.password_hash = None
        session[f"unlocked_{record.id}"] = True
    elif "password" in data:
        new_pwd = str(data.get("password", "")).strip()
        if new_pwd:
            record.password_hash = generate_password_hash(new_pwd, method="scrypt")
            session[f"unlocked_{record.id}"] = False

    # 3. Shorten Expiration if requested
    if "expiration_hours" in data:
        try:
            exp_h = max(1, min(12, int(data.get("expiration_hours"))))
            new_exp = record.uploaded_at + timedelta(hours=exp_h)
            if new_exp > utc_now():
                record.expires_at = new_exp
        except (ValueError, TypeError):
            pass

    db.session.commit()

    return jsonify({
        "success": True,
        "display_title": record.display_name,
        "has_password": record.has_password,
        "expires_at": record.expires_at.isoformat() + "Z",
        "remaining_seconds": record.remaining_seconds
    }), 200


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

