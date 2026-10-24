from datetime import datetime, timezone, timedelta
from flask import (
    Blueprint,
    render_template,
    request,
    jsonify,
    current_app,
    abort
)
from app.extensions import db
from app.models import FileRecord, IntegrityCheck, SecurityEvent, utc_now
from app.security import admin_required, generate_csrf_token, validate_csrf, compute_sha256
from app.storage import get_storage_path, get_stored_file_metadata
from app.integrity import verify_file_integrity
from app.audit import log_security_event, EVENT_FORENSIC_INSPECTION

forensics_bp = Blueprint("forensics", __name__, url_prefix="/admin/forensics")


@forensics_bp.route("/")
@admin_required
def forensics_index():
    """Main forensic investigation workspace."""
    files = FileRecord.query.order_by(FileRecord.uploaded_at.desc()).all()
    selected_id = request.args.get("file_id", type=int)
    
    # Auto-select the first file if none explicitly chosen
    if not selected_id and files:
        selected_id = files[0].id

    selected_file = None
    os_meta = None
    live_hash = None
    history = []
    events = []

    if selected_id:
        selected_file = FileRecord.query.get(selected_id)
        if selected_file:
            os_meta = get_stored_file_metadata(selected_file.storage_id)
            path = get_storage_path(selected_file.storage_id)
            if path.exists():
                try:
                    live_hash = compute_sha256(path)
                except Exception:
                    live_hash = "Error computing hash"
            else:
                live_hash = "FILE_MISSING_ON_DISK"

            history = IntegrityCheck.query.filter_by(
                file_record_id=selected_file.id
            ).order_by(IntegrityCheck.checked_at.desc()).all()

            events = SecurityEvent.query.filter_by(
                file_record_id=selected_file.id
            ).order_by(SecurityEvent.timestamp.desc()).all()

            log_security_event(
                event_type=EVENT_FORENSIC_INSPECTION,
                outcome="SUCCESS",
                severity="INFO",
                file_record_id=selected_file.id,
                details=f"Admin inspected forensic metadata for file #{selected_file.id} ({selected_file.original_filename})"
            )

    return render_template(
        "forensic_analysis.html",
        files=files,
        selected_file=selected_file,
        os_meta=os_meta,
        live_hash=live_hash,
        history=history,
        events=events,
        csrf_token=generate_csrf_token()
    )


@forensics_bp.route("/verify/<int:file_id>", methods=["POST"])
@admin_required
def verify_integrity_route(file_id: int):
    """Trigger manual cryptographic SHA-256 verification of a file."""
    csrf_token = request.headers.get("X-CSRFToken") or request.form.get("csrf_token")
    if not validate_csrf(csrf_token):
        return jsonify({"error": "CSRF validation failed"}), 403

    record = FileRecord.query.get_or_404(file_id)
    res = verify_file_integrity(record, initiated_by="ADMIN_MANUAL")
    return jsonify(res)


# =========================================================================
# CONTROLLED DEMONSTRATION WORKFLOWS (FOR INS MINI-PROJECT EVALUATION)
# =========================================================================

@forensics_bp.route("/demo/tamper/<int:file_id>", methods=["POST"])
@admin_required
def demo_tamper(file_id: int):
    """
    Controlled demonstration endpoint for evaluation examiners:
    Injects simulated corruption bytes into the stored file to demonstrate
    real-time cryptographic integrity violation detection.
    """
    csrf_token = request.headers.get("X-CSRFToken") or request.form.get("csrf_token")
    if not validate_csrf(csrf_token):
        return jsonify({"error": "CSRF validation failed"}), 403

    record = FileRecord.query.get_or_404(file_id)
    path = get_storage_path(record.storage_id)

    if not path.exists():
        return jsonify({"error": "Physical file does not exist in storage"}), 404

    # Inject simulated corruption byte sequence
    with open(path, "ab") as f:
        f.write(b"\n# [FORENSIC DEMO TAMPERING PAYLOAD]\n")

    return jsonify({
        "success": True,
        "message": f"Simulated tamper payload injected into file #{file_id} ({record.original_filename}). Storage SHA-256 has changed.",
        "storage_id": record.storage_id
    })


@forensics_bp.route("/demo/expire/<int:file_id>", methods=["POST"])
@admin_required
def demo_expire(file_id: int):
    """
    Controlled demonstration endpoint for evaluation examiners:
    Simulates the passage of 12 hours by setting expires_at into the past,
    allowing instant demonstration of expiration enforcement and cleanup.
    """
    csrf_token = request.headers.get("X-CSRFToken") or request.form.get("csrf_token")
    if not validate_csrf(csrf_token):
        return jsonify({"error": "CSRF validation failed"}), 403

    record = FileRecord.query.get_or_404(file_id)
    record.expires_at = utc_now() - timedelta(minutes=10)
    record.status = "expired"
    db.session.commit()

    return jsonify({
        "success": True,
        "message": f"File #{file_id} expiration accelerated to 10 minutes ago. Expiration enforcement is now active.",
        "expires_at": record.expires_at.isoformat() + "Z"
    })

