from werkzeug.security import check_password_hash
from flask import (
    Blueprint,
    render_template,
    request,
    redirect,
    url_for,
    session,
    flash,
    jsonify
)
from app.extensions import db, limiter
from app.models import Administrator, FileRecord, SecurityEvent, IntegrityCheck, utc_now
from app.security import admin_required, generate_csrf_token, validate_csrf
from app.cleanup import run_expired_files_cleanup
from app.audit import (
    log_security_event,
    EVENT_ADMIN_LOGIN_SUCCESS,
    EVENT_ADMIN_LOGIN_FAIL,
    EVENT_ADMIN_LOGOUT,
    EVENT_UNAUTHORIZED_ACCESS
)

admin_bp = Blueprint("admin", __name__, url_prefix="/admin")


@admin_bp.route("/login", methods=["GET", "POST"])
@limiter.limit("5 per minute")
def login():
    """Administrative authentication interface."""
    if session.get("admin_logged_in"):
        return redirect(url_for("admin.dashboard"))

    if request.method == "POST":
        csrf_token = request.form.get("csrf_token")
        if not validate_csrf(csrf_token):
            flash("Invalid or expired session security token. Please try again.", "danger")
            return render_template("admin_login.html", csrf_token=generate_csrf_token())

        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        admin_user = Administrator.query.filter_by(username=username, active_status=True).first()

        if admin_user and check_password_hash(admin_user.password_hash, password):
            session["admin_logged_in"] = True
            session["admin_user_id"] = admin_user.id
            session["admin_username"] = admin_user.username
            admin_user.last_login_at = utc_now()
            db.session.commit()

            log_security_event(
                event_type=EVENT_ADMIN_LOGIN_SUCCESS,
                outcome="SUCCESS",
                severity="INFO",
                details=f"Admin '{username}' successfully authenticated"
            )

            next_url = request.args.get("next")
            if next_url and next_url.startswith("/admin"):
                return redirect(next_url)
            return redirect(url_for("admin.dashboard"))
        else:
            log_security_event(
                event_type=EVENT_ADMIN_LOGIN_FAIL,
                outcome="FAILURE",
                severity="HIGH",
                details=f"Failed admin login attempt for username: {username}"
            )
            flash("Invalid administrative credentials.", "danger")

    return render_template("admin_login.html", csrf_token=generate_csrf_token())


@admin_bp.route("/logout", methods=["POST"])
@admin_required
def logout():
    """Securely terminate administrator session."""
    username = session.get("admin_username", "unknown")
    session.clear()
    log_security_event(
        event_type=EVENT_ADMIN_LOGOUT,
        outcome="SUCCESS",
        severity="INFO",
        details=f"Admin '{username}' logged out"
    )
    flash("You have been securely logged out.", "info")
    return redirect(url_for("admin.login"))


@admin_bp.route("/dashboard")
@admin_required
def dashboard():
    """Comprehensive security monitoring dashboard with storage analytics and telemetry."""
    from datetime import timedelta
    from sqlalchemy import func

    total_uploads = FileRecord.query.count()
    active_files = FileRecord.query.filter_by(status="active").count()
    expired_files = FileRecord.query.filter(
        (FileRecord.status == "expired") | (FileRecord.expires_at <= utc_now())
    ).count()
    deleted_files = FileRecord.query.filter_by(status="deleted").count()
    tampered_files = FileRecord.query.filter_by(status="tampered").count()

    total_downloads = SecurityEvent.query.filter_by(event_type="FILE_DOWNLOAD_SUCCESS").count()
    expired_denials = SecurityEvent.query.filter_by(event_type="DOWNLOAD_BLOCKED_EXPIRED").count()
    integrity_failures = SecurityEvent.query.filter_by(event_type="INTEGRITY_CHECK_FAIL").count()

    # Storage Usage Calculation (Active bytes stored in S3/disk)
    active_bytes_query = db.session.query(func.sum(FileRecord.file_size)).filter_by(status="active").scalar() or 0
    total_bytes_stored_ever = db.session.query(func.sum(FileRecord.file_size)).scalar() or 0
    
    # 10 GB Free Tier Limit
    STORAGE_QUOTA_BYTES = 10 * 1024 * 1024 * 1024
    storage_used_pct = round((active_bytes_query / STORAGE_QUOTA_BYTES) * 100, 2)
    storage_used_mb = round(active_bytes_query / (1024 * 1024), 2)
    storage_used_gb = round(active_bytes_query / (1024 * 1024 * 1024), 3)
    storage_quota_gb = 10.0

    # 7-day Historical Storage / Upload Trajectory for Graph
    now = utc_now()
    history_labels = []
    history_uploads_data = []
    history_storage_mb_data = []
    
    for i in range(6, -1, -1):
        day_start = (now - timedelta(days=i)).replace(hour=0, minute=0, second=0, microsecond=0)
        day_end = day_start + timedelta(days=1)
        day_label = day_start.strftime("%b %d")
        
        day_uploads = FileRecord.query.filter(
            FileRecord.uploaded_at >= day_start,
            FileRecord.uploaded_at < day_end
        ).count()
        
        day_bytes = db.session.query(func.sum(FileRecord.file_size)).filter(
            FileRecord.uploaded_at >= day_start,
            FileRecord.uploaded_at < day_end
        ).scalar() or 0
        
        history_labels.append(day_label)
        history_uploads_data.append(day_uploads)
        history_storage_mb_data.append(round(day_bytes / (1024 * 1024), 2))

    recent_events = SecurityEvent.query.order_by(SecurityEvent.timestamp.desc()).limit(25).all()

    return render_template(
        "admin_dashboard.html",
        total_uploads=total_uploads,
        active_files=active_files,
        expired_files=expired_files,
        deleted_files=deleted_files,
        tampered_files=tampered_files,
        total_downloads=total_downloads,
        expired_denials=expired_denials,
        integrity_failures=integrity_failures,
        active_bytes=active_bytes_query,
        storage_used_mb=storage_used_mb,
        storage_used_gb=storage_used_gb,
        storage_quota_gb=storage_quota_gb,
        storage_used_pct=storage_used_pct,
        storage_history_labels=history_labels,
        storage_history_uploads=history_uploads_data,
        storage_history_mb=history_storage_mb_data,
        recent_events=recent_events,
        csrf_token=generate_csrf_token()
    )


@admin_bp.route("/files")
@admin_required
def files_list():
    """List and filter file records."""
    status_filter = request.args.get("status")
    query = FileRecord.query.order_by(FileRecord.uploaded_at.desc())
    if status_filter:
        query = query.filter_by(status=status_filter)
    files = query.limit(100).all()

    return render_template(
        "admin_files.html",
        files=files,
        current_filter=status_filter or "all",
        csrf_token=generate_csrf_token()
    )


@admin_bp.route("/events")
@admin_required
def events_list():
    """List all recorded security events with pagination and severity filter."""
    severity = request.args.get("severity")
    query = SecurityEvent.query.order_by(SecurityEvent.timestamp.desc())
    if severity:
        query = query.filter_by(severity=severity.upper())
    events = query.limit(100).all()

    return render_template(
        "admin_events.html",
        events=events,
        current_severity=severity or "all",
        csrf_token=generate_csrf_token()
    )


@admin_bp.route("/cleanup", methods=["POST"])
@admin_required
def trigger_cleanup():
    """Trigger manual execution of the background cleanup worker."""
    csrf_token = request.form.get("csrf_token") or request.headers.get("X-CSRFToken")
    if not validate_csrf(csrf_token):
        return jsonify({"error": "CSRF validation failed"}), 403

    stats = run_expired_files_cleanup()
    return jsonify({
        "success": True,
        "message": f"Cleanup complete: {stats['found']} expired detected, {stats['deleted_storage']} files purged from storage.",
        "stats": stats
    })

