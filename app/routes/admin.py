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
from app.models import (
    Administrator,
    FileRecord,
    SecurityEvent,
    IntegrityCheck,
    BlockedHash,
    AbuseReport,
    BlockedIp,
    utc_now
)
from app.scanner import dispatch_background_malware_scan
from app.security import admin_required, generate_csrf_token, validate_csrf, hash_token
from app.storage import delete_stored_file
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
    pending_abuse_reports = AbuseReport.query.filter_by(status="pending").count()
    total_blocked_hashes = BlockedHash.query.count()
    total_blocked_ips = BlockedIp.query.count()
    total_malware_flagged = FileRecord.query.filter(
        FileRecord.malware_status.in_(["malicious", "suspicious"])
    ).count()

    recent_blocked_ips = BlockedIp.query.order_by(BlockedIp.blocked_at.desc()).limit(6).all()
    recent_abuse_reports = AbuseReport.query.order_by(AbuseReport.submitted_at.desc()).limit(6).all()

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
        pending_abuse_reports=pending_abuse_reports,
        total_blocked_hashes=total_blocked_hashes,
        total_blocked_ips=total_blocked_ips,
        total_malware_flagged=total_malware_flagged,
        recent_blocked_ips=recent_blocked_ips,
        recent_abuse_reports=recent_abuse_reports,
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

    banned_ips = {b.ip_address for b in BlockedIp.query.all()}

    return render_template(
        "admin_files.html",
        files=files,
        banned_ips=banned_ips,
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


@admin_bp.route("/blocked-ips", methods=["GET"])
@admin_required
def blocked_ips_list():
    """List and manage all blocked client IP addresses and devices."""
    if request.is_json:
        ips = BlockedIp.query.order_by(BlockedIp.blocked_at.desc()).all()
        return jsonify([ip.to_dict() for ip in ips])

    query_str = (request.args.get("q") or "").strip()
    query = BlockedIp.query.order_by(BlockedIp.blocked_at.desc())
    if query_str:
        query = query.filter(
            (BlockedIp.ip_address.ilike(f"%{query_str}%")) |
            (BlockedIp.reason.ilike(f"%{query_str}%")) |
            (BlockedIp.notes.ilike(f"%{query_str}%"))
        )
    blocked_ips = query.all()
    total_blocked = BlockedIp.query.count()
    repeat_violators = BlockedIp.query.filter(BlockedIp.violation_count > 1).count()

    return render_template(
        "admin_blocked_ips.html",
        blocked_ips=blocked_ips,
        total_blocked=total_blocked,
        repeat_violators=repeat_violators,
        search_query=query_str,
        csrf_token=generate_csrf_token()
    )


@admin_bp.route("/blocked-ips/ban", methods=["POST"])
@admin_required
def ban_ip():
    """Block/ban an IP address with optional cascading purge of active uploads."""
    csrf = request.headers.get("X-CSRFToken") or request.form.get("csrf_token")
    if not validate_csrf(csrf):
        if request.is_json:
            return jsonify({"error": "Invalid CSRF token"}), 403
        flash("Invalid security token.", "danger")
        return redirect(request.referrer or url_for("admin.blocked_ips_list"))

    data = request.get_json(silent=True) or request.form
    ip_addr = (data.get("ip_address") or "").strip()
    reason = (data.get("reason") or "ADMIN_BAN").strip()
    notes = (data.get("notes") or "").strip()
    purge_files = data.get("purge_files") in [True, "true", "1", "on"]

    if not ip_addr:
        if request.is_json:
            return jsonify({"error": "IP address is required"}), 400
        flash("IP address is required.", "danger")
        return redirect(request.referrer or url_for("admin.blocked_ips_list"))

    existing = BlockedIp.query.filter_by(ip_address=ip_addr).first()
    if existing:
        existing.reason = reason
        if notes:
            existing.notes = f"{existing.notes}\n{notes}".strip() if existing.notes else notes
        existing.violation_count += 1
    else:
        new_ban = BlockedIp(
            ip_address=ip_addr,
            reason=reason,
            notes=notes,
            violation_count=1,
            blocked_at=utc_now()
        )
        db.session.add(new_ban)

    purged_count = 0
    if purge_files:
        user_files = FileRecord.query.filter_by(uploader_ip=ip_addr, status="active").all()
        for f in user_files:
            try:
                delete_stored_file(f.storage_id)
            except Exception:
                pass
            f.status = "deleted"
            purged_count += 1
            if not BlockedHash.query.filter_by(sha256_hash=f.sha256_reference).first():
                db.session.add(BlockedHash(
                    sha256_hash=f.sha256_reference,
                    reason=f"IP_BAN_{reason}",
                    notes=f"Purged on ban of IP {ip_addr}"
                ))

    db.session.commit()

    log_security_event(
        event_type="ADMIN_IP_BANNED",
        outcome="SUCCESS",
        severity="HIGH",
        ip_address=ip_addr,
        details=f"Admin banned IP {ip_addr}. Reason: {reason}. Purged {purged_count} active files."
    )

    if request.is_json:
        return jsonify({"success": True, "ip_address": ip_addr, "purged_files": purged_count}), 200
    flash(f"IP address {ip_addr} has been blocked ({purged_count} files purged).", "success")
    return redirect(request.referrer or url_for("admin.blocked_ips_list"))


@admin_bp.route("/blocked-ips/unban", methods=["POST"])
@admin_required
def unban_ip():
    """Unblock/unban an IP address, restoring their platform access."""
    csrf = request.headers.get("X-CSRFToken") or request.form.get("csrf_token")
    if not validate_csrf(csrf):
        if request.is_json:
            return jsonify({"error": "Invalid CSRF token"}), 403
        flash("Invalid security token.", "danger")
        return redirect(request.referrer or url_for("admin.blocked_ips_list"))

    data = request.get_json(silent=True) or request.form
    ip_addr = (data.get("ip_address") or "").strip()

    if not ip_addr:
        if request.is_json:
            return jsonify({"error": "IP address is required"}), 400
        flash("IP address is required.", "danger")
        return redirect(request.referrer or url_for("admin.blocked_ips_list"))

    entry = BlockedIp.query.filter_by(ip_address=ip_addr).first()
    if entry:
        db.session.delete(entry)
        db.session.commit()
        log_security_event(
            event_type="ADMIN_IP_UNBANNED",
            outcome="SUCCESS",
            severity="MEDIUM",
            ip_address=ip_addr,
            details=f"Admin lifted ban on IP {ip_addr}"
        )
        if request.is_json:
            return jsonify({"success": True, "ip_address": ip_addr}), 200
        flash(f"Ban lifted for IP {ip_addr}. Platform access restored.", "success")
    else:
        if request.is_json:
            return jsonify({"error": "IP address was not banned"}), 404
        flash(f"IP {ip_addr} was not on the ban list.", "warning")

    return redirect(request.referrer or url_for("admin.blocked_ips_list"))


@admin_bp.route("/abuse-reports", methods=["GET"])
@admin_required
def abuse_reports_list():
    """List and manage all abuse reports with uploader telemetry."""
    if request.is_json or request.headers.get("Accept") == "application/json":
        reports = AbuseReport.query.order_by(AbuseReport.submitted_at.desc()).all()
        return jsonify([r.to_dict() for r in reports])

    status_filter = request.args.get("status")
    category_filter = request.args.get("category")

    query = AbuseReport.query.order_by(AbuseReport.submitted_at.desc())
    if status_filter and status_filter != "all":
        query = query.filter_by(status=status_filter)
    if category_filter and category_filter != "all":
        query = query.filter_by(category=category_filter)

    reports = query.limit(100).all()
    banned_ips = {b.ip_address for b in BlockedIp.query.all()}

    import re
    report_items = []
    for r in reports:
        target_file = None
        uploader_ip = None
        if r.file_record_id:
            target_file = FileRecord.query.get(r.file_record_id)
        if not target_file:
            match = re.search(r"([0-9]{4}-[0-9]{4})", r.token_or_url)
            if match:
                t_hash = hash_token(match.group(1))
                target_file = FileRecord.query.filter_by(share_token_hash=t_hash).first()
        if target_file:
            uploader_ip = target_file.uploader_ip

        report_items.append({
            "report": r,
            "target_file": target_file,
            "uploader_ip": uploader_ip,
            "is_uploader_banned": bool(uploader_ip and uploader_ip in banned_ips)
        })

    pending_count = AbuseReport.query.filter_by(status="pending").count()
    resolved_count = AbuseReport.query.filter_by(status="resolved").count()
    rejected_count = AbuseReport.query.filter_by(status="rejected").count()

    return render_template(
        "admin_abuse_reports.html",
        report_items=report_items,
        pending_count=pending_count,
        resolved_count=resolved_count,
        rejected_count=rejected_count,
        current_status=status_filter or "all",
        current_category=category_filter or "all",
        csrf_token=generate_csrf_token()
    )


@admin_bp.route("/abuse-reports/<int:report_id>/reject", methods=["POST"])
@admin_required
def reject_abuse_report(report_id: int):
    """Reject an invalid or unsubstantiated abuse report."""
    csrf = request.headers.get("X-CSRFToken") or request.form.get("csrf_token")
    if not validate_csrf(csrf):
        if request.is_json:
            return jsonify({"error": "Invalid CSRF token"}), 403
        flash("Invalid security token.", "danger")
        return redirect(request.referrer or url_for("admin.abuse_reports_list"))

    report = AbuseReport.query.get_or_404(report_id)
    notes = request.form.get("notes") or (request.json.get("notes") if request.is_json else "")
    report.status = "rejected"
    report.resolved_at = utc_now()
    report.admin_notes = f"Rejected: {notes}".strip()
    db.session.commit()

    log_security_event(
        event_type="ADMIN_ABUSE_REPORT_REJECTED",
        outcome="SUCCESS",
        severity="INFO",
        details=f"Admin rejected Abuse Report #{report.id} ({report.category})"
    )

    if request.is_json:
        return jsonify({"success": True, "status": "rejected"}), 200
    flash(f"Abuse Report #{report.id} rejected.", "info")
    return redirect(request.referrer or url_for("admin.abuse_reports_list"))


@admin_bp.route("/abuse-reports/<int:report_id>/resolve", methods=["POST"])
@admin_required
def resolve_abuse_report(report_id: int):
    """Resolve an abuse report with optional instant purge & hash blocklisting."""
    csrf = request.headers.get("X-CSRFToken") or request.form.get("csrf_token")
    if not validate_csrf(csrf):
        if request.is_json:
            return jsonify({"error": "Invalid CSRF token"}), 403
        flash("Invalid security token.", "danger")
        return redirect(request.referrer or url_for("admin.abuse_reports_list"))

    report = AbuseReport.query.get_or_404(report_id)
    action = request.form.get("action") or (request.json.get("action") if request.is_json else "resolve")
    admin_notes = request.form.get("notes") or (request.json.get("notes") if request.is_json else "")

    report.status = "resolved"
    report.resolved_at = utc_now()
    report.admin_notes = admin_notes

    if action == "purge_and_block":
        import re
        target = report.token_or_url.strip()
        match = re.search(r"([0-9]{4}-[0-9]{4})", target)
        token = match.group(1) if match else target

        t_hash = hash_token(token)
        file_rec = FileRecord.query.filter_by(share_token_hash=t_hash).first()
        if not file_rec and report.file_record_id:
            file_rec = FileRecord.query.get(report.file_record_id)

        if file_rec:
            existing_block = BlockedHash.query.filter_by(sha256_hash=file_rec.sha256_reference).first()
            if not existing_block:
                block_entry = BlockedHash(
                    sha256_hash=file_rec.sha256_reference,
                    reason=f"ABUSE_{report.category.upper()}",
                    notes=f"Purged via Abuse Report #{report.id}: {admin_notes}"
                )
                db.session.add(block_entry)

            delete_stored_file(file_rec.storage_id)
            file_rec.status = "deleted"

            log_security_event(
                event_type="ADMIN_ABUSE_TAKEDOWN",
                outcome="SUCCESS",
                severity="HIGH",
                details=f"Admin purged file {file_rec.storage_id} and quarantined hash {file_rec.sha256_reference[:16]}... for Abuse Report #{report.id}"
            )

    db.session.commit()
    if request.is_json or request.headers.get("X-CSRFToken") or request.headers.get("Accept") == "application/json":
        return jsonify({"success": True, "status": report.status})
    flash(f"Abuse Report #{report.id} resolved successfully.", "success")
    return redirect(request.referrer or url_for("admin.abuse_reports_list"))


@admin_bp.route("/malware", methods=["GET"])
@admin_required
def malware_dashboard():
    """Monitor VirusTotal scan results, engine consensus, and threat detections."""
    status_filter = request.args.get("status")
    query = FileRecord.query.order_by(FileRecord.uploaded_at.desc())
    if status_filter and status_filter != "all":
        query = query.filter_by(malware_status=status_filter)

    files = query.limit(100).all()
    banned_ips = {b.ip_address for b in BlockedIp.query.all()}

    total_scanned = FileRecord.query.filter(FileRecord.malware_status.isnot(None)).count()
    malicious_count = FileRecord.query.filter_by(malware_status="malicious").count()
    suspicious_count = FileRecord.query.filter_by(malware_status="suspicious").count()
    clean_count = FileRecord.query.filter_by(malware_status="clean").count()
    pending_count = FileRecord.query.filter(FileRecord.malware_status.in_(["pending", "scanning"])).count()

    return render_template(
        "admin_malware.html",
        files=files,
        banned_ips=banned_ips,
        total_scanned=total_scanned,
        malicious_count=malicious_count,
        suspicious_count=suspicious_count,
        clean_count=clean_count,
        pending_count=pending_count,
        current_status=status_filter or "all",
        csrf_token=generate_csrf_token()
    )


@admin_bp.route("/files/<int:file_id>/rescan", methods=["POST"])
@admin_required
def rescan_file(file_id: int):
    """Trigger an immediate VirusTotal background scan for a file."""
    csrf = request.headers.get("X-CSRFToken") or request.form.get("csrf_token")
    if not validate_csrf(csrf):
        if request.is_json:
            return jsonify({"error": "Invalid CSRF token"}), 403
        flash("Invalid security token.", "danger")
        return redirect(request.referrer or url_for("admin.malware_dashboard"))

    file_rec = FileRecord.query.get_or_404(file_id)
    file_rec.malware_status = "scanning"
    db.session.commit()

    from flask import current_app
    dispatch_background_malware_scan(current_app._get_current_object(), file_rec.id)

    if request.is_json:
        return jsonify({"success": True, "message": f"VirusTotal scan initiated for file #{file_id}."}), 200
    flash(f"VirusTotal scan triggered for '{file_rec.original_filename}'. Results will update in background.", "info")
    return redirect(request.referrer or url_for("admin.malware_dashboard"))


@admin_bp.route("/user/<path:ip_address>", methods=["GET"])
@admin_required
def user_profile(ip_address: str):
    """360-degree forensic profile for a client IP/device: files, VirusTotal scans, abuse reports, and ban status."""
    ip_address = ip_address.strip()
    blocked_entry = BlockedIp.query.filter_by(ip_address=ip_address).first()
    is_banned = bool(blocked_entry)

    # All files uploaded by this IP
    files = FileRecord.query.filter_by(uploader_ip=ip_address).order_by(FileRecord.uploaded_at.desc()).all()
    file_ids = [f.id for f in files]

    # All abuse reports submitted against files from this IP
    abuse_reports = []
    if file_ids:
        abuse_reports = AbuseReport.query.filter(
            (AbuseReport.file_record_id.in_(file_ids)) |
            (AbuseReport.reporter_ip == ip_address)
        ).order_by(AbuseReport.submitted_at.desc()).all()

    # Security events
    events = SecurityEvent.query.filter_by(ip_address=ip_address).order_by(SecurityEvent.timestamp.desc()).limit(25).all()

    total_uploads = len(files)
    active_files = sum(1 for f in files if f.status == "active")
    total_bytes = sum(f.file_size for f in files)
    malicious_files = sum(1 for f in files if f.malware_status in ["malicious", "suspicious"])

    return render_template(
        "admin_user_profile.html",
        ip_address=ip_address,
        is_banned=is_banned,
        blocked_entry=blocked_entry,
        files=files,
        abuse_reports=abuse_reports,
        events=events,
        total_uploads=total_uploads,
        active_files=active_files,
        total_mb=round(total_bytes / (1024 * 1024), 2),
        malicious_files=malicious_files,
        csrf_token=generate_csrf_token()
    )


@admin_bp.route("/blocked-hashes", methods=["GET", "POST"])
@admin_required
def manage_blocked_hashes():
    """Inspect or manually quarantine a SHA-256 file hash."""
    if request.method == "POST":
        csrf = request.headers.get("X-CSRFToken") or request.form.get("csrf_token")
        if not validate_csrf(csrf):
            return jsonify({"error": "Invalid CSRF token"}), 403

        data = request.get_json(silent=True) or request.form
        sha256_val = (data.get("sha256") or "").strip().lower()
        reason = (data.get("reason") or "ADMIN_MANUAL").strip()
        notes = (data.get("notes") or "").strip()

        if len(sha256_val) != 64:
            return jsonify({"error": "Invalid SHA-256 hash length (must be 64 hex characters)"}), 400

        existing = BlockedHash.query.filter_by(sha256_hash=sha256_val).first()
        if existing:
            return jsonify({"error": "Hash is already in quarantine blocklist"}), 409

        new_block = BlockedHash(sha256_hash=sha256_val, reason=reason, notes=notes)
        db.session.add(new_block)
        db.session.commit()

        log_security_event(
            event_type="ADMIN_HASH_BLOCKED",
            outcome="SUCCESS",
            severity="HIGH",
            details=f"SHA-256 hash {sha256_val[:16]}... quarantined (Reason: {reason})"
        )
        return jsonify({"success": True, "entry": new_block.to_dict()}), 201

    blocks = BlockedHash.query.order_by(BlockedHash.blocked_at.desc()).all()
    return jsonify([b.to_dict() for b in blocks])


