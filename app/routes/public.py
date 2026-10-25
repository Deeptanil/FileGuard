import os
import re
from flask import Blueprint, render_template, jsonify, send_from_directory, current_app, redirect, url_for, request
from app.extensions import db
from app.models import AbuseReport, FileRecord, BlockedHash, BlockedIp
from app.security import generate_csrf_token, validate_csrf, get_client_ip, hash_token
from app.storage import delete_stored_file
from app.audit import log_security_event
from app.cleanup import run_expired_files_cleanup

public_bp = Blueprint("public", __name__)

@public_bp.route("/")
def index():
    """FileGuard homepage / landing page."""
    try:
        run_expired_files_cleanup()
    except Exception:
        pass
    csrf_token = generate_csrf_token()
    return render_template("index.html", csrf_token=csrf_token)


@public_bp.route("/upload")
def upload_page():
    """Redirect to the home page upload section."""
    return redirect(url_for("public.index", _anchor="upload-section"))


@public_bp.route("/history")
def history_page():
    """User upload and viewed files activity/history interface."""
    try:
        run_expired_files_cleanup()
    except Exception:
        pass
    csrf_token = generate_csrf_token()
    return render_template("history.html", csrf_token=csrf_token)


@public_bp.route("/terms")
def terms():
    """Terms of Service legal documentation."""
    csrf_token = generate_csrf_token()
    return render_template("terms.html", csrf_token=csrf_token)


@public_bp.route("/privacy")
def privacy():
    """Data Privacy Policy documentation."""
    csrf_token = generate_csrf_token()
    return render_template("privacy.html", csrf_token=csrf_token)


@public_bp.route("/cookies")
def cookie_policy():
    """Cookie & Local Storage Policy."""
    csrf_token = generate_csrf_token()
    return render_template("cookie_policy.html", csrf_token=csrf_token)


@public_bp.route("/dmca")
def dmca():
    """DMCA & Content Abuse Policy."""
    csrf_token = generate_csrf_token()
    return render_template("dmca.html", csrf_token=csrf_token)


@public_bp.route("/report", methods=["GET", "POST"])
def report_abuse():
    """Public content abuse & DMCA takedown intake portal."""
    if request.method == "POST":
        csrf = request.form.get("csrf_token") or request.headers.get("X-CSRFToken")
        if not validate_csrf(csrf):
            return jsonify({"error": "Invalid or expired CSRF token"}), 403

        token_or_url = (request.form.get("token_or_url") or "").strip()
        reporter_email = (request.form.get("reporter_email") or "").strip() or None
        category = (request.form.get("category") or "other").strip().lower()
        description = (request.form.get("description") or "").strip()

        if not token_or_url or not description:
            if request.is_json or request.headers.get("Accept") == "application/json":
                return jsonify({"error": "Token/URL and description are required"}), 400
            csrf_token = generate_csrf_token()
            return render_template(
                "report_abuse.html",
                csrf_token=csrf_token,
                error="Please provide both the target sharing token/URL and a description of the abuse.",
                prefill_token=token_or_url,
                prefill_category=category
            ), 400

        client_ip = get_client_ip()
        match = re.search(r"([0-9]{4}-[0-9]{4})", token_or_url)
        extracted_token = match.group(1) if match else token_or_url.strip()

        token_h = hash_token(extracted_token)
        file_rec = FileRecord.query.filter_by(share_token_hash=token_h).first()
        file_rec_id = file_rec.id if file_rec else None

        # Persist abuse submission
        report = AbuseReport(
            token_or_url=token_or_url[:255],
            reporter_email=reporter_email[:255] if reporter_email else None,
            category=category[:64],
            description=description,
            status="pending",
            file_record_id=file_rec_id,
            reporter_ip=client_ip
        )
        db.session.add(report)
        db.session.commit()

        # Check automated consensus takedown: more than 2 reports (> 2, i.e. >= 3)
        if file_rec and file_rec.status == "active":
            matching_reports_count = AbuseReport.query.filter(
                (AbuseReport.file_record_id == file_rec.id) | (AbuseReport.token_or_url.like(f"%{extracted_token}%"))
            ).count()

            if matching_reports_count > 2:
                # 1. Automated immediate takedown of the reported file
                delete_stored_file(file_rec.storage_id)
                file_rec.status = "deleted"
                if not BlockedHash.query.filter_by(sha256_hash=file_rec.sha256_reference).first():
                    db.session.add(BlockedHash(
                        sha256_hash=file_rec.sha256_reference,
                        reason=f"AUTO_TAKEDOWN_{category.upper()}",
                        notes=f"Automated consensus purge ({matching_reports_count} reports)"
                    ))

                log_security_event(
                    event_type="AUTO_ABUSE_TAKEDOWN",
                    outcome="SUCCESS",
                    severity="CRITICAL",
                    file_record_id=file_rec.id,
                    details=f"File {file_rec.original_filename} auto-purged following {matching_reports_count} abuse reports."
                )

                # 2. Cascade takedown: purge any active files from the same uploader IP
                uploader_ip = file_rec.uploader_ip
                if uploader_ip:
                    sibling_files = FileRecord.query.filter(
                        FileRecord.uploader_ip == uploader_ip,
                        FileRecord.status == "active",
                        FileRecord.id != file_rec.id
                    ).all()
                    for sib in sibling_files:
                        delete_stored_file(sib.storage_id)
                        sib.status = "deleted"
                        if not BlockedHash.query.filter_by(sha256_hash=sib.sha256_reference).first():
                            db.session.add(BlockedHash(
                                sha256_hash=sib.sha256_reference,
                                reason=f"CASCADE_TAKEDOWN_{category.upper()}",
                                notes=f"Cascaded takedown from reported sibling {file_rec.storage_id} (IP: {uploader_ip})"
                            ))

                    # 3. Automated IP ban for repeat offenders (>= 2 deleted/purged files from this IP)
                    total_purged_for_ip = FileRecord.query.filter(
                        FileRecord.uploader_ip == uploader_ip,
                        FileRecord.status == "deleted"
                    ).count()

                    if total_purged_for_ip >= 2:
                        ip_block = BlockedIp.query.filter_by(ip_address=uploader_ip).first()
                        if not ip_block:
                            ip_block = BlockedIp(
                                ip_address=uploader_ip,
                                reason="REPEATED_ABUSE_TAKEDOWNS",
                                violation_count=total_purged_for_ip,
                                notes=f"Automated ban: {total_purged_for_ip} files purged following verified abuse reports."
                            )
                            db.session.add(ip_block)
                        else:
                            ip_block.violation_count = total_purged_for_ip

                        log_security_event(
                            event_type="IP_AUTO_BANNED",
                            outcome="BLOCKED",
                            severity="CRITICAL",
                            ip_address=uploader_ip,
                            details=f"IP {uploader_ip} permanently banned after {total_purged_for_ip} files purged for policy violations."
                        )

                db.session.commit()

        log_security_event(
            event_type="ABUSE_REPORT_SUBMITTED",
            outcome="SUCCESS",
            severity="HIGH" if category in ["csam", "malware"] else "MEDIUM",
            ip_address=client_ip,
            details=f"Abuse report filed for target: {token_or_url[:64]} (Category: {category})"
        )

        if request.is_json or request.headers.get("Accept") == "application/json":
            return jsonify({"success": True, "message": "Report received successfully.", "report_id": report.id}), 201

        csrf_token = generate_csrf_token()
        return render_template(
            "report_abuse.html",
            csrf_token=csrf_token,
            success=True,
            report_id=report.id
        )

    prefill_token = request.args.get("token", "").strip()
    csrf_token = generate_csrf_token()
    return render_template("report_abuse.html", csrf_token=csrf_token, prefill_token=prefill_token)


@public_bp.route("/abuse")
def abuse_redirect():
    """Alias redirect to the abuse reporting portal."""
    token = request.args.get("token", "")
    return redirect(url_for("public.report_abuse", token=token) if token else url_for("public.report_abuse"))



@public_bp.route("/api/csrf-token")
def get_csrf():
    """Retrieve session CSRF token for dynamic asynchronous requests."""
    return jsonify({"csrf_token": generate_csrf_token()})


@public_bp.route("/robots.txt")
def robots_txt():
    """Serve robots.txt for search engine and AI web crawlers."""
    return send_from_directory(os.path.join(current_app.root_path, "static"), "robots.txt", mimetype="text/plain")


@public_bp.route("/sitemap.xml")
def sitemap_xml():
    """Serve sitemap.xml for Google, Bing, and indexers."""
    return send_from_directory(os.path.join(current_app.root_path, "static"), "sitemap.xml", mimetype="application/xml")


@public_bp.route("/llms.txt")
def llms_txt():
    """Serve llms.txt manifest for AI agents, Perplexity, ChatGPT, Claude, and Gemini."""
    return send_from_directory(os.path.join(current_app.root_path, "static"), "llms.txt", mimetype="text/markdown")


