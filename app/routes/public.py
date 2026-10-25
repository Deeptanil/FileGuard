import os
from flask import Blueprint, render_template, jsonify, send_from_directory, current_app, redirect, url_for, request
from app.extensions import db
from app.models import AbuseReport
from app.security import generate_csrf_token, validate_csrf, get_client_ip
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

        # Persist abuse submission
        report = AbuseReport(
            token_or_url=token_or_url[:255],
            reporter_email=reporter_email[:255] if reporter_email else None,
            category=category[:64],
            description=description,
            status="pending"
        )
        db.session.add(report)
        db.session.commit()

        client_ip = get_client_ip()
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


