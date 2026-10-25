import os
from flask import Blueprint, render_template, jsonify, send_from_directory, current_app, redirect, url_for
from app.security import generate_csrf_token
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


