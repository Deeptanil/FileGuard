from flask import Blueprint, render_template, jsonify
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
    """Direct file upload interface."""
    try:
        run_expired_files_cleanup()
    except Exception:
        pass
    csrf_token = generate_csrf_token()
    return render_template("upload.html", csrf_token=csrf_token)


@public_bp.route("/history")
def history_page():
    """User upload and viewed files activity/history interface."""
    try:
        run_expired_files_cleanup()
    except Exception:
        pass
    csrf_token = generate_csrf_token()
    return render_template("history.html", csrf_token=csrf_token)



@public_bp.route("/api/csrf-token")
def get_csrf():
    """Retrieve session CSRF token for dynamic asynchronous requests."""
    return jsonify({"csrf_token": generate_csrf_token()})

