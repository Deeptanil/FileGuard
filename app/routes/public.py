from flask import Blueprint, render_template, jsonify
from app.security import generate_csrf_token

public_bp = Blueprint("public", __name__)

@public_bp.route("/")
def index():
    """FileGuard homepage / landing page."""
    csrf_token = generate_csrf_token()
    return render_template("index.html", csrf_token=csrf_token)


@public_bp.route("/upload")
def upload_page():
    """Direct file upload interface."""
    csrf_token = generate_csrf_token()
    return render_template("upload.html", csrf_token=csrf_token)


@public_bp.route("/api/csrf-token")
def get_csrf():
    """Retrieve session CSRF token for dynamic asynchronous requests."""
    return jsonify({"csrf_token": generate_csrf_token()})

