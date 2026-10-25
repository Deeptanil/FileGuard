import os
from pathlib import Path
from flask import Flask, render_template, jsonify, request
from app.config import Config, DevelopmentConfig, ProductionConfig, TestingConfig
from app.extensions import db, limiter

def create_app(config_class=None):
    """Application factory for FileGuard."""
    app = Flask(__name__, instance_relative_config=True)

    # Determine configuration environment
    if config_class is None:
        env = os.getenv("FLASK_ENV", "development").lower()
        if env == "production":
            config_class = ProductionConfig
        elif env == "testing":
            config_class = TestingConfig
        else:
            config_class = DevelopmentConfig

    app.config.from_object(config_class)

    # Ensure storage and instance directories exist
    os.makedirs(app.config["STORAGE_DIR"], exist_ok=True)
    os.makedirs(app.instance_path, exist_ok=True)

    # Initialize extensions
    db.init_app(app)
    limiter.init_app(app)

    # Ensure database schema is migrated with new columns
    with app.app_context():
        try:
            db.create_all()
            # Perform safe alter table column additions for SQLite/Postgres
            from sqlalchemy import inspect, text
            inspector = inspect(db.engine)
            if "file_records" in inspector.get_table_names():
                existing_cols = {c["name"] for c in inspector.get_columns("file_records")}
                with db.engine.connect() as conn:
                    if "display_title" not in existing_cols:
                        conn.execute(text("ALTER TABLE file_records ADD COLUMN display_title VARCHAR(255)"))
                    if "password_hash" not in existing_cols:
                        conn.execute(text("ALTER TABLE file_records ADD COLUMN password_hash VARCHAR(255)"))
                    if "is_e2ee" not in existing_cols:
                        conn.execute(text("ALTER TABLE file_records ADD COLUMN is_e2ee BOOLEAN DEFAULT 0"))
                    if "is_encrypted_at_rest" not in existing_cols:
                        conn.execute(text("ALTER TABLE file_records ADD COLUMN is_encrypted_at_rest BOOLEAN DEFAULT 1"))
                    conn.commit()
        except Exception:
            pass

    # Register blueprints
    from app.routes.public import public_bp
    from app.routes.uploads import uploads_bp
    from app.routes.downloads import downloads_bp
    from app.routes.admin import admin_bp
    from app.routes.forensics import forensics_bp

    app.register_blueprint(public_bp)
    app.register_blueprint(uploads_bp)
    app.register_blueprint(downloads_bp)
    app.register_blueprint(admin_bp)
    app.register_blueprint(forensics_bp)

    # Register HTTP error handlers
    register_error_handlers(app)

    # Template context processor for security tokens
    @app.context_processor
    def inject_security_context():
        from app.security import generate_csrf_token
        return {"csrf_token": generate_csrf_token()}

    # Register global security response headers
    @app.after_request
    def set_security_headers(response):
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "SAMEORIGIN"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        
        # Defense-in-depth CSP policy
        csp = (
            "default-src 'self'; "
            "script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
            "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
            "font-src 'self' https://fonts.gstatic.com; "
            "img-src 'self' data:; "
            "connect-src 'self'"
        )
        response.headers["Content-Security-Policy"] = csp
        return response

    return app


def register_error_handlers(app: Flask):
    """Register uniform, security-hardened error handlers."""
    
    @app.errorhandler(400)
    def bad_request(e):
        if request.is_json:
            return jsonify({"error": "Bad request", "details": str(e.description if hasattr(e, 'description') else e)}), 400
        return render_template("errors/400.html", error=e), 400

    @app.errorhandler(403)
    def forbidden(e):
        if request.is_json:
            return jsonify({"error": "Forbidden", "message": "Access denied"}), 403
        return render_template("errors/403.html", error=e), 403

    @app.errorhandler(404)
    def not_found(e):
        if request.is_json:
            return jsonify({"error": "Resource not found"}), 404
        return render_template("errors/404.html"), 404

    @app.errorhandler(410)
    def gone(e):
        if request.is_json:
            return jsonify({"error": "File expired", "message": "The file has exceeded its 12-hour retention period"}), 410
        return render_template("expired.html"), 410

    @app.errorhandler(413)
    def file_too_large(e):
        max_mb = app.config.get("MAX_CONTENT_LENGTH_MB", 100)
        msg = f"File exceeds maximum upload limit of {max_mb} MB"
        if request.is_json:
            return jsonify({"error": msg}), 413
        return render_template("errors/413.html", max_mb=max_mb), 413

    @app.errorhandler(429)
    def ratelimit_handler(e):
        from app.audit import log_security_event, EVENT_RATE_LIMIT_EXCEEDED
        log_security_event(
            event_type=EVENT_RATE_LIMIT_EXCEEDED,
            outcome="BLOCKED",
            severity="MEDIUM",
            details=f"Rate limit exceeded on path: {request.path}"
        )
        if request.is_json:
            return jsonify({"error": "Rate limit exceeded. Please wait before retrying."}), 429
        return render_template("errors/429.html"), 429

    @app.errorhandler(500)
    def internal_error(e):
        if request.is_json:
            return jsonify({"error": "Internal server error"}), 500
        return render_template("errors/500.html"), 500

