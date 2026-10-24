import os
from app import create_app
from app.extensions import db

app = create_app()

if __name__ == "__main__":
    # Ensure tables are created if running directly
    with app.app_context():
        db.create_all()

    port = int(os.getenv("PORT", 5000))
    host = os.getenv("HOST", "127.0.0.1")
    debug = os.getenv("FLASK_DEBUG", "False").lower() in ("true", "1", "t")

    print("=" * 60)
    print("  FILEGUARD — Secure Temporary File Sharing")
    print("  Integrity Monitoring & Digital Forensics System")
    print(f"  Server URL: http://{host}:{port}")
    print(f"  Environment: {os.getenv('FLASK_ENV', 'development')}")
    print("=" * 60)

    app.run(host=host, port=port, debug=debug)

