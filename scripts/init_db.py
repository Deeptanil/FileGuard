import os
import sys
from pathlib import Path
from werkzeug.security import generate_password_hash

# Add parent directory to sys.path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app import create_app
from app.extensions import db
from app.models import Administrator

def init_database():
    """Initialize database tables and create administrative user."""
    app = create_app()
    with app.app_context():
        print("[*] Creating database tables...")
        db.create_all()

        username = os.getenv("ADMIN_USERNAME", "admin")
        password = os.getenv("ADMIN_PASSWORD", "FileGuard@Sec2026!")

        admin = Administrator.query.filter_by(username=username).first()
        if not admin:
            print(f"[*] Creating default administrator '{username}'...")
            admin = Administrator(
                username=username,
                password_hash=generate_password_hash(password, method="scrypt"),
                active_status=True
            )
            db.session.add(admin)
            db.session.commit()
            print(f"[+] Administrator account '{username}' successfully created.")
        else:
            print(f"[*] Administrator '{username}' already exists. Updating credentials...")
            admin.password_hash = generate_password_hash(password, method="scrypt")
            admin.active_status = True
            db.session.commit()
            print(f"[+] Administrator account '{username}' credentials updated.")

        print("[+] FileGuard database initialization complete.")

if __name__ == "__main__":
    init_database()

