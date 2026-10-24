import os
import sys
from pathlib import Path
from werkzeug.security import generate_password_hash
from sqlalchemy import text

# Add parent directory to sys.path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app import create_app
from app.extensions import db
from app.models import Administrator

def init_database():
    """Initialize database tables, run migrations, and create administrative user."""
    app = create_app()
    with app.app_context():
        print("[*] Creating database tables...")
        db.create_all()

        print("[*] Running schema migrations...")
        try:
            with db.engine.connect() as conn:
                dialect_name = db.engine.dialect.name
                if dialect_name == "postgresql":
                    conn.execute(text("ALTER TABLE file_records ADD COLUMN IF NOT EXISTS uploader_ip VARCHAR(64);"))
                    conn.execute(text("ALTER TABLE file_records ADD COLUMN IF NOT EXISTS is_bundle BOOLEAN DEFAULT FALSE;"))
                    conn.execute(text("CREATE INDEX IF NOT EXISTS ix_file_records_uploader_ip ON file_records (uploader_ip);"))
                    conn.commit()
                elif dialect_name == "sqlite":
                    cols = [row[1] for row in conn.execute(text("PRAGMA table_info(file_records);")).fetchall()]
                    if "uploader_ip" not in cols:
                        conn.execute(text("ALTER TABLE file_records ADD COLUMN uploader_ip VARCHAR(64);"))
                    if "is_bundle" not in cols:
                        conn.execute(text("ALTER TABLE file_records ADD COLUMN is_bundle BOOLEAN DEFAULT 0;"))
                    conn.commit()
            print("[+] Schema migrations applied successfully.")
        except Exception as e:
            print(f"[!] Warning during schema migration: {e}")

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

