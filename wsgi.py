import os
import sys
from pathlib import Path

# Add project root to sys.path
BASE_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(BASE_DIR))

from app import create_app
from app.extensions import db

# Initialize application factory
app = create_app()

# Auto-create tables if running in WSGI container
with app.app_context():
    db.create_all()

if __name__ == "__main__":
    app.run()

