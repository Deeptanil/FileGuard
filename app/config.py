import os
from pathlib import Path
from dotenv import load_dotenv

# Load .env if present
base_dir = Path(__file__).resolve().parent.parent
load_dotenv(base_dir / ".env")

class Config:
    """Base application configuration."""
    SECRET_KEY = os.getenv("SECRET_KEY", "insecure-default-change-in-production")
    
    # Base and storage paths
    BASE_DIR = base_dir
    STORAGE_DIR = Path(os.getenv("STORAGE_DIR", str(base_dir / "storage"))).resolve()
    INSTANCE_DIR = (base_dir / "instance").resolve()
    
    # Database URI (Auto-normalizes postgres:// and postgresql:// to postgresql+psycopg2:// for SQLAlchemy)
    _raw_db_uri = os.getenv("DATABASE_URI", f"sqlite:///{INSTANCE_DIR / 'fileguard.db'}")
    if _raw_db_uri:
        if _raw_db_uri.startswith("postgres://"):
            _raw_db_uri = _raw_db_uri.replace("postgres://", "postgresql+psycopg2://", 1)
        elif _raw_db_uri.startswith("postgresql://") and not _raw_db_uri.startswith("postgresql+"):
            _raw_db_uri = _raw_db_uri.replace("postgresql://", "postgresql+psycopg2://", 1)
    
    SQLALCHEMY_DATABASE_URI = _raw_db_uri
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    
    # Canonical sharing URL base
    CANONICAL_URL = os.getenv("CANONICAL_URL", "https://files.deeptanil.in").rstrip("/")
    
    # File upload controls
    MAX_CONTENT_LENGTH_MB = int(os.getenv("MAX_CONTENT_LENGTH_MB", "100"))
    MAX_CONTENT_LENGTH = MAX_CONTENT_LENGTH_MB * 1024 * 1024  # bytes
    
    ALLOWED_EXTENSIONS = set(
        ext.strip().lower().lstrip(".")
        for ext in os.getenv(
            "ALLOWED_EXTENSIONS",
            "pdf,png,jpg,jpeg,txt,csv,docx,xlsx,pptx,zip,mp4,mov,mp3,m4a,webm"
        ).split(",")
        if ext.strip()
    )
    
    # Security & retention policy
    EXPIRATION_HOURS = int(os.getenv("EXPIRATION_HOURS", "12"))
    IP_QUOTA_HOURS = int(os.getenv("IP_QUOTA_HOURS", "12"))
    IP_QUOTA_MB = int(os.getenv("IP_QUOTA_MB", "100"))
    
    # Session cookie hardening
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = "Lax"
    SESSION_COOKIE_SECURE = os.getenv("FLASK_ENV") == "production"
    PERMANENT_SESSION_LIFETIME = 3600  # 1 hour admin session
    
    # Rate Limiting defaults
    RATELIMIT_DEFAULT = os.getenv("RATELIMIT_DEFAULT", "200 per minute")
    RATELIMIT_STORAGE_URI = os.getenv("RATELIMIT_STORAGE_URI", "memory://")

    # Antivirus / Malware Detection
    VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY", "")
    VIRUSTOTAL_MIN_POSITIVES = int(os.getenv("VIRUSTOTAL_MIN_POSITIVES", "4"))

    # Storage Backend: 'local' (default) or 's3' (Backblaze B2, Cloudflare R2, AWS)
    STORAGE_BACKEND = os.getenv("STORAGE_BACKEND", "local").lower()
    S3_BUCKET_NAME = os.getenv("S3_BUCKET_NAME", "")
    S3_ENDPOINT_URL = os.getenv("S3_ENDPOINT_URL", "")
    AWS_ACCESS_KEY_ID = os.getenv("AWS_ACCESS_KEY_ID", "")
    AWS_SECRET_ACCESS_KEY = os.getenv("AWS_SECRET_ACCESS_KEY", "")
    AWS_DEFAULT_REGION = os.getenv("AWS_DEFAULT_REGION", "us-east-1")


class DevelopmentConfig(Config):
    DEBUG = True


class TestingConfig(Config):
    TESTING = True
    DEBUG = False
    SQLALCHEMY_DATABASE_URI = "sqlite:///:memory:"
    STORAGE_DIR = base_dir / "storage_test"
    RATELIMIT_ENABLED = False
    WTF_CSRF_ENABLED = False
    STORAGE_BACKEND = "local"


class ProductionConfig(Config):
    DEBUG = False
    SESSION_COOKIE_SECURE = True

