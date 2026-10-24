import os
import hmac
import hashlib
import secrets
import mimetypes
from pathlib import Path
from functools import wraps
from flask import session, request, abort, redirect, url_for, current_app
from werkzeug.utils import secure_filename

# Map of standard safe extensions to known MIME signatures/types
KNOWN_MIME_TYPES = {
    "pdf": "application/pdf",
    "png": "image/png",
    "jpg": "image/jpeg",
    "jpeg": "image/jpeg",
    "txt": "text/plain",
    "csv": "text/csv",
    "docx": "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
    "xlsx": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
    "pptx": "application/vnd.openxmlformats-officedocument.presentationml.presentation",
    "zip": "application/zip",
    "mp4": "video/mp4",
    "mov": "video/quicktime",
    "webm": "video/webm",
    "mp3": "audio/mpeg",
    "m4a": "audio/mp4",
}

# Magic bytes for binary file header sniffing (first 4-8 bytes)
MAGIC_SIGNATURES = {
    "pdf": [b"%PDF"],
    "png": [b"\x89PNG\r\n\x1a\n"],
    "jpg": [b"\xff\xd8\xff"],
    "jpeg": [b"\xff\xd8\xff"],
    "zip": [b"PK\x03\x04", b"PK\x05\x06"],
    "docx": [b"PK\x03\x04"],
    "xlsx": [b"PK\x03\x04"],
    "pptx": [b"PK\x03\x04"],
    "mp4": [b"ftyp", b"\x00\x00\x00"],
    "webm": [b"\x1a\x45\xdf\xa3"],
    "mp3": [b"ID3", b"\xff\xfb", b"\xff\xf3", b"\xff\xf2"],
}


def get_client_ip():
    """Retrieve sanitized client IP address, handling proxy headers carefully."""
    if request.headers.get("X-Forwarded-For"):
        # Take the leftmost IP from comma-separated list
        ip = request.headers.get("X-Forwarded-For").split(",")[0].strip()
        return ip[:64]
    return (request.remote_addr or "127.0.0.1")[:64]


def normalize_token(token: str) -> str:
    """
    Normalize sharing token format.
    Accepts either '4829-1047' or '48291047' and normalizes to canonical '4829-1047'.
    """
    clean = token.strip().replace("-", "")
    if len(clean) == 8 and clean.isdigit():
        return f"{clean[:4]}-{clean[4:]}"
    return token.strip()


def hash_token(token: str) -> str:
    """Hash sharing token using SHA-256 for secure storage (normalizing token format first)."""
    norm = normalize_token(token)
    return hashlib.sha256(norm.encode("utf-8")).hexdigest()


def generate_share_token() -> tuple[str, str]:
    """
    Generate an 8-digit hyphenated sharing token (e.g. 4829-1047) and its SHA-256 hash.
    Format: XXXX-XXXX (4 digits - 4 digits).
    Returns: (raw_hyphenated_token, token_hash)
    """
    import string
    first_4 = secrets.choice("123456789") + "".join(secrets.choice(string.digits) for _ in range(3))
    second_4 = "".join(secrets.choice(string.digits) for _ in range(4))
    raw_token = f"{first_4}-{second_4}"
    return raw_token, hash_token(raw_token)


def compute_sha256(file_path_or_stream, chunk_size: int = 65536) -> str:
    """
    Calculate the SHA-256 hex digest of a file or stream.
    Supports either a Path/string or a file-like object with .read().
    """
    hasher = hashlib.sha256()
    if hasattr(file_path_or_stream, "read"):
        pos = file_path_or_stream.tell() if hasattr(file_path_or_stream, "tell") else 0
        file_path_or_stream.seek(0)
        while chunk := file_path_or_stream.read(chunk_size):
            hasher.update(chunk)
        file_path_or_stream.seek(pos)
    else:
        with open(file_path_or_stream, "rb") as f:
            while chunk := f.read(chunk_size):
                hasher.update(chunk)
    return hasher.hexdigest()


def sanitize_filename(filename: str) -> tuple[str, str]:
    """
    Sanitize user-provided filename and extract its lowercase extension.
    Ensures path traversal prevention by stripping directory separators.
    """
    if not filename:
        return "unnamed_file", "txt"
    base = secure_filename(os.path.basename(filename))
    if not base:
        base = "file"
    if "." in base:
        parts = base.rsplit(".", 1)
        clean_name = parts[0][:100] + "." + parts[1].lower()[:10]
        ext = parts[1].lower()
    else:
        clean_name = base[:100]
        ext = ""
    return clean_name, ext


def inspect_file_type(stream, filename: str) -> tuple[bool, str, str]:
    """
    Inspect file extension and header magic bytes.
    Returns: (is_allowed, extension, detected_mime_type)
    """
    allowed_exts = current_app.config["ALLOWED_EXTENSIONS"]
    clean_name, ext = sanitize_filename(filename)

    if not ext or ext not in allowed_exts:
        return False, ext, "application/octet-stream"

    # Read leading bytes for magic signature sniffing
    stream.seek(0)
    header = stream.read(32)
    stream.seek(0)

    # Check magic signature if available
    expected_sigs = MAGIC_SIGNATURES.get(ext)
    if expected_sigs:
        matched = any(header.startswith(sig) for sig in expected_sigs)
        if not matched:
            # File content header does not match claimed extension signature
            return False, ext, "application/octet-stream"

    detected_mime = KNOWN_MIME_TYPES.get(ext) or mimetypes.guess_type(clean_name)[0] or "application/octet-stream"
    return True, ext, detected_mime


def generate_csrf_token() -> str:
    """Generate or retrieve per-session CSRF token."""
    if "_csrf_token" not in session:
        session["_csrf_token"] = secrets.token_hex(32)
    return session["_csrf_token"]


def validate_csrf(token: str | None) -> bool:
    """Validate submitted CSRF token against session token using constant-time comparison."""
    session_token = session.get("_csrf_token")
    if not session_token or not token:
        return False
    return hmac.compare_digest(session_token, token)


def admin_required(f):
    """Decorator to require authenticated administrator session."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get("admin_logged_in"):
            if request.is_json:
                abort(401, description="Authentication required")
            return redirect(url_for("admin.login", next=request.path))
        return f(*args, **kwargs)
    return decorated_function

