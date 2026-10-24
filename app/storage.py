import os
import uuid
import hashlib
from pathlib import Path
from flask import current_app

class StorageError(Exception):
    """Exception raised for storage filesystem errors."""
    pass


def get_storage_path(storage_id: str) -> Path:
    """
    Resolve safe filesystem path for an internal storage identifier.
    Guarantees path traversal cannot escape the configured storage directory.
    """
    storage_dir = Path(current_app.config["STORAGE_DIR"]).resolve()
    # Sanitize storage_id to prevent any slash or traversal pattern
    safe_id = "".join(c for c in storage_id if c.isalnum() or c in ("-", "_"))
    target = (storage_dir / safe_id).resolve()
    if not str(target).startswith(str(storage_dir)):
        raise StorageError("Path traversal attempt detected in storage path resolution")
    return target


def save_upload_stream(file_storage) -> tuple[str, int, str]:
    """
    Save incoming FileStorage to storage under a generated storage ID.
    Calculates SHA-256 and byte length during write.
    Returns: (storage_id, byte_size, sha256_hash)
    """
    storage_dir = Path(current_app.config["STORAGE_DIR"]).resolve()
    storage_dir.mkdir(parents=True, exist_ok=True)

    storage_id = f"fg_{uuid.uuid4().hex}"
    target_path = get_storage_path(storage_id)

    hasher = hashlib.sha256()
    bytes_written = 0
    max_bytes = current_app.config["MAX_CONTENT_LENGTH"]

    try:
        with open(target_path, "wb") as f:
            while chunk := file_storage.read(65536):
                bytes_written += len(chunk)
                if bytes_written > max_bytes:
                    raise StorageError(f"File exceeded maximum permitted size ({current_app.config['MAX_CONTENT_LENGTH_MB']} MB)")
                hasher.update(chunk)
                f.write(chunk)
    except Exception as e:
        # Cleanup incomplete or oversized file
        if target_path.exists():
            target_path.unlink(missing_ok=True)
        raise e

    return storage_id, bytes_written, hasher.hexdigest()


def delete_stored_file(storage_id: str) -> bool:
    """Safely delete a file from server storage."""
    try:
        path = get_storage_path(storage_id)
        if path.exists():
            path.unlink()
            return True
        return False
    except Exception:
        return False


def get_stored_file_metadata(storage_id: str) -> dict:
    """
    Inspect underlying OS filesystem metadata for digital forensics analysis.
    Returns file existence, size, and OS timestamps (mtime, ctime, atime).
    """
    try:
        path = get_storage_path(storage_id)
        if not path.exists():
            return {
                "exists": False,
                "disk_size": 0,
                "os_mtime": None,
                "os_ctime": None,
                "os_atime": None,
                "absolute_path": str(path)
            }
        stat = path.stat()
        return {
            "exists": True,
            "disk_size": stat.st_size,
            "os_mtime": stat.st_mtime,
            "os_ctime": stat.st_ctime,
            "os_atime": stat.st_atime,
            "absolute_path": str(path)
        }
    except Exception as e:
        return {
            "exists": False,
            "error": str(e),
            "disk_size": 0,
            "os_mtime": None,
            "os_ctime": None,
            "os_atime": None,
            "absolute_path": None
        }

