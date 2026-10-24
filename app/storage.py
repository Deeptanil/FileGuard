import os
import uuid
import hashlib
from pathlib import Path
from flask import current_app

class StorageError(Exception):
    """Exception raised for storage filesystem errors."""
    pass


def get_s3_client():
    """Instantiate S3-compatible client for Backblaze B2, Cloudflare R2, or AWS S3."""
    import boto3
    endpoint = current_app.config.get("S3_ENDPOINT_URL")
    return boto3.client(
        "s3",
        endpoint_url=endpoint if endpoint else None,
        aws_access_key_id=current_app.config.get("AWS_ACCESS_KEY_ID"),
        aws_secret_access_key=current_app.config.get("AWS_SECRET_ACCESS_KEY"),
        region_name=current_app.config.get("AWS_DEFAULT_REGION", "us-east-1")
    )


def get_storage_path(storage_id: str) -> Path:
    """
    Resolve safe filesystem path for an internal storage identifier.
    Guarantees path traversal cannot escape the configured storage directory.
    If storage backend is S3 and file is not yet cached locally, fetches from S3 on demand.
    """
    storage_dir = Path(current_app.config["STORAGE_DIR"]).resolve()
    storage_dir.mkdir(parents=True, exist_ok=True)

    # Sanitize storage_id to prevent any slash or traversal pattern
    safe_id = "".join(c for c in storage_id if c.isalnum() or c in ("-", "_"))
    target = (storage_dir / safe_id).resolve()
    if not str(target).startswith(str(storage_dir)):
        raise StorageError("Path traversal attempt detected in storage path resolution")

    # If backend is S3 and local cache doesn't exist, download from bucket
    if not target.exists() and current_app.config.get("STORAGE_BACKEND") == "s3":
        bucket = current_app.config.get("S3_BUCKET_NAME")
        if bucket:
            try:
                s3 = get_s3_client()
                s3.download_file(bucket, safe_id, str(target))
            except Exception:
                # File not found in S3
                pass

    return target


def save_upload_stream(file_storage) -> tuple[str, int, str]:
    """
    Save incoming FileStorage to storage under a generated storage ID.
    Calculates SHA-256 and byte length during write.
    If STORAGE_BACKEND is 's3', also pushes the file to Backblaze B2 / S3 bucket.
    Returns: (storage_id, byte_size, sha256_hash)
    """
    storage_dir = Path(current_app.config["STORAGE_DIR"]).resolve()
    storage_dir.mkdir(parents=True, exist_ok=True)

    storage_id = f"fg_{uuid.uuid4().hex}"
    target_path = (storage_dir / storage_id).resolve()

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

        # Upload to S3/Backblaze B2 if S3 backend is enabled
        if current_app.config.get("STORAGE_BACKEND") == "s3":
            bucket = current_app.config.get("S3_BUCKET_NAME")
            if bucket:
                s3 = get_s3_client()
                s3.upload_file(str(target_path), bucket, storage_id)

    except Exception as e:
        # Cleanup incomplete or oversized file
        if target_path.exists():
            target_path.unlink(missing_ok=True)
        raise e

    return storage_id, bytes_written, hasher.hexdigest()


def delete_stored_file(storage_id: str) -> bool:
    """Safely delete a file from server storage and S3 bucket if configured."""
    safe_id = "".join(c for c in storage_id if c.isalnum() or c in ("-", "_"))
    deleted_any = False

    # 1. Delete from local cache
    try:
        storage_dir = Path(current_app.config["STORAGE_DIR"]).resolve()
        path = (storage_dir / safe_id).resolve()
        if path.exists():
            path.unlink()
            deleted_any = True
    except Exception:
        pass

    # 2. Delete from S3/Backblaze B2
    if current_app.config.get("STORAGE_BACKEND") == "s3":
        bucket = current_app.config.get("S3_BUCKET_NAME")
        if bucket:
            try:
                s3 = get_s3_client()
                s3.delete_object(Bucket=bucket, Key=safe_id)
                deleted_any = True
            except Exception:
                pass

    return deleted_any


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
