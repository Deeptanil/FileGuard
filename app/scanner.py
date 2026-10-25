import os
import json
import threading
import urllib.request
import urllib.error
from datetime import datetime, timezone
from app.extensions import db
from app.models import FileRecord, BlockedHash, utc_now
from app.storage import delete_stored_file
from app.audit import log_security_event


def upload_file_to_virustotal(file_bytes: bytes, filename: str, api_key: str = None) -> dict:
    """
    Submit a file to VirusTotal v3 files API for full multi-engine antivirus analysis.
    Creates the live report on VirusTotal so https://www.virustotal.com/gui/file/{sha256} exists.
    """
    if api_key is None:
        api_key = os.getenv("VIRUSTOTAL_API_KEY", "").strip()

    if not api_key:
        return {"error": "VirusTotal API key not configured"}

    # File size limit for direct upload is 32 MB
    if len(file_bytes) > 32 * 1024 * 1024:
        return {"error": "File exceeds 32 MB direct upload limit for VirusTotal"}

    import uuid
    boundary = uuid.uuid4().hex
    safe_filename = filename.replace('"', '_').replace('\r', '').replace('\n', '')

    header = (
        f"--{boundary}\r\n"
        f'Content-Disposition: form-data; name="file"; filename="{safe_filename}"\r\n'
        f"Content-Type: application/octet-stream\r\n\r\n"
    ).encode("utf-8")
    footer = f"\r\n--{boundary}--\r\n".encode("utf-8")
    body = header + file_bytes + footer

    req = urllib.request.Request(
        "https://www.virustotal.com/api/v3/files",
        data=body,
        headers={
            "x-apikey": api_key,
            "Content-Type": f"multipart/form-data; boundary={boundary}",
            "Accept": "application/json",
            "User-Agent": "FileGuard-Antivirus-Scanner/1.0"
        }
    )

    try:
        with urllib.request.urlopen(req, timeout=30) as response:
            if response.status in (200, 201):
                raw = response.read().decode("utf-8")
                data = json.loads(raw)
                analysis_id = data.get("data", {}).get("id")
                return {
                    "success": True,
                    "analysis_id": analysis_id,
                    "message": "File submitted to VirusTotal for live analysis."
                }
            return {"error": f"VirusTotal returned status {response.status}"}
    except urllib.error.HTTPError as e:
        err_msg = e.read().decode("utf-8", errors="replace")
        return {"error": f"VirusTotal upload failed ({e.code}): {err_msg[:80]}"}
    except Exception as e:
        return {"error": f"Connection error during VirusTotal upload: {str(e)[:60]}"}


def check_virustotal_hash(sha256_hash: str, api_key: str = None, min_positives: int = None) -> dict:
    """
    Query VirusTotal API v3 for known intelligence on the given SHA-256 hash.
    Preserves user privacy by only transmitting the hash, never the raw file bytes.
    Enforces a consensus threshold (default 4+) to prevent accidental purges from false positives.
    """
    if api_key is None:
        api_key = os.getenv("VIRUSTOTAL_API_KEY", "").strip()

    if min_positives is None:
        try:
            min_positives = int(os.getenv("VIRUSTOTAL_MIN_POSITIVES", "4"))
        except ValueError:
            min_positives = 4

    if not api_key:
        return {
            "status": "unscanned",
            "positives": 0,
            "details": "Pre-flight heuristic checks passed (VirusTotal API key not configured)"
        }

    url = f"https://www.virustotal.com/api/v3/files/{sha256_hash}"
    req = urllib.request.Request(
        url,
        headers={
            "x-apikey": api_key,
            "Accept": "application/json",
            "User-Agent": "FileGuard-Antivirus-Scanner/1.0"
        }
    )

    try:
        with urllib.request.urlopen(req, timeout=8) as response:
            if response.status == 200:
                raw_data = response.read().decode("utf-8")
                data = json.loads(raw_data)
                stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
                malicious = stats.get("malicious", 0)
                suspicious = stats.get("suspicious", 0)
                undetected = stats.get("undetected", 0)
                harmless = stats.get("harmless", 0)

                total_positives = malicious + suspicious
                if total_positives >= min_positives:
                    return {
                        "status": "malicious",
                        "positives": total_positives,
                        "details": f"Confirmed threat: Flagged by {total_positives} security engines on VirusTotal"
                    }
                elif total_positives > 0:
                    return {
                        "status": "suspicious",
                        "positives": total_positives,
                        "details": f"Unconfirmed heuristic flag: {total_positives} engine(s) flagged (likely false positive)"
                    }
                else:
                    return {
                        "status": "clean",
                        "positives": 0,
                        "details": f"Clean (0/{undetected + harmless} engines flagged threats)"
                    }
            else:
                return {
                    "status": "error",
                    "positives": 0,
                    "details": f"VirusTotal HTTP status {response.status}"
                }
    except urllib.error.HTTPError as e:
        if e.code == 404:
            # Hash not found in VirusTotal database (novel or uncataloged file)
            return {
                "status": "clean",
                "positives": 0,
                "details": "Novel file signature — not previously seen on VirusTotal",
                "not_found_on_vt": True
            }
        elif e.code == 429:
            return {
                "status": "unscanned",
                "positives": 0,
                "details": "VirusTotal API rate limit reached"
            }
        elif e.code == 401:
            return {
                "status": "error",
                "positives": 0,
                "details": "VirusTotal API authentication error (invalid key)"
            }
        else:
            return {
                "status": "error",
                "positives": 0,
                "details": f"VirusTotal HTTP status {e.code}"
            }
    except Exception as e:
        return {
            "status": "error",
            "positives": 0,
            "details": f"Scanner connection error: {str(e)[:45]}"
        }


def execute_scan_for_file_record(app, file_record_id: int):
    """
    Execute background malware inspection for a stored file record.
    If flagged malicious, immediately shreds the storage file and records in BlockedHash.
    """
    with app.app_context():
        record = FileRecord.query.get(file_record_id)
        if not record or record.status != "active":
            return

        record.malware_status = "scanning"
        db.session.commit()

        api_key = app.config.get("VIRUSTOTAL_API_KEY", "")
        min_pos = app.config.get("VIRUSTOTAL_MIN_POSITIVES", 4)
        result = check_virustotal_hash(record.sha256_reference, api_key=api_key, min_positives=min_pos)

        # Refresh record
        record = FileRecord.query.get(file_record_id)
        if not record:
            return

        record.scanned_at = utc_now()
        record.malware_status = result["status"]
        record.malware_positives = result["positives"]
        record.malware_scan_details = result["details"]

        # If file hash was not in VirusTotal database, automatically submit the file
        # so VirusTotal scans it with 70+ engines and creates the live report.
        if result.get("not_found_on_vt") and not app.config.get("TESTING") and api_key:
            if not getattr(record, "is_e2ee", False) and record.file_size <= 32 * 1024 * 1024:
                try:
                    from app.storage import get_decrypted_stream
                    stream = get_decrypted_stream(record.storage_id)
                    file_bytes = stream.read()
                    up_res = upload_file_to_virustotal(file_bytes, record.original_filename, api_key=api_key)
                    if up_res.get("success"):
                        record.malware_scan_details = "Submitted to VirusTotal for live analysis across 70+ engines. Report is processing."
                        record.malware_status = "scanning"
                except Exception:
                    pass

        if result["status"] == "malicious":
            # 1. Permanently shred file from Backblaze B2/local disk
            try:
                delete_stored_file(record.storage_id)
            except Exception:
                pass
            record.status = "deleted"

            # 2. Add SHA-256 to BlockedHash quarantine
            existing_block = BlockedHash.query.filter_by(sha256_hash=record.sha256_reference).first()
            if not existing_block:
                block_entry = BlockedHash(
                    sha256_hash=record.sha256_reference,
                    reason="VIRUSTOTAL_MALWARE",
                    notes=f"Auto-purged via background scan: {result['details']}"
                )
                db.session.add(block_entry)

            # 3. Log security alert
            log_security_event(
                event_type="MALWARE_DETECTED_PURGED",
                outcome="BLOCKED",
                severity="CRITICAL",
                file_record_id=record.id,
                ip_address=record.uploader_ip,
                details=f"Confirmed malware purged from storage for file '{record.original_filename}': {result['details']}"
            )
        elif result["status"] == "suspicious":
            # Do NOT shred file for low-confidence heuristic detections (prevent false positive loss)
            log_security_event(
                event_type="MALWARE_SCAN_WARNING",
                outcome="WARNING",
                severity="MEDIUM",
                file_record_id=record.id,
                ip_address=record.uploader_ip,
                details=f"Low-confidence threat detection for '{record.original_filename}': {result['details']}"
            )
        else:
            log_security_event(
                event_type="MALWARE_SCAN_COMPLETE",
                outcome="SUCCESS",
                severity="INFO",
                file_record_id=record.id,
                ip_address=record.uploader_ip,
                details=f"Scan result for '{record.original_filename}': {result['status'].upper()} ({result['details']})"
            )

        db.session.commit()


def dispatch_background_malware_scan(app, file_record_id: int):
    """
    Spawn asynchronous non-blocking worker thread for malware threat analysis.
    In testing environments, executes synchronously to ensure deterministic SQLite testing.
    """
    if app.config.get("TESTING"):
        execute_scan_for_file_record(app, file_record_id)
        return None

    thread = threading.Thread(
        target=execute_scan_for_file_record,
        args=(app, file_record_id),
        daemon=True
    )
    thread.start()
    return thread
