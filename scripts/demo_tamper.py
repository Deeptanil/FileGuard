import sys
from pathlib import Path

# Add project root to sys.path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app import create_app
from app.models import FileRecord
from app.storage import get_storage_path
from app.integrity import verify_file_integrity

def main():
    """CLI tool to simulate file tampering for examiner demonstration."""
    app = create_app()
    with app.app_context():
        if len(sys.argv) < 2:
            print("Usage: python scripts/demo_tamper.py <file_record_id>")
            print("\nAvailable files in database:")
            for f in FileRecord.query.all():
                print(f"  ID #{f.id}: {f.original_filename} (Status: {f.status})")
            return

        file_id = int(sys.argv[1])
        record = FileRecord.query.get(file_id)
        if not record:
            print(f"[-] Error: FileRecord with ID {file_id} not found.")
            return

        path = get_storage_path(record.storage_id)
        if not path.exists():
            print(f"[-] Error: Storage file does not exist at {path}.")
            return

        print(f"[*] Target: File #{record.id} ({record.original_filename})")
        print(f"[*] Recorded Reference SHA-256: {record.sha256_reference}")

        # Inject simulated corruption bytes
        with open(path, "ab") as f:
            f.write(b"\n# [EXAMINER_DEMO_TAMPER_PAYLOAD]\n")

        print("[+] Injected corruption byte sequence into physical storage payload.")

        # Immediately execute integrity check
        result = verify_file_integrity(record, initiated_by="CLI_EXAMINER_DEMO")
        print(f"\n[+] Cryptographic Verification Result: {result['result']}")
        print(f"    Expected Hash: {result['expected']}")
        print(f"    Observed Hash: {result['observed']}")
        print(f"    Message:       {result['message']}")
        print(f"    Record Status: {record.status}")

if __name__ == "__main__":
    main()

