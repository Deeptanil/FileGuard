import sys
from pathlib import Path

# Add parent directory to sys.path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app import create_app
from app.cleanup import run_expired_files_cleanup

def main():
    """Run scheduled cleanup of expired files."""
    app = create_app()
    with app.app_context():
        print("[*] Starting FileGuard expired file cleanup worker...")
        stats = run_expired_files_cleanup()
        print(f"[+] Cleanup finished: {stats['found']} expired found, {stats['deleted_storage']} files purged from storage, {stats['missing_storage']} missing on disk, {stats['failed']} errors.")

if __name__ == "__main__":
    main()

