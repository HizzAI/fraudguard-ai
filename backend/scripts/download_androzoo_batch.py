import os
import sys
import csv
import logging
from pathlib import Path

sys.path.append(str(Path(__file__).resolve().parent.parent))
from scripts.androzoo_ingest import download_apk

logging.basicConfig(level=logging.INFO, format='%(levelname)s: %(message)s')
logger = logging.getLogger(__name__)

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
MANIFESTS_DIR = PROJECT_ROOT / "data" / "manifests"

def download_batch(csv_file, label, source_id):
    if not csv_file.is_file():
        logger.error(f"Cannot find {csv_file}")
        return 0, 0

    with open(csv_file, newline="") as f:
        reader = csv.DictReader(f)
        rows = list(reader)

    api_key = os.environ.get("ANDROZOO_API_KEY")
    if not api_key:
        logger.error("No API key found in environment variables.")
        sys.exit(1)

    success = 0
    failures = 0

    for i, row in enumerate(rows):
        sha256 = row["sha256"]
        logger.info(f"[{i+1}/{len(rows)}] Downloading {sha256}...")
        try:
            success_flag = download_apk(sha256=sha256, label=label, source_id=source_id)
            if success_flag:
                success += 1
            else:
                failures += 1
        except Exception as e:
            logger.error(f"Download failed for {sha256}: {e}")
            failures += 1

    return success, failures

def main():
    benign_csv = MANIFESTS_DIR / "benign_candidates_100.csv"
    malware_csv = MANIFESTS_DIR / "malware_candidates_100.csv"

    b_succ, b_fail = download_batch(benign_csv, label=0, source_id="androzoo_batch_100")
    m_succ, m_fail = download_batch(malware_csv, label=1, source_id="androzoo_batch_100")

    print("\n" + "="*50)
    print("DOWNLOAD BATCH SUMMARY")
    print("="*50)
    print(f"Benign Requested: 100 | Success: {b_succ} | Failures: {b_fail}")
    print(f"Malware Requested: 100 | Success: {m_succ} | Failures: {m_fail}")
    print("="*50)

if __name__ == "__main__":
    main()
