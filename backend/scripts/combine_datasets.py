import sys
import csv
import logging
from pathlib import Path

logging.basicConfig(level=logging.INFO, format='%(levelname)s: %(message)s')
logger = logging.getLogger(__name__)

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
MALEVAL_CSV = PROJECT_ROOT / "backend" / "scripts" / "training_data.csv"
ANDROZOO_CSV = PROJECT_ROOT / "data" / "processed" / "androzoo_features.csv"
COMBINED_CSV = PROJECT_ROOT / "data" / "processed" / "combined_training_data.csv"

def read_csv(path):
    if not path.is_file():
        return []
    with open(path, newline='') as f:
        return list(csv.DictReader(f))

def main():
    maleval_rows = read_csv(MALEVAL_CSV)
    androzoo_rows = read_csv(ANDROZOO_CSV)

    if not maleval_rows:
        logger.error("MalEval dataset is empty or missing.")
        sys.exit(1)
    if not androzoo_rows:
        logger.error("AndroZoo dataset is empty or missing.")
        sys.exit(1)

    maleval_features = [k for k in maleval_rows[0].keys() if k not in ("apk_name", "sha256", "label", "source")]
    androzoo_features = [k for k in androzoo_rows[0].keys() if k not in ("apk_name", "sha256", "label", "source")]

    if set(maleval_features) != set(androzoo_features):
        logger.error("Feature set mismatch between MalEval and AndroZoo datasets!")
        logger.error(f"MalEval len: {len(maleval_features)}, AndroZoo len: {len(androzoo_features)}")
        sys.exit(1)

    seen_hashes = {}
    combined = []
    duplicate_hashes = 0
    label_conflicts = 0

    benign_count = 0
    malware_count = 0

    for row in maleval_rows:
        # Standardize source if missing
        if "source" not in row:
            row["source"] = "maleval"

        h = row.get("sha256", "")
        if h in seen_hashes:
            duplicate_hashes += 1
            if seen_hashes[h] != row["label"]:
                label_conflicts += 1
            continue

        seen_hashes[h] = row["label"]
        combined.append(row)
        if int(row["label"]) == 0: benign_count += 1
        else: malware_count += 1

    for row in androzoo_rows:
        h = row.get("sha256", "")
        if h in seen_hashes:
            duplicate_hashes += 1
            if seen_hashes[h] != row["label"]:
                label_conflicts += 1
            continue

        seen_hashes[h] = row["label"]
        combined.append(row)
        if int(row["label"]) == 0: benign_count += 1
        else: malware_count += 1

    # Write combined
    if combined:
        headers = ["apk_name", "sha256", "label", "source"] + maleval_features
        with open(COMBINED_CSV, "w", newline='') as f:
            writer = csv.DictWriter(f, fieldnames=headers)
            writer.writeheader()
            writer.writerows(combined)

    print("\n" + "="*50)
    print("DATASET COMBINATION AUDIT")
    print("="*50)
    print(f"MalEval samples: {len(maleval_rows)}")
    print(f"AndroZoo samples: {len(androzoo_rows)}")
    print(f"Combined samples (unique): {len(combined)}")
    print(f"Duplicate SHA-256 rejected: {duplicate_hashes}")
    print(f"Label conflicts detected: {label_conflicts}")
    print(f"Feature columns: {len(maleval_features)} (Match: True)")
    print(f"Total Benign: {benign_count}")
    print(f"Total Malware: {malware_count}")
    print(f"Class Balance: {benign_count/(benign_count+malware_count)*100:.1f}% Benign / {malware_count/(benign_count+malware_count)*100:.1f}% Malware")
    print("="*50)

if __name__ == "__main__":
    main()
