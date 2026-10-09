import os
import sys
import json
import logging
import csv
from pathlib import Path

# Ensure backend module can be imported
sys.path.append(str(Path(__file__).resolve().parent.parent))

from app.analyzer.apk_analyzer import analyze_apk
from app.ml.feature_extractor import extract_features, FEATURE_NAMES

logging.basicConfig(level=logging.INFO, format='%(levelname)s: %(message)s')
logger = logging.getLogger(__name__)

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
ANDROZOO_RAW_DIR = PROJECT_ROOT / "data" / "raw" / "androzoo"
MANIFEST_CSV = PROJECT_ROOT / "data" / "manifests" / "androzoo_manifest.csv"
PROCESSED_CSV = PROJECT_ROOT / "data" / "processed" / "androzoo_features.csv"

def main():
    if not MANIFEST_CSV.is_file():
        logger.error(f"Manifest not found: {MANIFEST_CSV}")
        sys.exit(1)

    with open(MANIFEST_CSV, newline="") as f:
        manifest_rows = list(csv.DictReader(f))

    if not manifest_rows:
        logger.info("Manifest is empty. Nothing to process.")
        sys.exit(0)

    total_requested = len(manifest_rows)
    success_downloaded = 0
    download_failures = 0
    success_analyzed = 0
    analysis_failures = 0
    success_extracted = 0
    extraction_failures = 0

    benign_count = 0
    malware_count = 0
    missing_feature_count = 0
    constant_features_count = 0

    results = []
    seen_hashes = set()
    duplicate_hashes = 0

    for row in manifest_rows:
        sha256 = row["sha256"]
        apk_name = row["apk_name"]
        label = int(row["label"])

        apk_path = ANDROZOO_RAW_DIR / apk_name

        if not apk_path.is_file():
            logger.warning(f"[{apk_name}] Download failure/Missing file.")
            download_failures += 1
            continue

        success_downloaded += 1

        if sha256 in seen_hashes:
            duplicate_hashes += 1
            continue
        seen_hashes.add(sha256)

        if label == 0:
            benign_count += 1
        else:
            malware_count += 1

        try:
            # 1. Analyze APK (Phase 2)
            analysis_result = analyze_apk(str(apk_path))
            if analysis_result.get("analysis_status") != "success":
                analysis_failures += 1
                logger.error(f"[{apk_name}] Analysis failed.")
                continue
            success_analyzed += 1

            # 2. Extract Features (ML Phase)
            size_bytes = apk_path.stat().st_size
            features_out = extract_features(analysis_result, size_bytes=size_bytes)

            if features_out.get("status") != "success":
                extraction_failures += 1
                logger.error(f"[{apk_name}] Feature extraction failed.")
                continue

            flat_features = features_out["features"]

            # Verify 47 features
            if len(flat_features) != len(FEATURE_NAMES):
                logger.error(f"[{apk_name}] Feature count mismatch. Expected {len(FEATURE_NAMES)}, got {len(flat_features)}.")
                extraction_failures += 1
                continue

            # Verify no nulls
            has_null = False
            for v in flat_features.values():
                if v is None:
                    has_null = True
                    missing_feature_count += 1
            if has_null:
                extraction_failures += 1
                continue

            success_extracted += 1

            # 3. Compile row
            out_row = {
                "apk_name": apk_name,
                "sha256": sha256,
                "label": label,
                "source": "androzoo"
            }
            out_row.update(flat_features)
            results.append(out_row)

            logger.info(f"[{apk_name}] Successfully processed.")

        except Exception as e:
            logger.error(f"[{apk_name}] Failed: {str(e)}")
            extraction_failures += 1

    # Constant features check
    if results:
        feature_keys = FEATURE_NAMES
        for key in feature_keys:
            first_val = results[0][key]
            if all(r[key] == first_val for r in results):
                constant_features_count += 1

    # Write to CSV
    if results:
        headers = ["apk_name", "sha256", "label", "source"] + FEATURE_NAMES
        PROCESSED_CSV.parent.mkdir(parents=True, exist_ok=True)
        with open(PROCESSED_CSV, "w", newline='') as f:
            writer = csv.DictWriter(f, fieldnames=headers)
            writer.writeheader()
            writer.writerows(results)

    # Validation Summary
    print("\n" + "="*50)
    print("DATASET AUDIT REPORT")
    print("="*50)
    print(f"Total requested: {total_requested}")
    print(f"Successfully downloaded: {success_downloaded}")
    print(f"Download failures: {download_failures}")
    print(f"Successfully analyzed: {success_analyzed}")
    print(f"Analysis failures: {analysis_failures}")
    print(f"Successfully feature-extracted: {success_extracted}")
    print(f"Feature extraction failures: {extraction_failures}")
    print(f"Benign count: {benign_count}")
    print(f"Malware count: {malware_count}")
    print(f"Duplicate SHA-256 count: {duplicate_hashes}")
    print(f"Missing-feature count: {missing_feature_count}")
    print(f"Number of constant features: {constant_features_count}")
    print("="*50)

if __name__ == "__main__":
    main()
