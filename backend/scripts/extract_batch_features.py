import os
import sys
import json
import logging
import traceback
import urllib.request
from pathlib import Path
import csv

# Ensure backend module can be imported
sys.path.append(str(Path(__file__).resolve().parent.parent))

from app.analyzer.apk_analyzer import analyze_apk
from app.ml.feature_extractor import extract_features

logging.basicConfig(level=logging.INFO, format='%(levelname)s: %(message)s')
logger = logging.getLogger(__name__)

RAW_DATA_DIR = Path(__file__).resolve().parent.parent.parent / "data" / "raw"
OUTPUT_CSV = Path(__file__).resolve().parent.parent / "scripts" / "training_data.csv"

def get_label_sets():
    logger.info("Fetching metadata from Hugging Face for labeling...")
    b_req = urllib.request.urlopen("https://huggingface.co/datasets/Xinzxr/MalEval/resolve/main/info/benign_sample_info.json")
    benign_data = json.loads(b_req.read().decode())
    
    m_req = urllib.request.urlopen("https://huggingface.co/datasets/Xinzxr/MalEval/resolve/main/info/latest_sample_info.json")
    malware_data = json.loads(m_req.read().decode())
    
    m_req2 = urllib.request.urlopen("https://huggingface.co/datasets/Xinzxr/MalEval/resolve/main/info/archived_sample_info.json")
    malware_data.update(json.loads(m_req2.read().decode()))
    
    return set(benign_data.keys()), set(malware_data.keys())

def main():
    benign_hashes, malware_hashes = get_label_sets()
    
    apk_files = list(RAW_DATA_DIR.glob("*.apk"))
    logger.info(f"Discovered {len(apk_files)} APKs in {RAW_DATA_DIR}")
    
    results = []
    success_count = 0
    fail_count = 0
    benign_count = 0
    malware_count = 0
    
    for apk_path in apk_files:
        sha256 = apk_path.stem
        filename = apk_path.name
        
        # Determine label
        if sha256 in benign_hashes:
            label = 0
            benign_count += 1
        elif sha256 in malware_hashes:
            label = 1
            malware_count += 1
        else:
            logger.warning(f"[{filename}] Skipping: Unknown SHA-256 hash not found in MalEval metadata.")
            fail_count += 1
            continue
            
        logger.info(f"Processing [{filename}] (Label: {'Benign' if label == 0 else 'Malware'})")
        try:
            # 1. Analyze APK (Phase 2)
            analysis_result = analyze_apk(str(apk_path))
            
            # 2. Extract Features (ML Phase)
            size_bytes = apk_path.stat().st_size
            features_out = extract_features(analysis_result, size_bytes=size_bytes)
            
            if "features" in features_out:
                flat_features = features_out["features"]
            else:
                flat_features = features_out
            
            # 3. Compile row
            row = {
                "apk_name": filename,
                "sha256": sha256,
                "label": label
            }
            row.update(flat_features)
            results.append(row)
            success_count += 1
            logger.info(f"[{filename}] Success.")
        except Exception as e:
            logger.error(f"[{filename}] Failed: {str(e)}")
            fail_count += 1
            
    # Write to CSV
    if results:
        headers = ["apk_name", "sha256", "label"] + [k for k in results[0].keys() if k not in ("apk_name", "sha256", "label")]
        with open(OUTPUT_CSV, "w", newline='') as f:
            writer = csv.DictWriter(f, fieldnames=headers)
            writer.writeheader()
            writer.writerows(results)
    
    # Validation Summary
    print("\n" + "="*50)
    print("VALIDATION SUMMARY")
    print("="*50)
    print(f"Total APKs discovered: {len(apk_files)}")
    print(f"Benign count: {benign_count}")
    print(f"Malware count: {malware_count}")
    print(f"Successfully processed: {success_count}")
    print(f"Failed: {fail_count}")
    
    if results:
        print(f"Number of feature columns: {len(results[0]) - 3}") # Subtracting metadata columns
        
        # Missing values check
        missing_count = sum(1 for row in results for val in row.values() if val is None)
        print(f"Missing-value summary: {missing_count} missing values found.")
        
        # Duplicate SHA-256
        seen = set()
        duplicates = set()
        for row in results:
            if row["sha256"] in seen:
                duplicates.add(row["sha256"])
            seen.add(row["sha256"])
        print(f"Duplicate SHA-256 hashes: {len(duplicates)}")
    else:
        print("No CSV generated due to 0 successes.")
    print("="*50)

if __name__ == "__main__":
    main()
