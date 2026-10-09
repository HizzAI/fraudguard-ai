#!/usr/bin/env python3
"""
androzoo_batch_process.py — Steps 1-7 of the AndroZoo batch processing pipeline.

Runs:
  1. INVENTORY  — count files vs manifest, detect missing/empty/duplicate APKs
  2. ANALYSIS   — run existing analyze_apk() on each APK
  3. EXTRACTION — run existing extract_features() on each analysis result
  4. LABELS     — use labels ONLY from the manifest (vt_detection-derived), no leakage
  5. DATASET    — write backend/scripts/androzoo_training_data.csv (never touches training_data.csv)
  6. AUDIT      — full structured report
  7. COMPAT     — compare feature schema with existing MalEval training_data.csv

SECURITY:
  - No API key is read, printed, or used here.
  - Labels come exclusively from the manifest (pre-assigned from vt_detection at download time).
  - No model predictions, no risk scores, no rule-engine labels.

DO NOT MODIFY:
  - analyze_apk()
  - extract_features()
  - 47-feature definitions
  - training_data.csv (MalEval baseline)
"""

from __future__ import annotations

import csv
import json
import logging
import math
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

# ── Path setup ────────────────────────────────────────────────────────────────
SCRIPT_DIR   = Path(__file__).resolve().parent
BACKEND_DIR  = SCRIPT_DIR.parent
PROJECT_ROOT = BACKEND_DIR.parent

sys.path.insert(0, str(BACKEND_DIR))

from app.analyzer.apk_analyzer   import analyze_apk
from app.ml.feature_extractor    import extract_features, FEATURE_NAMES, FEATURE_COUNT

# ── Constants ─────────────────────────────────────────────────────────────────
ANDROZOO_RAW_DIR  = PROJECT_ROOT / "data" / "raw" / "androzoo"
MANIFEST_CSV      = PROJECT_ROOT / "data" / "manifests" / "androzoo_manifest.csv"
MALEVAL_CSV       = BACKEND_DIR  / "scripts" / "training_data.csv"
OUTPUT_CSV        = BACKEND_DIR  / "scripts" / "androzoo_training_data.csv"
FAILURES_CSV      = PROJECT_ROOT / "data" / "processed" / "androzoo_failures.csv"

# ── Logging ───────────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger(__name__)


# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────

def is_finite_number(v: Any) -> bool:
    """Return True only if v is a finite, non-NaN number."""
    try:
        f = float(v)
        return not (math.isnan(f) or math.isinf(f))
    except (TypeError, ValueError):
        return False


def read_maleval_feature_names() -> Optional[List[str]]:
    """Read the column headers from the existing MalEval training CSV."""
    if not MALEVAL_CSV.is_file():
        return None
    with open(MALEVAL_CSV, newline="") as f:
        reader = csv.DictReader(f)
        if reader.fieldnames is None:
            return None
        return [c for c in reader.fieldnames if c.startswith("feat_")]


# ─────────────────────────────────────────────────────────────────────────────
# STEP 1 — INVENTORY
# ─────────────────────────────────────────────────────────────────────────────

def inventory() -> Dict[str, Any]:
    """
    Compare the manifest against actual files on disk.
    Returns a dict of inventory statistics and a list of actionable rows.
    """
    logger.info("── STEP 1: INVENTORY ──────────────────────────────────────────")

    if not MANIFEST_CSV.is_file():
        logger.error(f"Manifest not found: {MANIFEST_CSV}")
        sys.exit(1)

    with open(MANIFEST_CSV, newline="") as f:
        manifest_rows = list(csv.DictReader(f))

    total_manifest = len(manifest_rows)

    # Physical APK files
    apk_files_on_disk = {p.stem: p for p in ANDROZOO_RAW_DIR.glob("*.apk")}
    total_on_disk = len(apk_files_on_disk)

    # Duplicate SHA-256 in manifest
    hashes_seen: Dict[str, int] = {}
    for row in manifest_rows:
        h = row["sha256"].lower()
        hashes_seen[h] = hashes_seen.get(h, 0) + 1
    manifest_duplicates = sum(1 for cnt in hashes_seen.values() if cnt > 1)

    # Map hash → label from manifest (skip duplicates beyond first)
    hash_to_label: Dict[str, int] = {}
    hash_to_row:   Dict[str, dict] = {}
    for row in manifest_rows:
        h = row["sha256"].lower()
        if h not in hash_to_label:
            hash_to_label[h] = int(row["label"])
            hash_to_row[h]   = row

    # Resolve which APKs are present, missing, or empty
    present: List[Dict] = []
    missing_from_disk: List[str] = []

    for h, row in hash_to_row.items():
        apk_path = ANDROZOO_RAW_DIR / row["apk_name"]
        if not apk_path.is_file():
            missing_from_disk.append(h)
            continue
        size = apk_path.stat().st_size
        present.append({
            "sha256":    h,
            "label":     hash_to_label[h],
            "apk_path":  apk_path,
            "apk_name":  row["apk_name"],
            "size_bytes": size,
            "source_id": row.get("source_id", "androzoo"),
        })

    empty_files = [r for r in present if r["size_bytes"] == 0]
    valid_files = [r for r in present if r["size_bytes"] > 0]

    benign_on_disk  = sum(1 for r in valid_files if r["label"] == 0)
    malware_on_disk = sum(1 for r in valid_files if r["label"] == 1)

    total_size_bytes = sum(r["size_bytes"] for r in valid_files)

    logger.info(f"  Manifest entries      : {total_manifest}")
    logger.info(f"  APKs on disk          : {total_on_disk}")
    logger.info(f"  Valid APKs (>0 bytes) : {len(valid_files)}")
    logger.info(f"  Empty files           : {len(empty_files)}")
    logger.info(f"  Missing from disk     : {len(missing_from_disk)}")
    logger.info(f"  Manifest duplicates   : {manifest_duplicates}")
    logger.info(f"  Benign on disk        : {benign_on_disk}")
    logger.info(f"  Malware on disk       : {malware_on_disk}")
    logger.info(f"  Total disk usage      : {total_size_bytes / 1_048_576:.1f} MB")

    return {
        "total_manifest":      total_manifest,
        "total_on_disk":       total_on_disk,
        "valid_files":         valid_files,
        "empty_files":         empty_files,
        "missing_from_disk":   missing_from_disk,
        "manifest_duplicates": manifest_duplicates,
        "benign_on_disk":      benign_on_disk,
        "malware_on_disk":     malware_on_disk,
        "total_size_bytes":    total_size_bytes,
    }


# ─────────────────────────────────────────────────────────────────────────────
# STEPS 2 & 3 — ANALYSIS + FEATURE EXTRACTION
# ─────────────────────────────────────────────────────────────────────────────

def analyze_and_extract(valid_files: List[Dict]) -> Dict[str, Any]:
    """
    Run analyze_apk() then extract_features() for each valid APK.
    Returns stats + lists of successful rows and failure records.
    """
    logger.info("── STEP 2+3: ANALYSIS & FEATURE EXTRACTION ────────────────────")

    results:  List[Dict] = []   # rows ready for CSV output
    failures: List[Dict] = []   # failed samples with reasons

    analysis_ok   = 0
    analysis_fail = 0
    extract_ok    = 0
    extract_fail  = 0

    total = len(valid_files)
    for i, entry in enumerate(valid_files, 1):
        sha256   = entry["sha256"]
        apk_path = entry["apk_path"]
        label    = entry["label"]
        apk_name = entry["apk_name"]

        if i % 20 == 0 or i == 1 or i == total:
            logger.info(f"  [{i:3d}/{total}] {apk_name[:50]}...")

        # ── STEP 2: Analyze ──────────────────────────────────────────────────
        try:
            analysis = analyze_apk(str(apk_path))
        except Exception as exc:
            analysis_fail += 1
            failures.append({
                "sha256":   sha256,
                "apk_name": apk_name,
                "label":    label,
                "stage":    "analysis",
                "reason":   str(exc)[:300],
            })
            continue

        if not isinstance(analysis, dict) or analysis.get("analysis_status") != "success":
            reason = analysis.get("error", "unknown analysis failure") if isinstance(analysis, dict) else "non-dict return"
            analysis_fail += 1
            failures.append({
                "sha256":   sha256,
                "apk_name": apk_name,
                "label":    label,
                "stage":    "analysis",
                "reason":   str(reason)[:300],
            })
            continue

        analysis_ok += 1

        # ── STEP 3: Extract features ─────────────────────────────────────────
        try:
            size_bytes = entry["size_bytes"]
            feat_result = extract_features(analysis, size_bytes=size_bytes)
        except Exception as exc:
            extract_fail += 1
            failures.append({
                "sha256":   sha256,
                "apk_name": apk_name,
                "label":    label,
                "stage":    "extraction",
                "reason":   str(exc)[:300],
            })
            continue

        if not isinstance(feat_result, dict) or feat_result.get("status") != "success":
            reason = feat_result.get("error", "unknown extraction failure") if isinstance(feat_result, dict) else "non-dict return"
            extract_fail += 1
            failures.append({
                "sha256":   sha256,
                "apk_name": apk_name,
                "label":    label,
                "stage":    "extraction",
                "reason":   str(reason)[:300],
            })
            continue

        flat = feat_result["features"]   # dict of feat_name → value

        # ── Verify 47 features ───────────────────────────────────────────────
        if len(flat) != FEATURE_COUNT:
            extract_fail += 1
            failures.append({
                "sha256":   sha256,
                "apk_name": apk_name,
                "label":    label,
                "stage":    "extraction",
                "reason":   f"wrong feature count: expected {FEATURE_COUNT}, got {len(flat)}",
            })
            continue

        # ── Verify ordering matches FEATURE_NAMES ────────────────────────────
        ordered_vals = []
        bad_feature = None
        for fname in FEATURE_NAMES:
            v = flat.get(fname)
            if v is None:
                bad_feature = f"missing: {fname}"
                break
            if not is_finite_number(v):
                bad_feature = f"non-finite: {fname}={v!r}"
                break
            ordered_vals.append(float(v))

        if bad_feature:
            extract_fail += 1
            failures.append({
                "sha256":   sha256,
                "apk_name": apk_name,
                "label":    label,
                "stage":    "validation",
                "reason":   bad_feature,
            })
            continue

        extract_ok += 1

        row = {
            "apk_name": apk_name,
            "sha256":   sha256,
            "label":    label,
            "source":   "androzoo",
        }
        for fname, val in zip(FEATURE_NAMES, ordered_vals):
            row[fname] = val
        results.append(row)

    logger.info(f"  Analysis  OK={analysis_ok}  FAIL={analysis_fail}")
    logger.info(f"  Extraction OK={extract_ok}  FAIL={extract_fail}")

    return {
        "results":       results,
        "failures":      failures,
        "analysis_ok":   analysis_ok,
        "analysis_fail": analysis_fail,
        "extract_ok":    extract_ok,
        "extract_fail":  extract_fail,
    }


# ─────────────────────────────────────────────────────────────────────────────
# STEP 5 — WRITE DATASET
# ─────────────────────────────────────────────────────────────────────────────

def write_dataset(results: List[Dict]) -> None:
    """Write androzoo_training_data.csv. NEVER touches training_data.csv."""
    logger.info("── STEP 5: WRITE DATASET ───────────────────────────────────────")
    OUTPUT_CSV.parent.mkdir(parents=True, exist_ok=True)
    fieldnames = ["apk_name", "sha256", "label", "source"] + FEATURE_NAMES
    with open(OUTPUT_CSV, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(results)
    logger.info(f"  Written: {OUTPUT_CSV}  ({len(results)} rows)")


def write_failures(failures: List[Dict], empty_files: List[Dict], missing: List[str]) -> None:
    """Write a failures CSV for traceability."""
    FAILURES_CSV.parent.mkdir(parents=True, exist_ok=True)
    rows = list(failures)
    for e in empty_files:
        rows.append({"sha256": e["sha256"], "apk_name": e["apk_name"],
                     "label": e["label"], "stage": "inventory", "reason": "empty file (0 bytes)"})
    for h in missing:
        rows.append({"sha256": h, "apk_name": "", "label": "",
                     "stage": "inventory", "reason": "missing from disk"})
    with open(FAILURES_CSV, "w", newline="") as f:
        fieldnames = ["sha256", "apk_name", "label", "stage", "reason"]
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)
    logger.info(f"  Failures log: {FAILURES_CSV}  ({len(rows)} entries)")


# ─────────────────────────────────────────────────────────────────────────────
# STEP 6 — AUDIT
# ─────────────────────────────────────────────────────────────────────────────

def compute_data_quality(results: List[Dict]) -> Dict[str, Any]:
    """Run quality checks on the final results list."""
    if not results:
        return {"note": "no results to audit"}

    n = len(results)
    sha256_set = set(r["sha256"] for r in results)
    duplicate_sha256 = n - len(sha256_set)

    nan_count    = 0
    inf_count    = 0
    nonnum_count = 0
    miss_count   = 0

    for r in results:
        for fname in FEATURE_NAMES:
            v = r.get(fname)
            if v is None:
                miss_count += 1
            else:
                try:
                    f = float(v)
                    if math.isnan(f):   nan_count    += 1
                    elif math.isinf(f): inf_count    += 1
                except (TypeError, ValueError):
                    nonnum_count += 1

    # Constant features
    constant_features = []
    for fname in FEATURE_NAMES:
        vals = {r[fname] for r in results if fname in r}
        if len(vals) <= 1:
            constant_features.append(fname)

    benign_count  = sum(1 for r in results if int(r["label"]) == 0)
    malware_count = sum(1 for r in results if int(r["label"]) == 1)

    return {
        "n":                    n,
        "duplicate_sha256":     duplicate_sha256,
        "nan_count":            nan_count,
        "inf_count":            inf_count,
        "nonnum_count":         nonnum_count,
        "miss_count":           miss_count,
        "constant_features":    constant_features,
        "n_constant_features":  len(constant_features),
        "feature_count":        FEATURE_COUNT,
        "benign_count":         benign_count,
        "malware_count":        malware_count,
    }


# ─────────────────────────────────────────────────────────────────────────────
# STEP 7 — COMPATIBILITY CHECK
# ─────────────────────────────────────────────────────────────────────────────

def compatibility_check(results: List[Dict]) -> Dict[str, Any]:
    """
    Compare AndroZoo feature schema against MalEval training_data.csv.
    Does NOT load model weights or make predictions.
    """
    logger.info("── STEP 7: COMPATIBILITY CHECK ─────────────────────────────────")

    maleval_features = read_maleval_feature_names()
    if maleval_features is None:
        return {"compatible": None, "note": "MalEval CSV not found or unreadable"}

    az_feature_set      = set(FEATURE_NAMES)
    maleval_feature_set = set(maleval_features)

    only_in_maleval = maleval_feature_set - az_feature_set
    only_in_androzoo = az_feature_set - maleval_feature_set
    same_count       = len(az_feature_set) == len(maleval_feature_set)
    same_names       = az_feature_set == maleval_feature_set
    same_order       = FEATURE_NAMES == maleval_features

    # Cross-dataset duplicate SHA-256 check
    maleval_hashes: set = set()
    if MALEVAL_CSV.is_file():
        with open(MALEVAL_CSV, newline="") as f:
            for row in csv.DictReader(f):
                h = row.get("sha256", "").lower()
                if h:
                    maleval_hashes.add(h)

    az_hashes = {r["sha256"].lower() for r in results}
    cross_duplicates = az_hashes & maleval_hashes

    compatible = same_names and same_order and len(cross_duplicates) == 0

    logger.info(f"  MalEval feature count : {len(maleval_features)}")
    logger.info(f"  AndroZoo feature count: {FEATURE_COUNT}")
    logger.info(f"  Feature names match   : {same_names}")
    logger.info(f"  Feature order match   : {same_order}")
    logger.info(f"  Cross-dataset SHA-256 duplicates: {len(cross_duplicates)}")
    logger.info(f"  Compatible            : {compatible}")

    return {
        "maleval_feature_count":   len(maleval_features),
        "androzoo_feature_count":  FEATURE_COUNT,
        "same_names":              same_names,
        "same_order":              same_order,
        "only_in_maleval":         list(only_in_maleval),
        "only_in_androzoo":        list(only_in_androzoo),
        "cross_dataset_duplicates": len(cross_duplicates),
        "compatible":              compatible,
    }


# ─────────────────────────────────────────────────────────────────────────────
# PRINT FULL AUDIT REPORT
# ─────────────────────────────────────────────────────────────────────────────

def print_audit(inv: Dict, proc: Dict, quality: Dict, compat: Dict) -> None:
    w = 62
    print("\n" + "=" * w)
    print("ANDROZOO DATASET AUDIT REPORT")
    print("=" * w)

    print("\n── DOWNLOAD ─────────────────────────────────────────────────")
    print(f"  Requested (from task)        : 200")
    print(f"  In manifest                  : {inv['total_manifest']}")
    print(f"  Physically on disk           : {inv['total_on_disk']}")
    print(f"  Valid APKs (>0 bytes)        : {len(inv['valid_files'])}")
    print(f"  Empty APK files              : {len(inv['empty_files'])}")
    print(f"  Missing from disk            : {len(inv['missing_from_disk'])}")
    print(f"  Manifest duplicates          : {inv['manifest_duplicates']}")
    print(f"  Benign on disk (label=0)     : {inv['benign_on_disk']}")
    print(f"  Malware on disk (label=1)    : {inv['malware_on_disk']}")
    print(f"  Total disk usage             : {inv['total_size_bytes']/1_048_576:.1f} MB")

    print("\n── ANALYSIS ─────────────────────────────────────────────────")
    print(f"  Attempted                    : {len(inv['valid_files'])}")
    print(f"  Succeeded                    : {proc['analysis_ok']}")
    print(f"  Failed                       : {proc['analysis_fail']}")

    print("\n── FEATURE EXTRACTION ───────────────────────────────────────")
    print(f"  Attempted                    : {proc['analysis_ok']}")
    print(f"  Succeeded                    : {proc['extract_ok']}")
    print(f"  Failed                       : {proc['extract_fail']}")

    print("\n── DATA QUALITY ─────────────────────────────────────────────")
    if "note" in quality:
        print(f"  {quality['note']}")
    else:
        print(f"  Final sample count           : {quality['n']}")
        print(f"  Number of feature columns    : {quality['feature_count']}")
        print(f"  Duplicate SHA-256 in output  : {quality['duplicate_sha256']}")
        print(f"  Missing feature values       : {quality['miss_count']}")
        print(f"  NaN values                   : {quality['nan_count']}")
        print(f"  Infinite values              : {quality['inf_count']}")
        print(f"  Non-numeric values           : {quality['nonnum_count']}")
        print(f"  Constant features            : {quality['n_constant_features']}")
        if quality["constant_features"]:
            for cf in quality["constant_features"]:
                print(f"    - {cf}")

    print("\n── LABELS ───────────────────────────────────────────────────")
    if "note" not in quality:
        total = quality["benign_count"] + quality["malware_count"]
        pct_b = 100 * quality["benign_count"] / total if total else 0
        pct_m = 100 * quality["malware_count"] / total if total else 0
        print(f"  Benign  (label=0)            : {quality['benign_count']}  ({pct_b:.1f}%)")
        print(f"  Malware (label=1)            : {quality['malware_count']}  ({pct_m:.1f}%)")
        print(f"  Rejected / unusable          : {proc['analysis_fail'] + proc['extract_fail']}")
        failures_total = len(inv['empty_files']) + len(inv['missing_from_disk']) + proc['analysis_fail'] + proc['extract_fail']
        print(f"  Total rejected samples       : {failures_total}")

    print("\n── COMPATIBILITY WITH MALEVAL ───────────────────────────────")
    if compat.get("compatible") is None:
        print(f"  {compat.get('note', 'Unknown')}")
    else:
        print(f"  MalEval feature count        : {compat['maleval_feature_count']}")
        print(f"  AndroZoo feature count       : {compat['androzoo_feature_count']}")
        print(f"  Feature names match          : {compat['same_names']}")
        print(f"  Feature order match          : {compat['same_order']}")
        print(f"  Cross-dataset SHA-256 dups   : {compat['cross_dataset_duplicates']}")
        if compat["only_in_maleval"]:
            print(f"  Only in MalEval              : {compat['only_in_maleval']}")
        if compat["only_in_androzoo"]:
            print(f"  Only in AndroZoo             : {compat['only_in_androzoo']}")
        status = "✅ COMPATIBLE" if compat["compatible"] else "❌ INCOMPATIBLE"
        print(f"  Compatibility status         : {status}")

    print("\n── FILES CREATED ────────────────────────────────────────────")
    print(f"  {OUTPUT_CSV}")
    print(f"  {FAILURES_CSV}")

    training_ready = (
        "note" not in quality
        and quality["nan_count"] == 0
        and quality["inf_count"] == 0
        and quality["miss_count"] == 0
        and quality["nonnum_count"] == 0
        and quality["duplicate_sha256"] == 0
        and quality["n"] > 0
        and compat.get("compatible", False)
    )
    print("\n── VERDICT ──────────────────────────────────────────────────")
    print(f"  Training-ready               : {'✅ YES' if training_ready else '⚠️  NOT YET'}")
    print(f"  Compatible with MalEval 47F  : {'✅ YES' if compat.get('compatible') else '❌ NO'}")
    print(f"  Models retrained             : ❌ NO (as instructed)")
    print("=" * w)
    print("STOP — Awaiting instructions before next phase.")
    print("=" * w)


# ─────────────────────────────────────────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────────────────────────────────────────

def main() -> None:
    # Step 1
    inv  = inventory()

    # Steps 2 + 3
    proc = analyze_and_extract(inv["valid_files"])

    # Step 4 (labels are already preserved from manifest in proc["results"])

    # Step 5
    write_dataset(proc["results"])
    write_failures(
        proc["failures"],
        inv["empty_files"],
        inv["missing_from_disk"],
    )

    # Step 6
    quality = compute_data_quality(proc["results"])

    # Step 7
    compat = compatibility_check(proc["results"])

    # Print full report
    print_audit(inv, proc, quality, compat)


if __name__ == "__main__":
    main()
