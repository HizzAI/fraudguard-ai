"""
androzoo_select.py — APK selection helper for AndroZoo metadata.

Phase 5B.5C-J: AndroZoo Dataset Expansion

PURPOSE:
    Filter and rank APK candidates from a local AndroZoo metadata CSV slice.
    This script does NOT download APKs and does NOT require an API key.
    Use it to choose SHA-256 hashes BEFORE calling androzoo_ingest.py.

DESIGN:
    - Accepts a local CSV file (a slice of AndroZoo's latest.csv).
    - Never downloads the full AndroZoo metadata automatically.
    - Filters by user-defined criteria (VT count, size, date, market).
    - Outputs a ranked candidate list to stdout and optionally to a CSV.
    - Deduplicates against the existing dataset before reporting candidates.

ANDROZOO METADATA COLUMNS (from latest.csv.gz):
    sha256, sha1, md5, dex_date, apk_size, pkg_name, vercode, vt_detection,
    vt_scan_date, dex_size, markets

USAGE:
    # After downloading a metadata slice to data/raw/androzoo/sample_meta.csv:
    python androzoo_select.py \\
        --metadata data/raw/androzoo/sample_meta.csv \\
        --vt-min 5 \\
        --vt-max 60 \\
        --size-max 10485760 \\
        --top 20 \\
        --label 1 \\
        --output data/manifests/androzoo_candidates.csv

    # For benign candidates (VT detections = 0):
    python androzoo_select.py \\
        --metadata data/raw/androzoo/sample_meta.csv \\
        --vt-min 0 --vt-max 0 \\
        --top 20 \\
        --label 0

IMPORTANT:
    Do NOT run this script on the full latest.csv.gz (can be many GB).
    Download only a manageable slice using a tool like:
        zcat latest.csv.gz | head -10001 > sample_meta.csv
    or filter with awk/grep before feeding to this script.
"""

from __future__ import annotations

import argparse
import csv
import logging
import sys
from pathlib import Path
from typing import Optional

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger(__name__)

_SCRIPT_DIR   = Path(__file__).resolve().parent
_PROJECT_ROOT = _SCRIPT_DIR.parent.parent

MALEVAL_RAW_DIR = _PROJECT_ROOT / "data" / "raw"
EXISTING_CSV    = _SCRIPT_DIR / "training_data.csv"
MANIFEST_CSV    = _PROJECT_ROOT / "data" / "manifests" / "androzoo_manifest.csv"

# Expected AndroZoo metadata columns
_AZ_COLUMNS = {
    "sha256", "sha1", "md5", "dex_date", "apk_size",
    "pkg_name", "vercode", "vt_detection", "vt_scan_date",
    "dex_size", "markets",
}


def _load_existing_hashes() -> set[str]:
    """Load all known SHA-256 hashes to support deduplication."""
    hashes: set[str] = set()
    if MALEVAL_RAW_DIR.is_dir():
        for apk_path in MALEVAL_RAW_DIR.glob("*.apk"):
            hashes.add(apk_path.stem.lower())
    if EXISTING_CSV.is_file():
        with open(EXISTING_CSV, newline="") as f:
            for row in csv.DictReader(f):
                if row.get("sha256"):
                    hashes.add(row["sha256"].lower())
    if MANIFEST_CSV.is_file():
        with open(MANIFEST_CSV, newline="") as f:
            for row in csv.DictReader(f):
                if row.get("sha256"):
                    hashes.add(row["sha256"].lower())
    return hashes


def select_candidates(
    metadata_path: Path,
    vt_min: int,
    vt_max: int,
    label: int,
    size_max: Optional[int],
    top: int,
    pkg_filter: Optional[str],
    market_filter: Optional[str],
    output_path: Optional[Path],
) -> list[dict]:
    """
    Filter and rank APK candidates from a local AndroZoo metadata CSV.

    Returns:
        List of selected candidate dicts sorted by vt_detection descending
        (for malware) or ascending (for benign).
    """
    if not metadata_path.is_file():
        logger.error(f"Metadata file not found: {metadata_path}")
        sys.exit(1)

    existing_hashes = _load_existing_hashes()
    logger.info(f"Loaded {len(existing_hashes)} existing hashes for deduplication.")

    candidates = []
    total_rows = 0
    skipped_dup = 0
    skipped_vt  = 0
    skipped_sz  = 0
    skipped_pkg = 0
    skipped_mkt = 0

    with open(metadata_path, newline="") as f:
        reader = csv.DictReader(f)
        if not reader.fieldnames:
            logger.error("Metadata CSV appears empty or has no header.")
            sys.exit(1)

        # Warn on unexpected schema
        found = set(reader.fieldnames)
        if "sha256" not in found:
            logger.error(
                "Metadata CSV does not have a 'sha256' column. "
                "Expected AndroZoo latest.csv format."
            )
            sys.exit(1)

        for row in reader:
            total_rows += 1
            sha256 = (row.get("sha256") or "").strip().lower()

            # Deduplication
            if sha256 in existing_hashes:
                skipped_dup += 1
                continue

            # VT filter
            try:
                vt = int(row.get("vt_detection") or -1)
            except ValueError:
                vt = -1

            if not (vt_min <= vt <= vt_max):
                skipped_vt += 1
                continue

            # Size filter
            if size_max is not None:
                try:
                    sz = int(row.get("apk_size") or 0)
                except ValueError:
                    sz = 0
                if sz > size_max:
                    skipped_sz += 1
                    continue

            # Package name filter (substring match)
            if pkg_filter:
                pkg = (row.get("pkg_name") or "").lower()
                if pkg_filter.lower() not in pkg:
                    skipped_pkg += 1
                    continue

            # Market filter (substring match)
            if market_filter:
                mkt = (row.get("markets") or "").lower()
                if market_filter.lower() not in mkt:
                    skipped_mkt += 1
                    continue

            candidates.append({
                "sha256":       sha256,
                "vt_detection": vt,
                "apk_size":     row.get("apk_size", ""),
                "pkg_name":     row.get("pkg_name", ""),
                "dex_date":     row.get("dex_date", ""),
                "markets":      row.get("markets", ""),
                "proposed_label": label,
            })

    # Sort: malware → highest VT first; benign → lowest VT first
    reverse_sort = label == 1
    candidates.sort(key=lambda r: int(r["vt_detection"]), reverse=reverse_sort)
    selected = candidates[:top]

    # Report
    print()
    print("=" * 60)
    print("ANDROZOO CANDIDATE SELECTION REPORT")
    print("=" * 60)
    print(f"  Metadata file:      {metadata_path}")
    print(f"  Total rows read:    {total_rows}")
    print(f"  Skipped (dup):      {skipped_dup}")
    print(f"  Skipped (VT):       {skipped_vt}")
    print(f"  Skipped (size):     {skipped_sz}")
    print(f"  Skipped (pkg):      {skipped_pkg}")
    print(f"  Skipped (market):   {skipped_mkt}")
    print(f"  Candidates after filter: {len(candidates)}")
    print(f"  Selected (top):     {len(selected)}")
    print(f"  Proposed label:     {'Malware (1)' if label == 1 else 'Benign (0)'}")
    if selected:
        print()
        print("  Top candidates:")
        for i, row in enumerate(selected, start=1):
            print(
                f"    {i:2}. sha256={row['sha256'][:16]}... "
                f"vt={row['vt_detection']} "
                f"size={row['apk_size']} "
                f"pkg={row['pkg_name']}"
            )
    print("=" * 60)

    if output_path and selected:
        output_path.parent.mkdir(parents=True, exist_ok=True)
        with open(output_path, "w", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=list(selected[0].keys()))
            writer.writeheader()
            writer.writerows(selected)
        logger.info(f"Candidates written to: {output_path}")

    return selected


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Select APK candidates from local AndroZoo metadata.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--metadata", required=True, type=Path,
        help="Path to a local AndroZoo metadata CSV slice (NOT latest.csv.gz directly).",
    )
    parser.add_argument(
        "--vt-min", type=int, default=5,
        help="Minimum VirusTotal detection count (default: 5).",
    )
    parser.add_argument(
        "--vt-max", type=int, default=60,
        help="Maximum VirusTotal detection count (default: 60).",
    )
    parser.add_argument(
        "--label", type=int, choices=[0, 1], required=True,
        help="Proposed label for the selected samples: 0=benign, 1=malware.",
    )
    parser.add_argument(
        "--size-max", type=int, default=None,
        help="Maximum APK size in bytes (optional). E.g., 10485760 for 10 MB.",
    )
    parser.add_argument(
        "--top", type=int, default=20,
        help="Maximum number of candidates to return (default: 20).",
    )
    parser.add_argument(
        "--pkg-filter", default=None,
        help="Filter by substring in package name (optional).",
    )
    parser.add_argument(
        "--market-filter", default=None,
        help="Filter by substring in markets field (optional).",
    )
    parser.add_argument(
        "--output", type=Path, default=None,
        help="Save selected candidates to this CSV path (optional).",
    )
    return parser


def main() -> None:
    args = _build_parser().parse_args()
    select_candidates(
        metadata_path=args.metadata,
        vt_min=args.vt_min,
        vt_max=args.vt_max,
        label=args.label,
        size_max=args.size_max,
        top=args.top,
        pkg_filter=args.pkg_filter,
        market_filter=args.market_filter,
        output_path=args.output,
    )


if __name__ == "__main__":
    main()
