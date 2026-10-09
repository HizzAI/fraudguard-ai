"""
androzoo_ingest.py — Safe AndroZoo APK ingestion workflow.

Phase 5B.5C-J: AndroZoo Dataset Expansion

PURPOSE:
    Download individual APKs from the AndroZoo repository, verify integrity,
    check for duplicates against the existing dataset, and record metadata
    in the manifest.

SECURITY RULES:
    - The ANDROZOO_API_KEY is ALWAYS read from the environment variable.
    - The API key is NEVER printed, logged, or written to any file.
    - This script is safe to commit; it contains no secrets.

USAGE:
    # Set your API key in the environment first:
    export ANDROZOO_API_KEY="<your-key>"

    # Test connectivity with a single known SHA-256:
    python androzoo_ingest.py download <sha256> --label <0|1> [--vt-count N]

    # Validate the manifest:
    python androzoo_ingest.py validate-manifest

    # Check deduplication status:
    python androzoo_ingest.py check-duplicates

DESIGN NOTES:
    - Does NOT import or modify analyze_apk() or extract_features().
    - Does NOT retrain models.
    - Does NOT download bulk metadata automatically.
    - The existing 40-sample MalEval dataset is untouched.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import logging
import os
import sys
import urllib.error
import urllib.parse
import urllib.request
from datetime import date, datetime
from pathlib import Path
from typing import Optional

# ---------------------------------------------------------------------------
# Logging — safe format: no key, no sensitive values
# ---------------------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Paths (relative to this script's location: backend/scripts/)
# ---------------------------------------------------------------------------
_SCRIPT_DIR   = Path(__file__).resolve().parent
_PROJECT_ROOT = _SCRIPT_DIR.parent.parent  # fraudguard-ai/

ANDROZOO_RAW_DIR  = _PROJECT_ROOT / "data" / "raw" / "androzoo"
MALEVAL_RAW_DIR   = _PROJECT_ROOT / "data" / "raw"  # flat dir with MalEval APKs
MANIFEST_CSV      = _PROJECT_ROOT / "data" / "manifests" / "androzoo_manifest.csv"
EXISTING_CSV      = _SCRIPT_DIR / "training_data.csv"

# AndroZoo official download endpoint
ANDROZOO_BASE_URL = "https://androzoo.uni.lu/api/download"

# Manifest columns (order matters for CSV writer)
MANIFEST_COLUMNS = [
    "sha256",
    "apk_name",
    "label",
    "source_dataset",
    "source_id",
    "collection_date",
    "status",
]

# ---------------------------------------------------------------------------
# Helpers — secret handling
# ---------------------------------------------------------------------------

def _get_api_key() -> str:
    """
    Read ANDROZOO_API_KEY from the environment.
    Raises SystemExit with a safe message if the variable is missing.
    NEVER prints or logs the key value.
    """
    key = os.environ.get("ANDROZOO_API_KEY", "")
    if not key:
        logger.error(
            "ANDROZOO_API_KEY environment variable is not set. "
            "Export it in your shell before running this script. "
            "See backend/.env.example for instructions."
        )
        sys.exit(1)
    # Confirm detection without revealing the value
    masked = f"{key[:4]}{'*' * max(0, len(key) - 4)}"
    logger.info(f"ANDROZOO_API_KEY detected (masked: {masked}).")
    return key


# ---------------------------------------------------------------------------
# SHA-256 utilities
# ---------------------------------------------------------------------------

def sha256_of_file(path: Path) -> str:
    """Calculate the SHA-256 digest of a local file."""
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            h.update(chunk)
    return h.hexdigest().lower()


def _load_existing_hashes() -> set[str]:
    """
    Return a set of SHA-256 hashes already in the dataset:
      1. All *.apk filenames in data/raw/ (MalEval prototype APKs).
      2. All sha256 values in training_data.csv.
      3. All sha256 values already in androzoo_manifest.csv.
    """
    hashes: set[str] = set()

    # From MalEval flat directory (filenames are their SHA-256)
    if MALEVAL_RAW_DIR.is_dir():
        for apk_path in MALEVAL_RAW_DIR.glob("*.apk"):
            hashes.add(apk_path.stem.lower())

    # From training_data.csv
    if EXISTING_CSV.is_file():
        with open(EXISTING_CSV, newline="") as f:
            reader = csv.DictReader(f)
            for row in reader:
                if row.get("sha256"):
                    hashes.add(row["sha256"].lower())

    # From androzoo_manifest.csv
    if MANIFEST_CSV.is_file():
        with open(MANIFEST_CSV, newline="") as f:
            reader = csv.DictReader(f)
            for row in reader:
                if row.get("sha256"):
                    hashes.add(row["sha256"].lower())

    return hashes


# ---------------------------------------------------------------------------
# Manifest helpers
# ---------------------------------------------------------------------------

def _read_manifest() -> list[dict]:
    if not MANIFEST_CSV.is_file():
        return []
    with open(MANIFEST_CSV, newline="") as f:
        return list(csv.DictReader(f))


def _write_manifest(rows: list[dict]) -> None:
    MANIFEST_CSV.parent.mkdir(parents=True, exist_ok=True)
    with open(MANIFEST_CSV, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=MANIFEST_COLUMNS)
        writer.writeheader()
        writer.writerows(rows)


def _append_to_manifest(row: dict) -> None:
    rows = _read_manifest()
    rows.append(row)
    _write_manifest(rows)


# ---------------------------------------------------------------------------
# Core download
# ---------------------------------------------------------------------------

def download_apk(
    sha256: str,
    label: int,
    vt_detection: Optional[int] = None,
    source_id: Optional[str] = None,
) -> bool:
    """
    Download a single APK from AndroZoo, verify its hash, and update the manifest.

    Args:
        sha256:       Hex SHA-256 of the APK to download.
        label:        0 = benign, 1 = malware.
        vt_detection: VirusTotal detection count from the AndroZoo metadata (optional).
        source_id:    Descriptive source tag for tracking purposes (optional).

    Returns:
        True if the download and hash verification both passed; False otherwise.
    """
    sha256 = sha256.strip().lower()

    # ── Pre-flight: validate input ───────────────────────────────────────────
    if len(sha256) != 64 or not all(c in "0123456789abcdef" for c in sha256):
        logger.error(f"Invalid SHA-256 format: '{sha256}' (must be 64 hex chars).")
        return False

    if label not in (0, 1):
        logger.error(f"Label must be 0 (benign) or 1 (malware). Got: {label!r}.")
        return False

    # ── Deduplication check ──────────────────────────────────────────────────
    existing_hashes = _load_existing_hashes()
    if sha256 in existing_hashes:
        logger.warning(
            f"SHA-256 {sha256[:16]}... already exists in the dataset. "
            "Skipping to avoid duplicate."
        )
        return False

    # ── API key ──────────────────────────────────────────────────────────────
    api_key = _get_api_key()

    # ── Build download URL ───────────────────────────────────────────────────
    params = urllib.parse.urlencode({"apikey": api_key, "sha256": sha256})
    url = f"{ANDROZOO_BASE_URL}?{params}"

    # ── Prepare destination ──────────────────────────────────────────────────
    ANDROZOO_RAW_DIR.mkdir(parents=True, exist_ok=True)
    dest_path = ANDROZOO_RAW_DIR / f"{sha256}.apk"

    # ── Download ─────────────────────────────────────────────────────────────
    logger.info(f"Requesting APK for SHA-256: {sha256[:16]}... (label={label})")
    try:
        # NOTE: the URL contains the API key in the query string; we do NOT log it.
        with urllib.request.urlopen(url, timeout=30) as response:
            if response.status != 200:
                logger.error(
                    f"AndroZoo returned HTTP {response.status} for SHA-256 {sha256[:16]}..."
                )
                return False
            data = response.read()
    except urllib.error.HTTPError as exc:
        logger.error(
            f"HTTP error {exc.code} while downloading SHA-256 {sha256[:16]}...: {exc.reason}"
        )
        return False
    except urllib.error.URLError as exc:
        logger.error(
            f"Network error while downloading SHA-256 {sha256[:16]}...: {exc.reason}"
        )
        return False

    # ── Write file ───────────────────────────────────────────────────────────
    dest_path.write_bytes(data)
    file_size = dest_path.stat().st_size
    logger.info(f"Download complete. File size: {file_size:,} bytes.")

    # ── Hash verification ────────────────────────────────────────────────────
    local_hash = sha256_of_file(dest_path)
    if local_hash != sha256:
        logger.error(
            f"SHA-256 MISMATCH! Expected: {sha256}, got: {local_hash}. "
            "Deleting corrupted file."
        )
        dest_path.unlink(missing_ok=True)
        return False

    logger.info(f"SHA-256 verification PASSED: {sha256[:16]}...")

    # ── Append to manifest ───────────────────────────────────────────────────
    manifest_row = {
        "sha256":           sha256,
        "apk_name":         f"{sha256}.apk",
        "label":            label,
        "source_dataset":   "androzoo",
        "source_id":        source_id or f"vt_{vt_detection}" if vt_detection is not None else "",
        "collection_date":  date.today().isoformat(),
        "status":           "downloaded_verified",
    }
    _append_to_manifest(manifest_row)
    logger.info(f"Manifest updated with SHA-256 {sha256[:16]}...")

    # ── Safe summary (no key, no raw data) ───────────────────────────────────
    print()
    print("=" * 60)
    print("ANDROZOO DOWNLOAD REPORT")
    print("=" * 60)
    print(f"  SHA-256 (first 16): {sha256[:16]}...")
    print(f"  Label:              {'Malware (1)' if label == 1 else 'Benign (0)'}")
    print(f"  File size:          {file_size:,} bytes")
    print(f"  Hash verification:  PASSED")
    print(f"  Destination:        {dest_path.relative_to(_PROJECT_ROOT)}")
    print(f"  Manifest:           {MANIFEST_CSV.relative_to(_PROJECT_ROOT)}")
    print("=" * 60)

    return True


# ---------------------------------------------------------------------------
# Manifest validation
# ---------------------------------------------------------------------------

def validate_manifest() -> bool:
    """Validate the manifest CSV structure and content."""
    if not MANIFEST_CSV.is_file():
        logger.error(f"Manifest not found at {MANIFEST_CSV}")
        return False

    rows = _read_manifest()
    ok = True

    print()
    print("=" * 60)
    print("MANIFEST VALIDATION REPORT")
    print("=" * 60)
    print(f"  Manifest path:  {MANIFEST_CSV.relative_to(_PROJECT_ROOT)}")
    print(f"  Total records:  {len(rows)}")

    if not rows:
        print("  Status:         EMPTY (no APKs ingested yet — this is expected)")
        print("=" * 60)
        return True

    issues = []
    sha256_seen: set[str] = set()

    for i, row in enumerate(rows, start=1):
        # Column completeness
        missing = [col for col in MANIFEST_COLUMNS if col not in row]
        if missing:
            issues.append(f"Row {i}: missing columns {missing}")
            ok = False

        # SHA-256 format
        sha = row.get("sha256", "")
        if len(sha) != 64:
            issues.append(f"Row {i}: invalid sha256 length ({len(sha)})")
            ok = False

        # Duplicate SHA-256 within manifest
        if sha in sha256_seen:
            issues.append(f"Row {i}: duplicate sha256 {sha[:16]}...")
            ok = False
        sha256_seen.add(sha)

        # Label range
        label = row.get("label", "")
        if str(label) not in ("0", "1"):
            issues.append(f"Row {i}: invalid label '{label}' (must be 0 or 1)")
            ok = False

        # Source dataset tag
        if row.get("source_dataset") != "androzoo":
            issues.append(f"Row {i}: unexpected source_dataset '{row.get('source_dataset')}'")
            ok = False

    if issues:
        print(f"  Issues found:   {len(issues)}")
        for issue in issues:
            print(f"    ! {issue}")
    else:
        print("  Issues found:   0")

    print(f"  Overall:        {'PASS' if ok else 'FAIL'}")
    print("=" * 60)
    return ok


# ---------------------------------------------------------------------------
# Duplicate checker
# ---------------------------------------------------------------------------

def check_duplicates() -> None:
    """Report on duplicate APKs between AndroZoo manifest and existing dataset."""
    manifest_rows = _read_manifest()
    existing_hashes = _load_existing_hashes()

    manifest_hashes = {row["sha256"].lower() for row in manifest_rows if row.get("sha256")}
    overlap = manifest_hashes & existing_hashes

    print()
    print("=" * 60)
    print("DEDUPLICATION REPORT")
    print("=" * 60)
    print(f"  Existing dataset hashes (MalEval + manifest): {len(existing_hashes)}")
    print(f"  AndroZoo manifest entries:                    {len(manifest_hashes)}")
    print(f"  Overlapping (duplicates):                     {len(overlap)}")
    if overlap:
        print("  Duplicate SHA-256 prefixes:")
        for h in sorted(overlap):
            print(f"    - {h[:16]}...")
    else:
        print("  No duplicates found.")
    print("=" * 60)


# ---------------------------------------------------------------------------
# API key detection check (safe — never prints the key value)
# ---------------------------------------------------------------------------

def check_env() -> None:
    """Confirm ANDROZOO_API_KEY is set, without revealing its value."""
    key = os.environ.get("ANDROZOO_API_KEY", "")
    print()
    print("=" * 60)
    print("ENVIRONMENT CHECK")
    print("=" * 60)
    if key:
        masked = f"{key[:4]}{'*' * max(0, len(key) - 4)}"
        print(f"  ANDROZOO_API_KEY: DETECTED (masked: {masked})")
        print(f"  Key length:       {len(key)} characters")
        print("  Status:           READY")
    else:
        print("  ANDROZOO_API_KEY: NOT SET")
        print("  Status:           NOT READY")
        print("  Action required:  export ANDROZOO_API_KEY='<your-key>'")
        print("  Reference:        backend/.env.example")
    print("=" * 60)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="AndroZoo APK ingestion workflow for FraudGuardAI.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Check environment variable is set (safe — does NOT print the key):
  python androzoo_ingest.py check-env

  # Download one APK (requires ANDROZOO_API_KEY set in environment):
  python androzoo_ingest.py download \\
      --sha256 <64-char-hex> \\
      --label 1 \\
      --vt-count 35 \\
      --source-id "androzoo_pilot_v1"

  # Validate the manifest:
  python androzoo_ingest.py validate-manifest

  # Check for duplicates:
  python androzoo_ingest.py check-duplicates
""",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    # check-env
    sub.add_parser(
        "check-env",
        help="Verify ANDROZOO_API_KEY is set (never prints the value).",
    )

    # download
    dl = sub.add_parser(
        "download",
        help="Download and verify a single APK by SHA-256.",
    )
    dl.add_argument(
        "--sha256", required=True,
        help="64-character hex SHA-256 of the APK to download.",
    )
    dl.add_argument(
        "--label", required=True, type=int, choices=[0, 1],
        help="Ground-truth label: 0 = benign, 1 = malware.",
    )
    dl.add_argument(
        "--vt-count", type=int, default=None,
        help="VirusTotal detection count from AndroZoo metadata (optional).",
    )
    dl.add_argument(
        "--source-id", default=None,
        help="Human-readable source tag for the manifest (optional).",
    )

    # validate-manifest
    sub.add_parser(
        "validate-manifest",
        help="Validate the structure and content of androzoo_manifest.csv.",
    )

    # check-duplicates
    sub.add_parser(
        "check-duplicates",
        help="Report on SHA-256 overlap between AndroZoo manifest and existing dataset.",
    )

    return parser


def main() -> None:
    parser = _build_parser()
    args = parser.parse_args()

    if args.command == "check-env":
        check_env()

    elif args.command == "download":
        success = download_apk(
            sha256=args.sha256,
            label=args.label,
            vt_detection=args.vt_count,
            source_id=args.source_id,
        )
        sys.exit(0 if success else 1)

    elif args.command == "validate-manifest":
        ok = validate_manifest()
        sys.exit(0 if ok else 1)

    elif args.command == "check-duplicates":
        check_duplicates()


if __name__ == "__main__":
    main()
