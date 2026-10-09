# FraudGuardAI Dataset Policy
**Version:** 0.1-draft (requires approval before Phase 4F.2)
**Date:** 2026-10-09
**Status:** PROPOSED — not in effect until explicitly approved

---

## 1. Scope and Purpose

This document defines the rules for collecting, labeling, filtering, and partitioning
Android APK data for FraudGuardAI model training and evaluation. It applies to all
dataset expansion activities starting with Phase 4F.2.

---

## 2. Label Definitions

### 2.1 Benign label (0)
An APK is assigned **label 0** if:
- Its `vt_detection` count in the AndroZoo metadata is **exactly 0** at the time of scan.
- Its `vt_scan_date` is **no older than 24 months** before the collection date.
- It does **not** appear on any known malware list, family list, or prior MalEval exclusion list.

> **⚠️ REQUIRES APPROVAL — decision point:**
> A `vt_detection = 0` threshold is the most conservative benign definition and is consistent
> with the existing 201 AndroZoo training samples (all 100 benign samples have VT=0).
> However, VT=0 does not guarantee the APK is truly benign — it may be a newly packed
> or obfuscated sample that no engine has yet flagged. This is a known limitation (see §8).

### 2.2 Malware label (1)
An APK is assigned **label 1** if:
- Its `vt_detection` count is **≥ 20**.
- Its `vt_scan_date` is **no older than 36 months** before the collection date.

> **⚠️ REQUIRES APPROVAL — decision point:**
> The existing 101 malware training samples all have `vt_detection ≥ 20` (min=20, max=45,
> mean=27.2). This threshold is consistent with the current dataset and with the
> `malware_candidates_100.csv` manifest (min=20). A threshold of ≥ 20 is more conservative
> than ≥ 5 or ≥ 10 (common in literature) but reduces ambiguity for a small dataset.
> If more malware samples are needed, the threshold could be lowered to ≥ 10, but this
> must be explicitly decided and recorded here before any download begins.

### 2.3 Gray zone (EXCLUDED)
APKs with `vt_detection` in **[1, 19]** are **excluded** from all training and evaluation sets.
- They are neither reliably benign nor clearly malicious.
- Including them could introduce label noise that distorts metrics on a small dataset.
- They may be retained in a separate manifest for future research but must never be silently added to training data.

---

## 3. Missing or Stale VirusTotal Metadata

- APKs with `vt_detection` or `vt_scan_date` **missing** (null) are **excluded**.
  - 425 rows in `sample_meta_100k.csv` have null VT fields; these are ineligible.
- APKs with `vt_scan_date` **> 24 months old** (for benign) or **> 36 months old** (for malware)
  are excluded from new collection batches.
  - Reason: An old zero-detection scan may no longer be valid. New malware families emerge.
  - Note: 59,152 of 99,999 rows in `sample_meta_100k.csv` have scans older than 2022-01-01.
    These are ineligible for new collection without a re-scan.

---

## 4. DEX Date Validity

- `dex_date` values of **1980-01-01** or **1981-*` are Unix epoch artefacts (timestamp=0
  stored as a DEX compile date). They carry **no temporal information**.
  - 70,075 of 99,999 rows in `sample_meta_100k.csv` have this artefact.
  - These rows are **not** excluded on this basis alone, but they cannot be used for
    temporal splits (see §6).
- APKs intended for a temporal holdout **must** have a valid, non-epoch `dex_date`
  (i.e., `dex_date >= 2010-01-01` and `dex_date <= collection_date + 30 days`).

---

## 5. Duplicate Handling

### 5.1 Duplicate APK hashes
- Any APK whose SHA-256 hash already exists in `combined_training_data.csv`,
  `candidate_training_data.csv`, or any approved holdout manifest is **excluded**.
- Deduplication is performed before download using `androzoo_select.py`'s built-in
  `existing_hashes` blocklist. The blocklist must include all of:
  - `backend/scripts/training_data.csv` (MalEval hashes)
  - `data/processed/combined_training_data.csv`
  - `data/manifests/androzoo_manifest.csv`

### 5.2 Identical feature vectors
- After feature extraction, any newly added APK that produces a feature vector already
  present in the training set is **flagged** in the build report.
- If the flag appears with a **conflicting label**, both rows are excluded and the conflict
  is recorded in the build report.
- If the flag appears with a **consistent label**, the duplicate row is dropped (the
  original is retained).

---

## 6. Temporal Split Strategy

> **⚠️ REQUIRES APPROVAL — decision point:**
> A temporal split is only feasible for samples with a valid, non-epoch `dex_date`.
> After excluding 1980/81 epoch rows, only 3,850 samples in `sample_meta_100k.csv`
> have a valid `dex_date >= 2010`. Of these, only 474 have `dex_date >= 2023`.
> Temporal holdout is technically feasible but the available post-2022 pool is small.

The recommended temporal split strategy is:
- **Training samples:** `dex_date < 2022-01-01` (or epoch-date, acceptable for training only)
- **Holdout samples:** `dex_date >= 2022-01-01`, with additional requirement of a valid non-epoch date

Holdout samples must be:
1. Listed in a dedicated manifest (`data/manifests/holdout_v1.csv`) before any download.
2. Downloaded and feature-extracted **after** training is complete.
3. Never inspected, visualized, or used for model selection or threshold tuning.
4. Evaluated exactly once, after the final candidate is selected.

---

## 7. Source Tracking and Provenance

Every APK in any dataset CSV must carry:
- `sha256` — unique identifier
- `label` — 0 or 1 (no missing values permitted)
- `source` — one of: `androzoo`, `fdroid`, `virusshare` (future sources)
- `source_id` — version identifier (e.g., `androzoo_pilot_v1`, `androzoo_batch_v2`)
- `collection_date` — ISO-8601 date of download
- `vt_detection` — the VT count at the time of the selection decision
- `vt_scan_date` — the date of that VT scan
- `dex_date` — raw value from AndroZoo metadata (epoch artefacts permitted but flagged)

**MalEval samples must remain excluded from formal training** until:
- A documented source for each APK (original dataset name, paper DOI) is identified.
- A VT detection count and scan date at or near the time of collection is retrieved.
- A label assignment method (manual expert review, VT threshold, family tag) is recorded.

The 17 conflicting-label rows from MalEval are permanently excluded regardless of the above.

---

## 8. Limitations of VirusTotal Detection Counts as Ground Truth

VT detection counts are **not** equivalent to ground truth labels. Known limitations:

1. **AV engine disagreement:** Engines use different heuristics. A VT=3 sample may be
   benign by one research group's standard and malware by another's.
2. **Newly packed malware evades detection:** A malicious APK may have VT=0 immediately
   after packing, then VT=30 six months later.
3. **Stale scans:** VT scan results change over time. An old VT=0 is weaker evidence of
   benignness than a recent VT=0.
4. **Family labeling inconsistency:** VT counts do not identify the malware family.
5. **The model trained on VT-derived labels predicts VT-derived labels**, not real-world
   maliciousness. This must be disclosed in all evaluation reports.

---

## 9. Reproducibility and Versioning

- Every new training or holdout batch must record: `source_id`, `collection_date`,
  `vt_detection`, `vt_scan_date`, and `dex_date`.
- Manifests are immutable once locked: a locked manifest is named `*_locked.csv` and
  must not be edited after lock date.
- The SHA-256 checksum of every dataset CSV must be recorded in its companion report JSON.
- Scripts used to build any dataset version must be committed to git before the download begins.

---

## 10. API Limits and Safe Handling

- AndroZoo API limit: **500,000 APK downloads per 6-month window per API key**.
- Download scripts must log every download attempt and its HTTP response code.
- APK files must be stored in an isolated directory and must not be executed, installed,
  or transferred to a production system.
- API keys must never be committed to git, printed to logs, or included in any report.

---

## 11. Approval Required Before Phase 4F.2

The following decisions require explicit sign-off before any download or expansion begins:

| # | Decision | Current Proposed Value | Status |
|---|----------|----------------------|--------|
| D1 | Malware VT threshold | >= 20 | PENDING APPROVAL |
| D2 | Benign VT threshold | = 0 | PENDING APPROVAL |
| D3 | Gray zone (excluded) | 1–19 | PENDING APPROVAL |
| D4 | Max VT scan staleness (benign) | 24 months | PENDING APPROVAL |
| D5 | Max VT scan staleness (malware) | 36 months | PENDING APPROVAL |
| D6 | Temporal holdout cutoff | dex_date >= 2022-01-01 | PENDING APPROVAL |
| D7 | MalEval re-inclusion path | Excluded until provenance verified | PENDING APPROVAL |
