#!/usr/bin/env python3
"""
final_svm_validation.py — Phase 5E final validation of the Combined SVM candidate.

Steps:
  1. Reproducibility check — re-run seed=42 CV, verify metrics match reported values
  2. Multi-seed validation — 5 seeds: [42, 123, 2026, 31415, 777]
  3. Confusion matrix summary
  4. SVM output mechanism audit
  5. Dataset sanity check
  6. Overfitting assessment
  7. Production recommendation
  8. Write production_candidate_validation.md

GUARANTEES:
  - Does NOT replace the production model.
  - Does NOT modify any dataset.
  - Does NOT modify the feature extractor or risk engine.
"""

from __future__ import annotations

import json
import math
import sys
from pathlib import Path
from typing import Any, Dict, List, Tuple

import numpy as np
import pandas as pd
from sklearn.metrics import confusion_matrix
from sklearn.model_selection import StratifiedKFold, cross_val_predict, cross_validate
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler
from sklearn.svm import SVC

# ── Paths ──────────────────────────────────────────────────────────────────
BACKEND_DIR  = Path(__file__).resolve().parent.parent
PROJECT_ROOT = BACKEND_DIR.parent

COMBINED_CSV = PROJECT_ROOT / "data" / "processed" / "combined_training_data.csv"
EVAL_DIR     = PROJECT_ROOT / "data" / "model_candidates"
REPORT_MD    = EVAL_DIR / "production_candidate_validation.md"
REPORT_JSON  = EVAL_DIR / "final_validation_results.json"

FEAT_PREFIX  = "feat_"
META_COLS    = {"apk_name", "sha256", "label", "source"}

SEEDS        = [42, 123, 2026, 31415, 777]
N_FOLDS      = 5
SCORING      = ["accuracy", "precision", "recall", "f1", "roc_auc"]
W            = 70

# Previously reported results to check reproducibility against
REPORTED     = {
    "accuracy":  0.900,
    "precision": 0.880,
    "recall":    0.934,
    "f1":        0.905,
    "roc_auc":   0.946,
    "fn":        8,
}


# ─────────────────────────────────────────────────────────────────────────────
def make_svm_pipeline(seed: int) -> Pipeline:
    """Exact same pipeline as used in expanded_evaluation.py."""
    return Pipeline([
        ("scaler", StandardScaler()),
        ("clf",    SVC(probability=True, random_state=seed)),
    ])


def run_cv(X: np.ndarray, y: np.ndarray, seed: int) -> Dict[str, Any]:
    """Run 5-fold stratified CV with the given seed. Return per-metric results + CM."""
    cv     = StratifiedKFold(n_splits=N_FOLDS, shuffle=True, random_state=seed)
    pipe   = make_svm_pipeline(seed)

    cv_out = cross_validate(pipe, X, y, cv=cv, scoring=SCORING, return_train_score=False)
    y_pred = cross_val_predict(pipe, X, y, cv=cv)
    cm     = confusion_matrix(y, y_pred, labels=[0, 1])
    tn, fp, fn, tp = cm.ravel()

    result = {
        "seed":  seed,
        "tn":    int(tn), "fp": int(fp), "fn": int(fn), "tp": int(tp),
        "metrics": {},
    }
    for metric in SCORING:
        folds = cv_out[f"test_{metric}"]
        result["metrics"][metric] = {
            "mean": float(np.mean(folds)),
            "std":  float(np.std(folds)),
            "folds": [float(v) for v in folds],
        }
    return result


# ─────────────────────────────────────────────────────────────────────────────
# STEP 1 — Reproducibility
# ─────────────────────────────────────────────────────────────────────────────

def step1_reproducibility(X: np.ndarray, y: np.ndarray) -> Tuple[Dict, bool]:
    print(f"\n── STEP 1: REPRODUCIBILITY CHECK (seed=42) ─────────────────────────")
    res   = run_cv(X, y, seed=42)
    m     = res["metrics"]
    tol   = 0.002  # tolerance for floating-point reproduction

    all_ok = True
    print(f"  {'Metric':<12}  {'Reported':>9}  {'Reproduced':>10}  {'Diff':>6}  {'OK?':>4}")
    print(f"  {'-'*12}  {'-'*9}  {'-'*10}  {'-'*6}  {'-'*4}")
    for metric in ["accuracy", "precision", "recall", "f1", "roc_auc"]:
        reported  = REPORTED[metric]
        reproduced = m[metric]["mean"]
        diff       = abs(reported - reproduced)
        ok         = diff <= tol
        if not ok:
            all_ok = False
        print(f"  {metric:<12}  {reported:>9.3f}  {reproduced:>10.3f}  {diff:>6.4f}  {'✅' if ok else '⚠️ '}")

    # FN check
    fn_ok = (res["fn"] == REPORTED["fn"])
    print(f"  {'FN count':<12}  {REPORTED['fn']:>9}  {res['fn']:>10}  {'':>6}  {'✅' if fn_ok else '⚠️ DIFF'}")

    print(f"\n  {'Reproducibility: PASSED ✅' if all_ok and fn_ok else 'Reproducibility: DIVERGED ⚠️'}")
    return res, (all_ok and fn_ok)


# ─────────────────────────────────────────────────────────────────────────────
# STEP 2 — Multi-Seed Validation
# ─────────────────────────────────────────────────────────────────────────────

def step2_multi_seed(X: np.ndarray, y: np.ndarray) -> List[Dict]:
    print(f"\n── STEP 2: MULTI-SEED VALIDATION ───────────────────────────────────")
    print(f"  Seeds: {SEEDS}")
    print(f"\n  {'Seed':>6}  {'Acc':>6}  {'Prec':>6}  {'Rec':>6}  {'F1':>6}  {'AUC':>6}  {'FP':>4}  {'FN':>4}")
    print(f"  {'-'*6}  {'-'*6}  {'-'*6}  {'-'*6}  {'-'*6}  {'-'*6}  {'-'*4}  {'-'*4}")

    all_results = []
    for seed in SEEDS:
        r = run_cv(X, y, seed)
        m = r["metrics"]
        print(f"  {seed:>6}  "
              f"{m['accuracy']['mean']:>6.3f}  "
              f"{m['precision']['mean']:>6.3f}  "
              f"{m['recall']['mean']:>6.3f}  "
              f"{m['f1']['mean']:>6.3f}  "
              f"{m['roc_auc']['mean']:>6.3f}  "
              f"{r['fp']:>4}  {r['fn']:>4}")
        all_results.append(r)

    # Aggregate statistics
    recalls = [r["metrics"]["recall"]["mean"] for r in all_results]
    f1s     = [r["metrics"]["f1"]["mean"]     for r in all_results]
    aucs    = [r["metrics"]["roc_auc"]["mean"] for r in all_results]
    accs    = [r["metrics"]["accuracy"]["mean"] for r in all_results]

    print(f"\n  {'Metric':<12}  {'Mean':>7}  {'Std':>6}  {'Min':>7}  {'Max':>7}")
    print(f"  {'-'*12}  {'-'*7}  {'-'*6}  {'-'*7}  {'-'*7}")
    for label, vals in [("Recall", recalls), ("F1", f1s), ("AUC", aucs), ("Accuracy", accs)]:
        print(f"  {label:<12}  {np.mean(vals):>7.3f}  {np.std(vals):>6.4f}  "
              f"{min(vals):>7.3f}  {max(vals):>7.3f}")

    return all_results


# ─────────────────────────────────────────────────────────────────────────────
# STEP 3 — Confusion Matrix
# ─────────────────────────────────────────────────────────────────────────────

def step3_confusion_matrix(seed42_res: Dict, all_seed_results: List[Dict]) -> None:
    print(f"\n── STEP 3: CONFUSION MATRIX (seed=42, aggregated across 5 folds) ──")
    r = seed42_res
    print(f"  True  Positives (TP — malware caught)   : {r['tp']}")
    print(f"  True  Negatives (TN — benign correct)   : {r['tn']}")
    print(f"  False Positives (FP — benign as malware): {r['fp']}")
    print(f"  False Negatives (FN — malware missed)   : {r['fn']}")
    total_malware = r["tp"] + r["fn"]
    total_benign  = r["tn"] + r["fp"]
    print(f"\n  Total malware samples tested : {total_malware}")
    print(f"  Total benign  samples tested : {total_benign}")
    print(f"\n  Malware detection rate (Recall)   : {r['tp']}/{total_malware} = "
          f"{r['tp']/total_malware*100:.1f}%")
    print(f"  Malware missed  (FN rate)         : {r['fn']}/{total_malware} = "
          f"{r['fn']/total_malware*100:.1f}%")
    print(f"  Benign false-alarm rate (FP rate) : {r['fp']}/{total_benign} = "
          f"{r['fp']/total_benign*100:.1f}%")
    print(f"\n  Interpretation:")
    print(f"    {r['fn']} out of {total_malware} malware APKs passed undetected.")
    print(f"    {r['fp']} out of {total_benign} benign APKs were incorrectly flagged.")
    print(f"    For a malware detector, missing {r['fn']} samples is the critical risk.")


# ─────────────────────────────────────────────────────────────────────────────
# STEP 4 — SVM Output Mechanism Audit
# ─────────────────────────────────────────────────────────────────────────────

def step4_svm_output_audit() -> Dict[str, str]:
    print(f"\n── STEP 4: SVM OUTPUT MECHANISM AUDIT ──────────────────────────────")

    svm_notes = {
        "training_pipeline_svm":
            "SVC(probability=True, random_state=42) wrapped in Pipeline([StandardScaler, SVC]).",

        "probability_mechanism":
            "SVC with probability=True uses Platt scaling (cross-validated logistic "
            "regression fitted on the decision_function scores). This produces "
            "predict_proba() → [[p_benign, p_malicious]].",

        "production_ml_engine_current_model":
            "ml_engine.py currently loads model_rf_v1.pkl (Random Forest). "
            "It calls model.predict_proba(X)[0] and uses classes_ to identify "
            "p_benign and p_malicious. Threshold is 0.5.",

        "svm_compatibility_with_ml_engine":
            "SVC(probability=True) exposes predict_proba() and classes_, identical "
            "interface to RandomForestClassifier. The ml_engine.py code would work "
            "unchanged with an SVM artifact — it only calls predict_proba() and "
            "reads .classes_.",

        "calibration_note":
            "Platt scaling in SVC(probability=True) is a form of probability "
            "calibration, but it is not isotonic calibration or Venn-prediction. "
            "For a small dataset (241 samples) the probabilities may not be perfectly "
            "calibrated. Isotonic regression or CalibratedClassifierCV could improve "
            "probability estimates in a future iteration — but should not be added "
            "automatically. This is flagged as a potential future improvement.",

        "current_threshold":
            "The production threshold in ml_engine.py is 0.5 (p_malicious >= 0.5 → "
            "'malicious'). Lowering this threshold would increase Recall at the cost "
            "of Precision. This is a product decision, not an engineering one.",

        "risk_engine_integration":
            "ml_engine.py returns a dict with probability_malicious, confidence, and "
            "prediction. The risk engine reads this dict independently — the SVM "
            "candidate would slot in without changing the risk engine or frontend.",

        "what_must_change_for_promotion":
            "Only one file changes: the model file at backend/app/ml/model_rf_v1.pkl "
            "must be replaced with the SVM artifact (serialized via joblib). The "
            "MODEL_VERSION constant in ml_engine.py should be updated (e.g., "
            "'svm-combined-v1.0') for audit traceability.",
    }

    for key, val in svm_notes.items():
        print(f"\n  [{key}]")
        print(f"    {val}")

    return svm_notes


# ─────────────────────────────────────────────────────────────────────────────
# STEP 5 — Dataset Sanity
# ─────────────────────────────────────────────────────────────────────────────

def step5_sanity(df: pd.DataFrame, feat_cols: List[str],
                 maleval_csv: Path, androzoo_csv: Path) -> Dict[str, Any]:
    print(f"\n── STEP 5: DATASET SANITY CHECK ─────────────────────────────────────")

    n        = len(df)
    benign   = int((df["label"] == 0).sum())
    malware  = int((df["label"] == 1).sum())
    n_feats  = len(feat_cols)
    nan_cnt  = int(df[feat_cols].isnull().sum().sum())
    inf_cnt  = int(np.isinf(df[feat_cols].values.astype(float)).sum())
    miss_cnt = int((df[feat_cols] == "").sum().sum()) if df[feat_cols].dtypes.eq(object).any() else 0

    # Cross-dataset SHA-256 collision
    maleval_hashes  = set(pd.read_csv(maleval_csv)["sha256"].str.lower()) if maleval_csv.is_file() else set()
    androzoo_hashes = set(pd.read_csv(androzoo_csv)["sha256"].str.lower()) if androzoo_csv.is_file() else set()
    combined_hashes = set(df["sha256"].str.lower())
    cross_collision = len(maleval_hashes & androzoo_hashes)

    checks = {
        "rows":           (n == 241, n, 241),
        "benign":         (benign == 120, benign, 120),
        "malware":        (malware == 121, malware, 121),
        "feature_count":  (n_feats == 47, n_feats, 47),
        "nan":            (nan_cnt == 0, nan_cnt, 0),
        "inf":            (inf_cnt == 0, inf_cnt, 0),
        "missing":        (miss_cnt == 0, miss_cnt, 0),
        "sha256_cross_collision": (cross_collision == 0, cross_collision, 0),
        "sha256_internal_dups":   (df["sha256"].nunique() == n, df["sha256"].nunique(), n),
    }

    all_ok = True
    print(f"  {'Check':<30}  {'Expected':>10}  {'Actual':>10}  {'OK?':>4}")
    print(f"  {'-'*30}  {'-'*10}  {'-'*10}  {'-'*4}")
    for check_name, (ok, actual, expected) in checks.items():
        if not ok:
            all_ok = False
        print(f"  {check_name:<30}  {str(expected):>10}  {str(actual):>10}  {'✅' if ok else '❌'}")

    print(f"\n  Dataset sanity: {'PASSED ✅' if all_ok else 'FAILED ❌'}")
    return {k: {"ok": v[0], "actual": v[1], "expected": v[2]} for k, v in checks.items()}


# ─────────────────────────────────────────────────────────────────────────────
# STEP 6 — Overfitting Assessment
# ─────────────────────────────────────────────────────────────────────────────

def step6_overfitting(all_seed_results: List[Dict]) -> Dict[str, Any]:
    print(f"\n── STEP 6: OVERFITTING / STABILITY ASSESSMENT ───────────────────────")

    recalls = [r["metrics"]["recall"]["mean"] for r in all_seed_results]
    f1s     = [r["metrics"]["f1"]["mean"] for r in all_seed_results]
    accs    = [r["metrics"]["accuracy"]["mean"] for r in all_seed_results]
    aucs    = [r["metrics"]["roc_auc"]["mean"] for r in all_seed_results]

    recall_std = float(np.std(recalls))
    recall_rng = max(recalls) - min(recalls)
    f1_std     = float(np.std(f1s))

    INSTABILITY_THRESHOLD = 0.05  # >5pp std on recall would be flagged

    flags = []
    if recall_std > INSTABILITY_THRESHOLD:
        flags.append(f"Recall std={recall_std:.4f} exceeds {INSTABILITY_THRESHOLD} — UNSTABLE")
    if recall_rng > 0.10:
        flags.append(f"Recall range={recall_rng:.4f} exceeds 10pp — HIGH VARIANCE")
    if min(recalls) < 0.80:
        flags.append(f"Min recall={min(recalls):.3f} drops below 80% — COLLAPSE RISK")

    print(f"  Recall across seeds  : {[f'{r:.3f}' for r in recalls]}")
    print(f"  Recall std           : {recall_std:.4f}  (threshold={INSTABILITY_THRESHOLD})")
    print(f"  Recall range (max-min): {recall_rng:.4f}")
    print(f"  F1 std               : {f1_std:.4f}")
    print(f"\n  Stability flags      : {flags if flags else 'None — STABLE ✅'}")
    print(f"\n  Caveats:")
    print(f"    - All evaluation is done on the training distribution (no true holdout).")
    print(f"    - 241 samples is still a small dataset; real-world recall may differ.")
    print(f"    - Cross-validation provides an unbiased estimate but cannot substitute")
    print(f"      for external validation on unseen, independently collected APKs.")
    print(f"    - Source domain difference (MalEval=academic, AndroZoo=production)")
    print(f"      is not fully controlled; per-source evaluation recommended post-deploy.")

    return {
        "recall_values":   recalls,
        "recall_mean":     float(np.mean(recalls)),
        "recall_std":      recall_std,
        "recall_min":      float(min(recalls)),
        "recall_max":      float(max(recalls)),
        "f1_std":          f1_std,
        "stability_flags": flags,
        "stable":          len(flags) == 0,
    }


# ─────────────────────────────────────────────────────────────────────────────
# STEP 7 — Production Recommendation
# ─────────────────────────────────────────────────────────────────────────────

def step7_recommendation(stability: Dict, repro_ok: bool, sanity_ok: bool) -> str:
    print(f"\n── STEP 7: PRODUCTION RECOMMENDATION ───────────────────────────────")

    stable      = stability["stable"]
    min_recall  = stability["recall_min"]
    mean_recall = stability["recall_mean"]

    all_pass = repro_ok and sanity_ok and stable and min_recall >= 0.85

    if all_pass:
        decision = "A"
        label    = "A — PROMOTE Combined SVM as production candidate"
    else:
        decision = "C"
        label    = "C — Additional validation required"

    print(f"\n  Reproducibility passed : {repro_ok}")
    print(f"  Dataset sanity passed  : {sanity_ok}")
    print(f"  Stability (multi-seed) : {stable}")
    print(f"  Min recall (≥0.85)     : {min_recall:.3f}  → {'✅' if min_recall >= 0.85 else '❌'}")
    print(f"\n  Decision: {label}")

    if decision == "A":
        print(f"""
  ── PROMOTION PREREQUISITES ────────────────────────────────────
  Candidate artifact : data/model_candidates/eval_candidate_combined_svm.pkl
  Required feature order: FEATURE_NAMES from feature_extractor.py (47 features, exact order)
  Preprocessing: StandardScaler fitted at training time (inside Pipeline — already included)
  Model loading: joblib.load(artifact_path) → Pipeline object
  Inference: pipeline.predict_proba(X)[0] → [p_benign, p_malicious]
  classes_ order: [0, 1] (benign=0, malicious=1)
  Target file: backend/app/ml/model_rf_v1.pkl  (replace with SVM artifact)
  ml_engine.py change: Update MODEL_VERSION = "svm-combined-v1.0"
  No other files need to change (risk engine, frontend, feature extractor untouched).

  ⛔ DO NOT perform this replacement until explicitly instructed.
""")

    return decision


# ─────────────────────────────────────────────────────────────────────────────
# STEP 8 — Write Markdown Report
# ─────────────────────────────────────────────────────────────────────────────

def step8_write_report(
    repro_res:    Dict,
    repro_ok:     bool,
    all_seed_res: List[Dict],
    stability:    Dict,
    svm_notes:    Dict,
    sanity:       Dict,
    decision:     str,
) -> None:

    recalls = [r["metrics"]["recall"]["mean"] for r in all_seed_res]
    f1s     = [r["metrics"]["f1"]["mean"] for r in all_seed_res]
    aucs    = [r["metrics"]["roc_auc"]["mean"] for r in all_seed_res]
    accs    = [r["metrics"]["accuracy"]["mean"] for r in all_seed_res]

    r42 = repro_res

    md = f"""# Production Candidate Validation Report
## Combined SVM — Phase 5E Final Validation

**Candidate:** SVM on Combined Dataset (241 samples, 47 features)
**Evaluation:** Stratified 5-Fold CV, 5 seeds, seed=42 reproducibility check
**Models NOT replaced.** This is a validation report only.

---

## 1. Reproducibility Result (seed=42)

| Metric | Reported | Reproduced | Diff | OK? |
|--------|---------|-----------|------|-----|
| Accuracy | {REPORTED['accuracy']:.3f} | {repro_res['metrics']['accuracy']['mean']:.3f} | {abs(REPORTED['accuracy']-repro_res['metrics']['accuracy']['mean']):.4f} | {'✅' if abs(REPORTED['accuracy']-repro_res['metrics']['accuracy']['mean'])<=0.002 else '⚠️'} |
| Precision | {REPORTED['precision']:.3f} | {repro_res['metrics']['precision']['mean']:.3f} | {abs(REPORTED['precision']-repro_res['metrics']['precision']['mean']):.4f} | {'✅' if abs(REPORTED['precision']-repro_res['metrics']['precision']['mean'])<=0.002 else '⚠️'} |
| Recall | {REPORTED['recall']:.3f} | {repro_res['metrics']['recall']['mean']:.3f} | {abs(REPORTED['recall']-repro_res['metrics']['recall']['mean']):.4f} | {'✅' if abs(REPORTED['recall']-repro_res['metrics']['recall']['mean'])<=0.002 else '⚠️'} |
| F1 | {REPORTED['f1']:.3f} | {repro_res['metrics']['f1']['mean']:.3f} | {abs(REPORTED['f1']-repro_res['metrics']['f1']['mean']):.4f} | {'✅' if abs(REPORTED['f1']-repro_res['metrics']['f1']['mean'])<=0.002 else '⚠️'} |
| AUC | {REPORTED['roc_auc']:.3f} | {repro_res['metrics']['roc_auc']['mean']:.3f} | {abs(REPORTED['roc_auc']-repro_res['metrics']['roc_auc']['mean']):.4f} | {'✅' if abs(REPORTED['roc_auc']-repro_res['metrics']['roc_auc']['mean'])<=0.002 else '⚠️'} |
| FN count | {REPORTED['fn']} | {repro_res['fn']} | — | {'✅' if repro_res['fn']==REPORTED['fn'] else '⚠️'} |

**Reproducibility: {'PASSED ✅' if repro_ok else 'DIVERGED ⚠️'}**

---

## 2. Multi-Seed Validation Results

| Seed | Accuracy | Precision | Recall | F1 | AUC | FP | FN |
|------|----------|-----------|--------|-----|-----|----|----|
"""
    for r in all_seed_res:
        m = r["metrics"]
        md += (f"| {r['seed']} | {m['accuracy']['mean']:.3f} | {m['precision']['mean']:.3f} | "
               f"{m['recall']['mean']:.3f} | {m['f1']['mean']:.3f} | {m['roc_auc']['mean']:.3f} | "
               f"{r['fp']} | {r['fn']} |\n")

    md += f"""
---

## 3. Mean/Std/Min/Max Recall & Key Metrics

| Metric | Mean | Std | Min | Max |
|--------|------|-----|-----|-----|
| Recall | {np.mean(recalls):.3f} | {np.std(recalls):.4f} | {min(recalls):.3f} | {max(recalls):.3f} |
| F1 | {np.mean(f1s):.3f} | {np.std(f1s):.4f} | {min(f1s):.3f} | {max(f1s):.3f} |
| AUC | {np.mean(aucs):.3f} | {np.std(aucs):.4f} | {min(aucs):.3f} | {max(aucs):.3f} |
| Accuracy | {np.mean(accs):.3f} | {np.std(accs):.4f} | {min(accs):.3f} | {max(accs):.3f} |

---

## 4. Confusion Matrix (seed=42, aggregated 5-fold)

| | Predicted Benign | Predicted Malware |
|-|-----------------|-----------------|
| **Actual Benign** | TN = {r42['tn']} | FP = {r42['fp']} |
| **Actual Malware** | FN = **{r42['fn']}** | TP = {r42['tp']} |

- **{r42['tp']}/{r42['tp']+r42['fn']} malware APKs detected** ({r42['tp']/(r42['tp']+r42['fn'])*100:.1f}% recall)
- **{r42['fn']}/{r42['tp']+r42['fn']} malware APKs missed** — these would pass undetected
- **{r42['fp']}/{r42['tn']+r42['fp']} benign APKs false-alarmed** — would cause user friction

---

## 5. SVM Output Mechanism

| Aspect | Detail |
|--------|--------|
| SVM class | `SVC(probability=True)` |
| Probability method | Platt scaling (fitted via internal cross-validation on `decision_function` scores) |
| Output interface | `predict_proba(X)` → `[[p_benign, p_malicious]]` |
| `classes_` order | `[0, 1]` — identical to Random Forest |
| Compatibility with `ml_engine.py` | **Yes — no changes needed** to the inference code |
| Current production model interface | `model.predict_proba(X)[0]` + `model.classes_` (same API) |
| Classification threshold | `p_malicious >= 0.5` → `"malicious"` (defined in `ml_engine.py`) |
| Probability calibration | Platt scaling is included. Isotonic regression / `CalibratedClassifierCV` could improve probability estimates in a future iteration. **Not added automatically.** |

---

## 6. Dataset Sanity Check

| Check | Expected | Actual | OK? |
|-------|----------|--------|-----|
| Total rows | 241 | {sanity['rows']['actual']} | {'✅' if sanity['rows']['ok'] else '❌'} |
| Benign samples | 120 | {sanity['benign']['actual']} | {'✅' if sanity['benign']['ok'] else '❌'} |
| Malware samples | 121 | {sanity['malware']['actual']} | {'✅' if sanity['malware']['ok'] else '❌'} |
| Feature columns | 47 | {sanity['feature_count']['actual']} | {'✅' if sanity['feature_count']['ok'] else '❌'} |
| NaN values | 0 | {sanity['nan']['actual']} | {'✅' if sanity['nan']['ok'] else '❌'} |
| Inf values | 0 | {sanity['inf']['actual']} | {'✅' if sanity['inf']['ok'] else '❌'} |
| Missing values | 0 | {sanity['missing']['actual']} | {'✅' if sanity['missing']['ok'] else '❌'} |
| Cross-dataset SHA-256 collisions | 0 | {sanity['sha256_cross_collision']['actual']} | {'✅' if sanity['sha256_cross_collision']['ok'] else '❌'} |
| Internal SHA-256 duplicates | 241 | {sanity['sha256_internal_dups']['actual']} | {'✅' if sanity['sha256_internal_dups']['ok'] else '❌'} |

---

## 7. Overfitting Assessment

- **Recall std across seeds:** {stability['recall_std']:.4f} (threshold = 0.05)
- **Recall range (max−min):** {stability['recall_max']-stability['recall_min']:.4f}
- **Stability flags:** {stability['stability_flags'] if stability['stability_flags'] else 'None — STABLE ✅'}

**Caveats:**
- All evaluation is within the training distribution — no true external holdout.
- 241 samples is a small dataset; real-world recall may differ from CV estimates.
- Source domain difference (MalEval=academic/vetted, AndroZoo=production) is not controlled.
- Per-source evaluation is recommended as a post-promotion monitoring step.

---

## 8. Promotion Prerequisites (if approved)

| Item | Value |
|------|-------|
| Candidate artifact | `data/model_candidates/eval_candidate_combined_svm.pkl` |
| Required feature order | `FEATURE_NAMES` from `feature_extractor.py` (47, exact order) |
| Preprocessing | `StandardScaler` (fitted, included inside the Pipeline artifact) |
| Model loading | `joblib.load(path)` → `Pipeline` |
| Inference call | `pipeline.predict_proba(X)[0]` → `[p_benign, p_malicious]` |
| `classes_` | `[0, 1]` |
| Target production file | `backend/app/ml/model_rf_v1.pkl` ← replace with SVM artifact |
| `ml_engine.py` change | Update `MODEL_VERSION = "svm-combined-v1.0"` |
| Risk engine | **No changes** |
| Frontend | **No changes** |
| Feature extractor | **No changes** |

---

## 9. Decision

**Decision: {'A — PROMOTE Combined SVM as production candidate' if decision == 'A' else 'C — Additional validation required'}**

{'All validation gates passed: reproducibility ✅, sanity ✅, stability ✅, min recall ≥ 85% ✅' if decision=='A' else 'One or more validation gates failed — see flags above.'}

> ⛔ **The production model has NOT been replaced.** This report documents the candidate and its prerequisites. Promotion must be explicitly instructed.

---

*Generated by `final_svm_validation.py` — Phase 5E Final Validation*
"""

    with open(REPORT_MD, "w") as f:
        f.write(md)
    print(f"\n  Markdown report saved: {REPORT_MD}")


# ─────────────────────────────────────────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────────────────────────────────────────

def main():
    print("=" * W)
    print("FRAUDGUARD-AI — PHASE 5E FINAL SVM VALIDATION")
    print("=" * W)

    if not COMBINED_CSV.is_file():
        print(f"ERROR: Combined CSV not found at {COMBINED_CSV}")
        sys.exit(1)

    df        = pd.read_csv(COMBINED_CSV)
    feat_cols = [c for c in df.columns if c.startswith(FEAT_PREFIX)]
    X         = df[feat_cols].values.astype(float)
    y         = df["label"].values.astype(int)

    # Step 1
    repro_res, repro_ok = step1_reproducibility(X, y)

    # Step 2
    all_seed_res = step2_multi_seed(X, y)

    # Step 3
    step3_confusion_matrix(repro_res, all_seed_res)

    # Step 4
    svm_notes = step4_svm_output_audit()

    # Step 5
    MALEVAL_CSV  = BACKEND_DIR / "scripts" / "training_data.csv"
    ANDROZOO_CSV = BACKEND_DIR / "scripts" / "androzoo_training_data.csv"
    sanity = step5_sanity(df, feat_cols, MALEVAL_CSV, ANDROZOO_CSV)
    sanity_ok = all(v["ok"] for v in sanity.values())

    # Step 6
    stability = step6_overfitting(all_seed_res)

    # Step 7
    decision = step7_recommendation(stability, repro_ok, sanity_ok)

    # Step 8
    step8_write_report(repro_res, repro_ok, all_seed_res, stability, svm_notes, sanity, decision)

    # Save JSON
    payload = {
        "repro_ok":        repro_ok,
        "repro_result":    repro_res,
        "multi_seed":      all_seed_res,
        "stability":       stability,
        "svm_notes":       svm_notes,
        "sanity":          sanity,
        "decision":        decision,
    }
    with open(REPORT_JSON, "w") as f:
        json.dump(payload, f, indent=2, default=str)
    print(f"  JSON report saved: {REPORT_JSON}")

    print("\n" + "=" * W)
    print("STOP — Validation complete. Production model NOT replaced.")
    print("=" * W)


if __name__ == "__main__":
    main()
