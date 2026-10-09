#!/usr/bin/env python3
"""
expanded_evaluation.py — Steps 1-9 of the expanded dataset evaluation.

Steps:
  1. Combine MalEval + AndroZoo → combined_training_data.csv (verified, deduplicated)
  2. Reproduce MalEval baseline (exact same methodology as baseline_experiment.py)
  3. Evaluate AndroZoo-only dataset
  4. Evaluate Combined dataset
  5. Build full metrics comparison table
  6. Malware-detection priority analysis (Recall → F1 → Precision → Accuracy)
  7. Constant-feature secondary experiment (identify globals, test removal impact)
  8. Save evaluation model artifacts (separate from production)
  9. Write full JSON report + print summary

GUARANTEES:
  - Does NOT replace the production model.
  - Does NOT modify training_data.csv or androzoo_training_data.csv.
  - Does NOT modify the feature extractor.
  - Does NOT modify the risk engine or frontend.
  - All preprocessing (StandardScaler) is fitted inside each CV fold via Pipeline.
  - Fixed random seed (42) throughout for reproducibility.
"""

from __future__ import annotations

import json
import pickle
import sys
from pathlib import Path
from typing import Any, Dict, List, Tuple

import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import confusion_matrix
from sklearn.model_selection import StratifiedKFold, cross_val_predict, cross_validate
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler
from sklearn.svm import SVC

# ── Paths ──────────────────────────────────────────────────────────────────
BACKEND_DIR  = Path(__file__).resolve().parent.parent
PROJECT_ROOT = BACKEND_DIR.parent

MALEVAL_CSV  = BACKEND_DIR / "scripts" / "training_data.csv"
ANDROZOO_CSV = BACKEND_DIR / "scripts" / "androzoo_training_data.csv"
COMBINED_CSV = PROJECT_ROOT / "data" / "processed" / "combined_training_data.csv"

# Evaluation artifacts go here — NOT in the production model directory
EVAL_DIR     = PROJECT_ROOT / "data" / "model_candidates"
REPORT_JSON  = EVAL_DIR / "evaluation_results.json"
REPORT_TXT   = EVAL_DIR / "evaluation_report.txt"

EVAL_DIR.mkdir(parents=True, exist_ok=True)

# ── Constants ─────────────────────────────────────────────────────────────
SEED         = 42
N_FOLDS      = 5
SCORING      = ["accuracy", "precision", "recall", "f1", "roc_auc"]
META_COLS    = {"apk_name", "sha256", "label", "source"}   # never features
W            = 70  # report width


# ─────────────────────────────────────────────────────────────────────────────
# STEP 1 — COMBINE DATASETS
# ─────────────────────────────────────────────────────────────────────────────

def combine_datasets() -> pd.DataFrame:
    """
    Combine MalEval + AndroZoo, deduplicate by SHA-256, verify integrity.
    Writes combined_training_data.csv. Returns DataFrame.
    Does NOT overwrite either source CSV.
    """
    print("\n── STEP 1: COMBINING DATASETS ──────────────────────────────────────")

    mal_df = pd.read_csv(MALEVAL_CSV)
    az_df  = pd.read_csv(ANDROZOO_CSV)

    # Standardize: ensure source column exists
    if "source" not in mal_df.columns:
        mal_df["source"] = "maleval"
    else:
        mal_df["source"] = mal_df["source"].fillna("maleval")

    az_df["source"] = az_df.get("source", pd.Series(["androzoo"] * len(az_df)))

    # Identify feature columns (same in both — already verified by quality comparison)
    feat_cols = [c for c in mal_df.columns if c.startswith("feat_")]

    # Align column order to MalEval
    common_cols = ["apk_name", "sha256", "label", "source"] + feat_cols

    for df_name, df in [("MalEval", mal_df), ("AndroZoo", az_df)]:
        missing = [c for c in common_cols if c not in df.columns]
        if missing:
            print(f"  ERROR: {df_name} is missing columns: {missing}")
            sys.exit(1)

    mal_aligned = mal_df[common_cols].copy()
    az_aligned  = az_df[common_cols].copy()

    combined = pd.concat([mal_aligned, az_aligned], ignore_index=True)

    # Deduplicate by SHA-256 (keep first occurrence)
    before = len(combined)
    combined = combined.drop_duplicates(subset=["sha256"], keep="first")
    deduped  = before - len(combined)

    # Integrity checks
    assert combined["label"].isin([0, 1]).all(),   "Invalid labels in combined!"
    assert combined[feat_cols].isnull().sum().sum() == 0, "NaN in combined features!"
    assert np.isinf(combined[feat_cols].values.astype(float)).sum() == 0, "Inf in combined features!"
    assert len(feat_cols) == 47,                   f"Expected 47 features, got {len(feat_cols)}!"

    n       = len(combined)
    benign  = int((combined["label"] == 0).sum())
    malware = int((combined["label"] == 1).sum())
    az_src  = int((combined["source"] == "androzoo").sum())
    mal_src = int((combined["source"] == "maleval").sum())

    # Write combined CSV
    combined.to_csv(COMBINED_CSV, index=False)

    print(f"  MalEval rows                 : {len(mal_df)}")
    print(f"  AndroZoo rows                : {len(az_df)}")
    print(f"  SHA-256 duplicates removed   : {deduped}")
    print(f"  Combined total rows          : {n}")
    print(f"  Benign (label=0)             : {benign}")
    print(f"  Malware (label=1)            : {malware}")
    print(f"  From MalEval source          : {mal_src}")
    print(f"  From AndroZoo source         : {az_src}")
    print(f"  Feature columns              : {len(feat_cols)}")
    print(f"  Written to                   : {COMBINED_CSV}")

    return combined, feat_cols


# ─────────────────────────────────────────────────────────────────────────────
# Model factory
# ─────────────────────────────────────────────────────────────────────────────

def make_models() -> Dict[str, Pipeline]:
    """Return fresh Pipeline instances — identical methodology to baseline_experiment.py."""
    return {
        "Logistic Regression": Pipeline([
            ("scaler", StandardScaler()),
            ("clf",    LogisticRegression(random_state=SEED, max_iter=1000)),
        ]),
        "Random Forest": Pipeline([
            ("scaler", StandardScaler()),
            ("clf",    RandomForestClassifier(random_state=SEED)),
        ]),
        "SVM": Pipeline([
            ("scaler", StandardScaler()),
            ("clf",    SVC(probability=True, random_state=SEED)),
        ]),
    }


# ─────────────────────────────────────────────────────────────────────────────
# STEPS 2-4 — EVALUATE A SINGLE DATASET
# ─────────────────────────────────────────────────────────────────────────────

def evaluate_dataset(
    label: str,
    df: pd.DataFrame,
    feat_cols: List[str],
    save_artifacts: bool = False,
) -> Dict[str, Any]:
    """
    Run stratified 5-fold CV for each of the 3 model types on the given dataset.
    Returns a dict of results.
    """
    print(f"\n── EVALUATING: {label.upper()} ─────────────────────────────────────────")
    n       = len(df)
    benign  = int((df["label"] == 0).sum())
    malware = int((df["label"] == 1).sum())
    print(f"  Samples: {n}  (Benign={benign}, Malware={malware})")

    X = df[feat_cols].values.astype(float)
    y = df["label"].values.astype(int)

    cv      = StratifiedKFold(n_splits=N_FOLDS, shuffle=True, random_state=SEED)
    models  = make_models()
    results = {
        "dataset":        label,
        "n":              n,
        "benign":         benign,
        "malware":        malware,
        "feature_count":  len(feat_cols),
        "cv_folds":       N_FOLDS,
        "models":         {},
    }

    for mname, pipeline in models.items():
        cv_out  = cross_validate(pipeline, X, y, cv=cv, scoring=SCORING, return_train_score=False)
        y_pred  = cross_val_predict(pipeline, X, y, cv=cv)
        cm      = confusion_matrix(y, y_pred, labels=[0, 1])

        tn, fp, fn, tp = cm.ravel()
        model_res = {
            "confusion_matrix": cm.tolist(),
            "tn": int(tn), "fp": int(fp), "fn": int(fn), "tp": int(tp),
            "metrics": {},
        }

        for metric in SCORING:
            fold_scores = cv_out[f"test_{metric}"]
            model_res["metrics"][metric] = {
                "mean": float(np.mean(fold_scores)),
                "std":  float(np.std(fold_scores)),
                "folds": [float(s) for s in fold_scores],
            }

        m = model_res["metrics"]
        print(f"  {mname:<22}  Acc={m['accuracy']['mean']:.3f}  "
              f"Prec={m['precision']['mean']:.3f}  "
              f"Rec={m['recall']['mean']:.3f}  "
              f"F1={m['f1']['mean']:.3f}  "
              f"AUC={m['roc_auc']['mean']:.3f}  "
              f"FN={fn}")

        results["models"][mname] = model_res

        # Save evaluation-candidate artifact (Step 8)
        if save_artifacts:
            # Retrain on full dataset for artifact
            pipeline.fit(X, y)
            safe_label   = label.lower().replace(" ", "_").replace("+", "plus")
            safe_mname   = mname.lower().replace(" ", "_")
            artifact_path = EVAL_DIR / f"eval_candidate_{safe_label}_{safe_mname}.pkl"
            with open(artifact_path, "wb") as f:
                pickle.dump({"pipeline": pipeline, "feature_cols": feat_cols,
                             "dataset": label, "model": mname,
                             "n_samples": n, "seed": SEED}, f)
            print(f"    ↳ Artifact saved: {artifact_path.name}")

    return results


# ─────────────────────────────────────────────────────────────────────────────
# STEP 7 — CONSTANT-FEATURE SECONDARY EXPERIMENT
# ─────────────────────────────────────────────────────────────────────────────

def secondary_constant_feature_experiment(
    combined_df: pd.DataFrame,
    feat_cols: List[str],
) -> Dict[str, Any]:
    """
    Identify globally constant features in the combined dataset.
    Evaluate the same 3 models with those features removed.
    Return results for comparison only — does NOT alter feat_cols or the feature extractor.
    """
    print(f"\n── STEP 7 (SECONDARY): CONSTANT-FEATURE EXPERIMENT ─────────────────")

    # Find features with zero variance in the combined dataset
    X_all = combined_df[feat_cols].values.astype(float)
    variances   = X_all.var(axis=0)
    const_mask  = variances == 0
    const_feats = [f for f, c in zip(feat_cols, const_mask) if c]
    active_feats = [f for f, c in zip(feat_cols, const_mask) if not c]

    print(f"  Globally constant features in combined: {len(const_feats)}")
    for cf in const_feats:
        print(f"    - {cf}")
    print(f"  Active features after removal          : {len(active_feats)}")

    if not const_feats:
        print("  No globally constant features — secondary experiment not needed.")
        return {"skipped": True, "reason": "no globally constant features"}

    print(f"  Running secondary CV with {len(active_feats)} features...")

    sec_results: Dict[str, Any] = {
        "constant_features_removed": const_feats,
        "remaining_features":        len(active_feats),
        "models": {},
    }

    X = combined_df[active_feats].values.astype(float)
    y = combined_df["label"].values.astype(int)
    cv = StratifiedKFold(n_splits=N_FOLDS, shuffle=True, random_state=SEED)

    for mname, pipeline in make_models().items():
        cv_out = cross_validate(pipeline, X, y, cv=cv, scoring=SCORING, return_train_score=False)
        m_res  = {}
        for metric in SCORING:
            fold_scores = cv_out[f"test_{metric}"]
            m_res[metric] = {
                "mean": float(np.mean(fold_scores)),
                "std":  float(np.std(fold_scores)),
            }
        sec_results["models"][mname] = m_res
        print(f"  {mname:<22}  Acc={m_res['accuracy']['mean']:.3f}  "
              f"Rec={m_res['recall']['mean']:.3f}  "
              f"F1={m_res['f1']['mean']:.3f}")

    return sec_results


# ─────────────────────────────────────────────────────────────────────────────
# STEP 5+6 — PRINT FULL COMPARISON TABLE + MALWARE-PRIORITY ANALYSIS
# ─────────────────────────────────────────────────────────────────────────────

def print_comparison_and_recommendation(
    all_results: Dict[str, Dict],
    secondary: Dict,
) -> None:

    print("\n" + "=" * W)
    print("STEP 5 — FULL MODEL COMPARISON TABLE")
    print("=" * W)
    print(f"{'Dataset':<12} {'Model':<22} {'Acc':>6} {'Prec':>6} {'Rec':>6} "
          f"{'F1':>6} {'AUC':>6} {'CV±':>6} {'FN':>4}")
    print("-" * W)

    all_rows = []
    for ds_name, ds_res in all_results.items():
        for mname, mres in ds_res["models"].items():
            m     = mres["metrics"]
            fn    = mres["fn"]
            row   = {
                "dataset": ds_name, "model": mname,
                "acc":  m["accuracy"]["mean"],  "acc_std":  m["accuracy"]["std"],
                "prec": m["precision"]["mean"], "rec":  m["recall"]["mean"],
                "f1":   m["f1"]["mean"],        "auc":  m["roc_auc"]["mean"],
                "fn":   fn,
                "cv_mean": m["f1"]["mean"],     "cv_std": m["f1"]["std"],
            }
            all_rows.append(row)
            print(f"{ds_name:<12} {mname:<22} {row['acc']:>6.3f} {row['prec']:>6.3f} "
                  f"{row['rec']:>6.3f} {row['f1']:>6.3f} {row['auc']:>6.3f} "
                  f"±{row['cv_std']:>5.3f} {fn:>4}")
        print()

    # ── STEP 6: Malware-detection priority ranking ─────────────────────────
    print("=" * W)
    print("STEP 6 — MALWARE-DETECTION PRIORITY RANKING")
    print("Priority: Recall → F1 → Precision → Accuracy")
    print("=" * W)

    # Filter combined-only rows for primary recommendation
    combined_rows = [r for r in all_rows if r["dataset"] == "Combined"]
    if not combined_rows:
        combined_rows = all_rows

    # Sort by: recall DESC, f1 DESC, precision DESC, accuracy DESC
    ranked = sorted(combined_rows,
                    key=lambda r: (r["rec"], r["f1"], r["prec"], r["acc"]),
                    reverse=True)

    print(f"\n  Ranked by malware-detection priority (Combined dataset):")
    for i, r in enumerate(ranked, 1):
        print(f"  {i}. {r['model']:<22}  Recall={r['rec']:.3f}  F1={r['f1']:.3f}  "
              f"Prec={r['prec']:.3f}  FN={r['fn']}")

    best = ranked[0]
    print(f"\n  ⭐ PRIMARY RECOMMENDATION (Combined): {best['model']}")
    print(f"     Recall={best['rec']:.3f}  F1={best['f1']:.3f}  "
          f"FN={best['fn']}  Accuracy={best['acc']:.3f}")

    print(f"""
  FALSE NEGATIVE / FALSE POSITIVE ANALYSIS:
  ─────────────────────────────────────────
  A False Negative (FN) means a REAL malware APK was classified as benign.
  This is the worst possible error for a malware detector — the threat passes
  through completely undetected.

  A False Positive (FP) means a benign APK was flagged as malware.
  This causes user friction but not a security breach.

  Therefore we rank: Recall first (minimise FN), then F1 (balances FP/FN).
  We explicitly DO NOT rank by Accuracy alone.
""")

    # ── Secondary experiment summary ───────────────────────────────────────
    print("=" * W)
    print("STEP 7 — SECONDARY EXPERIMENT: CONSTANT FEATURE REMOVAL")
    print("=" * W)

    if secondary.get("skipped"):
        print(f"  Skipped: {secondary['reason']}")
    else:
        print(f"  Constant features removed: {len(secondary['constant_features_removed'])}")
        print(f"  Remaining features: {secondary['remaining_features']}")
        print(f"\n  Results with reduced feature set vs full 47-feature set (Combined):")
        print(f"  {'Model':<22} {'Red.Rec':>8} {'Full Rec':>8} {'Δ Recall':>9} "
              f"{'Red.F1':>7} {'Full F1':>7}")
        print(f"  {'-'*22} {'-'*8} {'-'*8} {'-'*9} {'-'*7} {'-'*7}")

        for mname, sec_m in secondary["models"].items():
            full_row = next((r for r in combined_rows if r["model"] == mname), None)
            full_rec = full_row["rec"] if full_row else float("nan")
            full_f1  = full_row["f1"]  if full_row else float("nan")
            red_rec  = sec_m["recall"]["mean"]
            red_f1   = sec_m["f1"]["mean"]
            delta    = red_rec - full_rec
            print(f"  {mname:<22} {red_rec:>8.3f} {full_rec:>8.3f} "
                  f"{'▲' if delta >= 0 else '▼'}{abs(delta):>8.3f} "
                  f"{red_f1:>7.3f} {full_f1:>7.3f}")

        print("\n  NOTE: Secondary experiment is for informational purposes only.")
        print("  The 47-feature definition has NOT been changed.")

    return best, all_rows


# ─────────────────────────────────────────────────────────────────────────────
# STEP 9 — WRITE JSON REPORT
# ─────────────────────────────────────────────────────────────────────────────

def write_report(all_results: Dict, secondary: Dict, best: Dict) -> None:
    payload = {
        "evaluation": all_results,
        "secondary_constant_feature_experiment": secondary,
        "primary_recommendation": best,
        "notes": [
            "Production model NOT replaced.",
            "Evaluation artifacts saved to data/model_candidates/.",
            "Feature extractor NOT modified.",
            "All preprocessing (StandardScaler) was fit inside each CV fold.",
        ],
    }
    with open(REPORT_JSON, "w") as f:
        json.dump(payload, f, indent=2)
    print(f"\n  JSON report saved: {REPORT_JSON}")


# ─────────────────────────────────────────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────────────────────────────────────────

def main() -> None:
    print("=" * W)
    print("FRAUDGUARD-AI — EXPANDED DATASET EVALUATION")
    print("=" * W)

    # Step 1: Combine
    combined_df, feat_cols = combine_datasets()

    # Load individual source DataFrames
    mal_df = pd.read_csv(MALEVAL_CSV)
    az_df  = pd.read_csv(ANDROZOO_CSV)

    # Step 2: MalEval baseline (reproduced)
    mal_res = evaluate_dataset("MalEval",  mal_df,  feat_cols, save_artifacts=False)

    # Step 3: AndroZoo only
    az_res  = evaluate_dataset("AndroZoo", az_df,   feat_cols, save_artifacts=False)

    # Step 4: Combined (save evaluation artifacts)
    comb_res = evaluate_dataset("Combined", combined_df, feat_cols, save_artifacts=True)

    all_results = {
        "MalEval":  mal_res,
        "AndroZoo": az_res,
        "Combined": comb_res,
    }

    # Step 7: Secondary experiment
    secondary = secondary_constant_feature_experiment(combined_df, feat_cols)

    # Steps 5 + 6
    best, all_rows = print_comparison_and_recommendation(all_results, secondary)

    # Step 9: Save report
    write_report(all_results, secondary, best)

    print("\n" + "=" * W)
    print("STOP — Evaluation complete. Awaiting approval before any deployment.")
    print("=" * W)


if __name__ == "__main__":
    main()
