import os
import json
import numpy as np
import pandas as pd
from sklearn.model_selection import StratifiedKFold
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler
from sklearn.linear_model import LogisticRegression
from sklearn.ensemble import RandomForestClassifier
from scipy.stats import ttest_ind

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
CSV_PATH = os.path.join(BASE_DIR, "training_data.csv")
REPORT_PATH = os.path.join(BASE_DIR, "feature_behavior_report.txt")
JSON_PATH = os.path.join(BASE_DIR, "feature_behavior_results.json")

def main():
    if not os.path.exists(CSV_PATH):
        print(f"Error: {CSV_PATH} not found.")
        return
        
    df = pd.read_csv(CSV_PATH)
    drop_cols = ['apk_name', 'sha256', 'label']
    feature_cols = [c for c in df.columns if c not in drop_cols]
    
    X = df[feature_cols].values
    y = df['label'].values
    
    # 1. Class-wise Feature Analysis
    benign_df = df[df['label'] == 0]
    malware_df = df[df['label'] == 1]
    
    class_stats = {}
    correlations = {}
    for col in feature_cols:
        b_vals = benign_df[col].values
        m_vals = malware_df[col].values
        
        # t-test for separation statistic
        t_stat, p_val = ttest_ind(b_vals, m_vals, equal_var=False)
        # Handle constants
        if np.isnan(t_stat):
            t_stat, p_val = 0.0, 1.0
            
        corr = df[col].corr(df['label'])
        if np.isnan(corr):
            corr = 0.0
        correlations[col] = corr
            
        class_stats[col] = {
            "benign": {
                "mean": float(np.mean(b_vals)),
                "median": float(np.median(b_vals)),
                "std": float(np.std(b_vals)),
                "min": float(np.min(b_vals)),
                "max": float(np.max(b_vals)),
                "unique": int(len(np.unique(b_vals)))
            },
            "malware": {
                "mean": float(np.mean(m_vals)),
                "median": float(np.median(m_vals)),
                "std": float(np.std(m_vals)),
                "min": float(np.min(m_vals)),
                "max": float(np.max(m_vals)),
                "unique": int(len(np.unique(m_vals)))
            },
            "t_stat": float(t_stat),
            "p_value": float(p_val)
        }
    
    # 2 & 3. Model Explainability (LR and RF via CV)
    cv = StratifiedKFold(n_splits=5, shuffle=True, random_state=42)
    
    lr_pipeline = Pipeline([
        ("scaler", StandardScaler()),
        ("clf", LogisticRegression(random_state=42, max_iter=1000))
    ])
    rf_pipeline = Pipeline([
        ("scaler", StandardScaler()),
        ("clf", RandomForestClassifier(random_state=42))
    ])
    
    lr_coefs = []
    rf_importances = []
    
    for train_idx, test_idx in cv.split(X, y):
        X_train, y_train = X[train_idx], y[train_idx]
        
        lr_pipeline.fit(X_train, y_train)
        rf_pipeline.fit(X_train, y_train)
        
        # Extract LR coefficients
        # clf is the second step
        lr_coefs.append(lr_pipeline.named_steps["clf"].coef_[0])
        
        # Extract RF importances
        rf_importances.append(rf_pipeline.named_steps["clf"].feature_importances_)
        
    lr_coefs = np.array(lr_coefs)
    rf_importances = np.array(rf_importances)
    
    lr_mean_coef = np.mean(lr_coefs, axis=0)
    lr_std_coef = np.std(lr_coefs, axis=0)
    
    rf_mean_imp = np.mean(rf_importances, axis=0)
    rf_std_imp = np.std(rf_importances, axis=0)
    
    # 5. Constant Features
    nunique = df[feature_cols].nunique()
    constant_features = nunique[nunique <= 1].index.tolist()

    # Generate Report
    with open(REPORT_PATH, 'w') as f:
        f.write("==================================================\n")
        f.write("FRAUDGUARD AI - FEATURE BEHAVIOR & EXPLAINABILITY\n")
        f.write("==================================================\n\n")
        
        f.write("5. CONSTANT-FEATURE ANALYSIS\n")
        f.write("--------------------------------------------------\n")
        f.write(f"The following {len(constant_features)} features are entirely constant (zero variance) in this 40-sample dataset:\n")
        for c in constant_features:
            f.write(f"  - {c}\n")
        f.write("\nConclusion: These features provide no discriminative power here. ")
        f.write("However, they can be safely ignored (or safely passed to StandardScaler, which assigns a 0 coefficient) ")
        f.write("during preprocessing without crashing the pipeline. Do NOT delete them from the source schema, as they may become active in a larger dataset.\n\n")

        f.write("1. CLASS-WISE FEATURE STATISTICS (Top 5 by absolute t-statistic)\n")
        f.write("--------------------------------------------------\n")
        # Sort by t_stat absolute value
        top_ttest = sorted(class_stats.items(), key=lambda x: abs(x[1]["t_stat"]), reverse=True)
        for col, stats in top_ttest[:5]:
            f.write(f"Feature: {col}\n")
            f.write(f"  Benign : Mean={stats['benign']['mean']:.4f}, Std={stats['benign']['std']:.4f}, Unique={stats['benign']['unique']}\n")
            f.write(f"  Malware: Mean={stats['malware']['mean']:.4f}, Std={stats['malware']['std']:.4f}, Unique={stats['malware']['unique']}\n")
            f.write(f"  Separation (t-stat): {stats['t_stat']:.4f} (p-val: {stats['p_value']:.4e})\n\n")
            
        f.write("2. LOGISTIC REGRESSION EXPLAINABILITY\n")
        f.write("--------------------------------------------------\n")
        f.write("Mean coefficients across 5-fold CV (Absolute Top 10):\n")
        lr_ranking = sorted(zip(feature_cols, lr_mean_coef, lr_std_coef), key=lambda x: abs(x[1]), reverse=True)
        for col, mean, std in lr_ranking[:10]:
            f.write(f"  - {col}: {mean:.4f} ± {std:.4f}\n")
        f.write("\n")
        
        f.write("3. RANDOM FOREST FEATURE IMPORTANCE\n")
        f.write("--------------------------------------------------\n")
        f.write("Mean Gini importance across 5-fold CV (Top 10):\n")
        f.write("(Note: This is model-derived feature importance, not causal importance.)\n")
        rf_ranking = sorted(zip(feature_cols, rf_mean_imp, rf_std_imp), key=lambda x: x[1], reverse=True)
        for col, mean, std in rf_ranking[:10]:
            f.write(f"  - {col}: {mean:.4f} ± {std:.4f}\n")
        f.write("\n")
        
        f.write("4. CROSS-METHOD COMPARISON\n")
        f.write("--------------------------------------------------\n")
        f.write("Features that consistently appear highly ranked across methods:\n")
        # Get top 10 from each
        top_corr = set([x[0] for x in sorted(correlations.items(), key=lambda x: abs(x[1]), reverse=True)[:10]])
        top_lr = set([x[0] for x in lr_ranking[:10]])
        top_rf = set([x[0] for x in rf_ranking[:10]])
        
        intersection = top_corr.intersection(top_lr).intersection(top_rf)
        for col in intersection:
            f.write(f"  - {col} (High Pearson, High LR Coef, High RF Importance)\n")
        f.write("\n")
        
        f.write("6. POTENTIAL DATASET-CONSTRUCTION ARTIFACTS\n")
        f.write("--------------------------------------------------\n")
        f.write("Warning: Given the extremely small sample size (40 APKs), features with high importance may simply be artifacts of class-specific sampling.\n")
        f.write("For example:\n")
        for col in intersection:
            if "cert_present" in col or "size" in col or "dex" in col:
                f.write(f"  - [WARN] {col} is heavily utilized but might just reflect differing source repositories (e.g. F-Droid benign vs randomly scraped malware) rather than inherent malice.\n")
        f.write("  - [WARN] Zero-variance features are a direct artifact of small sample size.\n\n")
        
        f.write("7. CONCLUSION\n")
        f.write("--------------------------------------------------\n")
        f.write("These findings describe feature/model behavior on the 40-sample prototype dataset and do not establish real-world malware-detection performance.\n")
        f.write("==================================================\n")

    # JSON output
    results = {
        "constant_features": constant_features,
        "class_stats": class_stats,
        "lr_explainability": [{"feature": c, "mean_coef": float(m), "std_coef": float(s)} for c, m, s in lr_ranking],
        "rf_importance": [{"feature": c, "mean_imp": float(m), "std_imp": float(s)} for c, m, s in rf_ranking],
    }
    with open(JSON_PATH, 'w') as jf:
        json.dump(results, jf, indent=2)
        
    print(f"Report generated successfully at {REPORT_PATH}")

if __name__ == "__main__":
    main()
