import os
import sys
import pandas as pd
import numpy as np

# Use absolute paths
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
CSV_PATH = os.path.join(BASE_DIR, "training_data.csv")
REPORT_PATH = os.path.join(BASE_DIR, "dataset_audit_report.txt")

def generate_report():
    if not os.path.exists(CSV_PATH):
        print(f"Error: {CSV_PATH} not found.")
        sys.exit(1)
        
    df = pd.read_csv(CSV_PATH)
    
    with open(REPORT_PATH, 'w') as f:
        f.write("==================================================\n")
        f.write("FRAUDGUARD AI - DATASET INTEGRITY & FEATURE AUDIT\n")
        f.write("==================================================\n\n")
        
        # 1. Dataset shape
        f.write("1. DATASET SHAPE\n")
        f.write(f"- Rows: {df.shape[0]}\n")
        f.write(f"- Columns (total): {df.shape[1]}\n")
        feature_cols = [c for c in df.columns if c not in ['apk_name', 'sha256', 'label']]
        f.write(f"- Feature count: {len(feature_cols)}\n\n")
        
        # 2. Label validation
        f.write("2. LABEL VALIDATION\n")
        if 'label' in df.columns:
            counts = df['label'].value_counts().to_dict()
            f.write(f"- Unique labels: {list(counts.keys())}\n")
            f.write(f"- Count per label: {counts}\n")
            
            is_valid = set(counts.keys()).issubset({0, 1})
            f.write(f"- Confirm benign=0 and malware=1: {'PASS' if is_valid else 'FAIL'}\n\n")
        else:
            f.write("- Label column NOT FOUND.\n\n")
            
        # 3. Feature-type audit
        f.write("3. FEATURE-TYPE AUDIT\n")
        num_cols = df[feature_cols].select_dtypes(include=['int64', 'float64']).columns
        bool_cols = df[feature_cols].select_dtypes(include=['bool']).columns
        cat_cols = df[feature_cols].select_dtypes(include=['object', 'string', 'category']).columns
        
        f.write(f"- Numeric columns count: {len(num_cols)}\n")
        f.write(f"- Boolean columns count: {len(bool_cols)}\n")
        f.write(f"- Categorical/String columns count: {len(cat_cols)}\n")
        if len(cat_cols) > 0:
            f.write(f"- Unexpected object columns: {list(cat_cols)}\n")
        f.write("\n")
        
        # 4. Missing-value audit
        f.write("4. MISSING-VALUE AUDIT\n")
        missing_counts = df.isnull().sum()
        total_missing = missing_counts.sum()
        f.write(f"- Total missing values: {total_missing}\n")
        if total_missing > 0:
            f.write("- Missing count per column:\n")
            for col, cnt in missing_counts[missing_counts > 0].items():
                f.write(f"  * {col}: {cnt}\n")
        f.write("\n")
        
        # 5. Constant/near-constant features
        f.write("5. CONSTANT / NEAR-CONSTANT FEATURES\n")
        nunique = df[feature_cols].nunique()
        constant_features = nunique[nunique <= 1].index.tolist()
        f.write(f"- Features with only one unique value ({len(constant_features)}):\n")
        for col in constant_features:
            f.write(f"  * {col} (constant value: {df[col].iloc[0]})\n")
        
        low_variance = nunique[(nunique > 1) & (nunique <= 3)].index.tolist()
        f.write(f"- Features with extremely low variance (<= 3 unique vals): {len(low_variance)}\n\n")
        
        # 6. Duplicate audit
        f.write("6. DUPLICATE AUDIT\n")
        dup_rows = df.duplicated().sum()
        f.write(f"- Duplicate rows (exact match): {dup_rows}\n")
        if 'sha256' in df.columns:
            dup_hashes = df['sha256'].duplicated().sum()
            f.write(f"- Duplicate SHA-256 values: {dup_hashes}\n")
        f.write("\n")
        
        # 7. Feature leakage audit
        f.write("7. FEATURE LEAKAGE AUDIT\n")
        suspicious = []
        for col in df.columns:
            lower = col.lower()
            if 'label' in lower and col != 'label':
                suspicious.append(col)
            elif 'class' in lower or 'malware' in lower or 'benign' in lower:
                suspicious.append(col)
            elif 'split' in lower or 'test' in lower or 'train' in lower:
                suspicious.append(col)
        
        f.write(f"- Suspicious leakage columns found: {len(suspicious)}\n")
        for col in suspicious:
            f.write(f"  * [WARN] {col}\n")
        
        # Ensure apk_name/sha256 aren't passed into the model feature set accidentally
        f.write("- Metadata non-feature columns: apk_name, sha256, label (EXPECTED to be separated during training)\n\n")
        
        # 8. Feature distribution
        f.write("8. FEATURE DISTRIBUTION (Numeric Features)\n")
        desc = df[num_cols].describe().T
        for col in num_cols:
            n_uni = df[col].nunique()
            f.write(f"- {col}: min={desc.loc[col, 'min']}, max={desc.loc[col, 'max']}, mean={desc.loc[col, 'mean']:.4f}, std={desc.loc[col, 'std']:.4f}, unique={n_uni}\n")
        f.write("\n")
        
        # 9. Correlation audit
        f.write("9. CORRELATION AUDIT (Pearson correlation with label)\n")
        if 'label' in df.columns:
            # Drop constant columns to avoid NaN correlations
            valid_cols = [c for c in num_cols if c not in constant_features]
            if valid_cols:
                corr = df[valid_cols + ['label']].corr()['label'].drop('label')
                corr = corr.fillna(0)  # Handle any remaining NaNs gracefully
                sorted_corr = corr.abs().sort_values(ascending=False)
                
                f.write("- Top 10 strongest absolute correlations with label:\n")
                for col, val in sorted_corr.head(10).items():
                    actual_val = corr[col]
                    f.write(f"  * {col}: {actual_val:.4f}\n")
                
                sus_corr = sorted_corr[sorted_corr > 0.95].index.tolist()
                if sus_corr:
                    f.write(f"\n- [WARN] Extremely suspicious correlations (>0.95) flagged for manual review:\n")
                    for col in sus_corr:
                        f.write(f"  * {col}: {corr[col]:.4f}\n")
                else:
                    f.write("\n- No extremely suspicious correlations (>0.95) found.\n")
            else:
                f.write("- No valid numeric columns to correlate.\n")
        f.write("\n==================================================\n")

    # Generate PASS/WARN summary for terminal
    print("\n" + "="*50)
    print("DATASET AUDIT: PASS / WARN SUMMARY")
    print("="*50)
    
    warnings = 0
    if len(cat_cols) > 0:
        print(f"[WARN] Found {len(cat_cols)} non-numeric feature columns!")
        warnings += 1
        
    if total_missing > 0:
        print(f"[WARN] Found {total_missing} missing values!")
        warnings += 1
        
    if dup_rows > 0:
        print(f"[WARN] Found {dup_rows} exact duplicate rows!")
        warnings += 1
        
    if 'sha256' in df.columns and df['sha256'].duplicated().sum() > 0:
        print(f"[WARN] Found duplicate SHA-256 hashes!")
        warnings += 1
        
    if len(suspicious) > 0:
        print(f"[WARN] Found {len(suspicious)} potential leakage columns!")
        warnings += 1
        
    if 'label' in df.columns:
        valid_cols = [c for c in num_cols if c not in constant_features]
        if valid_cols:
            corr = df[valid_cols + ['label']].corr()['label'].drop('label')
            sus_corr = corr.abs()[corr.abs() > 0.95]
            if len(sus_corr) > 0:
                print(f"[WARN] Found {len(sus_corr)} features with >0.95 correlation to label!")
                warnings += 1
                
    if len(constant_features) > 0:
        print(f"[INFO] Found {len(constant_features)} constant features (not necessarily an error, but noted).")

    print(f"\nRESULT: {'PASS' if warnings == 0 else 'WARN (See dataset_audit_report.txt for details)'}")
    print(f"Report written to: {REPORT_PATH}")
    print("="*50)

if __name__ == "__main__":
    generate_report()
