import pandas as pd
import json
import hashlib
from pathlib import Path

def main():
    PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
    ORIG_CSV = PROJECT_ROOT / "data" / "processed" / "combined_training_data.csv"
    CANDIDATE_CSV = PROJECT_ROOT / "data" / "processed" / "candidate_training_data.csv"
    REPORT_JSON = PROJECT_ROOT / "data" / "processed" / "candidate_data_report.json"
    
    df = pd.read_csv(ORIG_CSV)
    orig_rows = len(df)
    
    feat_cols = [c for c in df.columns if c.startswith("feat_")]
    
    # Identify duplicate groups
    exact_dup_mask = df.duplicated(subset=feat_cols, keep=False)
    dup_df = df[exact_dup_mask]
    
    conflicting_groups = []
    
    # We group by the feature values
    for _, group in dup_df.groupby(feat_cols):
        if group['label'].nunique() > 1:
            conflicting_groups.append(group.index)
            
    exclude_indices = []
    for idx_list in conflicting_groups:
        exclude_indices.extend(idx_list)
        
    df_clean = df.drop(index=exclude_indices).copy()
    
    # Identify constant features
    const_feats = [c for c in feat_cols if df_clean[c].nunique() <= 1]
    df_clean = df_clean.drop(columns=const_feats)
    
    final_feat_cols = [c for c in df_clean.columns if c.startswith("feat_")]
    
    df_clean.to_csv(CANDIDATE_CSV, index=False)
    
    # Create report
    with open(CANDIDATE_CSV, 'rb') as f:
        checksum = hashlib.sha256(f.read()).hexdigest()
        
    report = {
        "original_rows": orig_rows,
        "candidate_rows": len(df_clean),
        "excluded_rows": len(exclude_indices),
        "exclusion_reason": "Conflicting labels for identical feature vectors",
        "dropped_constant_features": const_feats,
        "final_feature_count": len(final_feat_cols),
        "retained_source_distribution": df_clean['source'].value_counts().to_dict(),
        "retained_label_distribution": df_clean['label'].value_counts().to_dict(),
        "final_features": final_feat_cols,
        "candidate_data_checksum_sha256": checksum
    }
    
    with open(REPORT_JSON, "w") as f:
        json.dump(report, f, indent=2)
        
    print(f"Candidate data built. Excluded {len(exclude_indices)} rows. Dropped {len(const_feats)} features.")
    print(f"Saved to {CANDIDATE_CSV}")

if __name__ == "__main__":
    main()
