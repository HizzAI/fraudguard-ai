import json
import joblib
import pandas as pd
import numpy as np
from pathlib import Path
from sklearn.model_selection import train_test_split, GridSearchCV
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler
from sklearn.svm import SVC
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, roc_auc_score, confusion_matrix

def main():
    PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
    CANDIDATE_CSV = PROJECT_ROOT / "data" / "processed" / "candidate_training_data.csv"
    CANDIDATE_MODEL_PATH = PROJECT_ROOT / "backend" / "app" / "ml" / "model_svm_candidate.pkl"
    CANDIDATE_FEAT_PATH = PROJECT_ROOT / "backend" / "app" / "ml" / "candidate_features.json"
    REPORT_JSON = PROJECT_ROOT / "data" / "processed" / "candidate_evaluation_report.json"
    
    if not CANDIDATE_CSV.exists():
        print("Candidate data not found.")
        return
        
    df = pd.read_csv(CANDIDATE_CSV)
    
    # Composite label for stratification
    df['stratify_key'] = df['source'] + '_' + df['label'].astype(str)
    
    # Check minimum class size for stratification
    min_class_size = df['stratify_key'].value_counts().min()
    if min_class_size < 2:
        print(f"Cannot stratify due to small class size ({min_class_size}). Stopping.")
        return
        
    # Split
    train_df, test_df = train_test_split(df, test_size=0.2, stratify=df['stratify_key'], random_state=42)
    
    # Features
    feat_cols = [c for c in df.columns if c.startswith("feat_")]
    X_train = train_df[feat_cols].values.astype(float)
    y_train = train_df['label'].values.astype(int)
    
    X_test = test_df[feat_cols].values.astype(float)
    y_test = test_df['label'].values.astype(int)
    
    # Pipeline
    pipe = Pipeline([
        ('scaler', StandardScaler()),
        ('clf', SVC(probability=True, random_state=42))
    ])
    
    # GridSearch for selection on Train ONLY
    param_grid = {
        'clf__C': [0.1, 1.0, 10.0],
        'clf__kernel': ['linear', 'rbf']
    }
    
    grid = GridSearchCV(pipe, param_grid, cv=5, scoring='recall', refit=True)
    grid.fit(X_train, y_train)
    
    best_model = grid.best_estimator_
    
    # Evaluate on Holdout
    y_pred = best_model.predict(X_test)
    y_proba = best_model.predict_proba(X_test)[:, 1]
    
    cm = confusion_matrix(y_test, y_pred)
    tn, fp, fn, tp = cm.ravel()
    
    metrics = {
        "accuracy": float(accuracy_score(y_test, y_pred)),
        "precision": float(precision_score(y_test, y_pred)),
        "recall": float(recall_score(y_test, y_pred)),
        "f1": float(f1_score(y_test, y_pred)),
        "roc_auc": float(roc_auc_score(y_test, y_proba)),
        "tp": int(tp), "tn": int(tn), "fp": int(fp), "fn": int(fn)
    }
    
    # Save model and features
    joblib.dump(best_model, CANDIDATE_MODEL_PATH)
    with open(CANDIDATE_FEAT_PATH, 'w') as f:
        json.dump({"features": feat_cols}, f)
        
    # Report
    report = {
        "split_methodology": "Stratified 80/20 train/test split on composite key (source + label) before any fitting",
        "train_size": len(train_df),
        "test_size": len(test_df),
        "train_distribution": train_df['stratify_key'].value_counts().to_dict(),
        "test_distribution": test_df['stratify_key'].value_counts().to_dict(),
        "best_cv_params": grid.best_params_,
        "best_cv_recall": grid.best_score_,
        "holdout_metrics": metrics,
        "feature_count": len(feat_cols),
        "limitations": "Although stratified, the test set is only 45 samples (with ~4 from MalEval). " 
                       "This is extremely small and wide confidence intervals exist on these metrics. "
                       "This random split measures performance on a similar mixed-source distribution, "
                       "not true cross-source generalization."
    }
    
    with open(REPORT_JSON, 'w') as f:
        json.dump(report, f, indent=2)
        
    print("Candidate evaluation complete.")
    print(json.dumps(report, indent=2))

if __name__ == "__main__":
    main()
