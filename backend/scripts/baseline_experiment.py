import os
import json
import numpy as np
import pandas as pd
from sklearn.model_selection import StratifiedKFold, cross_validate, cross_val_predict
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler
from sklearn.linear_model import LogisticRegression
from sklearn.ensemble import RandomForestClassifier
from sklearn.svm import SVC
from sklearn.metrics import confusion_matrix

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
CSV_PATH = os.path.join(BASE_DIR, "training_data.csv")
REPORT_PATH = os.path.join(BASE_DIR, "baseline_report.txt")
JSON_PATH = os.path.join(BASE_DIR, "baseline_results.json")

def main():
    if not os.path.exists(CSV_PATH):
        print(f"Error: {CSV_PATH} not found.")
        return
        
    df = pd.read_csv(CSV_PATH)
    
    # 1. Feature / Label separation
    drop_cols = ['apk_name', 'sha256', 'label']
    feature_cols = [c for c in df.columns if c not in drop_cols]
    
    X = df[feature_cols].values
    y = df['label'].values
    
    # 2. Models setup
    # Logistic Regression requires scaling for convergence and fairness
    # SVM strongly requires scaling
    # Random Forest doesn't care, but a Pipeline makes it uniform.
    
    models = {
        "Logistic Regression": Pipeline([
            ("scaler", StandardScaler()),
            ("clf", LogisticRegression(random_state=42, max_iter=1000))
        ]),
        "Random Forest": Pipeline([
            ("scaler", StandardScaler()),
            ("clf", RandomForestClassifier(random_state=42))
        ]),
        "SVM": Pipeline([
            ("scaler", StandardScaler()),
            # probability=True needed for ROC-AUC
            ("clf", SVC(probability=True, random_state=42))
        ])
    }
    
    cv = StratifiedKFold(n_splits=5, shuffle=True, random_state=42)
    
    scoring = ['accuracy', 'precision', 'recall', 'f1', 'roc_auc']
    
    results_json = {
        "dataset_size": len(df),
        "num_features": len(feature_cols),
        "cv_strategy": "Stratified 5-Fold CV",
        "models": {}
    }
    
    with open(REPORT_PATH, 'w') as f:
        f.write("==================================================\n")
        f.write("FRAUDGUARD AI - BASELINE ML EXPERIMENT REPORT\n")
        f.write("==================================================\n\n")
        f.write(f"1. Dataset size: {len(df)} samples (20 Benign, 20 Malware)\n")
        f.write(f"2. Number of features: {len(feature_cols)}\n")
        f.write("3. Cross-validation strategy: Stratified 5-Fold CV\n")
        f.write(f"4. Models evaluated: {', '.join(models.keys())}\n\n")
        f.write("==================================================\n")
        f.write("MODEL PERFORMANCE\n")
        f.write("==================================================\n\n")
        
        for name, pipeline in models.items():
            f.write(f"--- {name} ---\n")
            
            # Cross-validate to get fold-by-fold metrics
            cv_results = cross_validate(pipeline, X, y, cv=cv, scoring=scoring, return_train_score=False)
            
            # cross_val_predict to get aggregated confusion matrix
            y_pred = cross_val_predict(pipeline, X, y, cv=cv)
            cm = confusion_matrix(y, y_pred, labels=[0, 1])
            
            model_metrics = {}
            for metric in scoring:
                fold_scores = cv_results[f"test_{metric}"]
                mean_score = np.mean(fold_scores)
                std_score = np.std(fold_scores)
                
                model_metrics[metric] = {
                    "mean": float(mean_score),
                    "std": float(std_score),
                    "folds": [float(x) for x in fold_scores]
                }
                
                f.write(f"- {metric.capitalize()}:\n")
                f.write(f"  * Mean ± Std: {mean_score:.4f} ± {std_score:.4f}\n")
                f.write(f"  * Fold scores: {', '.join([f'{s:.4f}' for s in fold_scores])}\n")
                
            f.write("\n- Aggregated Confusion Matrix (Across 5 Folds):\n")
            f.write(f"  * True Negatives (Correct Benign): {cm[0,0]}\n")
            f.write(f"  * False Positives (Incorrect Malware): {cm[0,1]}\n")
            f.write(f"  * False Negatives (Incorrect Benign): {cm[1,0]}\n")
            f.write(f"  * True Positives (Correct Malware): {cm[1,1]}\n\n")
            
            results_json["models"][name] = {
                "metrics": model_metrics,
                "confusion_matrix": cm.tolist()
            }
            
        f.write("==================================================\n")
        f.write("INTERPRETATION\n")
        f.write("==================================================\n")
        f.write("The metrics above represent baseline cross-validation performance on the 40-sample prototype dataset.\n")
        f.write("Do NOT claim the resulting metrics represent real-world malware detection capability.\n")
        f.write("Do NOT describe the highest-scoring model as 'best' for production.\n")
    
    with open(JSON_PATH, 'w') as jf:
        json.dump(results_json, jf, indent=2)
        
    print(f"Experiment completed. Report saved to {REPORT_PATH}")
    print(f"Results JSON saved to {JSON_PATH}")

if __name__ == "__main__":
    main()
