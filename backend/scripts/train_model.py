"""
train_model.py — Offline script to train the Phase 5B ML classifier.

This script expects a dataset (e.g., CCCS-CIC-AndMal-2020) that has already
been mapped to the 47-feature schema defined in feature_extractor.py.
It trains a Random Forest model and serializes it using joblib.

Usage:
  python train_model.py path/to/mapped_dataset.csv
"""

import sys
import argparse
from pathlib import Path

try:
    import pandas as pd
    import numpy as np
    from sklearn.ensemble import RandomForestClassifier
    from sklearn.model_selection import train_test_split
    from sklearn.metrics import classification_report, accuracy_score
    import joblib
except ImportError:
    print("Dependencies missing. Please install scikit-learn, numpy, pandas, joblib.")
    sys.exit(1)

# Import the feature names from the main app
# Ensure the script is run from a path where 'app' is resolvable
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from app.ml.feature_extractor import FEATURE_NAMES, FEATURE_COUNT

MODEL_OUT_PATH = Path(__file__).resolve().parent.parent / "app" / "ml" / "model_rf_v1.pkl"

def parse_args():
    parser = argparse.ArgumentParser(description="Train FraudGuard ML classifier")
    parser.add_argument("dataset_csv", help="Path to the mapped CSV dataset")
    parser.add_argument("--trees", type=int, default=100, help="Number of trees in forest")
    parser.add_argument("--depth", type=int, default=15, help="Max depth of trees")
    parser.add_argument("--random-state", type=int, default=42, help="Random seed")
    return parser.parse_args()


def train(args):
    print(f"Loading dataset from {args.dataset_csv}...")
    try:
        df = pd.read_csv(args.dataset_csv)
    except Exception as e:
        print(f"Failed to load dataset: {e}")
        return

    # Assume the target column is 'label' (0=benign, 1=malicious)
    if "label" not in df.columns:
        print("Error: Dataset must contain a 'label' column (0=benign, 1=malicious)")
        return

    # Verify all required features are present
    missing_features = [f for f in FEATURE_NAMES if f not in df.columns]
    if missing_features:
        print(f"Error: Dataset is missing {len(missing_features)} required features.")
        print(f"Missing: {missing_features[:5]} ...")
        return

    X = df[FEATURE_NAMES].values
    y = df["label"].values

    print(f"Dataset loaded: {len(df)} samples, {X.shape[1]} features.")
    print("Splitting into train/test (80/20)...")
    
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=args.random_state, stratify=y
    )

    print(f"Training Random Forest (trees={args.trees}, depth={args.depth})...")
    clf = RandomForestClassifier(
        n_estimators=args.trees,
        max_depth=args.depth,
        random_state=args.random_state,
        n_jobs=-1,
        class_weight="balanced"
    )
    
    clf.fit(X_train, y_train)

    print("Evaluating model...")
    y_pred = clf.predict(X_test)
    
    acc = accuracy_score(y_test, y_pred)
    print(f"\nAccuracy: {acc:.4f}\n")
    print("Classification Report:")
    print(classification_report(y_test, y_pred, target_names=["Benign", "Malicious"]))

    print(f"Saving model to {MODEL_OUT_PATH} ...")
    MODEL_OUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(clf, MODEL_OUT_PATH)
    
    print("Training complete! Model is ready for inference.")

if __name__ == "__main__":
    args = parse_args()
    train(args)
