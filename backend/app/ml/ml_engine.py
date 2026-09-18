"""
ml_engine.py — Loads the trained Random Forest model and performs inference.

CONTRACT:
  - Input:  the dict returned by extract_features() (from feature_extractor.py).
  - Output: a "ml" dict ready to be inserted into the /upload-apk response.
  - If no model file exists (model not yet trained), returns status="unavailable".
  - If extract_features() returned status="unavailable", returns status="unavailable".
  - Never raises an exception to the caller — all errors are caught and surfaced
    as status="failed" with a reason string.
  - Never fabricates a prediction. If the model file is missing or any error
    occurs, prediction is always null.

MODEL FILE:
  Expected at: backend/app/ml/model_rf_v1.pkl
  Serialized with joblib.dump().
  Must be trained separately using scripts/train_model.py.
  The model must expose .predict_proba(X) → [[p_benign, p_malicious]].

DISCLAIMER (always included):
  The ML output is a probabilistic estimate based on historical training data.
  It must never be presented as a definitive verdict.
"""

import logging
from pathlib import Path
from typing import Dict, Any, Optional

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
MODEL_VERSION  = "rf-v1.0"
_MODEL_PATH    = Path(__file__).resolve().parent / "model_rf_v1.pkl"
_DISCLAIMER    = (
    "This is a probabilistic classifier trained on historical data. "
    "It does not guarantee detection of all malware types. "
    "It must be used alongside the deterministic risk assessment, "
    "not as a replacement."
)

# ---------------------------------------------------------------------------
# Lazy model cache — loaded once on first call
# ---------------------------------------------------------------------------
_model_cache: Optional[Any] = None
_model_load_attempted: bool  = False


def _load_model() -> Optional[Any]:
    """
    Attempts to load the model from disk exactly once.
    Returns the model object on success, None if file is absent or load fails.
    """
    global _model_cache, _model_load_attempted
    if _model_load_attempted:
        return _model_cache

    _model_load_attempted = True

    if not _MODEL_PATH.exists():
        logger.info(
            "ML model not found at %s. "
            "ML classification will be unavailable until the model is trained "
            "and placed at this path.",
            _MODEL_PATH,
        )
        return None

    try:
        import joblib
        _model_cache = joblib.load(_MODEL_PATH)
        logger.info("ML model loaded from %s", _MODEL_PATH)
        return _model_cache
    except Exception as exc:
        logger.error("Failed to load ML model: %s", exc)
        return None


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------

def calculate_ml(feature_result: Dict[str, Any]) -> Dict[str, Any]:
    """
    Runs ML inference on the extracted feature vector.

    Args:
        feature_result: The dict returned by extract_features().
                        Must have keys: "features", "status", "version".

    Returns:
        A "ml" dict with keys:
          status, model_version, feature_vector_version,
          prediction, confidence, probability_malicious,
          probability_benign, features_used, disclaimer
    """
    # ── 1. Feature extraction must have succeeded ────────────────────────────
    if feature_result.get("status") != "success":
        return _unavailable_ml(
            "ML classification requires a successful APK analysis.",
            feature_result.get("version"),
        )

    # ── 2. Model must be available ───────────────────────────────────────────
    model = _load_model()
    if model is None:
        return _unavailable_ml(
            "ML model has not been trained yet. "
            "Run scripts/train_model.py to generate model_rf_v1.pkl.",
            feature_result.get("version"),
        )

    # ── 3. Build feature array ───────────────────────────────────────────────
    try:
        import numpy as np
        from app.ml.feature_extractor import feature_dict_to_list, FEATURE_COUNT

        features_dict = feature_result["features"]
        feature_list  = feature_dict_to_list(features_dict)

        if len(feature_list) != FEATURE_COUNT:
            raise ValueError(
                f"Feature vector length mismatch: expected {FEATURE_COUNT}, "
                f"got {len(feature_list)}"
            )

        X = np.array(feature_list, dtype=float).reshape(1, -1)

    except Exception as exc:
        logger.error("Feature array construction failed: %s", exc)
        return _failed_ml(str(exc), feature_result.get("version"))

    # ── 4. Run inference ─────────────────────────────────────────────────────
    try:
        # RandomForestClassifier.classes_ order is [0=benign, 1=malicious]
        # predict_proba returns [[p_class0, p_class1]]
        proba = model.predict_proba(X)[0]

        # Guard against unexpected class ordering
        classes = list(model.classes_)
        if len(classes) != 2:
            raise ValueError(f"Unexpected model classes: {classes}")

        # classes_ is sorted numerically: 0=benign, 1=malicious
        p_benign    = float(proba[classes.index(0)])
        p_malicious = float(proba[classes.index(1)])

        prediction  = "malicious" if p_malicious >= 0.5 else "benign"
        confidence  = round(max(p_benign, p_malicious), 4)

    except Exception as exc:
        logger.error("ML inference failed: %s", exc)
        return _failed_ml(str(exc), feature_result.get("version"))

    logger.info(
        "ML inference complete: prediction=%s p_malicious=%.4f confidence=%.4f",
        prediction, p_malicious, confidence,
    )

    return {
        "status":                "success",
        "model_version":         MODEL_VERSION,
        "feature_vector_version": feature_result.get("version"),
        "prediction":            prediction,
        "confidence":            confidence,
        "probability_malicious": round(p_malicious, 4),
        "probability_benign":    round(p_benign, 4),
        "features_used":         FEATURE_COUNT,
        "disclaimer":            _DISCLAIMER,
    }


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _unavailable_ml(reason: str, fv_version: Optional[str]) -> Dict[str, Any]:
    """Returned when model is absent or feature extraction failed."""
    return {
        "status":                "unavailable",
        "model_version":         None,
        "feature_vector_version": fv_version,
        "prediction":            None,
        "confidence":            None,
        "probability_malicious": None,
        "probability_benign":    None,
        "features_used":         None,
        "disclaimer":            reason,
    }


def _failed_ml(reason: str, fv_version: Optional[str]) -> Dict[str, Any]:
    """Returned when model exists but inference itself errored."""
    return {
        "status":                "failed",
        "model_version":         MODEL_VERSION,
        "feature_vector_version": fv_version,
        "prediction":            None,
        "confidence":            None,
        "probability_malicious": None,
        "probability_benign":    None,
        "features_used":         None,
        "disclaimer":            f"ML inference error: {reason}",
    }
