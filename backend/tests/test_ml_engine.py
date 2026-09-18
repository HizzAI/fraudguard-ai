"""
test_ml_engine.py — Unit tests for Phase 5B ML engine integration.

Tests verify:
  - Unavailable states (failed analysis, missing model).
  - Successful inference (when a dummy model is mocked).
  - The feature array is shaped correctly and matches FEATURE_COUNT.
  - The graceful failure mechanism when inference raises an exception.
"""

import pytest
import numpy as np
from unittest.mock import patch, MagicMock

from app.ml.ml_engine import (
    calculate_ml,
    MODEL_VERSION,
    _DISCLAIMER,
)
from app.ml.feature_extractor import FEATURE_COUNT


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def mock_feature_result_success():
    """A minimal successful feature extraction result."""
    return {
        "status": "success",
        "version": "fv-1.0",
        "features": {f"feat_{i}": 0 for i in range(FEATURE_COUNT)}  # dummy keys for size
    }

@pytest.fixture
def mock_feature_result_failed():
    """A failed feature extraction result."""
    return {
        "status": "unavailable",
        "version": "fv-1.0",
        "features": {f"feat_{i}": 0 for i in range(FEATURE_COUNT)}
    }

@pytest.fixture
def mock_rf_model():
    """Mocks a trained RandomForestClassifier."""
    mock_model = MagicMock()
    mock_model.classes_ = [0, 1]  # 0=benign, 1=malicious
    # Return 20% benign, 80% malicious
    mock_model.predict_proba.return_value = np.array([[0.2, 0.8]])
    return mock_model

@pytest.fixture
def mock_rf_model_benign():
    """Mocks a trained RandomForestClassifier predicting benign."""
    mock_model = MagicMock()
    mock_model.classes_ = [0, 1]
    # Return 90% benign, 10% malicious
    mock_model.predict_proba.return_value = np.array([[0.9, 0.1]])
    return mock_model


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

class TestMLEngine:

    def test_calculate_ml_unavailable_when_analysis_failed(self, mock_feature_result_failed):
        """If feature extraction failed, ML should be unavailable."""
        result = calculate_ml(mock_feature_result_failed)
        assert result["status"] == "unavailable"
        assert result["prediction"] is None
        assert result["confidence"] is None
        assert "requires a successful APK analysis" in result["disclaimer"]

    @patch("app.ml.ml_engine._load_model")
    def test_calculate_ml_unavailable_when_model_missing(self, mock_load_model, mock_feature_result_success):
        """If the model file doesn't exist, ML should be unavailable."""
        mock_load_model.return_value = None
        result = calculate_ml(mock_feature_result_success)
        
        assert result["status"] == "unavailable"
        assert result["prediction"] is None
        assert "ML model has not been trained yet" in result["disclaimer"]

    @patch("app.ml.feature_extractor.FEATURE_NAMES", [f"feat_{i}" for i in range(FEATURE_COUNT)])
    @patch("app.ml.ml_engine._load_model")
    def test_calculate_ml_success_malicious(self, mock_load_model, mock_rf_model, mock_feature_result_success):
        """Valid features + malicious prediction should return expected payload."""
        mock_load_model.return_value = mock_rf_model
        
        result = calculate_ml(mock_feature_result_success)
        
        assert result["status"] == "success"
        assert result["prediction"] == "malicious"
        assert result["probability_malicious"] == 0.8
        assert result["probability_benign"] == 0.2
        assert result["confidence"] == 0.8
        assert result["model_version"] == MODEL_VERSION
        assert result["features_used"] == FEATURE_COUNT
        assert result["disclaimer"] == _DISCLAIMER

    @patch("app.ml.feature_extractor.FEATURE_NAMES", [f"feat_{i}" for i in range(FEATURE_COUNT)])
    @patch("app.ml.ml_engine._load_model")
    def test_calculate_ml_success_benign(self, mock_load_model, mock_rf_model_benign, mock_feature_result_success):
        """Valid features + benign prediction should return expected payload."""
        mock_load_model.return_value = mock_rf_model_benign
        
        result = calculate_ml(mock_feature_result_success)
        
        assert result["status"] == "success"
        assert result["prediction"] == "benign"
        assert result["probability_malicious"] == 0.1
        assert result["probability_benign"] == 0.9
        assert result["confidence"] == 0.9

    @patch("app.ml.feature_extractor.FEATURE_NAMES", [f"feat_{i}" for i in range(FEATURE_COUNT)])
    @patch("app.ml.ml_engine._load_model")
    def test_calculate_ml_handles_inference_exception(self, mock_load_model, mock_rf_model, mock_feature_result_success):
        """If model.predict_proba throws, it should return a 'failed' status, not crash."""
        mock_rf_model.predict_proba.side_effect = Exception("Simulated inference crash")
        mock_load_model.return_value = mock_rf_model
        
        result = calculate_ml(mock_feature_result_success)
        
        assert result["status"] == "failed"
        assert result["prediction"] is None
        assert "Simulated inference crash" in result["disclaimer"]
