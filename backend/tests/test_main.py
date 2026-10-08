import os
import pytest
from unittest.mock import patch
from fastapi.testclient import TestClient
from pathlib import Path
from app.main import app

def test_cors_development(monkeypatch):
    monkeypatch.setenv("CORS_ORIGINS", "http://localhost:5173,http://127.0.0.1:5173")
    import importlib
    import app.main
    importlib.reload(app.main)
    client = TestClient(app.main.app)
    
    response = client.options(
        "/upload-apk",
        headers={
            "Origin": "http://localhost:5173",
            "Access-Control-Request-Method": "POST"
        }
    )
    assert response.status_code == 200
    assert response.headers.get("access-control-allow-origin") == "http://localhost:5173"

def test_cors_production(monkeypatch):
    monkeypatch.setenv("CORS_ORIGINS", "https://fraudguard-ai.vercel.app")
    import importlib
    import app.main
    importlib.reload(app.main)
    client = TestClient(app.main.app)
    
    response = client.options(
        "/upload-apk",
        headers={
            "Origin": "https://fraudguard-ai.vercel.app",
            "Access-Control-Request-Method": "POST"
        }
    )
    assert response.status_code == 200
    assert response.headers.get("access-control-allow-origin") == "https://fraudguard-ai.vercel.app"

    # Unrelated origin should not be accepted
    response_bad = client.options(
        "/upload-apk",
        headers={
            "Origin": "https://evil.com",
            "Access-Control-Request-Method": "POST"
        }
    )
    assert response_bad.headers.get("access-control-allow-origin") is None

def test_upload_apk_success_and_cleanup():
    client = TestClient(app)
    
    with patch("app.main.analyze_apk") as mock_analyze, \
         patch("app.main.calculate_risk") as mock_risk, \
         patch("app.main.extract_features") as mock_feat, \
         patch("app.main.calculate_ml") as mock_ml, \
         patch("app.main.os.remove") as mock_remove, \
         patch("app.main.os.path.exists", return_value=True):
         
        mock_analyze.return_value = {"status": "success"}
        mock_risk.return_value = {"score": 50}
        mock_feat.return_value = {"feat": 1}
        mock_ml.return_value = {"malware_probability": 0.5}

        file_content = b"fake apk content"
        response = client.post(
            "/upload-apk",
            files={"file": ("test.apk", file_content, "application/vnd.android.package-archive")}
        )
        
        assert response.status_code == 200
        assert response.json()["status"] == "success"
        
        assert mock_remove.called
        removed_file = mock_remove.call_args[0][0]
        assert removed_file.endswith(".apk")

def test_upload_apk_failure_cleanup():
    client = TestClient(app)
    
    with patch("app.main.analyze_apk") as mock_analyze, \
         patch("app.main.os.remove") as mock_remove, \
         patch("app.main.os.path.exists", return_value=True):
         
        mock_analyze.side_effect = Exception("Simulated analysis crash")
        
        try:
            response = client.post(
                "/upload-apk",
                files={"file": ("test.apk", b"bad data", "application/vnd.android.package-archive")}
            )
        except Exception:
            pass # FastAPI testclient might raise the exception directly depending on config
            
        assert mock_remove.called
        removed_file = mock_remove.call_args[0][0]
        assert removed_file.endswith(".apk")
