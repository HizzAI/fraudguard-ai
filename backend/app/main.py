from fastapi import FastAPI, UploadFile, File, HTTPException
from fastapi.middleware.cors import CORSMiddleware
import os
import shutil
import tempfile
from pathlib import Path
from app.analyzer.apk_analyzer import analyze_apk
from app.risk.risk_engine import calculate_risk
from app.ml.feature_extractor import extract_features
from app.ml.ml_engine import calculate_ml

app = FastAPI(
    title="FraudGuard AI",
    description="AI-powered Android APK risk analysis platform",
    version="2.0.0"
)

# Parse CORS_ORIGINS from environment, fallback to localhost for development
cors_origins_env = os.environ.get("CORS_ORIGINS", "http://localhost:5173,http://127.0.0.1:5173")
origins = [origin.strip() for origin in cors_origins_env.split(",") if origin.strip()]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.get("/health")
async def health_check():
    """
    Health check endpoint.
    """
    return {"status": "ok"}

@app.post("/upload-apk")
async def upload_apk(file: UploadFile = File(...)):
    """
    Accepts an uploaded APK file, validates its extension, and processes it in a temporary location.
    """
    if not file.filename.lower().endswith(".apk"):
        raise HTTPException(status_code=400, detail="Only .apk files are allowed.")
    
    # Create a temporary file that will be cleaned up automatically
    fd, tmp_path = tempfile.mkstemp(suffix=".apk")
    try:
        try:
            with os.fdopen(fd, 'wb') as buffer:
                shutil.copyfileobj(file.file, buffer)
        except Exception as e:
            raise HTTPException(status_code=500, detail=f"Failed to save the file: {str(e)}")
        finally:
            file.file.close()
            
        file_path = Path(tmp_path)
        file_size = file_path.stat().st_size
        
        # Phase 2: static analysis
        analysis_result = analyze_apk(str(file_path))

        # Phase 3: deterministic risk scoring
        # calculate_risk() consumes analysis_result — it never re-parses the APK.
        # If analysis failed, it returns a null risk state (no fabricated score).
        analysis_result["risk"] = calculate_risk(analysis_result)

        # Phase 5B: ML classification
        # extract_features() converts the Phase 2 output into a 47-feature vector.
        # calculate_ml() runs inference if the trained model is present.
        # Both return graceful unavailable states on failure — no exceptions bubble up.
        feature_result = extract_features(analysis_result, size_bytes=file_size)
        analysis_result["ml"] = calculate_ml(feature_result)

        return {
            "filename": file.filename,
            "content_type": file.content_type,
            "size_bytes": file_size,
            "message": "File uploaded and analyzed successfully",
            **analysis_result
        }
    finally:
        # Cleanup occurs even if analysis fails or an exception is thrown
        if os.path.exists(tmp_path):
            os.remove(tmp_path)
