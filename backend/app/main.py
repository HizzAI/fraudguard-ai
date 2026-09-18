from fastapi import FastAPI, UploadFile, File, HTTPException
from fastapi.middleware.cors import CORSMiddleware
import shutil
from pathlib import Path
from app.analyzer.apk_analyzer import analyze_apk

app = FastAPI(
    title="FraudGuard AI",
    description="AI-powered Android APK risk analysis platform",
    version="1.0.0"
)

# Allow the React dev server (and any local origin) to call the API
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "http://127.0.0.1:5173"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# Use absolute path to ensure uploads go to backend/uploads regardless of where the app is run from
BASE_DIR = Path(__file__).resolve().parent.parent
UPLOAD_DIR = BASE_DIR / "uploads"

# Ensure the uploads directory exists
UPLOAD_DIR.mkdir(parents=True, exist_ok=True)

@app.get("/health")
async def health_check():
    """
    Health check endpoint.
    """
    return {"status": "ok"}

@app.post("/upload-apk")
async def upload_apk(file: UploadFile = File(...)):
    """
    Accepts an uploaded APK file, validates its extension, and saves it.
    """
    if not file.filename.lower().endswith(".apk"):
        raise HTTPException(status_code=400, detail="Only .apk files are allowed.")
    
    file_path = UPLOAD_DIR / file.filename
    
    try:
        # Save the uploaded file to the uploads directory
        with file_path.open("wb") as buffer:
            shutil.copyfileobj(file.file, buffer)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to save the file: {str(e)}")
    finally:
        file.file.close()
        
    file_size = file_path.stat().st_size
    
    # Perform static analysis on the saved APK
    analysis_result = analyze_apk(str(file_path))
    
    return {
        "filename": file.filename,
        "content_type": file.content_type,
        "size_bytes": file_size,
        "message": "File uploaded and analyzed successfully",
        **analysis_result
    }
