# FraudGuard AI

Android APK static analysis platform. Upload an APK, get back structured metadata extracted by Androguard — package name, permissions, components, DEX info, API references, and certificate details.

## Stack

| Layer    | Tech                          |
|----------|-------------------------------|
| Backend  | Python · FastAPI · Androguard |
| Frontend | React · Vite                  |

## Project Structure

```
fraudguard-ai/
├── backend/
│   ├── app/
│   │   ├── main.py              # FastAPI app, /health + /upload-apk endpoints
│   │   └── analyzer/
│   │       └── apk_analyzer.py  # Androguard static analysis module
│   └── requirements.txt
└── frontend/
    └── src/
        ├── App.jsx              # Full React UI
        └── index.css            # Styles
```

## Running Locally

### Backend

```bash
cd backend
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
uvicorn app.main:app --host 127.0.0.1 --port 8000
```

Health check: `http://127.0.0.1:8000/health`  
Upload endpoint: `POST http://127.0.0.1:8000/upload-apk` (multipart field: `file`)

### Frontend

```bash
cd frontend
npm install
npm run dev
```

Open: `http://localhost:5173`

## API Response Shape

```json
{
  "filename": "example.apk",
  "analysis_status": "success",
  "app": { "package_name": "...", "label": "...", "version": "..." },
  "permissions": [],
  "components": { "activities": [], "services": [], "receivers": [], "providers": [] },
  "dex": { "count": 1 },
  "apis": [],
  "certificate": { "subject": "...", "issuer": "...", "serial_number": "..." },
  "errors": []
}
```

## Status

- **Phase 1** ✅ — FastAPI backend, APK upload + validation
- **Phase 2** ✅ — Androguard static analysis engine + React frontend
