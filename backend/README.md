# FraudGuard AI

AI-powered Android APK risk analysis and explainable security platform.

## Phase 1 - Project Foundation

### Backend

Built with Python and FastAPI.

#### Setup

1. Navigate to the backend directory.
2. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```
3. Run the development server:
   ```bash
   uvicorn app.main:app --reload
   ```

#### Endpoints

- `GET /health` - Returns `{"status": "ok"}`
- `POST /upload-apk` - Accepts an `.apk` file and saves it to the `uploads/` directory. Returns file information.
