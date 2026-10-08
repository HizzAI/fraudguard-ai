# Deployment Readiness Report
## Phase 5I — FraudGuardAI Repository Audit

**Date:** 2026-10-08  
**Status:** ⚠️ DEPLOYMENT BLOCKED  

---

## 1. Executive Summary

The ML and data pipeline have successfully generated a highly capable model (`svm-combined-v1.0`). The end-to-end integration is robust. However, a strict audit of the repository infrastructure reveals several architectural and configuration blockers that prevent an immediate push to production. 

The primary blockers revolve around hardcoded `localhost` references (CORS and frontend API URLs), serverless filesystem constraints (`backend/uploads/`), and git tracking configuration (`*.pkl` ignored).

---

## 2. Repository Structure

| Component | Status | Recommendation |
|-----------|--------|----------------|
| `frontend/` | React/Vite SPA | Ready for static hosting (e.g., Vercel) once env vars are set. |
| `backend/` | FastAPI App | Functionally ready, but deployment configuration is incomplete (no Dockerfile). |
| `data/` | Datasets & Models | `data/raw/` (APKs) should be excluded from final production images. |
| `backend/scripts/` | ML/Data Pipelines | Development only. Exclude from runtime environments. |
| `backend/tests/` | Pytest Suite | Development only. Exclude from runtime environments. |

---

## 3. Secret & Credential Audit

| Secret Type | Location | Tracked by Git? | Exposed? |
|-------------|----------|-----------------|----------|
| `ANDROZOO_API_KEY` | `backend/.env` | No (ignored by `.gitignore`) | No |
| `.env.local` / `.env` | `frontend/`, `backend/` | No | No |

**Finding:** NO secrets are exposed or tracked in source control. **SAFE.**

---

## 4. Git Ignore Audit

The `.gitignore` file correctly ignores:
- `backend/uploads/`
- `.env`, `.env.*`
- `__pycache__`, `venv/`, `node_modules/`
- `data/raw/androzoo/*.apk`

**CRITICAL FINDING:** 
The `.gitignore` explicitly ignores `*.pkl` (Model artifacts). 
Because the production model (`backend/app/ml/model_rf_v1.pkl`) is ignored, pushing this repository to a PaaS (like Vercel, Render, or Heroku) will result in a **missing model file at runtime**, crashing the ML inference.

---

## 5. Production Model Audit

| Check | Result |
|-------|--------|
| File | `backend/app/ml/model_rf_v1.pkl` |
| Size | **51.6 KB** (Extremely lightweight) |
| Interface | `predict()`, `predict_proba()`, `classes_` confirmed |
| Features | 47 features confirmed |
| Loadable | Yes (`joblib.load()` succeeds) |

---

## 6. Model Artifact / Git Size Audit

- **Model Size:** 51.6 KB
- **GitHub Limits:** GitHub limits individual files to 100MB.
- **Git LFS Required:** No.
- **Verdict:** The production model is remarkably small and **can reasonably be committed to GitHub**. However, `.gitignore` currently blocks this (see Section 4). 

---

## 7. Dataset / Runtime Artifact Audit

- **Raw Datasets (`data/raw/`):** Contains ~240 raw APKs. Total size is hundreds of MBs.
- **Processed Datasets (`data/processed/`, `data/manifests/`):** Contains CSV files.
- **Scripts & ML pipelines:** `backend/scripts/`
- **Verdict:** These are research, evaluation, and training artifacts. They are not required for the FastAPI runtime. If deploying via Docker, they should be excluded via `.dockerignore` to keep the image lightweight.

---

## 8. Backend Deployment Audit

- **Entry Point:** `backend/app/main.py` (FastAPI)
- **Dependencies:** `fastapi`, `androguard`, `scikit-learn`, `numpy`, `joblib`
- **Filesystem Constraints:** `backend/app/main.py` writes uploaded APKs to `BASE_DIR / "uploads"`.
- **Execution Constraints:** Androguard static analysis of large APKs can take upwards of 10-30 seconds.

---

## 9. Vercel Compatibility Audit

**Is the backend compatible with Vercel Serverless Functions?**
**No.** 

1. **Filesystem Limitations:** Vercel functions are strictly read-only except for the `/tmp` directory. Writing to `BASE_DIR / "uploads"` will immediately throw an `OSError: Read-only file system`.
2. **Timeout Limitations:** Vercel Hobby tier times out at 10 seconds (Pro at 60s). Heavy APK analysis via Androguard will likely breach the 10-second limit frequently.
3. **Dependency Size:** `androguard` + `scikit-learn` + `numpy` could exceed Vercel's strict deployment size limits (250MB uncompressed).

**Verdict:** Backend requires architectural adjustment (e.g. using `/tmp` or `tempfile`) before deploying to Vercel, but even then, timeouts make Vercel a poor choice for the backend.

---

## 10. Frontend Production Audit

- **Build:** `vite build` functions correctly.
- **Environment:** Relies on `VITE_API_BASE`.
- **CORS/Proxy:** Local development relies on Vite proxying `/upload-apk` to `http://127.0.0.1:8000`. 
- **Verdict:** Ready for Vercel deployment, provided `VITE_API_BASE` is configured in the Vercel dashboard.

---

## 11. CORS / API Connection Audit

**CRITICAL FINDING:**
In `backend/app/main.py`, CORS is hardcoded:
```python
allow_origins=["http://localhost:5173", "http://127.0.0.1:5173"],
```
If the frontend is deployed to `https://fraudguard-ai.vercel.app`, the backend will reject all requests. 
**The backend must be updated to accept the production frontend origin (ideally via an environment variable).**

---

## 12. Deployment Architecture Decision

**Option B:** Frontend can deploy to Vercel, but backend requires a separate compatible hosting environment.

- **Frontend:** Vercel or Netlify (Static Hosting).
- **Backend:** Google Cloud Run, Render, Railway, or a traditional VPS. 
- **Why?** Cloud Run / Render provide Docker-based environments with longer timeouts (up to minutes/hours), configurable memory, and ephemerally writable filesystems that will easily support Androguard + Scikit-Learn without rewriting the upload logic to use `/tmp` (though using `/tmp` is still best practice).

---

## 13. Git Status

- **Untracked files:** Dozens of scripts and evaluation CSVs in `backend/scripts/` and `data/raw/androzoo/`.
- **Modified files:** `backend/app/ml/ml_engine.py`, `.gitignore`
- **Missing from Git:** `backend/app/ml/model_rf_v1.pkl` (ignored)

---

## 14. Final Deployment Blockers

### 🛑 CRITICAL (Must fix before deployment)
1. **CORS Hardcoded to Localhost:** `backend/app/main.py` must dynamically accept the production frontend URL.
2. **Production Model Ignored:** `.gitignore` ignores `*.pkl`. The 51.6 KB `model_rf_v1.pkl` must be explicitly tracked (e.g., `!backend/app/ml/model_rf_v1.pkl`) or the host won't have it.
3. **Serverless Filesystem incompatibility (if using serverless):** Uploads go to `BASE_DIR / "uploads"`. This will fail on strictly read-only serverless environments.

### 🟠 HIGH
1. **Missing Dockerfile:** To deploy Option B (Cloud Run/Render), a `Dockerfile` and `.dockerignore` are highly recommended to ensure isolation and exclude the massive dataset artifacts.
2. **Missing Production Frontend URL:** `VITE_API_BASE` must be correctly injected into the frontend build.

### 🟡 MEDIUM / LOW
1. Clean up untracked files before committing. 
2. Update the `predict_proba` call to handle the `SVC(probability=True)` FutureWarning if upgrading sklearn.

---

## 15. Exact Next Steps

Before deployment, execute the following configuration changes:
1. Update `backend/app/main.py` CORS origins to use an environment variable (e.g., `FRONTEND_URL`).
2. Update `.gitignore` to allow tracking of `!backend/app/ml/model_rf_v1.pkl` and commit it.
3. (Optional but recommended) Update `backend/app/main.py` to use Python's `tempfile` module or `/tmp/` instead of `BASE_DIR / "uploads"`.
4. Create a `Dockerfile` for the backend.
5. Deploy Backend (Cloud Run/Render), get URL.
6. Deploy Frontend (Vercel) with `VITE_API_BASE` set to Backend URL.
