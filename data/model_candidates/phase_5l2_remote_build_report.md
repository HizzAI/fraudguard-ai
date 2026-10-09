# FraudGuardAI — Phase 5L.2: Remote Container Build Verification Report

**Date/Time:** 2026-10-09T16:00 IST (UTC+05:30)
**Phase:** 5L.2 — Remote Container Build Verification
**Final Status:** `BLOCKED — CLOUD ACCESS OR APPROVAL REQUIRED`

---

## 1. Repository Snapshot

| Field | Value |
|---|---|
| Repository root | `/Users/pratikshinde/Programming/fraudguard-ai` |
| Active branch | `main` |
| HEAD commit | `c345059398d394bc0989d1e6b7bdc91fe2eff065` |
| Expected checkpoint | `c345059` ✅ |
| Uncommitted changes | `backend/Dockerfile`, `backend/.dockerignore`, research scripts, data artifacts (all untracked; no staged or modified tracked files) |

---

## 2. Dockerfile Review

**File:** `backend/Dockerfile`

```dockerfile
FROM python:3.12-slim
ENV PYTHONUNBUFFERED=1
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY app/ ./app/
ENV PORT=8000
CMD ["sh", "-c", "uvicorn app.main:app --host 0.0.0.0 --port ${PORT}"]
```

| Check | Result |
|---|---|
| Base image | `python:3.12-slim` ✅ |
| Bind address | `--host 0.0.0.0` ✅ |
| Dynamic port | `--port ${PORT}` with `ENV PORT=8000` default ✅ |
| PYTHONUNBUFFERED | Set ✅ |
| Production model included | `app/ml/model_rf_v1.pkl` inside `app/` → copied by `COPY app/ ./app/` ✅ |
| Dependency manifest included | `requirements.txt` copied and installed ✅ |

**No concrete Dockerfile defects found.**

---

## 3. `.dockerignore` Review

**File:** `backend/.dockerignore`

```
.env
.env.*
!.env.example
__pycache__/
*.py[cod]
*$py.class
venv/
.venv/
uploads/
tests/
scripts/
.pytest_cache/
```

| Sensitive Item | Present on Disk | Excluded? |
|---|---|---|
| `backend/.env` (82 bytes) | Yes | ✅ `.env` rule |
| `backend/.env.*` patterns | Covered | ✅ `.env.*` rule |
| `backend/uploads/*.apk` (3 APKs present) | Yes | ✅ `uploads/` rule |
| `backend/scripts/` (AndroZoo & training scripts) | Yes | ✅ `scripts/` rule |
| `backend/venv/` | Yes | ✅ `venv/` rule |
| `backend/tests/` | Yes | ✅ `tests/` rule |
| Stray APK/CSV/key files in `backend/app/` | None found | N/A — clean |

> **Note on scope:** The `.dockerignore` is co-located with the Dockerfile at `backend/`. The build context root is `backend/`. The `.env` file at `backend/.env` is at the build context root and is correctly excluded by the `.env` rule. No sensitive files exist inside `backend/app/` that would bypass exclusion rules.

**No `.dockerignore` defects found. Sensitive files will not enter the image.**

---

## 4. Model Verification (Local — via `backend/venv`)

| Check | Result |
|---|---|
| `model_rf_v1.pkl` exists | ✅ (`backend/app/ml/model_rf_v1.pkl`, 52,789 bytes) |
| Model type | `sklearn.pipeline.Pipeline` |
| Classes | `[0, 1]` ✅ |
| `predict_proba()` supported | ✅ |

---

## 5. Google Cloud CLI and Authentication Status

### CLI Version

```
Google Cloud SDK 588.0.0
bq 2.1.39
bundled-python3-unix 3.14.7
core 2026.10.02
gcloud-crc32c 1.0.0
```

### Authentication

```
gcloud auth list  →  No credentialed accounts.
```

**❌ BLOCKER: No Google account is authenticated.**

```
gcloud config get-value project  →  (unset)
```

**❌ BLOCKER: No project is configured.**

### Verified Project Identifier

**Cannot be determined** — project is unset and no account is authenticated. `gcloud projects describe` was not run.

### Impact

Because no account is authenticated and no project is set:
- Billing status cannot be checked.
- Cloud Build API availability cannot be verified.
- Artifact Registry repository cannot be created or verified.
- No remote build can be submitted.

---

## 6. Billing and Authorization Checks

| Action | Cost / Risk | Status |
|---|---|---|
| `gcloud auth login` | Free | Required |
| Cloud Build API enable | May trigger billing | Unknown — project unset |
| Cloud Build minutes (first 120/day) | Free tier | Unknown |
| Cloud Build minutes (over 120 free/day) | ~$0.003/build-minute | Unknown |
| Artifact Registry repo creation | ~$0.10/GB/month storage | Unknown |
| Cloud Run deployment | Not applicable | **Prohibited by scope** |

**Approval required** before enabling any API or creating any Artifact Registry repository.

---

## 7. Remote Build

**Status: NOT ATTEMPTED**

The remote build was not submitted. Authentication and project configuration are hard prerequisites. Attempting a build without them would fail immediately at the Cloud Build API authentication step.

**Anticipated build command (pending approval):**

```bash
gcloud builds submit \
  --tag <REGION>-docker.pkg.dev/<PROJECT_ID>/<REPO>/fraudguard-backend:c345059 \
  backend/
```

---

## 8. Image Verification

**Status: NOT PERFORMED**

No image was built. No URI or digest is available.

---

## 9. Backend Regression Tests (Step 5)

**Environment:** `backend/venv` — Python 3.14.8, pytest (via `backend/venv/bin`)

```
80 passed, 21 warnings in 0.52s
```

**Result: ✅ 80/80 PASSED — Baseline confirmed.**

Warnings are `asyncio.iscoroutinefunction` deprecation notices from FastAPI/Starlette on Python 3.14. They do not affect test outcomes and are not introduced by this phase.

---

## 10. Secret / Data Exclusion Summary

| Data Type | Location | In Build Context? | Excluded? |
|---|---|---|---|
| `.env` (API keys) | `backend/.env` | Yes | ✅ `.dockerignore` |
| Raw APKs | `backend/uploads/` (3 files) | Yes | ✅ `.dockerignore` |
| AndroZoo scripts | `backend/scripts/` | Yes | ✅ `.dockerignore` |
| Training CSV | `backend/scripts/` | Yes | ✅ `.dockerignore` |
| Python venv | `backend/venv/` | Yes | ✅ `.dockerignore` |
| Research data (`data/`) | Outside `backend/` | No | Not in context |
| Frontend code | Outside `backend/` | No | Not in context |

**No unintentional inclusion of secrets, datasets, or raw APKs identified.**

---

## 11. Unresolved Issues

1. **No gcloud authentication** — primary blocker preventing all remote operations.
2. **No project configured** — billing state, project validity, and API enablement cannot be verified.
3. **Dockerfile and `.dockerignore` are untracked** — they exist on disk but have not been committed to git. This is appropriate for this phase but must be committed before a production push.

---

## 12. Next-Step Recommendation

1. Run `gcloud auth login` to authenticate with a Google account holding `roles/cloudbuild.builds.editor` and `roles/artifactregistry.writer` (or equivalent) on the target project.
2. Run `gcloud config set project <PROJECT_ID>` and confirm billing is active.
3. Confirm approval to enable Cloud Build API and Artifact Registry API if not already enabled (billing implications as noted above).
4. Confirm approval to create an Artifact Registry Docker repository (if one does not already exist).
5. Once all approvals are given, re-run Phase 5L.2 Step 3 with the anticipated command above.
6. After a successful remote build, commit `backend/Dockerfile` and `backend/.dockerignore` to track the container configuration at checkpoint `c345059`.

---

## Final Status

```
BLOCKED — CLOUD ACCESS OR APPROVAL REQUIRED
```

**Reason:** `gcloud auth list` reports no credentialed accounts; `gcloud config get-value project` reports `(unset)`. No remote build was submitted. All local checks — Dockerfile, `.dockerignore`, model introspection, and the full 80-test regression suite — passed independently.
