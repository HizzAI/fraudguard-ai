# FraudGuard AI

**AI-assisted Android APK security investigation platform.**

FraudGuard AI statically analyzes Android APK files, extracts security-relevant features, evaluates risk using a deterministic rule-based engine, and classifies potential malware using a machine learning model. Results are surfaced in an investigation dashboard with explainable findings.

> **Status:** Active prototype — development is ongoing. This is not a production-ready security product.

---

## Capabilities

| Capability | Status |
|---|---|
| APK upload (drag-and-drop or browse) | ✅ Implemented |
| Static APK analysis (Androguard) | ✅ Implemented |
| Package, label, and version extraction | ✅ Implemented |
| Permission enumeration and analysis | ✅ Implemented |
| Android component analysis (activities, services, receivers, providers) | ✅ Implemented |
| DEX file count and API call extraction | ✅ Implemented |
| Certificate subject / issuer extraction | ✅ Implemented |
| Deterministic 47-feature extraction | ✅ Implemented |
| Rule-based risk scoring with severity levels | ✅ Implemented |
| ML-based risk classification | ✅ Implemented (prototype model) |
| Explainable risk findings ("Why was this APK flagged?") | ✅ Implemented |
| Investigation dashboard | ✅ Implemented |
| Automated test suite (76 tests) | ✅ Implemented |
| ML training scripts and audit pipeline | ✅ Implemented |

---

## Architecture

```
APK (user upload)
       │
       ▼
  APK Analyzer  (Androguard 3.3.5)
       │  Extracts: package, permissions, components, DEX, certificate, APIs
       ▼
  47-Feature Extractor
       │  Converts analyzer output to a fixed-length numeric feature vector
       ▼
  Rule-Based Risk Engine   ──────────────────────────────────────────────┐
       │  Evaluates individual permission and API signals                 │
       │  Evaluates combination rules (e.g., SMS interception pattern)   │
       │  Returns: score 0–100, severity classification, findings list   │
       ▼                                                                  │
  ML Risk Model                                                           │
       │  Consumes the 47-feature vector                                  │
       │  Returns: ML classification, confidence (if model is present)   │
       ▼                                                                  │
  API Response (JSON)  ◄──────────────────────────────────────────────────┘
       │
       ▼
  Investigation Dashboard (React)
       │  Displays: risk dial, findings, evidence, certificate, components
```

---

## Technology Stack

| Layer | Technology |
|---|---|
| Backend framework | Python 3.12+, FastAPI 0.109 |
| APK static analysis | Androguard 3.3.5 |
| ML / feature extraction | scikit-learn ≥ 1.3, NumPy ≥ 1.24, joblib ≥ 1.3 |
| HTTP server | Uvicorn |
| Frontend framework | React 19, Vite 8 |
| Frontend styling | Tailwind CSS v4 |
| Frontend animation | Framer Motion |
| Frontend icons | Lucide React |
| Testing | pytest 9 |

---

## Project Structure

```
fraudguard-ai/
├── backend/
│   ├── app/
│   │   ├── main.py                  ← FastAPI app entry point
│   │   ├── analyzer/
│   │   │   └── apk_analyzer.py      ← Androguard APK static analysis
│   │   ├── ml/
│   │   │   ├── feature_extractor.py ← 47-feature extraction logic
│   │   │   └── ml_engine.py         ← ML inference engine
│   │   └── risk/
│   │       ├── risk_engine.py       ← Deterministic risk scoring
│   │       └── rules.py             ← Rule definitions
│   ├── scripts/
│   │   ├── acquire_dataset.py       ← MalEval dataset acquisition
│   │   ├── extract_batch_features.py← Batch APK feature extraction
│   │   ├── audit_training_data.py   ← Dataset integrity audit
│   │   ├── baseline_experiment.py   ← Stratified 5-fold CV baseline
│   │   ├── feature_behavior_audit.py← Feature explainability analysis
│   │   ├── train_model.py           ← Model training entry point
│   │   └── training_data.csv        ← Extracted feature dataset (40 APKs)
│   ├── tests/
│   │   ├── test_feature_extractor.py← 47-feature schema and logic tests
│   │   ├── test_ml_engine.py        ← ML engine unit tests
│   │   └── test_risk_engine.py      ← Risk engine and rule tests
│   └── requirements.txt
├── data/
│   └── raw/                         ← Prototype APK dataset (40 APKs)
│       └── <sha256>.apk             ← Named by SHA-256 (MalEval dataset)
├── frontend/
│   ├── src/
│   │   ├── App.jsx                  ← Main application UI
│   │   ├── components/ui/
│   │   │   └── cyber-matrix-hero.jsx← Animated landing component
│   │   ├── index.css                ← Tailwind CSS entry
│   │   └── main.jsx                 ← React entry point
│   ├── package.json
│   ├── vite.config.js
│   ├── tailwind.config.js
│   └── .env.example                 ← Environment variable template
├── .gitignore
└── README.md
```

---

## Local Setup

### Prerequisites

- Python 3.10+ with `pip`
- Node.js 18+ with `npm`

### Backend

```bash
# Navigate to the backend directory
cd backend

# Create and activate a virtual environment
python3 -m venv venv
source venv/bin/activate        # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Start the development server
uvicorn app.main:app --reload --host 127.0.0.1 --port 8000
```

The API will be available at `http://127.0.0.1:8000`. Interactive docs at `http://127.0.0.1:8000/docs`.

### Frontend

```bash
# Navigate to the frontend directory
cd frontend

# Copy environment variable template
cp .env.example .env.local
# Edit .env.local and set VITE_API_BASE=http://127.0.0.1:8000 for local development

# Install dependencies
npm install

# Start the development server
npm run dev
```

The frontend will be available at `http://localhost:5173`.

### Running Tests

```bash
cd backend
source venv/bin/activate
python -m pytest tests/ -v
```

---

## APK Analysis Workflow

1. The user uploads an `.apk` file via the investigation dashboard.
2. The backend saves the file to `backend/uploads/` (transient; not committed to source control).
3. `analyze_apk()` runs Androguard static analysis — the APK is **never executed**.
4. The analysis output is passed to `calculate_risk()` which evaluates predefined rules and returns a risk score (0–100), classification, and a findings list.
5. `extract_features()` converts the analysis output into a 47-dimension numeric feature vector.
6. `calculate_ml()` runs ML inference if a trained model is available. If no model is present, it returns a graceful "unavailable" response.
7. The combined JSON response is returned to the frontend, which renders the investigation dashboard.

---

## ML Pipeline

### 47-Feature Schema

The feature vector is deterministically extracted from the APK analyzer output and covers six groups:

| Group | Features | Example |
|---|---|---|
| A — Metadata | 2 | APK file size, DEX count |
| B — Permission counts | 2 | Total permissions, dangerous permission count |
| C — Permission flags | 27 | `SEND_SMS`, `RECEIVE_BOOT_COMPLETED`, `CAMERA`, etc. |
| D — Component counts | 4 | Activity, service, receiver, provider counts |
| E — API flags | 8 | Runtime exec, DexClassLoader, Reflection, SMS API, etc. |
| F — Certificate | 4 | Present flag, subject length, debug certificate flag |

The schema is fixed at 47 features. Changing the schema would break the ML pipeline and requires a full model retrain.

### Current Prototype Model

The current model is trained on a **40-APK prototype dataset** (20 benign, 20 malware from the MalEval dataset). It uses Stratified 5-Fold cross-validation and three baseline classifiers (Logistic Regression, Random Forest, SVM).

> ⚠️ **Disclaimer:** The current model is a development prototype. Its cross-validation metrics on the 40-sample dataset are **not representative of real-world malware detection performance** and should not be used as a production benchmark. Dataset expansion is ongoing.

---

## Dataset

### Current Prototype Dataset

- **Source:** MalEval dataset (`Xinzxr/MalEval` via Hugging Face)
- **Size:** 40 APKs — 20 benign, 20 malware
- **Labeling:** Based on MalEval's published ground truth, not self-assigned
- **Location:** `data/raw/` (files named by SHA-256)
- **Features:** Extracted via the existing 47-feature pipeline; stored in `backend/scripts/training_data.csv`
- **Status:** Prototype dataset for development evaluation. Dataset expansion is planned.

Previously evaluated datasets that were **rejected**:
- **CCCS-CIC-AndMal-2020 CSV** — feature names are anonymized (F0–F9503); no verified mapping to the 47 production features.
- **Zenodo 18627925** — dataset inaccessible or incompatible.

---

## Testing

The test suite covers three core modules:

```
tests/
├── test_feature_extractor.py  — 47-feature schema, group tests, edge cases
├── test_ml_engine.py          — inference availability, success/failure states
└── test_risk_engine.py        — rules, scoring, classification, determinism
```

**Current status:** 76 tests, all passing.

To run:

```bash
cd backend && python -m pytest tests/ -v
```

---

## Security Notes

- APKs are analyzed **statically only**. No APK is executed, installed, or run in an emulator as part of this pipeline.
- Uploaded APKs are stored temporarily in `backend/uploads/`. This directory is excluded from source control (`.gitignore`).
- All secrets (API keys, credentials) must be stored in `.env` or `.env.local` — never committed.
- `frontend/.env.example` documents required frontend environment variables.
- FraudGuard AI is a **research and prototype platform**. It is not a replacement for a professional mobile security sandbox or commercial malware analysis service.

---

## Current Project Status

FraudGuard AI is an actively developed prototype. The following components are complete and verified:

- ✅ Phase 1: Project setup and API scaffold
- ✅ Phase 2: APK static analysis pipeline (Androguard integration)
- ✅ Phase 3: Deterministic rule-based risk engine
- ✅ Phase 4: Investigation results dashboard (React)
- ✅ Phase 5B: ML infrastructure (feature extraction, ML engine, training scripts)
- ✅ Phase 5B.5C: Dataset acquisition, feature extraction pipeline, and ML baseline experiment

**Development is continuing.** The next areas of focus include:

- Dataset expansion and broader validation
- Integration of trained model inference into the active API
- Frontend ML classification display
- Improved explainability output

---

## Future Work

- Expand the prototype dataset with more APK sources (DREBIN, AndroZoo, or curated F-Droid samples)
- Validate the ML model on a held-out test set beyond the 40-sample prototype
- Integrate active ML inference into the production API response
- Surface ML classification results in the investigation dashboard
- Strengthen explainability (SHAP values, feature contribution visualization)
- Add more forensic indicators to the rule engine
- Explore streaming analysis pipeline for large APKs

---

## License

This project is developed for research and educational purposes as part of the Smart India Hackathon (SIH) 2026 prototype demonstration.
