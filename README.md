# FraudGuardAI

**AI-Assisted Android APK Security Investigation Platform**

FraudGuardAI is a web-based mobile application security investigation platform designed to analyze Android APK packages. It combines static binary deconstruction, a deterministic rule-based threat scoring engine, and a machine-learning classification model trained on calibrated static features.

Security analysts and developers can upload an Android application archive (`.apk`) through a clean, responsive web dashboard to receive an immediate security verdict, threat severity score, explainable forensic indicators, and structured technical evidence.

---

## Key Capabilities

- **Zero-Execution Static Inspection:** Analyzes raw application archives without executing, installing, or emulating untrusted bytecode.
- **Automated Package Deconstruction:** Extracts manifest metadata, declared permissions, exported/non-exported Android components, DEX bytecode counts, and X.509 digital certificates using Androguard.
- **Deterministic 47-Feature Extraction:** Maps APK structural and behavioral attributes into a fixed, leak-free numerical feature vector (`fv-1.0`).
- **Trained Machine-Learning Classification:** Classifies packages using a Support Vector Classifier pipeline (`svm-combined-v1.0`) with Platt scaling to output probabilistic predictions.
- **Rule-Based Threat Scoring:** Evaluates known high-risk permission pairings, dynamic payload loading indicators, and suspicious component signatures to compute an explainable risk score (0–100).
- **Interactive Analyst Dashboard:** Displays a plain-English top-level verdict, key forensic metrics, prioritized risk findings, and collapsible technical evidence.
- **Automated Regression Suite:** 81 automated tests verifying the feature extraction schema, risk engine rules, ML inference contracts, and API lifecycle.

---

## Technology Stack

| Layer | Technology | Purpose |
|---|---|---|
| **Frontend Framework** | React 19, Vite 8 | Single-page analyst dashboard interface |
| **Styling & Icons** | Tailwind CSS v4, Lucide React | Clean, responsive cybersecurity UI components |
| **Backend Framework** | Python 3.12+, FastAPI 0.109, Uvicorn | RESTful API server, async routing, file streaming |
| **Static Analysis** | Androguard 3.3.5 | Manifest deconstruction, Dalvik bytecode disassembly |
| **Machine Learning** | Scikit-learn ≥ 1.3, NumPy ≥ 1.24, Joblib ≥ 1.3 | Preprocessing pipelines, StandardScaler, SVM inference |
| **Testing** | Pytest 9.1, Starlette TestClient, HTTPX | Unit and integration test suite across backend services |

---

## System Architecture

FraudGuardAI is structured into a decoupled frontend-backend architecture:

```
                            [ User Browser / Analyst ]
                                        │
                         (React 19 / Vite Single-Page App)
                                        │  POST /upload-apk (multipart/form-data)
                                        ▼
                        [ FastAPI Backend (Port 8000) ]
                                        │
                       (Safe Temporary File Isolation)
                                        │
                                        ▼
                      [ Static Analyzer (Androguard 3.3.5) ]
                         ├── Manifest & Metadata Extraction
                         ├── Component Inventory
                         ├── DEX Dalvik Method Parsing
                         └── X.509 Certificate Inspection
                                        │
                                        ▼
               ┌────────────────────────┴────────────────────────┐
               │                                                 │
               ▼                                                 ▼
   [ Rule-Based Risk Engine ]                       [ 47-Feature Extractor (fv-1.0) ]
   ├── High-risk permissions                        └── Standardized 47-dim numeric vector
   ├── Permission combinations                                      │
   ├── API pattern indicators                                       ▼
   └── Component name heuristics                         [ Trained ML Model Engine ]
               │                                         └── svm-combined-v1.0 (SVC)
               │                                             (StandardScaler + Platt scaling)
               └────────────────────────┬────────────────────────┘
                                        │
                                        ▼
                       [ Structured JSON Response Payload ]
                                        │
                                        ▼
                         [ Analyst Investigation View ]
```

---

## APK Analysis Workflow

1. **Upload & Ingestion:** The analyst uploads an `.apk` file through the dashboard. The file extension is validated, and the archive is streamed to an isolated temporary file descriptor using `tempfile.mkstemp()`.
2. **Static Deconstruction:** The backend calls `analyze_apk()` via Androguard. The archive is parsed statically without ever executing Dalvik bytecode or launching emulation sandboxes.
3. **Deterministic Risk Scoring:** The extracted metadata dictionary is evaluated by `calculate_risk()`. Individual signals, component patterns, and multi-permission combinations are scored against standardized cybersecurity rules.
4. **Feature Vector Extraction:** `extract_features()` maps the analysis results into a fixed 47-dimensional numerical vector. Risk scores and engine verdicts are strictly excluded from this step to prevent label leakage.
5. **Machine-Learning Classification:** `calculate_ml()` loads the trained SVM pipeline (`model_rf_v1.pkl`), standardizes features, and evaluates malicious versus benign probability distributions.
6. **Ephemeral Cleanup:** A `finally` block ensures the uploaded temporary `.apk` file is unlinked from the file system immediately following analysis.
7. **Dashboard Presentation:** The frontend presents a high-level security verdict, risk score, key package indicators, prioritized plain-English findings, and collapsible technical evidence.

---

## The 47-Feature Extraction System

The machine-learning pipeline extracts a fixed 47-dimensional numeric vector defined by schema version `fv-1.0` in [`backend/app/ml/feature_extractor.py`](backend/app/ml/feature_extractor.py). All features are strictly extracted from static analysis results, preserving identical ordering across training and inference.

### Group A: File Metadata (2 Features)
| # | Exact Feature Name | Type | Description |
|---|---|---|---|
| 1 | `feat_size_bytes` | Numerical | Total APK file size in bytes. |
| 2 | `feat_dex_count` | Count | Total number of compiled `.dex` files present in the archive. |

### Group B: Permission Statistics (2 Features)
| # | Exact Feature Name | Type | Description |
|---|---|---|---|
| 3 | `feat_perm_total` | Count | Total number of permissions declared in `AndroidManifest.xml`. |
| 4 | `feat_perm_dangerous_count` | Count | Total count of declared permissions matching Android's dangerous permission group. |

### Group C: Permission-Presence Flags (25 Features)
Binary indicators (1 if requested, 0 if absent):
| # | Exact Feature Name | Type | Corresponding Android Permission |
|---|---|---|---|
| 5 | `feat_perm_send_sms` | Binary | `android.permission.SEND_SMS` |
| 6 | `feat_perm_receive_sms` | Binary | `android.permission.RECEIVE_SMS` |
| 7 | `feat_perm_read_sms` | Binary | `android.permission.READ_SMS` |
| 8 | `feat_perm_call_phone` | Binary | `android.permission.CALL_PHONE` |
| 9 | `feat_perm_read_call_log` | Binary | `android.permission.READ_CALL_LOG` |
| 10 | `feat_perm_fine_location` | Binary | `android.permission.ACCESS_FINE_LOCATION` |
| 11 | `feat_perm_bg_location` | Binary | `android.permission.ACCESS_BACKGROUND_LOCATION` |
| 12 | `feat_perm_read_contacts` | Binary | `android.permission.READ_CONTACTS` |
| 13 | `feat_perm_get_accounts` | Binary | `android.permission.GET_ACCOUNTS` |
| 14 | `feat_perm_read_external` | Binary | `android.permission.READ_EXTERNAL_STORAGE` |
| 15 | `feat_perm_write_external` | Binary | `android.permission.WRITE_EXTERNAL_STORAGE` |
| 16 | `feat_perm_manage_external` | Binary | `android.permission.MANAGE_EXTERNAL_STORAGE` |
| 17 | `feat_perm_camera` | Binary | `android.permission.CAMERA` |
| 18 | `feat_perm_record_audio` | Binary | `android.permission.RECORD_AUDIO` |
| 19 | `feat_perm_request_install` | Binary | `android.permission.REQUEST_INSTALL_PACKAGES` |
| 20 | `feat_perm_bind_accessibility` | Binary | `android.permission.BIND_ACCESSIBILITY_SERVICE` |
| 21 | `feat_perm_alert_window` | Binary | `android.permission.SYSTEM_ALERT_WINDOW` |
| 22 | `feat_perm_biometric` | Binary | `android.permission.USE_BIOMETRIC` |
| 23 | `feat_perm_receive_boot` | Binary | `android.permission.RECEIVE_BOOT_COMPLETED` |
| 24 | `feat_perm_foreground_svc` | Binary | `android.permission.FOREGROUND_SERVICE` |
| 25 | `feat_perm_process_calls` | Binary | `android.permission.PROCESS_OUTGOING_CALLS` |
| 26 | `feat_perm_read_phone_state` | Binary | `android.permission.READ_PHONE_STATE` |
| 27 | `feat_perm_change_network` | Binary | `android.permission.CHANGE_NETWORK_STATE` |
| 28 | `feat_perm_change_wifi` | Binary | `android.permission.CHANGE_WIFI_STATE` |
| 29 | `feat_perm_disable_keyguard` | Binary | `android.permission.DISABLE_KEYGUARD` |

### Group D: Application Component Statistics (4 Features)
| # | Exact Feature Name | Type | Description |
|---|---|---|---|
| 30 | `feat_activity_count` | Count | Total declared `<activity>` components. |
| 31 | `feat_service_count` | Count | Total declared `<service>` background components. |
| 32 | `feat_receiver_count` | Count | Total declared `<receiver>` broadcast receivers. |
| 33 | `feat_provider_count` | Count | Total declared `<provider>` content providers. |

### Group E: API-Related Indicators (11 Features)
Binary indicators matching Dalvik method signatures in decompiled DEX bytecode:
| # | Exact Feature Name | Type | Pattern Matches / Method Signatures |
|---|---|---|---|
| 34 | `feat_api_exec_runtime` | Binary | `Runtime;->exec`, `ProcessBuilder` |
| 35 | `feat_api_reflection` | Binary | `java/lang/reflect`, `getDeclaredMethod`, `getDeclaredField` |
| 36 | `feat_api_dynamic_dexload` | Binary | `DexClassLoader`, `PathClassLoader`, `loadClass` |
| 37 | `feat_api_crypto` | Binary | `javax/crypto`, `Cipher;->getInstance`, `SecretKeySpec` |
| 38 | `feat_api_sms_send` | Binary | `SmsManager;->sendTextMessage`, `sendMultipartTextMessage` |
| 39 | `feat_api_telephony_read` | Binary | `TelephonyManager;->getDeviceId`, `getSubscriberId`, `getLine1Number` |
| 40 | `feat_api_location_access` | Binary | `LocationManager;->getLastKnownLocation`, `FusedLocationProviderClient` |
| 41 | `feat_api_root_check` | Binary | `/system/bin/su`, `RootTools`, `Superuser` |
| 42 | `feat_api_clipboard` | Binary | `ClipboardManager;->getPrimaryClip`, `ClipboardManager;->getText` |
| 43 | `feat_api_camera_silent` | Binary | `Camera;->takePicture`, `CameraDevice;->createCaptureSession` |
| 44 | `feat_api_audio_record` | Binary | `AudioRecord;->startRecording`, `MediaRecorder;->start` |

### Group F: Certificate Indicators (3 Features)
| # | Exact Feature Name | Type | Description |
|---|---|---|---|
| 45 | `feat_cert_present` | Binary | Flag indicating whether a valid signing certificate was parsed. |
| 46 | `feat_cert_is_debug` | Binary | Flag indicating if certificate subject contains Android debug keystore strings. |
| 47 | `feat_cert_subject_len` | Numerical | Character length of the certificate subject Distinguished Name (DN). |

---

## Machine-Learning Model & Evaluation

### Model Specification
- **Model Identifier:** `svm-combined-v1.0`
- **Algorithm:** Support Vector Classifier (`SVC(probability=True, random_state=42)`) preceded by `StandardScaler` inside a scikit-learn `Pipeline`.
- **Target Classes:** `0` (Benign) and `1` (Malicious).
- **Inference Mechanism:** Predicts calibrated probabilities using Platt scaling. Decision threshold is set at $p(\text{malicious}) \ge 0.5$.
- **Runtime Artifact:** Serialized via `joblib` at `backend/app/ml/model_rf_v1.pkl` (approximately 52 KB).

### Training Dataset
The model was trained on a curated corpus of **241 usable APK samples**:
- **Benign Samples (120):** Sourced from AndroZoo (with confirmed VirusTotal detection count of exactly 0 within 24 months) and verified benchmark APKs.
- **Malware Samples (121):** Sourced from verified malware repositories and AndroZoo (with confirmed VirusTotal detection count $\ge 20$).
- Samples in the VirusTotal detection gray zone ($1 \le \text{detections} \le 19$) were excluded from training to reduce label ambiguity.

### Empirical Validation Results
Validation was conducted using Stratified 5-Fold Cross-Validation across multiple random seeds (42, 123, 2026, 31415, 777):

| Metric | Multi-Seed Mean | Standard Deviation | Min Fold Score | Max Fold Score |
|---|---|---|---|---|
| **Malware Recall** | **93.2%** | ± 0.95% | 91.8% | 94.2% |
| **ROC-AUC** | **94.8%** | ± 0.32% | 94.5% | 95.4% |
| **Accuracy** | **90.0%** | ± 0.46% | 89.2% | 90.5% |
| **Precision** | **88.0%** | ± 0.37% | 87.6% | 88.6% |
| **F1-Score** | **90.4%** | ± 0.49% | 89.5% | 90.9% |

*Note: These metrics describe cross-validation performance on the 241-sample research corpus and do not guarantee equivalent performance on arbitrary unseen or packed real-world malware.*

---

## Rule-Based Risk Assessment

The deterministic rule engine (`backend/app/risk/risk_engine.py`) evaluates independent security signals and behavioral combinations defined in `rules.py`. It assigns point weights based on severity:

- **Low Severity (5 pts):** Standard permissions with potential privacy implications (e.g., standard network access, wake locks).
- **Medium Severity (10–12 pts):** Sensitive data access (e.g., location access, contacts, camera, call logs).
- **High Severity (18–20 pts):** High-risk capabilities (e.g., direct SMS dispatch, background location tracking, package installation requests).
- **Critical Severity (30–35 pts):** Malicious behavioral combinations.

### High-Risk Combination Rules
1. **SMS / Banking Interception (`COMBO_SMS_INTERCEPT` - 35 pts):**  
   Triggers when an application requests `RECEIVE_SMS`, `READ_SMS`, and `INTERNET`. Common indicator for financial credential and OTP interception.
2. **Dropper / Dynamic Class Loading (`COMBO_DROPPER_PATTERN` - 35 pts):**  
   Triggers when an application requests `REQUEST_INSTALL_PACKAGES`, `INTERNET`, and references dynamic execution APIs (`DexClassLoader` or `PathClassLoader`).
3. **Surveillance Triad (`COMBO_SPYWARE_TRIAD` - 30 pts):**  
   Triggers when an application requests simultaneous background location access, audio recording, and camera permissions.
4. **Suspicious Component Naming:**  
   Flags services or broadcast receivers containing evasion or payload keywords (e.g., `payload`, `exploit`, `trojan`, `stealth`).

The total accumulated points are capped at 100 and mapped to four categorical tiers:
- **Low Risk:** 0 – 24 points
- **Medium Risk:** 25 – 49 points
- **High Risk:** 50 – 74 points
- **Critical Risk:** 75 – 100 points

---

## Installation & Local Setup

### Prerequisites
- **Python:** 3.10 or higher (Python 3.12 recommended)
- **Node.js:** 18 or higher with `npm`
- **Git**

### 1. Repository Clone
```bash
git clone https://github.com/HizzAI/FraudGuardAI.git
cd FraudGuardAI
```

### 2. Backend Setup
```bash
# Navigate to the backend directory
cd backend

# Create and activate a Python virtual environment
python3 -m venv venv
source venv/bin/activate       # On Windows: venv\Scripts\activate

# Install required backend dependencies
pip install -r requirements.txt
```

### 3. Frontend Setup
```bash
# Navigate to the frontend directory
cd ../frontend

# Install Node modules
npm install
```

---

## Environment Configuration

### Backend (`backend/.env`)
Copy the backend template:
```bash
cp backend/.env.example backend/.env
```
Key configuration variables in `backend/.env`:
```env
# Comma-separated list of allowed CORS origins
CORS_ORIGINS=http://localhost:5173,http://127.0.0.1:5173
```

### Frontend (`frontend/.env.local`)
Copy the frontend template:
```bash
cp frontend/.env.example frontend/.env.local
```
Set the API target URL for local development:
```env
# Points to the local FastAPI server
VITE_API_BASE=http://127.0.0.1:8000
```

---

## Running the Application

### 1. Start Backend Server
```bash
cd backend
source venv/bin/activate
uvicorn app.main:app --reload --host 127.0.0.1 --port 8000
```
- API Endpoint: `http://127.0.0.1:8000`
- Interactive OpenAPI Docs: `http://127.0.0.1:8000/docs`

### 2. Start Frontend Development Server
In a separate terminal:
```bash
cd frontend
npm run dev
```
- Web Dashboard: `http://localhost:5173`

---

## API Endpoints

### 1. Health Check
- **Route:** `GET /health`
- **Purpose:** Verifies that the FastAPI server is active.
- **Request:** No parameters or payload.
- **Response:**
  ```json
  {
    "status": "ok"
  }
  ```

### 2. Upload and Analyze APK
- **Route:** `POST /upload-apk`
- **Purpose:** Ingests an Android package archive, performs static analysis, calculates risk, and runs ML classification.
- **Request:** `multipart/form-data`
  - Field name: `file` (must have `.apk` extension)
- **Response:**
  ```json
  {
    "filename": "sample.apk",
    "content_type": "application/vnd.android.package-archive",
    "size_bytes": 1428570,
    "message": "File uploaded and analyzed successfully",
    "analysis_status": "success",
    "app": {
      "package_name": "com.example.app",
      "label": "Example App",
      "version": "1.0.0"
    },
    "permissions": ["android.permission.INTERNET"],
    "components": {
      "activities": ["com.example.app.MainActivity"],
      "services": [],
      "receivers": [],
      "providers": []
    },
    "dex": { "count": 1 },
    "apis": ["Ljava/lang/reflect/Method;->invoke"],
    "certificate": {
      "subject": "CN=Example, O=Organization",
      "issuer": "CN=Example, O=Organization",
      "serial_number": 123456789
    },
    "risk": {
      "score": 15,
      "classification": "Low",
      "findings": [],
      "summary": "Low risk indicators detected."
    },
    "ml": {
      "status": "success",
      "model_version": "svm-combined-v1.0",
      "feature_vector_version": "fv-1.0",
      "prediction": "benign",
      "confidence": 0.935,
      "probability_malicious": 0.065,
      "probability_benign": 0.935,
      "features_used": 47,
      "disclaimer": "This is a probabilistic classifier trained on historical data..."
    },
    "errors": []
  }
  ```

---

## Testing & Validation

The platform includes an automated regression test suite covering schema integrity, inference contracts, rule accuracy, and endpoint behavior.

To run tests:
```bash
cd backend
source venv/bin/activate
pytest tests/ -v
```

### Test Suite Structure
```
backend/tests/
├── test_feature_extractor.py  # 46 tests: 47-feature schema, group isolation, edge cases
├── test_risk_engine.py        # 25 tests: rule definitions, score caps, combinations, determinism
├── test_ml_engine.py          # 6 tests: inference availability, prediction bounds, probabilistic sums
└── test_main.py               # 4 tests: CORS handling, upload validation, tempfile cleanup
```
*Current status: 81 tests, all passing.*

---

## Deployment Architecture

FraudGuardAI is designed for split cloud deployment:

- **Frontend Hosting (Vercel):** The React/Vite application is deployed to static CDN edge networks. Set the `VITE_API_BASE` environment variable in the Vercel dashboard to the public URL of the deployed backend.
- **Backend Hosting (Render / Cloud Run):** The FastAPI service runs inside a Python 3.12 container runtime (`backend/Dockerfile`).
- **CORS Handling:** Set `CORS_ORIGINS` in the backend environment to include the deployed Vercel domain (e.g., `https://your-app.vercel.app`).
- **Storage Lifecycle:** Container filesystem requirements remain stateless because uploaded APKs are processed in ephemeral storage and removed upon completion.

---

## Security Considerations & Limitations

- **No Dynamic Execution:** Analysis is strictly static. The engine does not execute Dalvik bytecode, monitor runtime memory, or intercept network traffic. Advanced evasive behaviors (such as time-delayed bombs or cloud command-and-control payloads) may not be exposed via static analysis alone.
- **Decision-Support Tool:** Risk scores and ML predictions are probabilistic indicators intended to guide human analysts. They should not be treated as absolute guarantees of safety or malice.
- **Packers and Obfuscators:** Highly obfuscated or packed APKs (e.g., commercial packers or encrypted DEX loaders) may obscure method calls and component declarations from static analysis.
- **Certificate Verification:** Developer signing certificate data is parsed from the archive, but FraudGuardAI does not validate certificates against external Certificate Authorities or Google Play developer registries.
- **Safe Handling:** Uploaded APKs are untrusted binaries. The platform parses them in temporary storage without installation, but users should handle live malware samples within isolated environments.

---

## Future Enhancements

- **Explainable AI Visualizations:** Direct visualization of SHAP (Shapley Additive exPlanations) values to highlight which of the 47 features contributed most to each classification.
- **Broader Dataset Expansion:** Ongoing collection of modern, verified benign and malicious callsets across Android 13+ targets.
- **Dynamic Analysis Sandbox Hooks:** Optional integration with sandboxes (such as CAPE or Cuckoo) for auxiliary network and dynamic behavioral profiling.
- **Historical Analysis Vault:** Optional database storage to archive past scan reports and track malware campaign trends across teams.

---

## License

**Project Type:** Department Mini-Project
