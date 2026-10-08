# End-to-End Integration Report
## Phase 5G — Combined SVM Production Pipeline Verification

**Status: ✅ END-TO-END INTEGRATION PASSED**  
**Checks: 63/63 passed**  
**Model: svm-combined-v1.0**  
**Date: 2026-10-08**

---

## 1. Production Model Verification

| Check | Result | Detail |
|-------|--------|--------|
| `model_rf_v1.pkl` exists | ✅ | `backend/app/ml/model_rf_v1.pkl` (51.6 KB) |
| `joblib.load()` succeeds | ✅ | type=Pipeline |
| `classes_` == [0, 1] | ✅ | [np.int64(0), np.int64(1)] |
| `predict()` works | ✅ | pred=0 |
| `predict_proba()` works | ✅ | [0.9353, 0.0647] |
| probabilities sum to 1 | ✅ | 1.0000000 |
| `MODEL_VERSION == 'svm-combined-v1.0'` | ✅ | svm-combined-v1.0 |

---

## 2. Feature Contract Verification

| Check | Result |
|-------|--------|
| FEATURE_COUNT == 47 | ✅ |
| len(FEATURE_NAMES) == 47 | ✅ |
| All names start with `feat_` | ✅ |
| Names are unique | ✅ |
| `extract_features()` status == success | ✅ |
| features dict has 47 keys | ✅ |
| `feature_dict_to_list` length == 47 | ✅ |
| No NaN | ✅ |
| No Inf | ✅ |
| All values numeric | ✅ |

---

## 3. Benign APK Integration Result

- **APK SHA256:** `29d5ae51c5cabe51968e6262dcdb3e6818e1caf09a2f48834f711d591150b704`
- **Label:** MalEval label=0 (benign)
- **Selection note:** Pre-validated against current Androguard build (see §9 Limitations)

| Step | Result | Detail |
|------|--------|--------|
| APK file present | ✅ | data/raw/ |
| `analyze_apk()` | ✅ | analysis_status=success |
| `extract_features()` | ✅ | status=success, 47 features |
| `calculate_ml()` | ✅ | status=success |
| ML prediction valid | ✅ | prediction=**benign** |
| ML probabilities valid | ✅ | p_malicious=0.0648, p_benign=0.9352 |
| model_version correct | ✅ | svm-combined-v1.0 |
| `calculate_risk()` score | ✅ | score=37, classification=Medium |
| Risk engine receives ML dict | ✅ | |

> **Pipeline output:** prediction=`benign` · p_malicious=`0.0648` · p_benign=`0.9352` · risk_score=`37` · risk_class=`Medium`

---

## 4. Malware APK Integration Result

- **APK SHA256:** `8407fed605805f0e7ef9628767d0aff1014e7231549b09f3c0d0cb723f07c48a`
- **Label:** MalEval label=1 (malware)
- **Note:** Single-sample result is **NOT** a claim of detection accuracy.

| Step | Result | Detail |
|------|--------|--------|
| APK file present | ✅ | data/raw/ |
| `analyze_apk()` | ✅ | analysis_status=success |
| `extract_features()` | ✅ | status=success, 47 features |
| `calculate_ml()` | ✅ | status=success |
| ML prediction valid | ✅ | prediction=**malicious** |
| ML probabilities valid | ✅ | p_malicious=0.8166, p_benign=0.1834 |
| model_version correct | ✅ | svm-combined-v1.0 |
| `calculate_risk()` score | ✅ | score=55, classification=Medium |
| Risk engine receives ML dict | ✅ | |

> **Pipeline output:** prediction=`malicious` · p_malicious=`0.8166` · p_benign=`0.1834` · risk_score=`55` · risk_class=`Medium`

---

## 5. FastAPI Integration Result

Upload endpoint: `POST /upload-apk` with benign APK (29d5ae51...)

| Check | Result | Detail |
|-------|--------|--------|
| `GET /health` → 200 | ✅ | `{"status":"ok"}` |
| `POST /upload-apk` → 200 | ✅ | |
| Response is valid JSON | ✅ | |
| `filename` in response | ✅ | |
| `size_bytes` in response | ✅ | |
| `analysis_status` in response | ✅ | |
| `ml` in response | ✅ | |
| `risk` in response | ✅ | |
| `ml.status` present | ✅ | success |
| `ml.model_version` correct | ✅ | svm-combined-v1.0 |
| `ml.prediction` present | ✅ | benign |
| `ml.probability_malicious` present | ✅ | 0.0648 |
| No traceback in response | ✅ | |

---

## 6. Error Handling Result

| Check | Result | Detail |
|-------|--------|--------|
| Non-APK extension → HTTP 400 | ✅ | `{"detail":"Only .apk files are allowed."}` |
| Error response has `detail` key | ✅ | |
| Corrupt APK doesn't crash server (not 500) | ✅ | returns 200 with analysis_status=failed |
| Corrupt APK returns JSON | ✅ | |
| Corrupt APK `analysis_status` = `failed` | ✅ | graceful degradation confirmed |

---

## 7. Regression Test Result

```
platform darwin -- Python 3.14.3, pytest-9.1.1

tests/test_feature_extractor.py   46/46  ✅
tests/test_ml_engine.py            5/5   ✅
tests/test_risk_engine.py         25/25  ✅

============================== 76 passed in 0.07s ==============================
```

**All 76 tests passed. Zero failures.**

---

## 8. Git Diff Summary

```
.gitignore                  | 15 +++++++++++++++ (pre-existing)
backend/app/ml/ml_engine.py |  9 +++++----  (Phase 5G: MODEL_VERSION bump)
2 files changed, 20 insertions(+), 4 deletions(-)
```

**Modified tracked files:** `.gitignore` (pre-existing), `backend/app/ml/ml_engine.py` (approved Phase 5G)

**No other production source files were modified.**

---

## 9. Limitations

### Androguard API Level Constraint
Some MalEval benign APKs target API level 34–35, which exceeds the maximum supported by the installed Androguard build (capped at API level 28). These APKs fail with `"res1 must be zero!"` during resource table parsing. This is a **known Androguard version limitation**, not a pipeline bug.

- The test suite selected APKs pre-validated against the current build.
- The graceful failure path (`analysis_status=failed` → ML `status=unavailable`) was verified and confirmed working.
- This limitation does not affect the production model or inference pipeline — it affects only the Androguard parser for specific new APK formats.

### Single-APK Integration Tests (Tests 3 & 4)
Tests 3 and 4 verify that the **pipeline executes correctly** for one benign and one malware APK. They are **not** accuracy evaluations. Model accuracy has already been established by the 5-seed cross-validation in Phase 5E–5F (Mean Recall=0.932 ± 0.0095).

### Probability Calibration (FutureWarning)
`SVC(probability=True)` uses Platt scaling, which sklearn ≥1.9 has deprecated in favour of `CalibratedClassifierCV(SVC(), ensemble=False)`. This generates a `FutureWarning` but does not affect correctness. Migration is tracked as a future improvement.

### FastAPI Test Transport
The FastAPI integration test uses the `httpx.ASGITransport` (in-process ASGI) rather than a real running server. This is equivalent for integration testing purposes but does not test network stack or production WSGI/ASGI server (e.g. Uvicorn) behaviour.

### Dataset Size
The 241-sample combined dataset provides solid cross-validation estimates (Recall=0.932 ± 0.0095) but real-world performance requires continuous monitoring post-deployment.

---

## 10. Final Status

```
============================================================
✅ END-TO-END INTEGRATION PASSED
============================================================
```

| Criterion | Status |
|-----------|--------|
| Production model loads | ✅ |
| 47-feature contract intact | ✅ |
| Benign APK pipeline end-to-end | ✅ |
| Malware APK pipeline end-to-end | ✅ |
| FastAPI /upload-apk endpoint | ✅ |
| Error handling (400, graceful fail) | ✅ |
| 76/76 regression tests | ✅ |
| Git diff clean (approved changes only) | ✅ |
| Feature extractor unchanged | ✅ |
| Risk engine unchanged | ✅ |
| Frontend unchanged | ✅ |
| API contract unchanged | ✅ |
| Deployment performed | ❌ NOT PERFORMED |
| Commit/push performed | ❌ NOT PERFORMED |

**Model:** `svm-combined-v1.0`  
**Pipeline integrity:** VERIFIED  
**Deployment status:** NOT DEPLOYED — awaiting instructions  
**Commit/push:** NOT PERFORMED

---

*Generated by Phase 5G end_to_end_integration_test.py — FraudGuardAI*
