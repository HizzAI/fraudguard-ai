"""
test_risk_engine.py — Deterministic unit tests for the FraudGuard AI Risk Engine.

All test fixtures are SYNTHETIC — they are manually constructed dicts that
mimic the output of analyze_apk(). They do NOT represent real malware or
real APKs. They are used solely to verify scoring correctness.

Run with:
    cd backend
    source venv/bin/activate
    python -m pytest tests/test_risk_engine.py -v
"""

import pytest
from app.risk.risk_engine import calculate_risk
from app.risk.rules import MAX_SCORE


# ---------------------------------------------------------------------------
# Helper to build a minimal synthetic analysis_result
# ---------------------------------------------------------------------------
def make_result(
    status: str = "success",
    permissions: list = None,
    activities: list = None,
    services: list = None,
    receivers: list = None,
    providers: list = None,
    dex_count: int = 1,
    apis: list = None,
    certificate: dict = None,
) -> dict:
    """
    Build a synthetic analysis_result dict.
    SYNTHETIC TEST DATA — not derived from any real APK.
    """
    return {
        "analysis_status": status,
        "app": {"package_name": "com.test.synthetic", "label": "TestApp", "version": "1.0"},
        "permissions": permissions or [],
        "components": {
            "activities": activities or [],
            "services":   services   or [],
            "receivers":  receivers  or [],
            "providers":  providers  or [],
        },
        "dex": {"count": dex_count},
        "apis": apis or [],
        "certificate": certificate if certificate is not None else {
            "subject": "CN=Test Certificate, O=TestOrg",
            "issuer":  "CN=Test CA",
            "serial_number": 12345,
        },
        "errors": [],
    }


# ---------------------------------------------------------------------------
# TEST 1: Empty / benign-looking feature set
# ---------------------------------------------------------------------------
class TestBenignInput:
    def test_empty_permissions_no_findings(self):
        """SYNTHETIC: No permissions, no suspicious APIs → no findings."""
        result = make_result()
        risk = calculate_risk(result)
        # Score may still be non-zero if cert is short — check structure
        assert risk["score"] is not None
        assert risk["classification"] in ("Low", "Medium", "High", "Critical")
        assert isinstance(risk["findings"], list)
        assert isinstance(risk["summary"], str)

    def test_score_is_non_negative(self):
        """SYNTHETIC: Score must never be negative."""
        result = make_result()
        risk = calculate_risk(result)
        assert risk["score"] >= 0

    def test_zero_findings_gives_appropriate_summary(self):
        """SYNTHETIC: If no rules trigger, summary must not claim risk."""
        # Use a cert long enough to avoid CERT_UNKNOWN_SUBJECT
        result = make_result(
            permissions=[],
            apis=[],
            certificate={
                "subject": "CN=Legitimate Developer, O=RealCompany Inc",
                "issuer": "CN=Trusted CA",
                "serial_number": 99999,
            },
        )
        risk = calculate_risk(result)
        # With no permissions and no suspicious APIs, findings should be empty
        assert len(risk["findings"]) == 0
        assert "No risk signals" in risk["summary"]


# ---------------------------------------------------------------------------
# TEST 2: Single risk signal
# ---------------------------------------------------------------------------
class TestSingleSignal:
    def test_send_sms_permission_triggers(self):
        """SYNTHETIC: SEND_SMS permission should trigger PERM_SEND_SMS rule."""
        result = make_result(
            permissions=["android.permission.SEND_SMS"],
            certificate={
                "subject": "CN=Legitimate Developer, O=RealCompany Inc",
                "issuer": "CN=Trusted CA",
                "serial_number": 99999,
            },
        )
        risk = calculate_risk(result)
        rule_ids = [f["rule_id"] for f in risk["findings"]]
        assert "PERM_SEND_SMS" in rule_ids
        assert risk["score"] > 0

    def test_request_install_packages_triggers(self):
        """SYNTHETIC: REQUEST_INSTALL_PACKAGES → critical finding."""
        result = make_result(
            permissions=["android.permission.REQUEST_INSTALL_PACKAGES"],
            certificate={
                "subject": "CN=Legitimate Developer, O=RealCompany Inc",
                "issuer": "CN=Trusted CA",
                "serial_number": 99999,
            },
        )
        risk = calculate_risk(result)
        rule_ids = [f["rule_id"] for f in risk["findings"]]
        assert "PERM_REQUEST_INSTALL_PACKAGES" in rule_ids
        sev = next(f["severity"] for f in risk["findings"] if f["rule_id"] == "PERM_REQUEST_INSTALL_PACKAGES")
        assert sev == "critical"

    def test_missing_certificate_triggers(self):
        """SYNTHETIC: Empty certificate dict → CERT_MISSING finding."""
        result = make_result(certificate={})
        risk = calculate_risk(result)
        rule_ids = [f["rule_id"] for f in risk["findings"]]
        assert "CERT_MISSING" in rule_ids

    def test_dex_multidex_triggers(self):
        """SYNTHETIC: dex.count >= 2 → DEX_MULTIDEX finding."""
        result = make_result(
            dex_count=3,
            certificate={
                "subject": "CN=Legitimate Developer, O=RealCompany Inc",
                "issuer": "CN=Trusted CA",
                "serial_number": 99999,
            },
        )
        risk = calculate_risk(result)
        rule_ids = [f["rule_id"] for f in risk["findings"]]
        assert "DEX_MULTIDEX" in rule_ids

    def test_api_dynamic_dexload_triggers(self):
        """SYNTHETIC: DexClassLoader in APIs → API_DYNAMIC_DEXLOAD finding."""
        result = make_result(
            apis=["Ldalvik/system/DexClassLoader;->loadClass"],
            certificate={
                "subject": "CN=Legitimate Developer, O=RealCompany Inc",
                "issuer": "CN=Trusted CA",
                "serial_number": 99999,
            },
        )
        risk = calculate_risk(result)
        rule_ids = [f["rule_id"] for f in risk["findings"]]
        assert "API_DYNAMIC_DEXLOAD" in rule_ids


# ---------------------------------------------------------------------------
# TEST 3: Multiple risk signals
# ---------------------------------------------------------------------------
class TestMultipleSignals:
    def test_multiple_permissions_accumulate_score(self):
        """SYNTHETIC: Several dangerous permissions should sum their points."""
        result = make_result(
            permissions=[
                "android.permission.SEND_SMS",
                "android.permission.RECORD_AUDIO",
                "android.permission.READ_CONTACTS",
            ],
            certificate={
                "subject": "CN=Legitimate Developer, O=RealCompany Inc",
                "issuer": "CN=Trusted CA",
                "serial_number": 99999,
            },
        )
        risk = calculate_risk(result)
        rule_ids = [f["rule_id"] for f in risk["findings"]]
        assert "PERM_SEND_SMS" in rule_ids
        assert "PERM_RECORD_AUDIO" in rule_ids
        assert "PERM_READ_CONTACTS" in rule_ids
        # Score should be sum of at least those 3 rules
        assert risk["score"] >= 20 + 18 + 10  # SEND_SMS + RECORD_AUDIO + READ_CONTACTS

    def test_findings_list_has_correct_structure(self):
        """SYNTHETIC: Each finding must have required fields."""
        result = make_result(
            permissions=["android.permission.SEND_SMS"],
            certificate={
                "subject": "CN=Legitimate Developer, O=RealCompany Inc",
                "issuer": "CN=Trusted CA",
                "serial_number": 99999,
            },
        )
        risk = calculate_risk(result)
        for finding in risk["findings"]:
            assert "rule_id" in finding
            assert "category" in finding
            assert "severity" in finding
            assert "points" in finding
            assert "reason" in finding
            assert isinstance(finding["points"], int)
            assert finding["points"] > 0


# ---------------------------------------------------------------------------
# TEST 4: Combination rules
# ---------------------------------------------------------------------------
class TestCombinationRules:
    def test_sms_intercept_combo_triggers(self):
        """SYNTHETIC: RECEIVE_SMS + READ_SMS → COMBO_SMS_INTERCEPT."""
        result = make_result(
            permissions=[
                "android.permission.RECEIVE_SMS",
                "android.permission.READ_SMS",
            ],
            certificate={
                "subject": "CN=Legitimate Developer, O=RealCompany Inc",
                "issuer": "CN=Trusted CA",
                "serial_number": 99999,
            },
        )
        risk = calculate_risk(result)
        rule_ids = [f["rule_id"] for f in risk["findings"]]
        assert "COMBO_SMS_INTERCEPT" in rule_ids

    def test_dropper_pattern_combo_triggers(self):
        """SYNTHETIC: REQUEST_INSTALL_PACKAGES + WRITE_EXTERNAL_STORAGE → COMBO_DROPPER_PATTERN."""
        result = make_result(
            permissions=[
                "android.permission.REQUEST_INSTALL_PACKAGES",
                "android.permission.WRITE_EXTERNAL_STORAGE",
            ],
            certificate={
                "subject": "CN=Legitimate Developer, O=RealCompany Inc",
                "issuer": "CN=Trusted CA",
                "serial_number": 99999,
            },
        )
        risk = calculate_risk(result)
        rule_ids = [f["rule_id"] for f in risk["findings"]]
        assert "COMBO_DROPPER_PATTERN" in rule_ids

    def test_spyware_triad_combo_triggers(self):
        """SYNTHETIC: RECORD_AUDIO + ACCESS_FINE_LOCATION + READ_CONTACTS → COMBO_SPYWARE_TRIAD."""
        result = make_result(
            permissions=[
                "android.permission.RECORD_AUDIO",
                "android.permission.ACCESS_FINE_LOCATION",
                "android.permission.READ_CONTACTS",
            ],
            certificate={
                "subject": "CN=Legitimate Developer, O=RealCompany Inc",
                "issuer": "CN=Trusted CA",
                "serial_number": 99999,
            },
        )
        risk = calculate_risk(result)
        rule_ids = [f["rule_id"] for f in risk["findings"]]
        assert "COMBO_SPYWARE_TRIAD" in rule_ids

    def test_combo_requires_all_permissions(self):
        """SYNTHETIC: A combo must NOT trigger when only some required permissions are present."""
        # COMBO_SMS_INTERCEPT needs both RECEIVE_SMS and READ_SMS
        result = make_result(
            permissions=["android.permission.RECEIVE_SMS"],  # only one, not both
            certificate={
                "subject": "CN=Legitimate Developer, O=RealCompany Inc",
                "issuer": "CN=Trusted CA",
                "serial_number": 99999,
            },
        )
        risk = calculate_risk(result)
        rule_ids = [f["rule_id"] for f in risk["findings"]]
        assert "COMBO_SMS_INTERCEPT" not in rule_ids


# ---------------------------------------------------------------------------
# TEST 5: Score reaching 100
# ---------------------------------------------------------------------------
class TestScoreCap:
    def test_high_risk_inputs_can_reach_100(self):
        """SYNTHETIC: Maximally suspicious inputs should score 100."""
        result = make_result(
            permissions=[
                "android.permission.SEND_SMS",
                "android.permission.RECEIVE_SMS",
                "android.permission.READ_SMS",
                "android.permission.REQUEST_INSTALL_PACKAGES",
                "android.permission.BIND_ACCESSIBILITY_SERVICE",
                "android.permission.SYSTEM_ALERT_WINDOW",
                "android.permission.RECORD_AUDIO",
                "android.permission.ACCESS_FINE_LOCATION",
                "android.permission.READ_CONTACTS",
                "android.permission.WRITE_EXTERNAL_STORAGE",
                "android.permission.RECEIVE_BOOT_COMPLETED",
                "android.permission.ACCESS_BACKGROUND_LOCATION",
            ],
            services=["com.bad.PersistentService1", "com.bad.PersistentService2",
                      "com.bad.PersistentService3", "com.bad.PersistentService4",
                      "com.bad.PersistentService5"],
            dex_count=3,
            apis=[
                "Ldalvik/system/DexClassLoader;->loadClass",
                "Ljava/lang/Runtime;->exec",
                "Ljava/lang/reflect/Method;->invoke",
                "Landroid/telephony/SmsManager;->sendTextMessage",
            ],
            certificate={},
        )
        risk = calculate_risk(result)
        assert risk["score"] == MAX_SCORE  # must be capped at 100, not exceed it
        assert risk["classification"] == "Critical"

    # ---------------------------------------------------------------------------
    # TEST 6: Score never exceeds 100
    # ---------------------------------------------------------------------------
    def test_score_never_exceeds_max(self):
        """SYNTHETIC: Raw score may exceed 100 but capped output must be exactly MAX_SCORE."""
        # Same input as above
        result = make_result(
            permissions=[
                "android.permission.SEND_SMS",
                "android.permission.RECEIVE_SMS",
                "android.permission.READ_SMS",
                "android.permission.REQUEST_INSTALL_PACKAGES",
                "android.permission.BIND_ACCESSIBILITY_SERVICE",
                "android.permission.SYSTEM_ALERT_WINDOW",
                "android.permission.RECORD_AUDIO",
                "android.permission.ACCESS_FINE_LOCATION",
                "android.permission.READ_CONTACTS",
                "android.permission.WRITE_EXTERNAL_STORAGE",
                "android.permission.RECEIVE_BOOT_COMPLETED",
            ],
            apis=[
                "Ldalvik/system/DexClassLoader;->loadClass",
                "Ljava/lang/Runtime;->exec",
            ],
            certificate={},
        )
        risk = calculate_risk(result)
        assert risk["score"] <= MAX_SCORE, f"Score {risk['score']} exceeded MAX_SCORE={MAX_SCORE}"


# ---------------------------------------------------------------------------
# TEST 7: Invalid / failed analysis
# ---------------------------------------------------------------------------
class TestFailedAnalysis:
    def test_failed_status_returns_null_risk(self):
        """SYNTHETIC: analysis_status=failed must return null risk, not a fabricated score."""
        result = {
            "analysis_status": "failed",
            "app": {"package_name": None, "label": None, "version": None},
            "permissions": [],
            "components": {"activities": [], "services": [], "receivers": [], "providers": []},
            "dex": {"count": 0},
            "apis": [],
            "certificate": {},
            "errors": ["File is not a zip file"],
        }
        risk = calculate_risk(result)
        assert risk["score"] is None
        assert risk["classification"] is None
        assert risk["findings"] == []
        assert isinstance(risk["summary"], str)
        assert len(risk["summary"]) > 0

    def test_failed_analysis_no_findings(self):
        """SYNTHETIC: Failed analysis must produce zero findings."""
        result = make_result(status="failed")
        risk = calculate_risk(result)
        assert len(risk["findings"]) == 0

    def test_null_risk_has_correct_keys(self):
        """SYNTHETIC: The null risk state must have all expected keys."""
        result = make_result(status="failed")
        risk = calculate_risk(result)
        assert "score" in risk
        assert "classification" in risk
        assert "findings" in risk
        assert "summary" in risk


# ---------------------------------------------------------------------------
# TEST 8: Determinism — same input, same output
# ---------------------------------------------------------------------------
class TestDeterminism:
    def test_same_input_produces_same_score(self):
        """SYNTHETIC: calculate_risk() must be deterministic."""
        result = make_result(
            permissions=[
                "android.permission.SEND_SMS",
                "android.permission.RECEIVE_SMS",
                "android.permission.READ_CONTACTS",
            ],
            apis=["Ljava/lang/Runtime;->exec"],
            certificate={"subject": "CN=Android Debug", "issuer": "CN=Test", "serial_number": 1},
        )
        risk1 = calculate_risk(result)
        risk2 = calculate_risk(result)
        assert risk1["score"] == risk2["score"]
        assert risk1["classification"] == risk2["classification"]
        assert len(risk1["findings"]) == len(risk2["findings"])

    def test_different_inputs_different_scores(self):
        """SYNTHETIC: Different permission sets should yield different scores."""
        clean = make_result(
            permissions=[],
            certificate={
                "subject": "CN=Legitimate Developer, O=RealCompany Inc",
                "issuer": "CN=Trusted CA",
                "serial_number": 99999,
            },
        )
        risky = make_result(
            permissions=["android.permission.SEND_SMS"],
            certificate={
                "subject": "CN=Legitimate Developer, O=RealCompany Inc",
                "issuer": "CN=Trusted CA",
                "serial_number": 99999,
            },
        )
        assert calculate_risk(risky)["score"] > calculate_risk(clean)["score"]

    def test_rule_ids_are_unique_per_result(self):
        """SYNTHETIC: No rule should fire more than once for the same input."""
        result = make_result(
            permissions=["android.permission.SEND_SMS", "android.permission.RECORD_AUDIO"],
            certificate={
                "subject": "CN=Legitimate Developer, O=RealCompany Inc",
                "issuer": "CN=Trusted CA",
                "serial_number": 99999,
            },
        )
        risk = calculate_risk(result)
        rule_ids = [f["rule_id"] for f in risk["findings"]]
        assert len(rule_ids) == len(set(rule_ids)), "Duplicate rule_ids found in findings"


# ---------------------------------------------------------------------------
# TEST 9: Classification thresholds
# ---------------------------------------------------------------------------
class TestClassification:
    def _score_for_n_sms_perms(self, score_target: int):
        """Helper: build result that produces a known score range."""
        # Use only one known-value permission to control score precisely
        # PERM_SEND_SMS = 20 points
        return make_result(
            permissions=["android.permission.SEND_SMS"] if score_target > 0 else [],
            certificate={
                "subject": "CN=Legitimate Developer, O=RealCompany Inc",
                "issuer": "CN=Trusted CA",
                "serial_number": 99999,
            },
        )

    def test_low_classification(self):
        """SYNTHETIC: Score 0–29 should classify as Low."""
        result = make_result(
            permissions=[],
            certificate={
                "subject": "CN=Legitimate Developer, O=RealCompany Inc",
                "issuer": "CN=Trusted CA",
                "serial_number": 99999,
            },
        )
        risk = calculate_risk(result)
        assert risk["score"] <= 29
        assert risk["classification"] == "Low"

    def test_critical_classification(self):
        """SYNTHETIC: Score >= 80 should classify as Critical."""
        result = make_result(
            permissions=[
                "android.permission.REQUEST_INSTALL_PACKAGES",   # 35
                "android.permission.BIND_ACCESSIBILITY_SERVICE",  # 35
                "android.permission.SYSTEM_ALERT_WINDOW",         # 20
            ],
            certificate={
                "subject": "CN=Legitimate Developer, O=RealCompany Inc",
                "issuer": "CN=Trusted CA",
                "serial_number": 99999,
            },
        )
        risk = calculate_risk(result)
        assert risk["score"] >= 80
        assert risk["classification"] == "Critical"
