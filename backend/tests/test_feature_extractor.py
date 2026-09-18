"""
test_feature_extractor.py — Unit tests for the Phase 5B feature extractor.

Tests verify:
  - Feature vector has exactly 47 features with exactly the right names.
  - A failed analysis produces a zero-vector with status="unavailable".
  - Individual feature groups compute correctly from known inputs.
  - The feature dict can be converted to an ordered list.
  - All values are int or float (never strings or None).
"""

import pytest
from app.ml.feature_extractor import (
    extract_features,
    feature_dict_to_list,
    FEATURE_NAMES,
    FEATURE_COUNT,
    FEATURE_VECTOR_VERSION,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

def _make_analysis(
    status: str = "success",
    permissions=None,
    activities=None,
    services=None,
    receivers=None,
    providers=None,
    dex_count: int = 1,
    apis=None,
    certificate=None,
) -> dict:
    """Helper: build a minimal analyze_apk()-style result dict."""
    return {
        "analysis_status": status,
        "app": {"package_name": "com.example.test", "label": "Test", "version": "1.0"},
        "permissions": permissions or [],
        "components": {
            "activities": activities or [],
            "services":   services or [],
            "receivers":  receivers or [],
            "providers":  providers or [],
        },
        "dex": {"count": dex_count},
        "apis": apis or [],
        "certificate": certificate or {},
        "errors": [],
    }


# ---------------------------------------------------------------------------
# Schema tests
# ---------------------------------------------------------------------------

class TestFeatureSchema:
    def test_feature_count_is_47(self):
        assert FEATURE_COUNT == 47

    def test_feature_names_length_matches_constant(self):
        assert len(FEATURE_NAMES) == FEATURE_COUNT

    def test_all_feature_names_are_strings(self):
        assert all(isinstance(n, str) for n in FEATURE_NAMES)

    def test_feature_names_are_unique(self):
        assert len(FEATURE_NAMES) == len(set(FEATURE_NAMES))

    def test_feature_names_start_with_feat_prefix(self):
        assert all(n.startswith("feat_") for n in FEATURE_NAMES)

    def test_version_string_is_set(self):
        assert FEATURE_VECTOR_VERSION.startswith("fv-")


# ---------------------------------------------------------------------------
# Failed analysis handling
# ---------------------------------------------------------------------------

class TestFailedAnalysis:
    def test_failed_status_returns_unavailable(self):
        result = extract_features(_make_analysis(status="failed"))
        assert result["status"] == "unavailable"

    def test_failed_status_returns_zero_vector(self):
        result = extract_features(_make_analysis(status="failed"))
        assert all(v == 0 for v in result["features"].values())

    def test_failed_status_returns_all_feature_names(self):
        result = extract_features(_make_analysis(status="failed"))
        assert set(result["features"].keys()) == set(FEATURE_NAMES)

    def test_failed_status_returns_version(self):
        result = extract_features(_make_analysis(status="failed"))
        assert result["version"] == FEATURE_VECTOR_VERSION


# ---------------------------------------------------------------------------
# Successful extraction — output shape
# ---------------------------------------------------------------------------

class TestSuccessfulExtractionShape:
    def test_returns_success_status(self):
        result = extract_features(_make_analysis())
        assert result["status"] == "success"

    def test_returns_all_47_features(self):
        result = extract_features(_make_analysis())
        assert len(result["features"]) == FEATURE_COUNT

    def test_feature_names_match_schema(self):
        result = extract_features(_make_analysis())
        assert set(result["features"].keys()) == set(FEATURE_NAMES)

    def test_all_values_are_numeric(self):
        result = extract_features(_make_analysis())
        for k, v in result["features"].items():
            assert isinstance(v, (int, float)), f"{k} is not numeric: {type(v)}"

    def test_no_none_values(self):
        result = extract_features(_make_analysis())
        for k, v in result["features"].items():
            assert v is not None, f"{k} is None"


# ---------------------------------------------------------------------------
# Group A: File metadata
# ---------------------------------------------------------------------------

class TestGroupAMetadata:
    def test_size_bytes_passed_correctly(self):
        result = extract_features(_make_analysis(), size_bytes=12345678)
        assert result["features"]["feat_size_bytes"] == 12345678

    def test_size_bytes_defaults_to_zero(self):
        result = extract_features(_make_analysis())
        assert result["features"]["feat_size_bytes"] == 0

    def test_dex_count_extracted(self):
        result = extract_features(_make_analysis(dex_count=3))
        assert result["features"]["feat_dex_count"] == 3

    def test_dex_count_zero_when_none(self):
        result = extract_features(_make_analysis(dex_count=0))
        assert result["features"]["feat_dex_count"] == 0


# ---------------------------------------------------------------------------
# Group B: Permission counts
# ---------------------------------------------------------------------------

class TestGroupBPermissionCounts:
    def test_total_permission_count(self):
        perms = [
            "android.permission.INTERNET",
            "android.permission.CAMERA",
            "android.permission.SEND_SMS",
        ]
        result = extract_features(_make_analysis(permissions=perms))
        assert result["features"]["feat_perm_total"] == 3

    def test_dangerous_count_only_counts_mapped_permissions(self):
        perms = [
            "android.permission.INTERNET",    # not in dangerous map
            "android.permission.CAMERA",      # in map
            "android.permission.SEND_SMS",    # in map
        ]
        result = extract_features(_make_analysis(permissions=perms))
        assert result["features"]["feat_perm_dangerous_count"] == 2

    def test_zero_permissions(self):
        result = extract_features(_make_analysis(permissions=[]))
        assert result["features"]["feat_perm_total"] == 0
        assert result["features"]["feat_perm_dangerous_count"] == 0


# ---------------------------------------------------------------------------
# Group C: Permission one-hot flags
# ---------------------------------------------------------------------------

class TestGroupCPermissionFlags:
    def test_send_sms_flag_set(self):
        perms = ["android.permission.SEND_SMS"]
        result = extract_features(_make_analysis(permissions=perms))
        assert result["features"]["feat_perm_send_sms"] == 1

    def test_camera_flag_set(self):
        perms = ["android.permission.CAMERA"]
        result = extract_features(_make_analysis(permissions=perms))
        assert result["features"]["feat_perm_camera"] == 1

    def test_request_install_flag_set(self):
        perms = ["android.permission.REQUEST_INSTALL_PACKAGES"]
        result = extract_features(_make_analysis(permissions=perms))
        assert result["features"]["feat_perm_request_install"] == 1

    def test_flags_are_zero_when_permission_absent(self):
        result = extract_features(_make_analysis(permissions=[]))
        perm_flags = [k for k in FEATURE_NAMES if k.startswith("feat_perm_") and k not in
                      ("feat_perm_total", "feat_perm_dangerous_count")]
        for flag in perm_flags:
            assert result["features"][flag] == 0, f"{flag} should be 0"

    def test_permission_matching_is_case_insensitive(self):
        perms = ["ANDROID.PERMISSION.SEND_SMS"]
        result = extract_features(_make_analysis(permissions=perms))
        assert result["features"]["feat_perm_send_sms"] == 1


# ---------------------------------------------------------------------------
# Group D: Component counts
# ---------------------------------------------------------------------------

class TestGroupDComponentCounts:
    def test_activity_count(self):
        result = extract_features(_make_analysis(activities=["a", "b", "c"]))
        assert result["features"]["feat_activity_count"] == 3

    def test_service_count(self):
        result = extract_features(_make_analysis(services=["s1", "s2"]))
        assert result["features"]["feat_service_count"] == 2

    def test_receiver_count(self):
        result = extract_features(_make_analysis(receivers=["r1"]))
        assert result["features"]["feat_receiver_count"] == 1

    def test_provider_count(self):
        result = extract_features(_make_analysis(providers=["p1", "p2", "p3", "p4"]))
        assert result["features"]["feat_provider_count"] == 4

    def test_all_zeros_when_no_components(self):
        result = extract_features(_make_analysis())
        assert result["features"]["feat_activity_count"] == 0
        assert result["features"]["feat_service_count"] == 0
        assert result["features"]["feat_receiver_count"] == 0
        assert result["features"]["feat_provider_count"] == 0


# ---------------------------------------------------------------------------
# Group E: API indicator flags
# ---------------------------------------------------------------------------

class TestGroupEApiFlags:
    def test_runtime_exec_flag(self):
        apis = ["Ljava/lang/Runtime;->exec([Ljava/lang/String;)Ljava/lang/Process;"]
        result = extract_features(_make_analysis(apis=apis))
        assert result["features"]["feat_api_exec_runtime"] == 1

    def test_dexclassloader_flag(self):
        apis = ["Ldalvik/system/DexClassLoader;-><init>"]
        result = extract_features(_make_analysis(apis=apis))
        assert result["features"]["feat_api_dynamic_dexload"] == 1

    def test_reflection_flag(self):
        apis = ["Ljava/lang/reflect/Method;->invoke"]
        result = extract_features(_make_analysis(apis=apis))
        assert result["features"]["feat_api_reflection"] == 1

    def test_sms_send_api_flag(self):
        apis = ["Landroid/telephony/SmsManager;->sendTextMessage"]
        result = extract_features(_make_analysis(apis=apis))
        assert result["features"]["feat_api_sms_send"] == 1

    def test_audio_record_flag(self):
        apis = ["Landroid/media/AudioRecord;->startRecording()V"]
        result = extract_features(_make_analysis(apis=apis))
        assert result["features"]["feat_api_audio_record"] == 1

    def test_all_api_flags_zero_with_no_apis(self):
        result = extract_features(_make_analysis(apis=[]))
        api_flags = [k for k in FEATURE_NAMES if k.startswith("feat_api_")]
        for flag in api_flags:
            assert result["features"][flag] == 0, f"{flag} should be 0"


# ---------------------------------------------------------------------------
# Group F: Certificate indicators
# ---------------------------------------------------------------------------

class TestGroupFCertificate:
    def test_no_cert_produces_zero_cert_features(self):
        result = extract_features(_make_analysis(certificate={}))
        assert result["features"]["feat_cert_present"] == 0
        assert result["features"]["feat_cert_is_debug"] == 0
        assert result["features"]["feat_cert_subject_len"] == 0

    def test_valid_cert_sets_present_flag(self):
        cert = {"subject": "CN=Test App, O=Test Inc", "issuer": "CN=Test CA"}
        result = extract_features(_make_analysis(certificate=cert))
        assert result["features"]["feat_cert_present"] == 1

    def test_subject_length_computed(self):
        subject = "CN=Test App, O=Test Inc"
        cert = {"subject": subject, "issuer": "CN=Test CA"}
        result = extract_features(_make_analysis(certificate=cert))
        assert result["features"]["feat_cert_subject_len"] == len(subject)

    def test_debug_cert_detected(self):
        cert = {"subject": "CN=Android Debug, O=Android, C=US"}
        result = extract_features(_make_analysis(certificate=cert))
        assert result["features"]["feat_cert_is_debug"] == 1

    def test_non_debug_cert_is_not_flagged(self):
        cert = {"subject": "CN=FraudGuard App, O=My Company Ltd, C=IN"}
        result = extract_features(_make_analysis(certificate=cert))
        assert result["features"]["feat_cert_is_debug"] == 0


# ---------------------------------------------------------------------------
# feature_dict_to_list
# ---------------------------------------------------------------------------

class TestFeatureDictToList:
    def test_returns_list_of_correct_length(self):
        result = extract_features(_make_analysis())
        as_list = feature_dict_to_list(result["features"])
        assert len(as_list) == FEATURE_COUNT

    def test_order_matches_feature_names(self):
        perms = ["android.permission.SEND_SMS"]
        result = extract_features(_make_analysis(permissions=perms))
        as_list = feature_dict_to_list(result["features"])
        send_sms_idx = FEATURE_NAMES.index("feat_perm_send_sms")
        assert as_list[send_sms_idx] == 1

    def test_size_bytes_is_first(self):
        result = extract_features(_make_analysis(), size_bytes=9999)
        as_list = feature_dict_to_list(result["features"])
        assert as_list[0] == 9999  # feat_size_bytes is index 0

    def test_dex_count_is_second(self):
        result = extract_features(_make_analysis(dex_count=5))
        as_list = feature_dict_to_list(result["features"])
        assert as_list[1] == 5  # feat_dex_count is index 1
