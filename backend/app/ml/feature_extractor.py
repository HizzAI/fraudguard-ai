"""
feature_extractor.py — Converts analyze_apk() output into the 47-feature ML vector.

CONTRACT:
  - Input:  the dict returned by analyze_apk() (Phase 2 output).
  - Output: a dict with exactly FEATURE_NAMES keys, all int or float values.
  - The same input always produces the same output (deterministic).
  - This module NEVER calls analyze_apk() or calculate_risk(). It only reads
    the dict already produced by those functions.
  - The feature vector MUST NOT include any fields from the risk engine output
    (risk.score, risk.classification, risk.findings) to avoid label leakage.
  - If analysis_status != "success", returns a zero-vector (all features = 0)
    and sets _extraction_status = "unavailable".

FEATURE VECTOR (v1.0 — 47 features):
  Group A — File metadata       (2)
  Group B — Permission counts   (2)
  Group C — Permission flags    (25)
  Group D — Component counts    (4)
  Group E — API indicator flags (11)
  Group F — Certificate flags   (3)

IMPORTANT: Never change the order of FEATURE_NAMES without bumping
FEATURE_VECTOR_VERSION. The trained model depends on column position.
"""

from typing import Dict, Any, List

# ---------------------------------------------------------------------------
# Version tag — bump whenever the feature schema changes
# ---------------------------------------------------------------------------
FEATURE_VECTOR_VERSION = "fv-1.0"

# ---------------------------------------------------------------------------
# Ordered list of feature names
# The model is trained with columns in exactly this order.
# ---------------------------------------------------------------------------
FEATURE_NAMES: List[str] = [
    # ── Group A: File metadata (2) ──────────────────────────────────────────
    "feat_size_bytes",
    "feat_dex_count",
    # ── Group B: Permission counts (2) ──────────────────────────────────────
    "feat_perm_total",
    "feat_perm_dangerous_count",
    # ── Group C: Specific permission one-hot flags (25) ─────────────────────
    "feat_perm_send_sms",
    "feat_perm_receive_sms",
    "feat_perm_read_sms",
    "feat_perm_call_phone",
    "feat_perm_read_call_log",
    "feat_perm_fine_location",
    "feat_perm_bg_location",
    "feat_perm_read_contacts",
    "feat_perm_get_accounts",
    "feat_perm_read_external",
    "feat_perm_write_external",
    "feat_perm_manage_external",
    "feat_perm_camera",
    "feat_perm_record_audio",
    "feat_perm_request_install",
    "feat_perm_bind_accessibility",
    "feat_perm_alert_window",
    "feat_perm_biometric",
    "feat_perm_receive_boot",
    "feat_perm_foreground_svc",
    "feat_perm_process_calls",
    "feat_perm_read_phone_state",
    "feat_perm_change_network",
    "feat_perm_change_wifi",
    "feat_perm_disable_keyguard",
    # ── Group D: Component counts (4) ───────────────────────────────────────
    "feat_activity_count",
    "feat_service_count",
    "feat_receiver_count",
    "feat_provider_count",
    # ── Group E: API indicator flags (11) ───────────────────────────────────
    "feat_api_exec_runtime",
    "feat_api_reflection",
    "feat_api_dynamic_dexload",
    "feat_api_crypto",
    "feat_api_sms_send",
    "feat_api_telephony_read",
    "feat_api_location_access",
    "feat_api_root_check",
    "feat_api_clipboard",
    "feat_api_camera_silent",
    "feat_api_audio_record",
    # ── Group F: Certificate indicators (3) ─────────────────────────────────
    "feat_cert_present",
    "feat_cert_is_debug",
    "feat_cert_subject_len",
]

FEATURE_COUNT = len(FEATURE_NAMES)  # must equal 47

# ---------------------------------------------------------------------------
# Dangerous permission → feature name mapping (Group C)
# Each entry maps a lowercase Android permission suffix to a feat_ key.
# The full permission string is "android.permission.<SUFFIX>".
# ---------------------------------------------------------------------------
_PERMISSION_FEATURE_MAP: Dict[str, str] = {
    "android.permission.send_sms":                   "feat_perm_send_sms",
    "android.permission.receive_sms":                "feat_perm_receive_sms",
    "android.permission.read_sms":                   "feat_perm_read_sms",
    "android.permission.call_phone":                 "feat_perm_call_phone",
    "android.permission.read_call_log":              "feat_perm_read_call_log",
    "android.permission.access_fine_location":       "feat_perm_fine_location",
    "android.permission.access_background_location": "feat_perm_bg_location",
    "android.permission.read_contacts":              "feat_perm_read_contacts",
    "android.permission.get_accounts":               "feat_perm_get_accounts",
    "android.permission.read_external_storage":      "feat_perm_read_external",
    "android.permission.write_external_storage":     "feat_perm_write_external",
    "android.permission.manage_external_storage":    "feat_perm_manage_external",
    "android.permission.camera":                     "feat_perm_camera",
    "android.permission.record_audio":               "feat_perm_record_audio",
    "android.permission.request_install_packages":   "feat_perm_request_install",
    "android.permission.bind_accessibility_service": "feat_perm_bind_accessibility",
    "android.permission.system_alert_window":        "feat_perm_alert_window",
    "android.permission.use_biometric":              "feat_perm_biometric",
    "android.permission.receive_boot_completed":     "feat_perm_receive_boot",
    "android.permission.foreground_service":         "feat_perm_foreground_svc",
    "android.permission.process_outgoing_calls":     "feat_perm_process_calls",
    "android.permission.read_phone_state":           "feat_perm_read_phone_state",
    "android.permission.change_network_state":       "feat_perm_change_network",
    "android.permission.change_wifi_state":          "feat_perm_change_wifi",
    "android.permission.disable_keyguard":           "feat_perm_disable_keyguard",
}

# ---------------------------------------------------------------------------
# API pattern → feature name mapping (Group E)
# Each tuple is (pattern_substring_lowercase, feat_key).
# Pattern matching mirrors the logic in rules.py API_RULES.
# ---------------------------------------------------------------------------
_API_FEATURE_MAP: List[tuple] = [
    ("runtime;->exec",          "feat_api_exec_runtime"),
    ("processbuilder",          "feat_api_exec_runtime"),   # same feature
    ("java/lang/reflect",       "feat_api_reflection"),
    ("getdeclaredmethod",       "feat_api_reflection"),
    ("getdeclaredfield",        "feat_api_reflection"),
    ("dexclassloader",          "feat_api_dynamic_dexload"),
    ("pathclassloader",         "feat_api_dynamic_dexload"),
    ("loadclass",               "feat_api_dynamic_dexload"),
    ("javax/crypto",            "feat_api_crypto"),
    ("cipher;->getinstance",    "feat_api_crypto"),
    ("secretkeyspec",           "feat_api_crypto"),
    ("smsmanager;->sendtextmessage",       "feat_api_sms_send"),
    ("smsmanager;->sendmultiparttextmessage", "feat_api_sms_send"),
    ("telephonymanager;->getdeviceid",     "feat_api_telephony_read"),
    ("telephonymanager;->getsubscriberid", "feat_api_telephony_read"),
    ("telephonymanager;->getline1number",  "feat_api_telephony_read"),
    ("locationmanager;->getlastknownlocation", "feat_api_location_access"),
    ("fusedlocationproviderclient",        "feat_api_location_access"),
    ("/system/bin/su",          "feat_api_root_check"),
    ("roottools",               "feat_api_root_check"),
    ("superuser",               "feat_api_root_check"),
    ("clipboardmanager;->getprimaryclip", "feat_api_clipboard"),
    ("clipboardmanager;->gettext",        "feat_api_clipboard"),
    ("camera;->takepicture",              "feat_api_camera_silent"),
    ("cameradevice;->createcapturesession", "feat_api_camera_silent"),
    ("audiorecord;->startrecording",      "feat_api_audio_record"),
    ("mediarecorder;->start",             "feat_api_audio_record"),
]


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------

def extract_features(
    analysis_result: Dict[str, Any],
    size_bytes: int = 0,
) -> Dict[str, Any]:
    """
    Converts the output of analyze_apk() into the 47-feature ML vector.

    Args:
        analysis_result: The dict returned by analyze_apk().
        size_bytes:      The APK file size in bytes (available in main.py
                         as file_path.stat().st_size; passed explicitly so
                         this module does not touch the filesystem).

    Returns:
        A dict with:
          - "features":    dict of {feat_name: int/float} with exactly 47 keys
          - "status":      "success" or "unavailable"
          - "version":     FEATURE_VECTOR_VERSION string
    """
    if analysis_result.get("analysis_status") != "success":
        return _unavailable_features()

    permissions: List[str] = analysis_result.get("permissions") or []
    components: Dict       = analysis_result.get("components") or {}
    activities: List[str]  = components.get("activities") or []
    services: List[str]    = components.get("services") or []
    receivers: List[str]   = components.get("receivers") or []
    providers: List[str]   = components.get("providers") or []
    dex_count: int         = (analysis_result.get("dex") or {}).get("count", 0)
    apis: List[str]        = analysis_result.get("apis") or []
    certificate: Dict      = analysis_result.get("certificate") or {}

    permissions_lower = {p.lower() for p in permissions}
    apis_lower        = [a.lower() for a in apis]

    # ── Initialise all features to 0 ────────────────────────────────────────
    feat: Dict[str, int] = {name: 0 for name in FEATURE_NAMES}

    # ── Group A: File metadata ───────────────────────────────────────────────
    feat["feat_size_bytes"] = int(size_bytes)
    feat["feat_dex_count"]  = int(dex_count)

    # ── Group B: Permission counts ───────────────────────────────────────────
    feat["feat_perm_total"] = len(permissions)
    dangerous_count = sum(
        1 for perm_lower in _PERMISSION_FEATURE_MAP
        if perm_lower in permissions_lower
    )
    feat["feat_perm_dangerous_count"] = dangerous_count

    # ── Group C: Per-permission one-hot flags ────────────────────────────────
    for perm_lower, feat_key in _PERMISSION_FEATURE_MAP.items():
        if perm_lower in permissions_lower:
            feat[feat_key] = 1

    # ── Group D: Component counts ────────────────────────────────────────────
    feat["feat_activity_count"] = len(activities)
    feat["feat_service_count"]  = len(services)
    feat["feat_receiver_count"] = len(receivers)
    feat["feat_provider_count"] = len(providers)

    # ── Group E: API indicator flags ─────────────────────────────────────────
    for pattern, feat_key in _API_FEATURE_MAP:
        if feat[feat_key] == 0:  # only check if not already set
            if any(pattern in api for api in apis_lower):
                feat[feat_key] = 1

    # ── Group F: Certificate indicators ─────────────────────────────────────
    if certificate:
        feat["feat_cert_present"] = 1
        subject = (certificate.get("subject") or "").lower()
        if "android debug" in subject or ("debug" in subject and "cn=" in subject):
            feat["feat_cert_is_debug"] = 1
        feat["feat_cert_subject_len"] = len(certificate.get("subject") or "")
    # else: all three cert features remain 0 (cert absent)

    return {
        "features": feat,
        "status":   "success",
        "version":  FEATURE_VECTOR_VERSION,
    }


def feature_dict_to_list(features: Dict[str, int]) -> List[int]:
    """
    Converts a feature dict to an ordered list suitable for numpy array creation.
    The order is guaranteed by FEATURE_NAMES.
    """
    return [features[name] for name in FEATURE_NAMES]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _unavailable_features() -> Dict[str, Any]:
    """Returns a zero-vector with unavailable status for failed analyses."""
    return {
        "features": {name: 0 for name in FEATURE_NAMES},
        "status":   "unavailable",
        "version":  FEATURE_VECTOR_VERSION,
    }
