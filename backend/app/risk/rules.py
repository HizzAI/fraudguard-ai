"""
rules.py — Centralized deterministic risk rule definitions for FraudGuard AI.

Each rule maps a specific signal (extracted from Phase 2 APK analysis) to:
  - A unique rule_id
  - A category (Permissions, Components, Certificate, DEX, APIs)
  - A severity level (low / medium / high / critical)
  - A point value added to the risk score
  - A human-readable reason string (used for explainability)

DESIGN PRINCIPLES:
  - Rules are data, not scattered conditionals.
  - Scoring logic lives in risk_engine.py; this file only defines signals.
  - No ML, no GenAI, no external lookups.
  - All signals are grounded in actual Phase 2 output fields.
  - Labels like "malicious" are intentionally avoided. Rules describe
    capabilities or anomalies, not verdicts.
"""

from typing import List, Dict


# ---------------------------------------------------------------------------
# Severity → base point value mapping (used for combination rules)
# ---------------------------------------------------------------------------
SEVERITY_POINTS: Dict[str, int] = {
    "low":      5,
    "medium":  12,
    "high":    20,
    "critical": 35,
}


# ---------------------------------------------------------------------------
# DANGEROUS PERMISSIONS
#
# Source: Android documentation — "Dangerous" permission group.
# These grant access to private user data or device capabilities
# that can be misused by malware.
# ---------------------------------------------------------------------------
DANGEROUS_PERMISSION_RULES: List[Dict] = [
    # --- Telephony ---
    {
        "rule_id": "PERM_SEND_SMS",
        "category": "Permissions",
        "severity": "high",
        "points": 20,
        "permission": "android.permission.SEND_SMS",
        "reason": "App can send SMS messages. This is a common capability in SMS-fraud and toll-fraud malware.",
    },
    {
        "rule_id": "PERM_RECEIVE_SMS",
        "category": "Permissions",
        "severity": "medium",
        "points": 12,
        "permission": "android.permission.RECEIVE_SMS",
        "reason": "App can intercept incoming SMS messages, including OTP/2FA codes.",
    },
    {
        "rule_id": "PERM_READ_SMS",
        "category": "Permissions",
        "severity": "medium",
        "points": 12,
        "permission": "android.permission.READ_SMS",
        "reason": "App can read SMS inbox. Combined with RECEIVE_SMS, enables OTP interception.",
    },
    {
        "rule_id": "PERM_CALL_PHONE",
        "category": "Permissions",
        "severity": "medium",
        "points": 12,
        "permission": "android.permission.CALL_PHONE",
        "reason": "App can initiate phone calls without user interaction.",
    },
    {
        "rule_id": "PERM_READ_CALL_LOG",
        "category": "Permissions",
        "severity": "medium",
        "points": 10,
        "permission": "android.permission.READ_CALL_LOG",
        "reason": "App can read call history.",
    },
    # --- Location ---
    {
        "rule_id": "PERM_ACCESS_FINE_LOCATION",
        "category": "Permissions",
        "severity": "medium",
        "points": 10,
        "permission": "android.permission.ACCESS_FINE_LOCATION",
        "reason": "App requests precise GPS location.",
    },
    {
        "rule_id": "PERM_ACCESS_BACKGROUND_LOCATION",
        "category": "Permissions",
        "severity": "high",
        "points": 18,
        "permission": "android.permission.ACCESS_BACKGROUND_LOCATION",
        "reason": "App can track location in the background without the user actively using it.",
    },
    # --- Contacts & Accounts ---
    {
        "rule_id": "PERM_READ_CONTACTS",
        "category": "Permissions",
        "severity": "medium",
        "points": 10,
        "permission": "android.permission.READ_CONTACTS",
        "reason": "App can access the device contact list.",
    },
    {
        "rule_id": "PERM_GET_ACCOUNTS",
        "category": "Permissions",
        "severity": "low",
        "points": 5,
        "permission": "android.permission.GET_ACCOUNTS",
        "reason": "App can enumerate device accounts (Google, email, etc.).",
    },
    # --- Storage ---
    {
        "rule_id": "PERM_READ_EXTERNAL_STORAGE",
        "category": "Permissions",
        "severity": "low",
        "points": 5,
        "permission": "android.permission.READ_EXTERNAL_STORAGE",
        "reason": "App can read files from external storage.",
    },
    {
        "rule_id": "PERM_WRITE_EXTERNAL_STORAGE",
        "category": "Permissions",
        "severity": "medium",
        "points": 8,
        "permission": "android.permission.WRITE_EXTERNAL_STORAGE",
        "reason": "App can write files to external storage.",
    },
    {
        "rule_id": "PERM_MANAGE_EXTERNAL_STORAGE",
        "category": "Permissions",
        "severity": "high",
        "points": 18,
        "permission": "android.permission.MANAGE_EXTERNAL_STORAGE",
        "reason": "App requests broad access to all external storage (All Files Access).",
    },
    # --- Camera & Microphone ---
    {
        "rule_id": "PERM_CAMERA",
        "category": "Permissions",
        "severity": "medium",
        "points": 10,
        "permission": "android.permission.CAMERA",
        "reason": "App requests camera access.",
    },
    {
        "rule_id": "PERM_RECORD_AUDIO",
        "category": "Permissions",
        "severity": "high",
        "points": 18,
        "permission": "android.permission.RECORD_AUDIO",
        "reason": "App can record audio via the microphone.",
    },
    # --- Device admin / system-level ---
    {
        "rule_id": "PERM_REQUEST_INSTALL_PACKAGES",
        "category": "Permissions",
        "severity": "critical",
        "points": 35,
        "permission": "android.permission.REQUEST_INSTALL_PACKAGES",
        "reason": "App can install other APKs. This is a primary vector for dropper/downloader malware.",
    },
    {
        "rule_id": "PERM_BIND_ACCESSIBILITY_SERVICE",
        "category": "Permissions",
        "severity": "critical",
        "points": 35,
        "permission": "android.permission.BIND_ACCESSIBILITY_SERVICE",
        "reason": "App binds an Accessibility Service, which can observe and control the UI of all other apps.",
    },
    {
        "rule_id": "PERM_SYSTEM_ALERT_WINDOW",
        "category": "Permissions",
        "severity": "high",
        "points": 20,
        "permission": "android.permission.SYSTEM_ALERT_WINDOW",
        "reason": "App can draw overlays on top of other apps. Used in overlay/phishing attacks.",
    },
    {
        "rule_id": "PERM_USE_BIOMETRIC",
        "category": "Permissions",
        "severity": "low",
        "points": 5,
        "permission": "android.permission.USE_BIOMETRIC",
        "reason": "App uses biometric authentication APIs.",
    },
    {
        "rule_id": "PERM_RECEIVE_BOOT_COMPLETED",
        "category": "Permissions",
        "severity": "medium",
        "points": 10,
        "permission": "android.permission.RECEIVE_BOOT_COMPLETED",
        "reason": "App starts automatically after device boot. Common in persistent malware.",
    },
    {
        "rule_id": "PERM_FOREGROUND_SERVICE",
        "category": "Permissions",
        "severity": "low",
        "points": 5,
        "permission": "android.permission.FOREGROUND_SERVICE",
        "reason": "App runs foreground services, allowing long-running background operations.",
    },
    {
        "rule_id": "PERM_PROCESS_OUTGOING_CALLS",
        "category": "Permissions",
        "severity": "medium",
        "points": 12,
        "permission": "android.permission.PROCESS_OUTGOING_CALLS",
        "reason": "App can intercept or redirect outgoing calls.",
    },
    {
        "rule_id": "PERM_READ_PHONE_STATE",
        "category": "Permissions",
        "severity": "medium",
        "points": 10,
        "permission": "android.permission.READ_PHONE_STATE",
        "reason": "App can access device identifiers (IMEI, phone number, etc.).",
    },
    {
        "rule_id": "PERM_CHANGE_NETWORK_STATE",
        "category": "Permissions",
        "severity": "low",
        "points": 5,
        "permission": "android.permission.CHANGE_NETWORK_STATE",
        "reason": "App can modify network connectivity settings.",
    },
    {
        "rule_id": "PERM_CHANGE_WIFI_STATE",
        "category": "Permissions",
        "severity": "low",
        "points": 5,
        "permission": "android.permission.CHANGE_WIFI_STATE",
        "reason": "App can modify Wi-Fi state.",
    },
    {
        "rule_id": "PERM_DISABLE_KEYGUARD",
        "category": "Permissions",
        "severity": "high",
        "points": 20,
        "permission": "android.permission.DISABLE_KEYGUARD",
        "reason": "App can disable the lock screen.",
    },
    {
        "rule_id": "PERM_KILL_BACKGROUND_PROCESSES",
        "category": "Permissions",
        "severity": "low",
        "points": 5,
        "permission": "android.permission.KILL_BACKGROUND_PROCESSES",
        "reason": "App can terminate other running processes.",
    },
]


# ---------------------------------------------------------------------------
# DANGEROUS PERMISSION COMBINATIONS
#
# Some permissions are individually moderate risk but together represent a
# well-known attack pattern. Each combination is scored ONCE as a unit to
# avoid double-counting individual permissions.
#
# The engine will apply the combination bonus only when ALL listed permissions
# are present. The individual permissions still score separately.
# The combo adds a smaller incremental penalty to signal the pattern.
# ---------------------------------------------------------------------------
PERMISSION_COMBINATION_RULES: List[Dict] = [
    {
        "rule_id": "COMBO_SMS_INTERCEPT",
        "category": "Permissions:Combination",
        "severity": "critical",
        "points": 25,
        "required_permissions": [
            "android.permission.RECEIVE_SMS",
            "android.permission.READ_SMS",
        ],
        "reason": (
            "App declares both RECEIVE_SMS and READ_SMS simultaneously. "
            "This combination enables full SMS interception, a key technique "
            "in banking trojan OTP theft."
        ),
    },
    {
        "rule_id": "COMBO_SPYWARE_TRIAD",
        "category": "Permissions:Combination",
        "severity": "critical",
        "points": 30,
        "required_permissions": [
            "android.permission.RECORD_AUDIO",
            "android.permission.ACCESS_FINE_LOCATION",
            "android.permission.READ_CONTACTS",
        ],
        "reason": (
            "App requests microphone, precise location, and contacts simultaneously. "
            "This triad is characteristic of spyware and stalkerware."
        ),
    },
    {
        "rule_id": "COMBO_DROPPER_PATTERN",
        "category": "Permissions:Combination",
        "severity": "critical",
        "points": 30,
        "required_permissions": [
            "android.permission.REQUEST_INSTALL_PACKAGES",
            "android.permission.WRITE_EXTERNAL_STORAGE",
        ],
        "reason": (
            "App can write to storage AND install packages. "
            "This is the primary pattern of dropper malware that downloads "
            "and silently installs additional payloads."
        ),
    },
    {
        "rule_id": "COMBO_OVERLAY_ATTACK",
        "category": "Permissions:Combination",
        "severity": "critical",
        "points": 25,
        "required_permissions": [
            "android.permission.SYSTEM_ALERT_WINDOW",
            "android.permission.BIND_ACCESSIBILITY_SERVICE",
        ],
        "reason": (
            "App requests both overlay drawing and Accessibility Service binding. "
            "Together these enable phishing overlays that are controlled programmatically."
        ),
    },
    {
        "rule_id": "COMBO_FRAUD_PATTERN",
        "category": "Permissions:Combination",
        "severity": "critical",
        "points": 25,
        "required_permissions": [
            "android.permission.SEND_SMS",
            "android.permission.READ_CONTACTS",
            "android.permission.RECEIVE_BOOT_COMPLETED",
        ],
        "reason": (
            "App can send SMS, read contacts, and start on boot. "
            "This pattern is consistent with SMS fraud malware that persists "
            "and targets the victim's contact list."
        ),
    },
]


# ---------------------------------------------------------------------------
# COMPONENT-BASED RULES
#
# Based on substring patterns in component class names.
# These are heuristic signals — not definitive verdicts.
# ---------------------------------------------------------------------------
COMPONENT_RULES: List[Dict] = [
    {
        "rule_id": "COMP_MANY_SERVICES",
        "category": "Components",
        "severity": "medium",
        "points": 10,
        "description": "App declares 5 or more background services.",
        "reason": (
            "A large number of background services increases the app's "
            "persistence surface and may indicate stealthy background activity."
        ),
        "threshold": 5,  # minimum service count to trigger
    },
    {
        "rule_id": "COMP_MANY_RECEIVERS",
        "category": "Components",
        "severity": "medium",
        "points": 10,
        "description": "App declares 5 or more broadcast receivers.",
        "reason": (
            "Many broadcast receivers suggest the app responds to a wide range "
            "of system events (boot, SMS, connectivity changes)."
        ),
        "threshold": 5,
    },
]


# ---------------------------------------------------------------------------
# COMPONENT NAME PATTERN RULES
#
# Substring matches on component class names that suggest suspicious intent.
# These are heuristic signals, not certainties.
# ---------------------------------------------------------------------------
COMPONENT_NAME_PATTERNS: List[Dict] = [
    {
        "rule_id": "COMP_NAME_KEYLOG",
        "category": "Components:NamePattern",
        "severity": "critical",
        "points": 35,
        "patterns": ["keylog", "keylogger"],
        "reason": "A component name contains 'keylog', suggesting possible keylogging functionality.",
    },
    {
        "rule_id": "COMP_NAME_SPY",
        "category": "Components:NamePattern",
        "severity": "high",
        "points": 20,
        "patterns": ["spy", "spyware"],
        "reason": "A component name contains a spyware-related keyword.",
    },
    {
        "rule_id": "COMP_NAME_RAT",
        "category": "Components:NamePattern",
        "severity": "critical",
        "points": 35,
        "patterns": ["rat", "remote_admin", "remoteadmin"],
        "reason": "A component name suggests Remote Access Trojan (RAT) functionality.",
    },
]


# ---------------------------------------------------------------------------
# DEX-BASED RULES
#
# Based on dex.count and api list patterns.
# ---------------------------------------------------------------------------
DEX_RULES: List[Dict] = [
    {
        "rule_id": "DEX_MULTIDEX",
        "category": "DEX",
        "severity": "low",
        "points": 5,
        "description": "App uses multiple DEX files (MultiDex).",
        "reason": (
            "App contains more than one DEX file. While common in large legitimate apps, "
            "multiple DEX files can also be used to hide code in secondary DEX files."
        ),
        "threshold": 2,  # trigger when dex.count >= threshold
    },
]


# ---------------------------------------------------------------------------
# API/METHOD REFERENCE RULES
#
# Substring matches in the `apis` list (format: "Lclass/path;->methodName").
# These are code-level indicators extracted from DEX bytecode by Androguard.
# They indicate what Android APIs the app references, not necessarily calls.
# ---------------------------------------------------------------------------
API_RULES: List[Dict] = [
    {
        "rule_id": "API_EXEC_RUNTIME",
        "category": "APIs",
        "severity": "high",
        "points": 20,
        "patterns": ["Runtime;->exec", "ProcessBuilder"],
        "reason": (
            "App references Runtime.exec() or ProcessBuilder, which can be used "
            "to execute system commands — a technique used in privilege escalation."
        ),
    },
    {
        "rule_id": "API_REFLECTION",
        "category": "APIs",
        "severity": "medium",
        "points": 12,
        "patterns": ["java/lang/reflect", "getDeclaredMethod", "getDeclaredField", "invoke"],
        "reason": (
            "App uses Java reflection. Reflection is commonly used to hide API calls "
            "from static analysis and bypass security scanners."
        ),
    },
    {
        "rule_id": "API_DYNAMIC_DEXLOAD",
        "category": "APIs",
        "severity": "critical",
        "points": 35,
        "patterns": ["DexClassLoader", "PathClassLoader", "loadClass"],
        "reason": (
            "App references DexClassLoader or PathClassLoader. "
            "Dynamic DEX loading is used to load encrypted or remotely-fetched payloads at runtime."
        ),
    },
    {
        "rule_id": "API_CRYPTO",
        "category": "APIs",
        "severity": "low",
        "points": 5,
        "patterns": ["javax/crypto", "Cipher;->getInstance", "SecretKeySpec"],
        "reason": (
            "App references cryptographic APIs. Alone this is not suspicious, "
            "but combined with network access or dynamic loading, it may indicate payload encryption."
        ),
    },
    {
        "rule_id": "API_SMS_SEND",
        "category": "APIs",
        "severity": "high",
        "points": 18,
        "patterns": ["SmsManager;->sendTextMessage", "SmsManager;->sendMultipartTextMessage"],
        "reason": (
            "App references SmsManager send methods at the code level. "
            "Combined with SEND_SMS permission, this confirms SMS-sending capability."
        ),
    },
    {
        "rule_id": "API_TELEPHONY_READ",
        "category": "APIs",
        "severity": "medium",
        "points": 10,
        "patterns": ["TelephonyManager;->getDeviceId", "TelephonyManager;->getSubscriberId",
                     "TelephonyManager;->getLine1Number"],
        "reason": (
            "App reads device identifiers (IMEI, IMSI, phone number) via TelephonyManager."
        ),
    },
    {
        "rule_id": "API_LOCATION_ACCESS",
        "category": "APIs",
        "severity": "low",
        "points": 5,
        "patterns": ["LocationManager;->getLastKnownLocation", "FusedLocationProviderClient"],
        "reason": "App accesses location APIs in code.",
    },
    {
        "rule_id": "API_ROOT_CHECK",
        "category": "APIs",
        "severity": "high",
        "points": 20,
        "patterns": ["su", "/system/bin/su", "RootTools", "SuperUser"],
        "reason": (
            "App references root-related strings or libraries. "
            "This may indicate root detection evasion or privilege escalation attempts."
        ),
    },
    {
        "rule_id": "API_CLIPBOARD",
        "category": "APIs",
        "severity": "medium",
        "points": 10,
        "patterns": ["ClipboardManager;->getPrimaryClip", "ClipboardManager;->getText"],
        "reason": (
            "App reads from the clipboard. Clipboard reading can capture "
            "copied passwords, wallet addresses, or 2FA tokens."
        ),
    },
    {
        "rule_id": "API_CAMERA_SILENT",
        "category": "APIs",
        "severity": "high",
        "points": 18,
        "patterns": ["Camera;->takePicture", "CameraDevice;->createCaptureSession"],
        "reason": "App references camera capture APIs that can be invoked without user awareness.",
    },
    {
        "rule_id": "API_AUDIO_RECORD",
        "category": "APIs",
        "severity": "high",
        "points": 18,
        "patterns": ["AudioRecord;->startRecording", "MediaRecorder;->start"],
        "reason": "App references audio recording APIs at the code level.",
    },
]


# ---------------------------------------------------------------------------
# CERTIFICATE RULES
#
# Based on the certificate dict from Phase 2.
# Only trigger when certificate data is actually available.
# We do NOT call any cert "malicious". We note anomalies.
# ---------------------------------------------------------------------------
CERTIFICATE_RULES: List[Dict] = [
    {
        "rule_id": "CERT_MISSING",
        "category": "Certificate",
        "severity": "high",
        "points": 20,
        "description": "No certificate information was extracted.",
        "reason": (
            "The APK analysis produced no certificate data. "
            "Legitimate APKs are always signed. Missing certificate info may indicate "
            "a stripped, repacked, or malformed APK."
        ),
    },
    {
        "rule_id": "CERT_DEBUG_SUBJECT",
        "category": "Certificate",
        "severity": "medium",
        "points": 12,
        "patterns": ["CN=Android Debug", "debug"],
        "reason": (
            "The certificate subject contains debug-related keywords. "
            "Debug-signed APKs are not intended for production distribution."
        ),
    },
    {
        "rule_id": "CERT_UNKNOWN_SUBJECT",
        "category": "Certificate",
        "severity": "low",
        "points": 5,
        "description": "Certificate subject is very short or generic.",
        "min_subject_length": 10,
        "reason": (
            "The certificate subject is very short or generic, suggesting "
            "a self-signed certificate with minimal identity information."
        ),
    },
]


# ---------------------------------------------------------------------------
# SCORE CAPS AND CLASSIFICATION THRESHOLDS
# ---------------------------------------------------------------------------
MAX_SCORE: int = 100

CLASSIFICATION_THRESHOLDS: List[Dict] = [
    {"min": 80, "max": 100, "label": "Critical"},
    {"min": 60, "max": 79,  "label": "High"},
    {"min": 30, "max": 59,  "label": "Medium"},
    {"min": 0,  "max": 29,  "label": "Low"},
]
