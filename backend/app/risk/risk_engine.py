"""
risk_engine.py — Deterministic risk scoring engine for FraudGuard AI.

Consumes the structured output from Phase 2 (analyze_apk()) and returns a
risk assessment with score, classification, and per-rule findings.

CONTRACT:
  - Input:  the dict returned by analyze_apk()
  - Output: a "risk" sub-dict inserted into that same dict
  - The APK is never re-parsed here; this module never imports Androguard.
  - The same input always produces the same output (deterministic).
  - If analysis_status != "success", a null risk state is returned.
"""

import logging
from typing import Dict, Any, List, Optional

from app.risk.rules import (
    DANGEROUS_PERMISSION_RULES,
    PERMISSION_COMBINATION_RULES,
    COMPONENT_RULES,
    COMPONENT_NAME_PATTERNS,
    DEX_RULES,
    API_RULES,
    CERTIFICATE_RULES,
    CLASSIFICATION_THRESHOLDS,
    MAX_SCORE,
)

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------

def calculate_risk(analysis_result: Dict[str, Any]) -> Dict[str, Any]:
    """
    Calculates a deterministic risk score from an APK analysis result.

    Args:
        analysis_result: The dict returned by analyze_apk().

    Returns:
        A "risk" dict with keys: score, classification, findings, summary.
        This dict is meant to be attached to the analysis result as
        analysis_result["risk"].
    """
    if analysis_result.get("analysis_status") != "success":
        return _unavailable_risk(
            "APK analysis did not succeed. Risk scoring requires a successful analysis."
        )

    findings: List[Dict[str, Any]] = []

    # ── Extract data from analysis result (never re-parse the APK) ──────────
    permissions: List[str] = analysis_result.get("permissions") or []
    components: Dict     = analysis_result.get("components") or {}
    activities: List[str]= components.get("activities") or []
    services: List[str]  = components.get("services") or []
    receivers: List[str] = components.get("receivers") or []
    providers: List[str] = components.get("providers") or []
    dex_count: int       = (analysis_result.get("dex") or {}).get("count", 0)
    apis: List[str]      = analysis_result.get("apis") or []
    certificate: Dict    = analysis_result.get("certificate") or {}

    all_components: List[str] = activities + services + receivers + providers
    # Normalise to lowercase for pattern matching
    permissions_lower = [p.lower() for p in permissions]
    apis_lower        = [a.lower() for a in apis]
    components_lower  = [c.lower() for c in all_components]

    # ── 1. Dangerous permissions ────────────────────────────────────────────
    findings.extend(
        _evaluate_dangerous_permissions(permissions, permissions_lower)
    )

    # ── 2. Permission combination rules ────────────────────────────────────
    findings.extend(
        _evaluate_permission_combinations(permissions, permissions_lower)
    )

    # ── 3. Component count rules ────────────────────────────────────────────
    findings.extend(
        _evaluate_component_counts(services, receivers)
    )

    # ── 4. Component name patterns ─────────────────────────────────────────
    findings.extend(
        _evaluate_component_name_patterns(all_components, components_lower)
    )

    # ── 5. DEX rules ───────────────────────────────────────────────────────
    findings.extend(
        _evaluate_dex(dex_count)
    )

    # ── 6. API reference rules ─────────────────────────────────────────────
    findings.extend(
        _evaluate_apis(apis, apis_lower)
    )

    # ── 7. Certificate rules ───────────────────────────────────────────────
    findings.extend(
        _evaluate_certificate(certificate)
    )

    # ── Aggregate score (capped at MAX_SCORE) ──────────────────────────────
    raw_score = sum(f["points"] for f in findings)
    score = min(raw_score, MAX_SCORE)

    classification = _classify(score)
    summary = _build_summary(score, classification, findings)

    logger.info(
        "Risk calculation complete: score=%d classification=%s findings=%d",
        score, classification, len(findings)
    )

    return {
        "score": score,
        "classification": classification,
        "findings": findings,
        "summary": summary,
    }


# ---------------------------------------------------------------------------
# Evaluator functions — one per rule category
# ---------------------------------------------------------------------------

def _evaluate_dangerous_permissions(
    permissions: List[str],
    permissions_lower: List[str],
) -> List[Dict[str, Any]]:
    """Check each declared permission against the dangerous permission rule list."""
    triggered = []
    for rule in DANGEROUS_PERMISSION_RULES:
        perm = rule["permission"].lower()
        if perm in permissions_lower:
            triggered.append(_finding(rule))
    return triggered


def _evaluate_permission_combinations(
    permissions: List[str],
    permissions_lower: List[str],
) -> List[Dict[str, Any]]:
    """
    Check for dangerous permission combinations.
    A combination only triggers if ALL required permissions are present.
    """
    triggered = []
    for rule in PERMISSION_COMBINATION_RULES:
        required = [p.lower() for p in rule["required_permissions"]]
        if all(p in permissions_lower for p in required):
            triggered.append(_finding(rule))
    return triggered


def _evaluate_component_counts(
    services: List[str],
    receivers: List[str],
) -> List[Dict[str, Any]]:
    """Trigger count-threshold rules for services and receivers."""
    triggered = []
    for rule in COMPONENT_RULES:
        rule_id = rule["rule_id"]
        threshold = rule.get("threshold", 0)
        if rule_id == "COMP_MANY_SERVICES" and len(services) >= threshold:
            f = _finding(rule)
            f["matched_value"] = len(services)
            triggered.append(f)
        elif rule_id == "COMP_MANY_RECEIVERS" and len(receivers) >= threshold:
            f = _finding(rule)
            f["matched_value"] = len(receivers)
            triggered.append(f)
    return triggered


def _evaluate_component_name_patterns(
    all_components: List[str],
    components_lower: List[str],
) -> List[Dict[str, Any]]:
    """Check all component class names for suspicious keywords."""
    triggered = []
    triggered_rule_ids = set()

    for rule in COMPONENT_NAME_PATTERNS:
        if rule["rule_id"] in triggered_rule_ids:
            continue
        for pattern in rule["patterns"]:
            if any(pattern in comp for comp in components_lower):
                f = _finding(rule)
                f["matched_pattern"] = pattern
                triggered.append(f)
                triggered_rule_ids.add(rule["rule_id"])
                break  # one match per rule is enough
    return triggered


def _evaluate_dex(dex_count: int) -> List[Dict[str, Any]]:
    """Evaluate DEX count against configured thresholds."""
    triggered = []
    for rule in DEX_RULES:
        if rule["rule_id"] == "DEX_MULTIDEX" and dex_count >= rule["threshold"]:
            f = _finding(rule)
            f["matched_value"] = dex_count
            triggered.append(f)
    return triggered


def _evaluate_apis(
    apis: List[str],
    apis_lower: List[str],
) -> List[Dict[str, Any]]:
    """
    Check the api reference list for suspicious method patterns.
    Each rule triggers at most once, even if multiple patterns match.
    """
    triggered = []
    for rule in API_RULES:
        for pattern in rule["patterns"]:
            pattern_lower = pattern.lower()
            if any(pattern_lower in api for api in apis_lower):
                f = _finding(rule)
                f["matched_pattern"] = pattern
                triggered.append(f)
                break  # one match per rule is enough
    return triggered


def _evaluate_certificate(certificate: Dict) -> List[Dict[str, Any]]:
    """Evaluate certificate information for anomalies."""
    triggered = []

    # No certificate data at all
    if not certificate:
        cert_missing_rule = next(
            (r for r in CERTIFICATE_RULES if r["rule_id"] == "CERT_MISSING"), None
        )
        if cert_missing_rule:
            triggered.append(_finding(cert_missing_rule))
        return triggered

    subject = certificate.get("subject") or ""
    subject_lower = subject.lower()

    # Debug certificate
    debug_rule = next(
        (r for r in CERTIFICATE_RULES if r["rule_id"] == "CERT_DEBUG_SUBJECT"), None
    )
    if debug_rule:
        for pattern in debug_rule.get("patterns", []):
            if pattern.lower() in subject_lower:
                f = _finding(debug_rule)
                f["matched_pattern"] = pattern
                triggered.append(f)
                break

    # Very short/generic subject
    short_rule = next(
        (r for r in CERTIFICATE_RULES if r["rule_id"] == "CERT_UNKNOWN_SUBJECT"), None
    )
    if short_rule:
        min_len = short_rule.get("min_subject_length", 10)
        if len(subject) < min_len:
            triggered.append(_finding(short_rule))

    return triggered


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _finding(rule: Dict) -> Dict[str, Any]:
    """
    Build a single finding dict from a rule definition.
    Only includes the fields relevant to a finding (not rule metadata like 'patterns').
    """
    return {
        "rule_id":      rule["rule_id"],
        "category":     rule["category"],
        "severity":     rule["severity"],
        "points":       rule["points"],
        "reason":       rule.get("reason", rule.get("description", "")),
    }


def _classify(score: int) -> str:
    """Map a numeric score to a classification label."""
    for threshold in CLASSIFICATION_THRESHOLDS:
        if threshold["min"] <= score <= threshold["max"]:
            return threshold["label"]
    return "Low"  # fallback (score=0)


def _build_summary(score: int, classification: str, findings: List[Dict]) -> str:
    """Build a human-readable one-line summary of the risk assessment."""
    if not findings:
        return (
            "No risk signals were detected based on the available analysis data. "
            "This does not guarantee the APK is safe."
        )

    top = sorted(findings, key=lambda f: f["points"], reverse=True)
    top_reasons = "; ".join(f["rule_id"] for f in top[:3])
    return (
        f"Risk score: {score}/100 ({classification}). "
        f"Top signals: {top_reasons}. "
        f"{len(findings)} rule(s) triggered."
    )


def _unavailable_risk(reason: str) -> Dict[str, Any]:
    """Return a null-state risk dict when analysis failed or was incomplete."""
    return {
        "score": None,
        "classification": None,
        "findings": [],
        "summary": reason,
    }
