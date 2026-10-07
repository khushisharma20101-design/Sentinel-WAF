"""Central hybrid WAF detection pipeline.

All request sources should call ``detect``.  The pipeline is:
1. Normalize the request.
2. Run signature detection for known attacks.
3. If the signature layer marks the request as obfuscated/suspicious,
   extract features and ask the ML model for the second-stage verdict.
4. Return one common response shape for the UI and logging layer.
"""

import logging
import re
import urllib.parse

from src.hybrid_waf.utils.signature_checker import check_signature
from src.hybrid_waf.utils.preprocessor import extract_features
from src.hybrid_waf.utils.ml_checker import check_ml_prediction

logger = logging.getLogger("waf_detections")


def normalize_payload(raw: str) -> str:
    """Decode URL-encoded input up to three times for inspection."""
    decoded = raw or ""
    for _ in range(3):
        next_value = urllib.parse.unquote_plus(decoded)
        if next_value == decoded:
            break
        decoded = next_value
    return decoded


# These are classification signatures, not a second decision engine.
# The actual allow/block decision is still made by check_signature + ML.
CATEGORY_RULES = [
    ("SQL Injection", "SQLi-Rule-104", re.compile(
        r"('|\"|%27)\s*(or|and)\b|\bunion\s+(all\s+)?select\b|\b(drop|truncate|alter)\s+table\b|\bdelete\s+from\b|\bselect\s+.+\bfrom\b|--|/\*",
        re.I), "CRITICAL"),
    ("XSS", "XSS-002", re.compile(
        r"<\s*script\b|\bon\w+\s*=|javascript\s*:|<\s*(img|svg|iframe|body)\b|alert\s*\(",
        re.I), "HIGH"),
    ("CMD Injection", "CMDi-Rule-055", re.compile(
        r"(?:[|;]|&&)\s*(?:cat|ls|dir|whoami|pwd|net\s+user|ping|nc|wget|curl|rm|del)\b|`[^`]+`|\$\([^)]+\)",
        re.I), "CRITICAL"),
    ("Path Traversal", "LFI-Rule-021", re.compile(
        r"\.\.(?:/|\\)|/etc/(?:passwd|shadow)|[a-z]:\\+windows",
        re.I), "HIGH"),
    ("Reconnaissance Probing", "BOT-Rule-007", re.compile(
        r"\b(admin|root|sudo|system|config)\b",
        re.I), "MEDIUM"),
]


def classify_payload(payload: str) -> tuple[str, str | None, str]:
    """Return category, rule id and severity for a detected payload."""
    for category, rule_id, pattern, severity in CATEGORY_RULES:
        if pattern.search(payload):
            return category, rule_id, severity
    return "Suspicious Activity", "HYBRID-ML-001", "MEDIUM"


def detect(user_input: str, uri: str = "", get_data: str = "", post_data: str = "") -> dict:
    """Run one request through the complete hybrid WAF pipeline."""
    raw = user_input if isinstance(user_input, str) else str(user_input or "")
    uri = uri if isinstance(uri, str) else str(uri or raw)
    get_data = get_data if isinstance(get_data, str) else str(get_data or "")
    post_data = post_data if isinstance(post_data, str) else str(post_data or "")

    normalized = normalize_payload(raw)
    signature_result = check_signature(normalized)

    # Known attack: signature engine is authoritative.
    if signature_result == "malicious":
        category, rule_id, severity = classify_payload(normalized)
        return {
            "status": "BLOCKED",
            "severity": severity,
            "category": category,
            "rule_id": rule_id,
            "detection_stage": "SIGNATURE",
            "signature_result": "malicious",
            "ml_used": False,
        }

    # Suspicious/obfuscated: send the same request to the ML second stage.
    if signature_result == "obfuscated":
        features = extract_features(uri, get_data, post_data)
        prediction = int(check_ml_prediction(features))
        category, rule_id, severity = classify_payload(normalized)

        if prediction == 1:
            return {
                "status": "BLOCKED",
                "severity": max_severity(severity, "HIGH"),
                "category": category,
                "rule_id": rule_id,
                "detection_stage": "ML",
                "signature_result": "obfuscated",
                "ml_used": True,
                "ml_prediction": 1,
                "features": features,
            }

        return {
            "status": "PASSED",
            "severity": "CLEAN",
            "category": "Safe Traffic",
            "rule_id": None,
            "detection_stage": "ML",
            "signature_result": "obfuscated",
            "ml_used": True,
            "ml_prediction": 0,
            "features": features,
        }

    # No signature match: allow normally. ML is deliberately not run on
    # every request; it is the second-stage detector for suspicious input.
    return {
        "status": "PASSED",
        "severity": "CLEAN",
        "category": "Safe Traffic",
        "rule_id": None,
        "detection_stage": "SIGNATURE",
        "signature_result": "valid",
        "ml_used": False,
    }


def max_severity(current: str, minimum: str) -> str:
    order = {"CLEAN": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
    return current if order.get(current, 0) >= order[minimum] else minimum
