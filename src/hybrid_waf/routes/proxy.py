from flask import Blueprint, request, jsonify
import logging

from src.hybrid_waf.engine import detect

proxy_bp = Blueprint("proxy", __name__)
waf_logger = logging.getLogger("waf_detections")


def _legacy_response(result: dict) -> dict:
    """Keep the original /check_request response shape for home.html."""
    if result["status"] == "BLOCKED":
        return {
            "status": "malicious",
            "message": "Critical Alert! Malicious pattern detected in your request.<br>Access Denied!🔒",
            "detection_stage": result.get("detection_stage"),
            "category": result.get("category"),
            "rule_id": result.get("rule_id"),
        }
    if result.get("ml_used"):
        return {
            "status": "obfuscated",
            "ml_verdict": "🚨 Threat Confirmed! AI Defense System Blocked Suspicious Activity.🔒" if result["status"] == "BLOCKED" else "✅ Advanced AI Scan Complete: Request Verified Safe ✨",
            "message": "Suspicious Pattern Detected - Engaging Advanced AI Analysis...",
            "features": result.get("features", []),
            "detection_stage": result.get("detection_stage"),
        }
    return {
        "status": "valid",
        "message": "All Clear! Your request passed our security checks with flying colors.✨",
        "detection_stage": result.get("detection_stage"),
    }


@proxy_bp.route("/check_request", methods=["POST"])
def check_request():
    data = request.get_json(silent=True) or {}
    user_input = data.get("user_request", "")
    uri = data.get("uri", user_input)
    get_data = data.get("get_data", "")
    post_data = data.get("post_data", "")

    result = detect(user_input, uri, get_data, post_data)
    waf_logger.info(
        "stage=%s status=%s category=%s payload=%r",
        result.get("detection_stage"), result["status"], result["category"], user_input,
    )
    return jsonify(_legacy_response(result))
