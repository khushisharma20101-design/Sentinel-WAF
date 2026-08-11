from flask import Blueprint, request, jsonify
from src.hybrid_waf.utils.signature_checker import check_signature
from src.hybrid_waf.routes.main import log_to_db  # <-- Database function connect kiya
import logging

# Create a dedicated logger for WAF detections
waf_logger = logging.getLogger('waf_detections')
waf_logger.setLevel(logging.INFO)

# Create file handler
fh = logging.FileHandler('logs/detections.log')
fh.setLevel(logging.INFO)

# Create formatter
formatter = logging.Formatter('%(asctime)s - %(message)s', datefmt='%Y-%m-%d %H:%M:%S')
fh.setFormatter(formatter)

# Add the handler to the logger
waf_logger.addHandler(fh)

proxy_bp = Blueprint('proxy', __name__)

@proxy_bp.route('/check_request', methods=['POST'])
def check_request():
    data = request.get_json()
    
    user_input = data.get("user_request", "")
    uri = data.get("uri", user_input)
    get_data = data.get("get_data", "")
    post_data = data.get("post_data", "")
    
    # --- Step 1: Signature-Based Detection ---
    signature_result = check_signature(user_input)
    
    if signature_result == "valid":
        waf_logger.info(f"Type: VALID REQUEST | Input: {user_input} | Status: ALLOWED")
        return jsonify({
            "status": "valid",
            "message": "All Clear! Your request passed our security checks with flying colors.✨"
        })

    if signature_result == "malicious":
        waf_logger.info(
            f"\nType: SIGNATURE ATTACK\nInput: {user_input}\nURI: {uri}\nStatus: BLOCKED\n--------------------\n"
        )
        
        # <-- NEW: Pata lagana ki kis type ka attack hai aur use DB me bhejni ki koshish
        u_lower = user_input.lower()
        if "select" in u_lower or "union" in u_lower or "'" in u_lower or "or " in u_lower:
            attack_type = "SQL Injection"
        elif "<script>" in u_lower or "alert(" in u_lower or "onerror" in u_lower:
            attack_type = "XSS Attack"
        else:
            attack_type = "Signature Match"
            
        log_to_db(user_input, attack_type)  # Database me save ho raha hai!
        
        return jsonify({
            "status": "malicious",
            "message": "Critical Alert! Malicious pattern detected in your request.<br>Access Denied!🔒"
        })
    
    # --- Step 2: ML-Based Anomaly Detection (Only for obfuscated requests) ---
    if signature_result == "obfuscated":
        from src.hybrid_waf.utils.preprocessor import extract_features
        from src.hybrid_waf.utils.ml_checker import check_ml_prediction
        
        features = extract_features(uri, get_data, post_data)
        prediction = check_ml_prediction(features)
        
        final_status = "malicious" if prediction == 1 else "valid"
        waf_logger.info(f"{user_input} - malicious(ML)" if prediction == 1 else f"{user_input} - valid")
        
        if final_status == "malicious":
            # <-- NEW: ML dwara detect huye attack ko DB me save karna
            log_to_db(user_input, "ML Anomaly Attack")
            
        return jsonify({
            "status": "obfuscated",
            "ml_verdict": (
                "🚨 Threat Confirmed! AI Defense System Blocked Suspicious Activity.🔒" 
                if final_status == "malicious" 
                else "✅ Advanced AI Scan Complete: Request Verified Safe ✨"
            ),
            "message": "Suspicious Pattern Detected - Engaging Advanced AI Analysis...",
            "features": features
        })
