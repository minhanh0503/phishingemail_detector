from analyzer.feature_engine import (
    analyze_sender_email,
    analyze_url_domain,
    analyze_domain_whois
)

from analyzer.preprocessor import (
    extract_urls,
    extract_domain_from_url
)

from analyzer.ml_predictor import predict_email
from analyzer.rule_engine import run_rule_engine
from analyzer.scoring import compute_final_risk 

def analyze_email_risk(sender_email: str, email_body: str) -> dict:

    result = {
        "sender_email": sender_email,
        "sender_analysis": {},
        "url_analyses": [],
        "whois_analyses": [],
        "ml_prediction": {},
        "rule_engine": {},
        "scoring": {},
        "total_risk_score": 0,
        "verdict": "LOW",
        "explanation": {}
    }

    # ML
    ml_result = predict_email(email_body)
    result["ml_prediction"] = ml_result

    # Sender
    sender_result = analyze_sender_email(sender_email)
    sender_domain = sender_result.get("domain")
    result["sender_analysis"] = sender_result

    # URLs
    urls = extract_urls(email_body)

    for url in urls:
        domain = extract_domain_from_url(url)

        result["url_analyses"].append({
            "url": url,
            "domain": domain
        })

        # WHOIS
        if domain not in [w["domain"] for w in result["whois_analyses"]]:
            whois_result = analyze_domain_whois(domain)
            result["whois_analyses"].append(whois_result)

    # RULE ENGINE
    rule_result = run_rule_engine(
        sender_email,
        email_body,
        urls,
        sender_domain,
        result["whois_analyses"]
    )

    result["rule_engine"] = rule_result

    # SCORING (single source of truth)
    score_result = compute_final_risk(
        rule_result["score"],
        ml_result["confidence"]
    )

    result["scoring"] = score_result
    result["total_risk_score"] = score_result["final_score"]

    # VERDICT
    score = result["total_risk_score"]

    if score >= 80:
        result["verdict"] = "HIGH"
    elif score >= 40:
        result["verdict"] = "MEDIUM"
    else:
        result["verdict"] = "LOW"

    # EXPLANATION
    summary = []

    if ml_result["prediction"] == "PHISHING":
        summary.append("ML model detected phishing patterns in email text")

    if rule_result["score"] > 50:
        summary.append("Rule engine detected multiple phishing indicators")

    if len(urls) > 0:
        summary.append("Email contains external links which increase risk")

    result["explanation"] = {
        "summary": summary,
        "ml": {
            "prediction": ml_result["prediction"],
            "confidence": ml_result["confidence"]
        },
        "rules": {
            "score": rule_result["score"],
            "reasons": rule_result["reasons"]
        },
        "signals": {
            "has_links": len(urls) > 0,
            "sender_domain": sender_domain
        }
    }

    return result