from backend.analyzer.email_domain_analyzer import analyze_sender_email
from backend.analyzer.urldomain_analyzer import analyze_url_domain
from backend.analyzer.whois_analyzer import analyze_domain_whois
from backend.utils.urls_utils import extract_urls, extract_domain_from_url

def analyze_email_risk(sender_email: str, email_body: str) -> dict:
    result = {
        "sender_email": sender_email,
        "total_risk_score": 0,
        "sender_analysis": {},
        "url_analyses": [],
        "whois_analyses": [],
        "verdict": "LOW"
    }

    # 1️⃣ Sender analysis
    sender_result = analyze_sender_email(sender_email)
    sender_domain = sender_result.get("domain")

    result["sender_analysis"] = sender_result
    result["total_risk_score"] += sender_result.get("risk_score", 0)

    # 2️⃣ URL extraction
    urls = extract_urls(email_body)

    for url in urls:
        domain = extract_domain_from_url(url)

        # URL domain analysis
        url_result = analyze_url_domain(domain, sender_domain)
        result["url_analyses"].append({
            "url": url,
            "analysis": url_result
        })
        result["total_risk_score"] += url_result["risk_score"]

        # WHOIS analysis (avoid duplicates)
        if domain not in [w["domain"] for w in result["whois_analyses"]]:
            whois_result = analyze_domain_whois(domain)
            result["whois_analyses"].append(whois_result)
            result["total_risk_score"] += whois_result["risk_score"]

    # 3️⃣ Verdict
    score = result["total_risk_score"]
    if score >= 80:
        result["verdict"] = "HIGH"
    elif score >= 40:
        result["verdict"] = "MEDIUM"
    else:
        result["verdict"] = "LOW"

    return result
