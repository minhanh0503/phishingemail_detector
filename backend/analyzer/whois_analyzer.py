import whois
from datetime import datetime

SUSPICIOUS_DOMAIN_AGE_DAYS = 90


def analyze_domain_whois(domain: str) -> dict:
    result = {
        "domain": domain,
        "domain_age_days": None,
        "is_new_domain": False,
        "whois_available": True,
        "risk_score": 0,
        "reason": []
    }

    try:
        w = whois.whois(domain)

        creation_date = w.creation_date

        # Sometimes WHOIS returns a list
        if isinstance(creation_date, list):
            creation_date = creation_date[0]

        if creation_date:
            age_days = (datetime.utcnow() - creation_date).days
            result["domain_age_days"] = age_days

            if age_days < SUSPICIOUS_DOMAIN_AGE_DAYS:
                result["is_new_domain"] = True
                result["risk_score"] += 40
                result["reason"].append(
                    f"Domain registered {age_days} days ago (very new)"
                )
        else:
            result["whois_available"] = False
            result["risk_score"] += 20
            result["reason"].append("WHOIS creation date not available")

    except Exception:
        result["whois_available"] = False
        result["risk_score"] += 30
        result["reason"].append("WHOIS lookup failed")

    return result
