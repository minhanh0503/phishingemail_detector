from utils.constants import (
    FREE_EMAIL_PROVIDERS,
    LEGITIMATE_BRANDS,
    SUSPICIOUS_KEYWORDS,
    SUSPICIOUS_TLDS
)
from analyzer.preprocessor import (
    extract_domain,
    extract_local_part,
    extract_tld,
)
from utils.string_utils import levenshtein
import re
from utils.constants import SUSPICIOUS_TLDS
import whois
from datetime import datetime

#email domain analyzer
def analyze_sender_email(email: str, display_name: str = ""):
    risk_score = 0.0
    signals = []

    domain = extract_domain(email)
    local_part = extract_local_part(email)
    tld = extract_tld(domain)

    # Free email impersonation
    if domain in FREE_EMAIL_PROVIDERS and display_name:
        signals.append("Free email provider used for impersonation")
        risk_score += 0.3

    # Suspicious local-part keywords
    for word in SUSPICIOUS_KEYWORDS:
        if word in local_part:
            signals.append(f"Suspicious keyword in sender address: '{word}'")
            risk_score += 0.1
            break

    # Suspicious TLD
    if tld in SUSPICIOUS_TLDS:
        signals.append(f"Suspicious top-level domain: .{tld}")
        risk_score += 0.2

    # Look-alike domain detection
    for legit in LEGITIMATE_BRANDS:
        distance = levenshtein(domain, legit)
        if 0 < distance <= 2:
            signals.append(
                f"Look-alike domain detected ({domain} → {legit})"
            )
            risk_score += 0.4
            break

    return {
        "risk_score": min(risk_score, 1.0),
        "signals": signals
    }

#URL analyzer
URL_SHORTENERS = {
    "bit.ly", "tinyurl.com", "goo.gl", "t.co", "ow.ly"
}


def is_ip_address(domain: str) -> bool:
    return bool(re.match(r"^\d{1,3}(\.\d{1,3}){3}$", domain))


def analyze_url_domain(domain: str, sender_domain: str | None = None) -> dict:
    result = {
        "domain": domain,
        "risk_score": 0,
        "flags": []
    }

    #  IP-based URL
    if is_ip_address(domain):
        result["risk_score"] += 50
        result["flags"].append("IP-based URL")

    # URL shortener
    if domain in URL_SHORTENERS:
        result["risk_score"] += 30
        result["flags"].append("URL shortener")

    # Suspicious TLD
    tld = domain.split(".")[-1]
    if tld in SUSPICIOUS_TLDS:
        result["risk_score"] += 20
        result["flags"].append(f"Suspicious TLD .{tld}")

    # Sender vs URL mismatch
    if sender_domain and sender_domain not in domain:
        result["risk_score"] += 15
        result["flags"].append("URL domain does not match sender domain")

    return result


# who is analyzer
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

