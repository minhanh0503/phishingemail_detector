import re
from backend.utils.constants import SUSPICIOUS_TLDS

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

    # 1️⃣ IP-based URL
    if is_ip_address(domain):
        result["risk_score"] += 50
        result["flags"].append("IP-based URL")

    # 2️⃣ URL shortener
    if domain in URL_SHORTENERS:
        result["risk_score"] += 30
        result["flags"].append("URL shortener")

    # 3️⃣ Suspicious TLD
    tld = domain.split(".")[-1]
    if tld in SUSPICIOUS_TLDS:
        result["risk_score"] += 20
        result["flags"].append(f"Suspicious TLD .{tld}")

    # 4️⃣ Sender vs URL mismatch
    if sender_domain and sender_domain not in domain:
        result["risk_score"] += 15
        result["flags"].append("URL domain does not match sender domain")

    return result
