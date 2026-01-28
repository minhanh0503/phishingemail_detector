from backend.utils.constants import (
    FREE_EMAIL_PROVIDERS,
    LEGITIMATE_BRANDS,
    SUSPICIOUS_KEYWORDS,
    SUSPICIOUS_TLDS
)
from backend.utils.string_utils import (
    extract_domain,
    extract_local_part,
    extract_tld,
    levenshtein
)

def analyze_sender_email(email: str, display_name: str = ""):
    risk_score = 0.0
    signals = []

    domain = extract_domain(email)
    local_part = extract_local_part(email)
    tld = extract_tld(domain)

    # 1️⃣ Free email impersonation
    if domain in FREE_EMAIL_PROVIDERS and display_name:
        signals.append("Free email provider used for impersonation")
        risk_score += 0.3

    # 2️⃣ Suspicious local-part keywords
    for word in SUSPICIOUS_KEYWORDS:
        if word in local_part:
            signals.append(f"Suspicious keyword in sender address: '{word}'")
            risk_score += 0.1
            break

    # 3️⃣ Suspicious TLD
    if tld in SUSPICIOUS_TLDS:
        signals.append(f"Suspicious top-level domain: .{tld}")
        risk_score += 0.2

    # 4️⃣ Look-alike domain detection
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
