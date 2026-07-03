def rule_sender(sender_email: str):
    score = 0
    reasons = []

    domain = sender_email.split("@")[-1].lower()

    free_providers = ["gmail.com", "yahoo.com", "outlook.com", "hotmail.com"]

    if domain in free_providers:
        score += 10
        reasons.append("Free email provider used")

    return score, reasons

def rule_urls(urls: list[str]):
    score = 0
    reasons = []

    shorteners = ["bit.ly", "tinyurl.com", "t.co", "goo.gl"]

    for url in urls:
        lower = url.lower()

        if "http://" in lower:
            score += 10
            reasons.append(f"Non-HTTPS link detected: {url}")

        if any(s in lower for s in shorteners):
            score += 15
            reasons.append(f"URL shortener used: {url}")

        if any(char.isdigit() for char in lower.split("/")[2]):
            score += 20
            reasons.append(f"IP-based or numeric domain detected: {url}")

    return score, reasons

def rule_keywords(email_body: str):
    score = 0
    reasons = []

    keywords = {
        "urgent": 10,
        "verify": 10,
        "password": 15,
        "login": 10,
        "bank": 15,
        "suspended": 20,
        "click here": 15,
        "immediately": 10
    }

    text = email_body.lower()

    for word, weight in keywords.items():
        if word in text:
            score += weight
            reasons.append(f"Suspicious keyword detected: '{word}'")

    return score, reasons

def rule_domain_mismatch(sender_domain: str, urls: list[str]):
    score = 0
    reasons = []

    if not sender_domain:
        return 0, ["Sender domain missing"]

    for url in urls:
        try:
            domain = url.split("/")[2].lower()
        except Exception:
            continue

        if sender_domain not in domain:
            score += 20
            reasons.append(f"Sender domain mismatch with URL: {url}")

    return score, reasons

def rule_domain_age(whois_result: dict):
    score = 0
    reasons = []

    age_days = whois_result.get("age_days", 9999)

    if age_days < 30:
        score += 25
        reasons.append("Very new domain (<30 days)")

    elif age_days < 180:
        score += 10
        reasons.append("Recently registered domain")

    return score, reasons

def run_rule_engine(sender_email, email_body, urls, sender_domain, whois_results):
    total_score = 0
    reasons = []

    s_score, s_reasons = rule_sender(sender_email)
    total_score += s_score
    reasons += s_reasons

    u_score, u_reasons = rule_urls(urls)
    total_score += u_score
    reasons += u_reasons

    k_score, k_reasons = rule_keywords(email_body)
    total_score += k_score
    reasons += k_reasons

    m_score, m_reasons = rule_domain_mismatch(sender_domain, urls)
    total_score += m_score
    reasons += m_reasons

    for w in whois_results:
        w_score, w_reasons = rule_domain_age(w)
        total_score += w_score
        reasons += w_reasons

    return {
        "score": total_score,
        "reasons": reasons
    }