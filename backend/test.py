from analyzer.riskengine_analyzer import analyze_email_risk
from pprint import pprint


def test_phishing_email():
    email_body = """
    Dear user,

    Your PayPal account has been limited.
    Verify immediately:
    https://secure-paypal-login-verify.xyz/auth
    http://192.168.1.1/login
    bit.ly/3fake

    Failure to act will result in suspension.
    """

    sender_email = "security@paypa1-support.com"

    result = analyze_email_risk(sender_email, email_body)

    # -----------------------------
    # PRINT RESULT
    # -----------------------------
    pprint(result)

    # -----------------------------
    # BASIC STRUCTURE TESTS
    # -----------------------------
    assert "total_risk_score" in result
    assert "ml_prediction" in result
    assert "rule_engine" in result
    assert "scoring" in result
    assert "explanation" in result

    # -----------------------------
    # SCORE VALIDATION
    # -----------------------------
    score = result["total_risk_score"]
    assert 0 <= score <= 100, f"Invalid score: {score}"

    # -----------------------------
    # ML VALIDATION
    # -----------------------------
    ml = result["ml_prediction"]
    assert "prediction" in ml
    assert "confidence" in ml
    assert 0.0 <= ml["confidence"] <= 1.0

    # -----------------------------
    # RULE ENGINE VALIDATION
    # -----------------------------
    rules = result["rule_engine"]
    assert "score" in rules
    assert "reasons" in rules
    assert isinstance(rules["reasons"], list)

    # -----------------------------
    # URL VALIDATION
    # -----------------------------
    assert len(result["url_analyses"]) > 0, "No URLs detected"

    print("\nALL TESTS PASSED")


if __name__ == "__main__":
    test_phishing_email()