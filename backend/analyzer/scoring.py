def normalize_rule_score(rule_score: int) -> float:
    """
    Convert rule score (0–100+) into probability (0–1)
    """
    return min(rule_score / 100, 1.0)


def compute_final_risk(rule_score: int, ml_confidence: float) -> dict:
    """
    Combine rule engine + ML model into final risk score
    """

    # normalize rule engine score
    rule_prob = normalize_rule_score(rule_score)

    # ML already gives probability (0–1)
    ml_prob = ml_confidence

    # weighted fusion
    final_prob = (0.65 * rule_prob) + (0.35 * ml_prob)

    final_score = int(final_prob * 100)

    return {
        "final_score": final_score,
        "rule_probability": rule_prob,
        "ml_probability": ml_prob,
        "combined_probability": final_prob
    }