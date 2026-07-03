import os
import streamlit as st
import requests

API_URL = "https://phishingemail-detector.onrender.com/analyze/email"

st.set_page_config(page_title="Phishing Detector", page_icon="🚨")

st.title("Phishing Email Detection (Hybrid AI System)")
st.write("ML + Rule Engine + URL + WHOIS Analysis")

# MODE
mode = st.radio("Mode", ["Quick ML", "Full Hybrid Analysis"])
st.write("DEBUG API_URL:", API_URL)
# STATE
if "email_text" not in st.session_state:
    st.session_state.email_text = ""

sender_email = st.text_input("Sender Email (optional)", value="test@example.com")

# SAMPLE BUTTON
if st.button("Use Sample Phishing Email"):
    st.session_state.email_text = (
        "Your account has been suspended. "
        "Click here to verify immediately!"
    )
    st.rerun()

# TEXT AREA
email_text = st.text_area(
    "Email Content",
    key="email_text",
    height=200
)

# ANALYZE
if st.button("Analyze Email"):

    if not email_text.strip():
        st.warning("Please enter an email.")
        st.stop()

    payload = {
        "email_body": email_text,
        "mode": mode
    }

    if sender_email.strip():
        payload["sender_email"] = sender_email

    try:
        response = requests.post(API_URL, json=payload)
        if response.status_code != 200:
            st.error(f"Backend error: {response.text}")
            st.stop()

        data = response.json()

    except Exception as e:
        st.error(f"Connection error: {e}")
        st.stop()

    # SAFE ACCESS (NORMALIZED)
    ml = data.get("ml_prediction") or {}
    rule_engine = data.get("rule_engine") or {}
    explanation = data.get("explanation") or {}

    score = data.get("total_risk_score", 0)
    rule_score = rule_engine.get("score", 0)
    ml_conf = ml.get("confidence", 0)

    # RESULT
    st.subheader("Result")

    st.write("### Verdict:", data.get("verdict", "N/A"))
    st.write("### Risk Score:", score)

    # ML
    st.write("## ML Prediction")
    st.json(ml)

    if ml_conf:
        st.progress(min(float(ml_conf), 1.0))

    # RULE ENGINE
    st.write("## Rule Engine Reasons")
    reasons = rule_engine.get("reasons", [])

    if reasons:
        for r in reasons:
            st.warning(r)
    else:
        st.info("No rule-based flags detected")

    # URLS
    st.write("## URLs Found")
    urls = data.get("url_analyses", [])

    if urls:
        for u in urls:
            st.write("•", u.get("url"))
    else:
        st.info("No URLs found in email")

    # SUMMARY
    st.write("## Why this email was flagged")
    summary = explanation.get("summary", [])

    if summary:
        for item in summary:
            st.info(item)
    else:
        st.info("No explanation available")

    # RISK VISUAL
    st.write("## Risk Score")
    st.progress(min(score / 100, 1.0))

    # METRICS
    st.write("## Risk Breakdown")

    col1, col2, col3 = st.columns(3)

    with col1:
        st.metric("Final Risk Score", score)

    with col2:
        st.metric("ML Confidence", f"{ml_conf:.2f}")

    with col3:
        st.metric("Rule Score", rule_score)

    # SAFETY SIGNALS
    st.write("## Security Signals")

    rule_reasons = explanation.get("rules", {}).get("reasons", [])

    if rule_reasons:
        for reason in rule_reasons:
            st.write("•", reason)