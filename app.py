import streamlit as st
import pickle
import os

def get_top_phishing_terms(text, model, vectorizer, top_n=5):
    feature_names = vectorizer.get_feature_names_out()
    tfidf_vector = vectorizer.transform([text])
    coef = model.coef_[0]

    # Contribution = TF-IDF value × model weight
    contributions = tfidf_vector.toarray()[0] * coef

    top_indices = contributions.argsort()[::-1][:top_n]

    results = []
    for idx in top_indices:
        if contributions[idx] > 0:
            results.append((feature_names[idx], contributions[idx]))

    return results

# ---------- Safe path handling ----------
BASE_DIR = os.path.dirname(os.path.abspath(__file__))

model_path = os.path.join(BASE_DIR, "model", "phishingmodel.pkl")
vectorizer_path = os.path.join(BASE_DIR, "model", "tfidf_vectorizer.pkl")

# ---------- Load model ----------
with open(model_path, "rb") as f:
    model = pickle.load(f)

with open(vectorizer_path, "rb") as f:
    vectorizer = pickle.load(f)

# ---------- App UI ----------
st.set_page_config(page_title="Phishing Email Detector", page_icon="🚨")

st.title("🚨 Phishing Email Detection")
st.write("Paste an email below to check whether it is **phishing** or **legitimate**.")

# Initialize session state
if "email_text" not in st.session_state:
    st.session_state.email_text = ""

# Sample button
if st.button("Use Sample Phishing Email"):
    st.session_state.email_text = (
        "Your account has been suspended. "
        "Click here to verify immediately!"
    )

email_text = st.text_area(
    "📧 Email Content",
    value=st.session_state.email_text,
    height=200
)

if st.button("Analyze Email"):
    if email_text.strip() == "":
        st.warning("Please enter an email.")
    else:
        transformed_text = vectorizer.transform([email_text])
        prediction = model.predict(transformed_text)[0]
        probability = model.predict_proba(transformed_text)[0]

        if prediction == 1:
            st.error("🚨 **Phishing Email Detected**")
            st.write(f"Confidence: **{probability[1] * 100:.2f}%**")
            # Explain phishing keywords
            top_terms = get_top_phishing_terms(email_text, model, vectorizer)

            if top_terms:
                st.subheader("Why was this email flagged?")
                for word, score in top_terms:
                    st.write(f"• **{word}** (impact: {score:.3f})")

        else:
            st.success("✅ **Legitimate Email**")
            st.write(f"Confidence: **{probability[0] * 100:.2f}%**")

st.caption("Model: Logistic Regression + TF-IDF (unigrams & bigrams) by Minh Anh Nguyen")
st.caption(
    "⚠️ This tool is for educational purposes and should not be the sole method for email security decisions."
)
st.sidebar.header("📌 Model Info")
st.sidebar.write("Algorithm: Logistic Regression")
st.sidebar.write("Features: TF-IDF (unigrams + bigrams)")
st.sidebar.write("F1-Score: ~98%")

