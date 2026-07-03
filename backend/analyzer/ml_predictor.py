from pathlib import Path
import joblib

BASE_DIR = Path(__file__).resolve().parent.parent
MODEL_DIR = BASE_DIR / "model"

model = joblib.load(MODEL_DIR / "phishingmodel.pkl")
vectorizer = joblib.load(MODEL_DIR / "tfidf_vectorizer.pkl")


def predict_email(email_body: str) -> dict:
    features = vectorizer.transform([email_body])

    prediction = model.predict(features)[0]
    probabilities = model.predict_proba(features)[0]

    return {
        "prediction": "PHISHING" if prediction == 1 else "LEGITIMATE",
        "confidence": float(max(probabilities)),
        "probabilities": {
            "legitimate": float(probabilities[0]),
            "phishing": float(probabilities[1])
        }
    }