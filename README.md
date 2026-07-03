# Phishing Email Detection System (Hybrid AI)

An end-to-end AI-powered security application that detects phishing attempts using machine learning and a rule-based heuristics engine. 

The system features a **FastAPI** backend and an interactive **Streamlit** dashboard, offering two analysis modes:
* **Quick ML Mode:** Fast prediction using a trained Logistic Regression model.
* **Full Hybrid Mode:** Comprehensive scoring using ML, rule engines, URL extraction, and live WHOIS domain analysis.

---

## System Architecture
Streamlit Frontend ──> FastAPI Backend ──> [ ML + Rule Engine + URL + WHOIS ]

---

## Features

### Detection Capabilities
* **Security Rules Engine:** Flags suspicious keywords, URL shorteners, IP-based URLs, domain mismatches, free email providers, and newly registered domains.
* **URL & WHOIS Analysis:** Extracts domains to check live registry age and active risk signals.
* **Explainable AI Output:** Provides a breakdown of the final weighted risk score.

### Tech Stack
* **Backend:** Python, FastAPI, Docker, `python-whois`, `scikit-learn`
* **Frontend:** Streamlit

---

## Installation & Setup

### 1. Clone the Repository
```bash
git clone [https://github.com/minhanh0503/phishingemail_detector.git](https://github.com/minhanh0503/phishingemail_detector.git)
cd phishingemail_detector
```
### 2. Backend Setup (FastAPI)
```bash
cd backend
pip install -r requirements.txt
uvicorn main:app --reload
```
Runs at: http://localhost:8000
### 3. Frontend Setup (Streamlit)
```bash
cd frontend
pip install -r requirements.txt
streamlit run app.py
```
Runs at: http://localhost:8501

---
## Docker Deployment
```bash
docker-compose up --build
```
## API Endpoints
Analyze Email

```bash
POST /analyze/email
```
Request Body:
JSON
```bash
{
  "sender_email": "test@example.com",
  "email_body": "Your account has been suspended...",
  "mode": "Quick ML" 
}
```
Response (Hybrid Mode):

JSON
```bash
{
  "verdict": "PHISHING",
  "total_risk_score": 87,
  "ml_prediction": {},
  "rule_engine": {},
  "url_analyses": [],
  "whois_analyses": []
}
```

---

## Model & Dataset
- Dataset: Phishing Email Dataset (Kaggle) (Not included in repo due to size)

- Model Pipeline: Text cleaning -> TF-IDF (unigrams + bigrams) -> Logistic Regression (lbfgs, max iterations: 1000).
---

## Evaluation Performance
- F1-Score: ~98%

- Confusion Matrix: 8,433 TP | 7,728 TN | 207 FP | 130 FN
---
## Links & Author
- Live Demo: [Streamlit App [Phising Detector](https://phishingemaildetectionsystem.streamlit.app/
)

- Developer: Minh Anh
---
## Disclaimer: This project is for educational and research purposes only. It is not intended to replace enterprise production security systems.

