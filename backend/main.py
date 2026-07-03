from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, EmailStr
from analyzer.riskengine_analyzer import analyze_email_risk
from analyzer.ml_predictor import predict_email

app = FastAPI(title="Phishing Detection API")

# Root endpoint just to confirm API is running
@app.get("/")
def read_root():
    return {"message": "Phishing Email Detector API is running"}

# Data model for request
class EmailAnalysisRequest(BaseModel):
    sender_email: EmailStr
    email_body: str
    mode: str = "Full Hybrid Analysis"

# Endpoint
@app.post("/analyze/email")
def analyze_email(request: EmailAnalysisRequest):
    try:


        if request.mode == "Quick ML":
            ml_result = predict_email(request.email_body)

            ml_score = int(ml_result["confidence"] * 100) if ml_result["prediction"] == "PHISHING" else 0

            return {
                "sender_email": request.sender_email,
                "sender_analysis": {},
                "url_analyses": [],
                "whois_analyses": [],
                "ml_prediction": ml_result,

                "rule_engine": {
                    "score": 0,
                    "reasons": []
                },

                "scoring": {
                    "final_score": ml_score,
                    "ml_score": ml_score,
                    "rule_score": 0
                },

                "total_risk_score": ml_score,

                "verdict": (
                    "HIGH" if ml_score >= 80 else
                    "MEDIUM" if ml_score >= 40 else
                    "LOW"
                ),

                "explanation": {
                    "summary": ["Quick ML analysis only"],
                    "ml": ml_result,
                    "rules": {
                        "score": 0,
                        "reasons": []
                    },
                    "signals": {
                        "has_links": False,
                        "sender_domain": None
                    }
                }
            }
        # FULL PIPELINE
        result = analyze_email_risk(
            sender_email=request.sender_email,
            email_body=request.email_body
        )

        return result

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))