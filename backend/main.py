from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, EmailStr
from backend.analyzer.riskengine_analyzer import analyze_email_risk

app = FastAPI(title="Phishing Detection API")

# Root endpoint just to confirm API is running
@app.get("/")
def read_root():
    return {"message": "Phishing Email Detector API is running 🚀"}

# Data model for request
class EmailAnalysisRequest(BaseModel):
    sender_email: EmailStr
    email_body: str

# Endpoint
@app.post("/analyze/email")
def analyze_email(request: EmailAnalysisRequest):
    try:
        result = analyze_email_risk(
            sender_email=request.sender_email,
            email_body=request.email_body
        )
        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
