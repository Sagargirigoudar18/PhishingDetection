from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import os
import re
import json
from datetime import datetime
from typing import Dict, Any, List, Optional

# Pydantic models for request/response
class DetectionRequest(BaseModel):
    content: str
    content_type: Optional[str] = "text"  # 'email', 'sms', 'whatsapp', 'url', 'text'

class DetectionResponse(BaseModel):
    is_phishing: bool
    confidence: float
    risk_level: str  # 'LOW', 'MEDIUM', 'HIGH'
    explanation: str
    recommendations: List[str]
    timestamp: str
    content_type: str

class HealthResponse(BaseModel):
    status: str
    timestamp: str

class RootResponse(BaseModel):
    message: str
    version: str

app = FastAPI(
    title="PhishShield API",
    description="Simple Phishing Detection API",
    version="1.0.0"
)

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

class SimplePhishingDetector:
    def __init__(self):
        self.suspicious_keywords = [
            'urgent', 'verify', 'account', 'suspended', 'click', 'link', 'password',
            'security', 'update', 'confirm', 'immediate', 'action', 'required',
            'bank', 'paypal', 'amazon', 'netflix', 'winner', 'prize', 'congratulations',
            'limited', 'offer', 'expire', 'risk', 'unauthorized', 'blocked'
        ]
        
        self.urgency_words = [
            'immediately', 'urgent', 'hurry', 'limited time', 'act now', 'don\'t delay',
            'expires', 'today only', 'last chance', 'warning', 'alert'
        ]

    def detect(self, text: str, content_type: str = "text") -> Dict[str, Any]:
        """Simple phishing detection"""
        text_lower = text.lower()
        
        # Count suspicious keywords
        keyword_count = sum(1 for word in self.suspicious_keywords if word in text_lower)
        
        # Count urgency words
        urgency_count = sum(1 for word in self.urgency_words if word in text_lower)
        
        # Check for URLs
        url_pattern = r'http[s]?://\S+'
        has_urls = bool(re.search(url_pattern, text))
        
        # Check for excessive exclamation marks
        exclamation_count = text.count('!')
        
        # Calculate risk score
        risk_score = 0
        risk_score += min(keyword_count * 0.1, 0.4)
        risk_score += min(urgency_count * 0.05, 0.2)
        if has_urls:
            risk_score += 0.2
        if exclamation_count > 2:
            risk_score += 0.1
        
        confidence = min(risk_score, 1.0)
        is_phishing = confidence >= 0.5
        
        # Determine risk level
        if confidence >= 0.7:
            risk_level = "HIGH"
        elif confidence >= 0.4:
            risk_level = "MEDIUM"
        else:
            risk_level = "LOW"
        
        # Generate explanation
        explanation = self.generate_explanation(text_lower, keyword_count, urgency_count, has_urls)
        
        # Get recommendations
        recommendations = self.get_recommendations(risk_level)
        
        return {
            "is_phishing": is_phishing,
            "confidence": confidence,
            "risk_level": risk_level,
            "explanation": explanation,
            "recommendations": recommendations,
            "timestamp": datetime.utcnow().isoformat(),
            "content_type": content_type
        }
    
    def generate_explanation(self, text: str, keyword_count: int, urgency_count: int, has_urls: bool) -> str:
        """Generate explanation for why something is suspicious"""
        reasons = []
        
        if urgency_count > 0:
            reasons.append("creates urgency to pressure quick action")
        if keyword_count > 2:
            reasons.append("contains multiple suspicious keywords")
        if has_urls:
            reasons.append("includes potentially dangerous links")
        if text.count('!!') > 1:
            reasons.append("uses excessive punctuation")
        
        if reasons:
            return "This message is suspicious because it " + ", ".join(reasons) + "."
        else:
            return "This message appears safe, but always remain cautious."
    
    def get_recommendations(self, risk_level: str) -> List[str]:
        """Get safety recommendations"""
        if risk_level == "HIGH":
            return [
                "Do not click any links or download attachments",
                "Do not provide personal or financial information",
                "Report this as phishing",
                "Delete the message"
            ]
        elif risk_level == "MEDIUM":
            return [
                "Be cautious with any links",
                "Verify the sender through official channels",
                "Look for signs of phishing"
            ]
        else:
            return [
                "Remain vigilant",
                "Verify unexpected messages"
            ]

# Initialize detector
detector = SimplePhishingDetector()

@app.get("/", response_model=RootResponse)
async def root():
    return {"message": "PhishShield API is running", "version": "1.0.0"}

@app.post("/api/detect/analyze", response_model=DetectionResponse)
async def analyze_content(request: DetectionRequest):
    """Analyze content for phishing"""
    try:
        content = request.content.strip()
        content_type = request.content_type or "text"
        
        if not content:
            raise HTTPException(status_code=400, detail="Content cannot be empty")
        
        result = detector.detect(content, content_type)
        return result
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Analysis failed: {str(e)}")

@app.get("/health", response_model=HealthResponse)
async def health_check():
    """Health check endpoint"""
    return {"status": "healthy", "timestamp": datetime.utcnow().isoformat()}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
