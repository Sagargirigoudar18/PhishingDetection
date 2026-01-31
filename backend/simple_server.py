from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from datetime import datetime
import uvicorn

app = FastAPI(title="PhishShield API", version="1.0.0")

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000", "http://127.0.0.1:3000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.get("/")
async def root():
    return {"message": "Phishing Detection API is running"}

@app.get("/health")
async def health_check():
    """Health check endpoint for frontend"""
    return {
        "status": "healthy",
        "timestamp": datetime.utcnow().isoformat(),
        "version": "1.0.0"
    }

@app.post("/api/detect/analyze")
async def analyze_content(request: dict):
    """Simple analysis endpoint"""
    content = request.get("content", "")
    content_type = request.get("content_type", "text")
    
    # Simple rule-based detection
    suspicious_keywords = ["urgent", "verify", "account", "suspended", "click", "password", "security"]
    is_phishing = any(keyword in content.lower() for keyword in suspicious_keywords)
    confidence = 0.8 if is_phishing else 0.2
    
    return {
        "is_phishing": is_phishing,
        "confidence": confidence,
        "risk_level": "HIGH" if confidence > 0.6 else "LOW",
        "explanation": "This message contains suspicious keywords" if is_phishing else "This message appears safe",
        "recommendations": ["Do not click links", "Verify sender"] if is_phishing else ["Message appears safe"],
        "timestamp": datetime.utcnow().isoformat(),
        "content_type": content_type
    }

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8080, log_level="info")
