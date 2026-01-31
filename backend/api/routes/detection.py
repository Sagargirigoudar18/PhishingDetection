from fastapi import APIRouter, HTTPException, status
from pydantic import BaseModel
from typing import List, Optional
from datetime import datetime
import logging
from ml.classifier_simple import PhishingClassifier
from features.url_analyzer_simple import URLAnalyzer
from genai.explainer_simple import PhishingExplainer

router = APIRouter()
logger = logging.getLogger(__name__)

class DetectionRequest(BaseModel):
    content: str
    content_type: str  # 'email', 'sms', 'whatsapp', 'url'
    metadata: Optional[dict] = None

class DetectionResult(BaseModel):
    is_phishing: bool
    confidence: float
    risk_level: str  # 'LOW', 'MEDIUM', 'HIGH'
    explanation: str
    recommendations: List[str]
    timestamp: str
    content_type: str

# Initialize components
classifier = PhishingClassifier()
url_analyzer = URLAnalyzer()
explainer = PhishingExplainer()

def analyze_text(text: str) -> dict:
    """Analyze text content for phishing indicators"""
    try:
        # Use the ML classifier
        is_phishing, confidence = classifier.predict(text)
        
        # Get explanation from GenAI
        explanation = explainer.generate_explanation(text)
        
        # Determine risk level
        if confidence >= 0.8:
            risk_level = "HIGH"
        elif confidence >= 0.5:
            risk_level = "MEDIUM"
        else:
            risk_level = "LOW"
            
        return {
            "is_phishing": is_phishing,
            "confidence": float(confidence),
            "risk_level": risk_level,
            "explanation": explanation,
            "recommendations": explainer.get_recommendations(risk_level.lower())
        }
    except Exception as e:
        logger.error(f"Error analyzing text: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to analyze content"
        )

def analyze_url(url: str) -> dict:
    """Analyze URL for phishing indicators"""
    try:
        # Get URL analysis
        url_analysis = url_analyzer.analyze_url(url)
        
        # Get text-based analysis of the URL
        text_analysis = analyze_text(url)
        
        # Combine results
        combined_confidence = (url_analysis['risk_score'] + text_analysis['confidence']) / 2
        
        if combined_confidence >= 0.7:
            risk_level = "HIGH"
        elif combined_confidence >= 0.4:
            risk_level = "MEDIUM"
        else:
            risk_level = "LOW"
            
        return {
            "is_phishing": combined_confidence >= 0.5,
            "confidence": float(combined_confidence),
            "risk_level": risk_level,
            "explanation": f"URL Analysis: {url_analysis.get('explanation', '')} {text_analysis['explanation']}",
            "recommendations": explainer.get_recommendations(risk_level.lower())
        }
    except Exception as e:
        logger.error(f"Error analyzing URL: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to analyze URL"
        )

@router.post("/analyze", response_model=DetectionResult)
async def analyze_content(request: DetectionRequest):
    """
    Analyze content for potential phishing attempts
    """
    try:
        content = request.content.strip()
        if not content:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Content cannot be empty"
            )
            
        # Route to appropriate analyzer
        if request.content_type == 'url':
            result = analyze_url(content)
        else:
            result = analyze_text(content)
            
        return {
            **result,
            "timestamp": datetime.utcnow().isoformat(),
            "content_type": request.content_type
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Unexpected error: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An unexpected error occurred"
        )
