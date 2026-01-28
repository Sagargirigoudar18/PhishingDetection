import re
import os
from typing import Tuple, Dict, Any
import logging

logger = logging.getLogger(__name__)

class PhishingClassifier:
    def __init__(self):
        self.model_path = "models/phishing_classifier.pkl"
        os.makedirs(os.path.dirname(self.model_path), exist_ok=True)
        
        # Simple phishing keywords and patterns
        self.suspicious_keywords = [
            'urgent', 'verify', 'account', 'suspended', 'click', 'link', 'password',
            'security', 'update', 'confirm', 'immediate', 'action', 'required',
            'bank', 'paypal', 'amazon', 'netflix', 'winner', 'prize', 'congratulations',
            'limited', 'offer', 'expire', 'risk', 'unauthorized', 'blocked'
        ]
        
        self.suspicious_patterns = [
            r'http[s]?://\S+',  # URLs
            r'\b\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}\b',  # Credit card numbers
            r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',  # Email addresses
            r'\+?\d{1,3}[-.\s]?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}',  # Phone numbers
        ]
        
        # Urgency indicators
        self.urgency_words = [
            'immediately', 'urgent', 'hurry', 'limited time', 'act now', 'don\'t delay',
            'expires', 'today only', 'last chance', 'warning', 'alert'
        ]

    def predict(self, text: str) -> Tuple[bool, float]:
        """
        Simple rule-based phishing detection
        Returns: (is_phishing, confidence_score)
        """
        try:
            text_lower = text.lower()
            
            # Count suspicious keywords
            keyword_count = sum(1 for word in self.suspicious_keywords if word in text_lower)
            
            # Count suspicious patterns
            pattern_count = 0
            for pattern in self.suspicious_patterns:
                if re.search(pattern, text):
                    pattern_count += 1
            
            # Count urgency words
            urgency_count = sum(1 for word in self.urgency_words if word in text_lower)
            
            # Check for all caps (often used in phishing)
            all_caps_ratio = sum(1 for c in text if c.isupper()) / len(text) if text else 0
            
            # Check for excessive exclamation marks
            exclamation_count = text.count('!')
            
            # Calculate risk score
            risk_score = 0
            
            # Keyword risk (0-0.4)
            risk_score += min(keyword_count * 0.1, 0.4)
            
            # Pattern risk (0-0.3)
            risk_score += min(pattern_count * 0.1, 0.3)
            
            # Urgency risk (0-0.2)
            risk_score += min(urgency_count * 0.05, 0.2)
            
            # Formatting risks (0-0.1)
            if all_caps_ratio > 0.3:
                risk_score += 0.05
            if exclamation_count > 2:
                risk_score += 0.05
            
            # Normalize to 0-1
            confidence = min(risk_score, 1.0)
            
            # Determine if it's phishing (threshold at 0.5)
            is_phishing = confidence >= 0.5
            
            return is_phishing, float(confidence)
            
        except Exception as e:
            logger.error(f"Error in prediction: {str(e)}")
            return False, 0.0

    def train(self, X, y):
        """
        Placeholder for training - not implemented for simple rule-based classifier
        """
        logger.info("Simple rule-based classifier doesn't require training")
        return {"accuracy": 0.7}  # Placeholder accuracy

    def save_model(self):
        """Save model state (not needed for rule-based)"""
        logger.info("Rule-based classifier doesn't need to save model")

    def load_model(self):
        """Load model state (not needed for rule-based)"""
        logger.info("Rule-based classifier doesn't need to load model")
