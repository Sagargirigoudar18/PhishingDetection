import os
import json
import logging
from typing import Dict, List, Optional

logger = logging.getLogger(__name__)

class PhishingExplainer:
    def __init__(self):
        self.explanation_file = "data/phishing_explanations.json"
        os.makedirs(os.path.dirname(self.explanation_file), exist_ok=True)
        
        # Load or initialize explanations
        self.explanations = self._load_explanations()
        
        # Predefined explanations for common patterns
        self.predefined_explanations = {
            'urgent': 'This message creates a false sense of urgency to pressure you into acting quickly without thinking.',
            'verify': 'Legitimate companies rarely ask you to verify account information via email or text.',
            'click': 'Be cautious of messages asking you to click on suspicious links.',
            'password': 'Never share your password or personal information in response to unsolicited messages.',
            'account': 'Scammers often claim there are problems with your account to trick you into revealing information.',
            'suspended': 'Your account is unlikely to be suspended without prior notice from the official service.',
            'prize': 'Messages claiming you\'ve won a prize you didn\'t enter are almost always scams.',
            'bank': 'Banks will never ask for sensitive information via email or text messages.',
            'paypal': 'PayPal will never ask you to confirm financial information via email.',
            'amazon': 'Amazon will not ask for your password or payment information via email.',
            'security': 'Security alerts from legitimate companies will come through official channels, not random emails.'
        }

    def _load_explanations(self) -> List[Dict]:
        """Load existing explanations from file"""
        if os.path.exists(self.explanation_file):
            try:
                with open(self.explanation_file, 'r', encoding='utf-8') as f:
                    return json.load(f)
            except Exception as e:
                logger.error(f"Error loading explanations: {str(e)}")
        
        # Default explanations
        return [
            {
                "pattern": "urgent action required",
                "explanation": "Creates a false sense of urgency to pressure you into acting quickly without thinking.",
                "risk_level": "high"
            },
            {
                "pattern": "verify your account",
                "explanation": "Legitimate companies rarely ask you to verify account information via email or text.",
                "risk_level": "high"
            }
        ]

    def _save_explanations(self):
        """Save explanations to file"""
        try:
            with open(self.explanation_file, 'w', encoding='utf-8') as f:
                json.dump(self.explanations, f, indent=2)
        except Exception as e:
            logger.error(f"Error saving explanations: {str(e)}")

    def generate_explanation(self, text: str, risk_factors: Dict = None) -> str:
        """
        Generate a human-readable explanation for a potential phishing attempt
        """
        try:
            text_lower = text.lower()
            explanations = []
            
            # Check for predefined patterns
            for keyword, explanation in self.predefined_explanations.items():
                if keyword in text_lower:
                    explanations.append(explanation)
            
            # Check for URLs
            if 'http' in text_lower or 'www.' in text_lower:
                explanations.append("This message contains links that may lead to malicious websites designed to steal your information.")
            
            # Check for personal information requests
            personal_info_keywords = ['ssn', 'social security', 'credit card', 'card number', 'cvv', 'pin']
            if any(keyword in text_lower for keyword in personal_info_keywords):
                explanations.append("This message asks for sensitive personal or financial information, which legitimate companies never request via email.")
            
            # Check for threats
            threat_keywords = ['suspend', 'terminate', 'close', 'legal action', 'lawsuit']
            if any(keyword in text_lower for keyword in threat_keywords):
                explanations.append("This message uses threats to scare you into taking immediate action, a common phishing tactic.")
            
            # Check for poor grammar (simple check)
            if text.count('!!') > 1 or text.count('??') > 0:
                explanations.append("This message contains unusual punctuation, which is often a sign of unprofessional communication.")
            
            # If no specific patterns found, provide a general explanation
            if not explanations:
                explanations.append("This message shows characteristics commonly found in phishing attempts. Please be cautious and verify the source through official channels.")
            
            # Combine explanations (limit to 3 to avoid being too long)
            return ' '.join(explanations[:3])
            
        except Exception as e:
            logger.error(f"Error generating explanation: {str(e)}")
            return "This message contains characteristics commonly found in phishing attempts. Please verify the source before taking any action."

    def get_recommendations(self, risk_level: str, risk_factors: Dict = None) -> List[str]:
        """
        Get recommended actions based on risk level and factors
        """
        recommendations = {
            "high": [
                "Do not click on any links or download attachments",
                "Do not provide any personal or financial information",
                "Report this as phishing to your email provider or IT department",
                "Delete the message immediately",
                "If you're concerned about your account, contact the company directly using their official website or phone number"
            ],
            "medium": [
                "Be cautious with any links in the message",
                "Verify the sender's email address carefully",
                "Look for signs of phishing like poor grammar or unusual requests",
                "When in doubt, contact the supposed sender through official channels"
            ],
            "low": [
                "Remain vigilant for suspicious requests",
                "Always verify unexpected messages through official channels",
                "Keep your security software updated"
            ]
        }
        
        return recommendations.get(risk_level.lower(), recommendations["medium"])

    def add_explanation(self, pattern: str, explanation: str, risk_level: str = "medium"):
        """
        Add a new explanation pattern to the knowledge base
        """
        new_explanation = {
            "pattern": pattern.lower(),
            "explanation": explanation,
            "risk_level": risk_level.lower()
        }
        
        self.explanations.append(new_explanation)
        self._save_explanations()
        logger.info(f"Added new explanation for pattern: {pattern}")

# Example usage
if __name__ == "__main__":
    explainer = PhishingExplainer()
    
    # Test explanation generation
    test_text = "URGENT: Your account will be suspended! Click here to verify now!"
    explanation = explainer.generate_explanation(test_text)
    print(f"Explanation: {explanation}")
    
    # Get recommendations
    recommendations = explainer.get_recommendations("high")
    print("\nRecommendations:")
    for rec in recommendations:
        print(f"- {rec}")
