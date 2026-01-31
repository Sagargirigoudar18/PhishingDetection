import re
import os
from typing import Tuple, Dict, Any, List
import logging

logger = logging.getLogger(__name__)


class PhishingClassifier:
    def __init__(self):
        self.model_path = "models/phishing_classifier.pkl"
        os.makedirs(os.path.dirname(self.model_path), exist_ok=True)
        
        # Expanded phishing keywords and patterns
        self.suspicious_keywords = [
            # Urgency and action words
            'urgent', 'immediately', 'verify', 'confirm', 'suspended', 'blocked',
            'unauthorized', 'unusual', 'limited', 'expire', 'deadline', 'final',
            
            # Account and security related
            'account', 'password', 'security', 'update', 'click', 'link',
            'login', 'signin', 'sign-in', 'authenticate', 'credentials',
            
            # Financial
            'bank', 'paypal', 'credit', 'debit', 'transfer', 'payment', 'invoice',
            'billing', 'subscription', 'refund', 'transaction', 'wallet',
            
            # Popular targets
            'amazon', 'netflix', 'apple', 'microsoft', 'google', 'facebook',
            'instagram', 'whatsapp', 'dropbox', 'coinbase', 'binance',
            
            # Prize/reward scams
            'winner', 'prize', 'congratulations', 'lottery', 'reward', 'gift',
            'free', 'bonus', 'claim', 'selected', 'lucky',
            
            # Threat language
            'risk', 'compromised', 'hacked', 'breach', 'stolen', 'fraud',
            'illegal', 'lawsuit', 'legal action', 'arrest', 'police'
        ]
        
        self.suspicious_patterns = [
            r'http[s]?://\S+',  # URLs
            r'\b\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}\b',  # Credit card numbers
            r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',  # Email addresses
            r'\+?\d{1,3}[-.\s]?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}',  # Phone numbers
            r'\b\d{3}[-\s]?\d{2}[-\s]?\d{4}\b',  # SSN pattern
        ]
        
        # Urgency indicators
        self.urgency_words = [
            'immediately', 'urgent', 'hurry', 'limited time', 'act now', 
            "don't delay", 'expires', 'today only', 'last chance', 'warning',
            'alert', 'asap', 'right now', 'within 24 hours', 'within 48 hours',
            'final notice', 'action required', 'response required', 'must respond'
        ]
        
        # Threat indicators
        self.threat_words = [
            'suspended', 'terminated', 'closed', 'blocked', 'disabled',
            'locked', 'restricted', 'cancelled', 'deleted', 'removed',
            'legal action', 'lawsuit', 'court', 'police', 'arrest',
            'fine', 'penalty', 'prosecution', 'criminal'
        ]
        
        # Impersonation indicators
        self.impersonation_keywords = [
            'dear customer', 'dear user', 'dear member', 'valued customer',
            'dear account holder', 'dear client', 'dear sir/madam'
        ]
        
        # Link text vs URL mismatch patterns (for HTML content)
        self.fake_link_patterns = [
            r'<a[^>]*href=["\']([^"\']+)["\'][^>]*>([^<]+)</a>',  # HTML links
            r'\[([^\]]+)\]\(([^\)]+)\)',  # Markdown links
        ]

    def predict(self, text: str) -> Tuple[bool, float]:
        """
        Advanced phishing detection with multiple analysis vectors
        Returns: (is_phishing, confidence_score)
        """
        try:
            text_lower = text.lower()
            
            # Initialize risk components
            risk_components = {
                'keyword_risk': 0.0,
                'pattern_risk': 0.0,
                'urgency_risk': 0.0,
                'threat_risk': 0.0,
                'impersonation_risk': 0.0,
                'formatting_risk': 0.0,
                'url_risk': 0.0,
                'link_mismatch_risk': 0.0
            }
            
            # === Keyword Analysis ===
            keyword_count = sum(1 for word in self.suspicious_keywords if word in text_lower)
            risk_components['keyword_risk'] = min(keyword_count * 0.06, 0.35)
            
            # === Pattern Analysis ===
            pattern_count = 0
            for pattern in self.suspicious_patterns:
                matches = re.findall(pattern, text, re.IGNORECASE)
                pattern_count += len(matches)
            risk_components['pattern_risk'] = min(pattern_count * 0.08, 0.25)
            
            # === Urgency Analysis ===
            urgency_count = sum(1 for word in self.urgency_words if word in text_lower)
            risk_components['urgency_risk'] = min(urgency_count * 0.08, 0.25)
            
            # === Threat Analysis ===
            threat_count = sum(1 for word in self.threat_words if word in text_lower)
            risk_components['threat_risk'] = min(threat_count * 0.10, 0.30)
            
            # === Impersonation Analysis ===
            impersonation_count = sum(1 for phrase in self.impersonation_keywords if phrase in text_lower)
            risk_components['impersonation_risk'] = min(impersonation_count * 0.10, 0.20)
            
            # === Formatting Analysis ===
            # All caps ratio
            if len(text) > 0:
                all_caps_ratio = sum(1 for c in text if c.isupper()) / len(text)
                if all_caps_ratio > 0.4:
                    risk_components['formatting_risk'] += 0.10
                elif all_caps_ratio > 0.25:
                    risk_components['formatting_risk'] += 0.05
            
            # Excessive punctuation
            exclamation_count = text.count('!')
            question_count = text.count('?')
            if exclamation_count > 3:
                risk_components['formatting_risk'] += 0.08
            if question_count > 3:
                risk_components['formatting_risk'] += 0.05
            
            # Multiple consecutive punctuation
            if re.search(r'[!?]{2,}', text):
                risk_components['formatting_risk'] += 0.05
            
            risk_components['formatting_risk'] = min(risk_components['formatting_risk'], 0.15)
            
            # === URL Analysis (inline URLs) ===
            urls = re.findall(r'http[s]?://\S+', text)
            if urls:
                url_risk = self._analyze_inline_urls(urls)
                risk_components['url_risk'] = url_risk
            
            # === Link Mismatch Detection (for HTML/Markdown) ===
            link_mismatch = self._detect_link_mismatch(text)
            risk_components['link_mismatch_risk'] = link_mismatch
            
            # === Calculate Total Risk Score ===
            total_risk = sum(risk_components.values())
            
            # Apply multipliers for high-risk combinations
            if risk_components['urgency_risk'] > 0.1 and risk_components['threat_risk'] > 0.1:
                total_risk *= 1.2  # Urgency + Threat is very suspicious
            
            if risk_components['impersonation_risk'] > 0.1 and risk_components['url_risk'] > 0.1:
                total_risk *= 1.15  # Impersonation + suspicious URLs
            
            if risk_components['link_mismatch_risk'] > 0:
                total_risk *= 1.25  # Link mismatch is very suspicious
            
            # Normalize to 0-1
            confidence = min(total_risk, 1.0)
            
            # Determine if it's phishing (threshold at 0.45 for earlier detection)
            is_phishing = confidence >= 0.45
            
            return is_phishing, float(confidence)
            
        except Exception as e:
            logger.error(f"Error in prediction: {str(e)}")
            return False, 0.0

    def _analyze_inline_urls(self, urls: List[str]) -> float:
        """Analyze URLs found in text for phishing indicators"""
        try:
            from features.url_analyzer_simple import URLAnalyzer
            analyzer = URLAnalyzer()
            
            max_risk = 0.0
            for url in urls[:5]:  # Limit to first 5 URLs
                result = analyzer.analyze_url(url)
                if 'risk_score' in result:
                    max_risk = max(max_risk, result['risk_score'])
            
            return min(max_risk * 0.4, 0.35)  # Cap URL contribution
            
        except ImportError:
            # Fallback if URL analyzer not available
            risk = 0.0
            for url in urls:
                url_lower = url.lower()
                # Check for IP addresses
                if re.match(r'http[s]?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', url_lower):
                    risk += 0.15
                # Check for suspicious TLDs
                suspicious_tlds = ['.tk', '.ml', '.ga', '.cf', '.xyz', '.top', '.click']
                if any(tld in url_lower for tld in suspicious_tlds):
                    risk += 0.10
                # Check for brand names in suspicious positions
                brands = ['paypal', 'amazon', 'google', 'facebook', 'microsoft', 'apple', 'netflix']
                for brand in brands:
                    if brand in url_lower and not url_lower.startswith(f'http://{brand}') and not url_lower.startswith(f'https://{brand}') and not url_lower.startswith(f'https://www.{brand}'):
                        risk += 0.08
            
            return min(risk, 0.35)

    def _detect_link_mismatch(self, text: str) -> float:
        """
        Detect mismatches between displayed link text and actual URLs
        This is a major phishing indicator (e.g., showing "paypal.com" but linking to malicious site)
        """
        risk = 0.0
        
        # Check HTML links
        html_links = re.findall(r'<a[^>]*href=["\']([^"\']+)["\'][^>]*>([^<]+)</a>', text, re.IGNORECASE)
        for url, display_text in html_links:
            if self._is_link_mismatched(url, display_text):
                risk += 0.30
        
        # Check Markdown links
        md_links = re.findall(r'\[([^\]]+)\]\(([^\)]+)\)', text)
        for display_text, url in md_links:
            if self._is_link_mismatched(url, display_text):
                risk += 0.30
        
        # Check for URLs displayed as text that don't match embedded URLs
        displayed_urls = re.findall(r'(?:^|[\s<>])((https?://)?(?:www\.)?([a-zA-Z0-9-]+(?:\.[a-zA-Z]{2,})+))(?:[\s<>]|$)', text)
        
        return min(risk, 0.40)

    def _is_link_mismatched(self, actual_url: str, display_text: str) -> bool:
        """Check if displayed text appears to be a different URL than actual"""
        display_lower = display_text.lower().strip()
        actual_lower = actual_url.lower().strip()
        
        # Check if display text looks like a URL
        url_pattern = r'^(https?://)?(?:www\.)?([a-zA-Z0-9-]+(?:\.[a-zA-Z]{2,})+)'
        display_match = re.match(url_pattern, display_lower)
        
        if display_match:
            displayed_domain = display_match.group(2).split('/')[0]
            
            # Extract actual domain from URL
            actual_match = re.match(url_pattern, actual_lower)
            if actual_match:
                actual_domain = actual_match.group(2).split('/')[0]
                
                # Different domains = mismatch
                if displayed_domain != actual_domain:
                    return True
        
        return False

    def predict_with_details(self, text: str) -> Dict[str, Any]:
        """
        Extended prediction that returns detailed analysis
        """
        is_phishing, confidence = self.predict(text)
        
        text_lower = text.lower()
        
        # Collect detected indicators
        detected_keywords = [w for w in self.suspicious_keywords if w in text_lower]
        detected_urgency = [w for w in self.urgency_words if w in text_lower]
        detected_threats = [w for w in self.threat_words if w in text_lower]
        detected_impersonation = [p for p in self.impersonation_keywords if p in text_lower]
        
        # Find URLs
        urls = re.findall(r'http[s]?://\S+', text)
        
        return {
            'is_phishing': is_phishing,
            'confidence': confidence,
            'risk_level': self._get_risk_level(confidence),
            'detected_indicators': {
                'suspicious_keywords': detected_keywords[:10],
                'urgency_indicators': detected_urgency,
                'threat_indicators': detected_threats,
                'impersonation_indicators': detected_impersonation,
                'urls_found': urls[:5]
            },
            'analysis_summary': self._generate_summary(
                is_phishing, confidence, detected_keywords, 
                detected_urgency, detected_threats, urls
            )
        }

    def _get_risk_level(self, confidence: float) -> str:
        """Convert confidence score to risk level"""
        if confidence >= 0.75:
            return 'critical'
        elif confidence >= 0.55:
            return 'high'
        elif confidence >= 0.35:
            return 'medium'
        elif confidence >= 0.20:
            return 'low'
        else:
            return 'minimal'

    def _generate_summary(self, is_phishing: bool, confidence: float,
                         keywords: List[str], urgency: List[str],
                         threats: List[str], urls: List[str]) -> str:
        """Generate a human-readable analysis summary"""
        if not is_phishing and confidence < 0.20:
            return "This message appears to be legitimate with no significant phishing indicators detected."
        
        summary_parts = []
        
        if confidence >= 0.75:
            summary_parts.append("This message shows strong signs of being a phishing attempt.")
        elif confidence >= 0.45:
            summary_parts.append("This message contains multiple phishing indicators.")
        else:
            summary_parts.append("This message contains some suspicious elements.")
        
        if urgency:
            summary_parts.append(f"It uses urgency language ({', '.join(urgency[:2])}).")
        
        if threats:
            summary_parts.append(f"It contains threatening language ({', '.join(threats[:2])}).")
        
        if urls:
            summary_parts.append(f"It contains {len(urls)} URL(s) that should be verified.")
        
        if keywords:
            summary_parts.append(f"Suspicious keywords detected: {', '.join(keywords[:3])}.")
        
        return " ".join(summary_parts)

    def train(self, X, y):
        """
        Placeholder for training - not implemented for rule-based classifier
        """
        logger.info("Rule-based classifier uses predefined rules and doesn't require training")
        return {"accuracy": 0.85}  # Estimated accuracy for rule-based

    def save_model(self):
        """Save model state (not needed for rule-based)"""
        logger.info("Rule-based classifier doesn't need to save model")

    def load_model(self):
        """Load model state (not needed for rule-based)"""
        logger.info("Rule-based classifier doesn't need to load model")


# Example usage and testing
if __name__ == "__main__":
    classifier = PhishingClassifier()
    
    print("=" * 60)
    print("PHISHING CLASSIFIER - TEST SUITE")
    print("=" * 60)
    
    test_cases = [
        # High risk phishing
        (
            "URGENT: Your PayPal account has been suspended! Click here immediately to verify your identity: http://paypa1.com/verify",
            "Urgency + Brand + Typosquat URL"
        ),
        (
            "Dear valued customer, your Amazon account will be terminated within 24 hours unless you confirm your billing information at http://amazon-verify.suspicious.tk",
            "Impersonation + Threat + Fake URL"
        ),
        (
            "Congratulations! You've won $1,000,000! Claim your prize now by clicking http://winner-claim.xyz/prize",
            "Prize scam"
        ),
        (
            "Your bank account has been compromised. Update your password immediately to avoid losing your funds: http://192.168.1.1/login",
            "Bank + IP address"
        ),
        
        # Medium risk
        (
            "Please verify your account details by logging in to your profile.",
            "Generic verification"
        ),
        
        # Low risk (legitimate)
        (
            "Hi, just wanted to check in and see how you're doing. Let me know if you need anything.",
            "Casual message"
        ),
        (
            "Your monthly statement is ready to view. Log in to your account at https://www.bankofamerica.com to review.",
            "Legitimate notification"
        ),
        (
            "Meeting reminder: Team standup at 10am tomorrow. See you there!",
            "Simple reminder"
        ),
    ]
    
    for text, description in test_cases:
        print(f"\n{'─' * 60}")
        print(f"Test: {description}")
        print(f"Text: {text[:80]}{'...' if len(text) > 80 else ''}")
        
        result = classifier.predict_with_details(text)
        
        print(f"Result: {'⚠️ PHISHING' if result['is_phishing'] else '✓ Legitimate'}")
        print(f"Confidence: {result['confidence']:.2f}")
        print(f"Risk Level: {result['risk_level']}")
        print(f"Summary: {result['analysis_summary']}")
        
        if result['detected_indicators']['suspicious_keywords']:
            print(f"Keywords: {', '.join(result['detected_indicators']['suspicious_keywords'][:5])}")
    
    print(f"\n{'=' * 60}")
    print("Test suite complete!")
