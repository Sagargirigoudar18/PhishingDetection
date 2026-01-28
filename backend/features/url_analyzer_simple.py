import re
from urllib.parse import urlparse
from typing import Dict, Any
import logging

logger = logging.getLogger(__name__)

class URLAnalyzer:
    def __init__(self):
        self.suspicious_keywords = [
            'secure', 'account', 'login', 'verify', 'banking', 'update', 'confirm',
            'ebay', 'paypal', 'amazon', 'netflix', 'credit', 'card', 'password',
            'suspended', 'blocked', 'urgent', 'immediate', 'action', 'required'
        ]
        
        self.suspicious_tlds = [
            '.tk', '.ml', '.ga', '.cf', '.info', '.biz', '.work', '.click',
            '.download', '.win', '.review', '.top', '.loan', '.trade'
        ]

    def analyze_url(self, url: str) -> Dict[str, Any]:
        """
        Analyze a URL for potential phishing indicators
        """
        try:
            if not url.startswith(('http://', 'https://')):
                url = 'http://' + url
                
            parsed = urlparse(url)
            domain = parsed.netloc.lower()
            path = parsed.path.lower()
            
            # Initialize result dictionary
            result = {
                'url': url,
                'domain': domain,
                'url_length': len(url),
                'has_https': parsed.scheme == 'https',
                'has_ip_address': self._has_ip_address(domain),
                'has_at_symbol': '@' in url,
                'has_redirect': '//' in url.replace(parsed.scheme + '://', ''),
                'has_hyphen': '-' in domain,
                'has_port': ':' in domain and not domain.endswith(':80') and not domain.endswith(':443'),
                'has_dot_in_path': '/.' in path,
                'has_underscore': '_' in domain,
                'has_double_slash': '//' in path,
                'has_equals_sign': '=' in path,
                'has_ampersand': '&' in url,
                'suspicious_keywords': self._check_keywords(url),
                'suspicious_tld': self._check_suspicious_tld(domain),
                'subdomain_count': domain.count('.') - 1,
                'risk_score': 0.0
            }
            
            # Calculate risk score (0-1)
            result['risk_score'] = self._calculate_risk_score(result)
            
            return result
            
        except Exception as e:
            logger.error(f"Error analyzing URL {url}: {str(e)}")
            return {'error': str(e), 'url': url}
    
    def _has_ip_address(self, domain: str) -> bool:
        """Check if domain is an IP address"""
        # Simple IP pattern check
        ip_pattern = r'^(\d{1,3}\.){3}\d{1,3}(:\d+)?$'
        return bool(re.match(ip_pattern, domain.split(':')[0]))
    
    def _check_keywords(self, url: str) -> list:
        """Check for suspicious keywords in URL"""
        return [kw for kw in self.suspicious_keywords if kw in url.lower()]
    
    def _check_suspicious_tld(self, domain: str) -> bool:
        """Check if domain has suspicious TLD"""
        return any(domain.endswith(tld) for tld in self.suspicious_tlds)
    
    def _calculate_risk_score(self, features: Dict[str, Any]) -> float:
        """
        Calculate a risk score based on URL features
        Returns a value between 0 (safe) and 1 (high risk)
        """
        score = 0.0
        
        # URL length (longer URLs are more suspicious)
        if features['url_length'] > 75:
            score += 0.15
        elif features['url_length'] > 50:
            score += 0.05
        
        # HTTPS (secure is good)
        if not features['has_https']:
            score += 0.1
            
        # IP address in URL
        if features['has_ip_address']:
            score += 0.3
            
        # Suspicious characters
        if features['has_at_symbol'] or features['has_redirect']:
            score += 0.2
            
        # Suspicious domain characteristics
        if features['has_hyphen'] or features['has_underscore']:
            score += 0.1
            
        # Suspicious path
        if features['has_dot_in_path'] or features['has_double_slash']:
            score += 0.1
            
        # Suspicious keywords
        if features['suspicious_keywords']:
            score += min(0.25, len(features['suspicious_keywords']) * 0.05)
            
        # Suspicious TLD
        if features['suspicious_tld']:
            score += 0.15
            
        # Multiple subdomains
        if features['subdomain_count'] > 2:
            score += 0.1
            
        # Port in URL
        if features['has_port']:
            score += 0.1
            
        # Cap the score at 1.0
        return min(1.0, score)

# Example usage
if __name__ == "__main__":
    analyzer = URLAnalyzer()
    test_urls = [
        "https://www.paypal.com/account/verify",
        "http://secure-login-bank.com/login.php",
        "https://www.google.com/search?q=test",
        "http://192.168.1.1/login"
    ]
    
    for url in test_urls:
        result = analyzer.analyze_url(url)
        print(f"\nAnalysis for: {url}")
        print(f"Risk Score: {result['risk_score']:.2f}")
        if 'suspicious_keywords' in result and result['suspicious_keywords']:
            print(f"Suspicious Keywords: {', '.join(result['suspicious_keywords'])}")
        if result['has_ip_address']:
            print("⚠️ Contains IP address")
