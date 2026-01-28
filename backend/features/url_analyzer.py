import re
import tldextract
import whois
from datetime import datetime
from urllib.parse import urlparse
import socket
import requests
from typing import Dict, Any
import logging

class URLAnalyzer:
    def __init__(self):
        self.suspicious_keywords = [
            'secure', 'account', 'login', 'verify', 'banking', 'update', 'confirm',
            'ebay', 'paypal', 'amazon', 'netflix', 'credit', 'card', 'password'
        ]
        self.logger = logging.getLogger(__name__)

    def analyze_url(self, url: str) -> Dict[str, Any]:
        """
        Analyze a URL for potential phishing indicators
        
        Args:
            url: The URL to analyze
            
        Returns:
            Dict containing analysis results
        """
        if not url.startswith(('http://', 'https://')):
            url = 'http://' + url
            
        try:
            parsed = urlparse(url)
            domain = parsed.netloc
            path = parsed.path.lower()
            
            # Extract domain information
            domain_info = tldextract.extract(domain)
            base_domain = f"{domain_info.domain}.{domain_info.suffix}"
            
            # Initialize result dictionary
            result = {
                'url': url,
                'domain': base_domain,
                'url_length': len(url),
                'has_https': parsed.scheme == 'https',
                'has_ip_address': self._has_ip_address(domain),
                'has_at_symbol': '@' in url,
                'has_redirect': '//' in url.replace(parsed.scheme + '://', ''),
                'has_hyphen': '-' in domain,
                'has_port': ':' in domain,
                'has_dot_in_path': '/.' in path,
                'has_underscore': '_' in domain,
                'has_double_slash': '//' in path,
                'has_equals_sign': '=' in path,
                'has_ampersand': '&' in url,
                'suspicious_keywords': self._check_keywords(url),
                'domain_age_days': self._get_domain_age(base_domain),
                'risk_score': 0.0
            }
            
            # Calculate risk score (0-1)
            result['risk_score'] = self._calculate_risk_score(result)
            
            return result
            
        except Exception as e:
            self.logger.error(f"Error analyzing URL {url}: {str(e)}")
            return {'error': str(e), 'url': url}
    
    def _has_ip_address(self, domain: str) -> bool:
        """Check if domain is an IP address"""
        try:
            socket.inet_aton(domain.replace('www.', '').split(':')[0])
            return True
        except (socket.error, ValueError):
            return False
    
    def _check_keywords(self, url: str) -> list:
        """Check for suspicious keywords in URL"""
        return [kw for kw in self.suspicious_keywords if kw in url.lower()]
    
    def _get_domain_age(self, domain: str) -> int:
        """Get domain age in days"""
        try:
            domain_info = whois.whois(domain)
            if domain_info.creation_date:
                if isinstance(domain_info.creation_date, list):
                    creation_date = domain_info.creation_date[0]
                else:
                    creation_date = domain_info.creation_date
                age = (datetime.now() - creation_date).days
                return max(0, age)
        except Exception as e:
            self.logger.warning(f"Could not get domain age for {domain}: {str(e)}")
        return 0
    
    def _calculate_risk_score(self, features: Dict[str, Any]) -> float:
        """
        Calculate a risk score based on URL features
        Returns a value between 0 (safe) and 1 (high risk)
        """
        score = 0.0
        
        # URL length (longer URLs are more suspicious)
        if features['url_length'] > 75:
            score += 0.2
        
        # HTTPS (secure is good)
        if not features['has_https']:
            score += 0.15
            
        # IP address in URL
        if features['has_ip_address']:
            score += 0.25
            
        # Suspicious characters
        if features['has_at_symbol'] or features['has_redirect']:
            score += 0.2
            
        # Suspicious domain characteristics
        if features['has_hyphen'] or features['has_underscore']:
            score += 0.1
            
        # Suspicious path
        if features['has_dot_in_path'] or features['has_double_slash']:
            score += 0.15
            
        # Suspicious keywords
        if features['suspicious_keywords']:
            score += min(0.3, len(features['suspicious_keywords']) * 0.05)
            
        # New domains are more suspicious
        if features['domain_age_days'] < 30:  # Less than 30 days old
            score += 0.2
        elif features['domain_age_days'] < 90:  # Less than 90 days old
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
