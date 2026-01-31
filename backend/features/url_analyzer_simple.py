import re
from urllib.parse import urlparse
from typing import Dict, Any, List, Tuple, Optional
import logging

logger = logging.getLogger(__name__)


# Popular domains frequently targeted by phishing attacks
POPULAR_DOMAINS = [
    'google.com', 'facebook.com', 'amazon.com', 'netflix.com', 'paypal.com',
    'apple.com', 'microsoft.com', 'github.com', 'linkedin.com', 'twitter.com',
    'instagram.com', 'dropbox.com', 'yahoo.com', 'gmail.com', 'outlook.com',
    'chase.com', 'bankofamerica.com', 'wellsfargo.com', 'citibank.com',
    'usbank.com', 'coinbase.com', 'binance.com', 'spotify.com', 'adobe.com',
    'zoom.us', 'slack.com', 'ebay.com', 'walmart.com', 'target.com',
    'bestbuy.com', 'uber.com', 'lyft.com', 'airbnb.com', 'booking.com',
    'whatsapp.com', 'telegram.org', 'discord.com', 'twitch.tv', 'reddit.com',
    'steam.com', 'steamcommunity.com', 'office.com', 'live.com', 'icloud.com',
    'docusign.com', 'dhl.com', 'fedex.com', 'ups.com', 'usps.com',
    'americanexpress.com', 'discover.com', 'capitalone.com', 'schwab.com',
    'fidelity.com', 'vanguard.com', 'robinhood.com', 'venmo.com', 'zelle.com'
]

# Brand names to detect in subdomain/path impersonation
BRAND_NAMES = [
    'google', 'facebook', 'amazon', 'netflix', 'paypal', 'apple', 'microsoft',
    'github', 'linkedin', 'twitter', 'instagram', 'dropbox', 'yahoo', 'gmail',
    'outlook', 'chase', 'bankofamerica', 'wellsfargo', 'citibank', 'coinbase',
    'binance', 'spotify', 'adobe', 'zoom', 'slack', 'ebay', 'walmart', 'uber',
    'airbnb', 'whatsapp', 'telegram', 'discord', 'twitch', 'reddit', 'steam',
    'office', 'icloud', 'docusign', 'dhl', 'fedex', 'ups', 'usps', 'amex',
    'capitalone', 'schwab', 'fidelity', 'vanguard', 'robinhood', 'venmo', 'zelle'
]

# Homograph/Confusable character mapping (visually similar characters)
CONFUSABLE_CHARS = {
    # Cyrillic lookalikes
    'а': 'a', 'е': 'e', 'о': 'o', 'р': 'p', 'с': 'c', 'у': 'y', 
    'х': 'x', 'і': 'i', 'ј': 'j', 'ѕ': 's', 'ԁ': 'd', 'ԛ': 'q',
    'ԝ': 'w', 'ɡ': 'g', 'ʀ': 'r', 'ɴ': 'n', 'ᴍ': 'm', 'ᴋ': 'k',
    'ᴠ': 'v', 'ᴢ': 'z', 'ь': 'b', 'ҝ': 'k', 'ɑ': 'a', 'ε': 'e',
    # Greek lookalikes
    'α': 'a', 'β': 'b', 'γ': 'y', 'ν': 'v', 'ο': 'o', 'ρ': 'p',
    'τ': 't', 'υ': 'u', 'χ': 'x', 'ω': 'w',
    # Number/symbol substitutions commonly used
    '0': 'o', '1': 'l', '!': 'i', '$': 's', '3': 'e', '4': 'a',
    '5': 's', '8': 'b', '@': 'a', '7': 't', '9': 'g', '2': 'z',
    # Other confusables
    'ı': 'i', 'ɩ': 'i', 'ł': 'l', 'ɫ': 'l', 'ʟ': 'l', 'ṃ': 'm',
    'ṇ': 'n', 'ṅ': 'n', 'ṛ': 'r', 'ṣ': 's', 'ṭ': 't', 'ṿ': 'v',
    'ẉ': 'w', 'ẏ': 'y', 'ẓ': 'z', 'ḃ': 'b', 'ḋ': 'd', 'ḟ': 'f',
    'ḣ': 'h', 'ṁ': 'm', 'ṗ': 'p', 'ṡ': 's', 'ṫ': 't', 'ẇ': 'w',
    'ẋ': 'x', 'ẏ': 'y',
}

# Common typosquatting patterns (keyboard adjacency)
KEYBOARD_ADJACENT = {
    'a': ['s', 'q', 'z', 'w'],
    'b': ['v', 'g', 'h', 'n'],
    'c': ['x', 'd', 'f', 'v'],
    'd': ['s', 'e', 'r', 'f', 'c', 'x'],
    'e': ['w', 's', 'd', 'r'],
    'f': ['d', 'r', 't', 'g', 'v', 'c'],
    'g': ['f', 't', 'y', 'h', 'b', 'v'],
    'h': ['g', 'y', 'u', 'j', 'n', 'b'],
    'i': ['u', 'j', 'k', 'o'],
    'j': ['h', 'u', 'i', 'k', 'm', 'n'],
    'k': ['j', 'i', 'o', 'l', 'm'],
    'l': ['k', 'o', 'p'],
    'm': ['n', 'j', 'k'],
    'n': ['b', 'h', 'j', 'm'],
    'o': ['i', 'k', 'l', 'p'],
    'p': ['o', 'l'],
    'q': ['w', 'a'],
    'r': ['e', 'd', 'f', 't'],
    's': ['a', 'w', 'e', 'd', 'z', 'x'],
    't': ['r', 'f', 'g', 'y'],
    'u': ['y', 'h', 'j', 'i'],
    'v': ['c', 'f', 'g', 'b'],
    'w': ['q', 'a', 's', 'e'],
    'x': ['z', 's', 'd', 'c'],
    'y': ['t', 'g', 'h', 'u'],
    'z': ['a', 's', 'x'],
}


class URLAnalyzer:
    def __init__(self):
        self.suspicious_keywords = [
            'secure', 'account', 'login', 'verify', 'banking', 'update', 'confirm',
            'ebay', 'paypal', 'amazon', 'netflix', 'credit', 'card', 'password',
            'suspended', 'blocked', 'urgent', 'immediate', 'action', 'required',
            'signin', 'sign-in', 'authenticate', 'wallet', 'recovery', 'unlock'
        ]
        
        self.suspicious_tlds = [
            '.tk', '.ml', '.ga', '.cf', '.info', '.biz', '.work', '.click',
            '.download', '.win', '.review', '.top', '.loan', '.trade', '.zip',
            '.mov', '.xyz', '.icu', '.buzz', '.site', '.online', '.live'
        ]
        
        self.popular_domains = POPULAR_DOMAINS
        self.brand_names = BRAND_NAMES

    def analyze_url(self, url: str) -> Dict[str, Any]:
        """
        Analyze a URL for potential phishing indicators including:
        - Typosquatting
        - Homograph attacks
        - Brand impersonation
        - Fake link patterns
        """
        try:
            if not url.startswith(('http://', 'https://')):
                url = 'http://' + url
                
            parsed = urlparse(url)
            domain = parsed.netloc.lower()
            path = parsed.path.lower()
            
            # Extract base domain (without subdomains)
            domain_parts = domain.split('.')
            if len(domain_parts) >= 2:
                base_domain = '.'.join(domain_parts[-2:])
            else:
                base_domain = domain
            
            # Initialize result dictionary with basic features
            result = {
                'url': url,
                'domain': domain,
                'base_domain': base_domain,
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
                'subdomain_count': domain.count('.') - 1 if '.' in domain else 0,
                
                # Advanced detection features
                'typosquatting_info': None,
                'homograph_info': None,
                'brand_impersonation_info': None,
                'is_punycode': False,
                
                'risk_score': 0.0,
                'risk_factors': []
            }
            
            # Check for punycode (internationalized domain names)
            result['is_punycode'] = 'xn--' in domain.lower()
            
            # Advanced phishing detection
            result['typosquatting_info'] = self._detect_typosquatting(base_domain)
            result['homograph_info'] = self._detect_homograph_attack(domain)
            result['brand_impersonation_info'] = self._detect_brand_impersonation(url, domain, path)
            
            # Calculate comprehensive risk score
            result['risk_score'], result['risk_factors'] = self._calculate_risk_score(result)
            
            return result
            
        except Exception as e:
            logger.error(f"Error analyzing URL {url}: {str(e)}")
            return {'error': str(e), 'url': url}
    
    def _has_ip_address(self, domain: str) -> bool:
        """Check if domain is an IP address"""
        ip_pattern = r'^(\d{1,3}\.){3}\d{1,3}(:\d+)?$'
        return bool(re.match(ip_pattern, domain.split(':')[0]))
    
    def _check_keywords(self, url: str) -> List[str]:
        """Check for suspicious keywords in URL"""
        return [kw for kw in self.suspicious_keywords if kw in url.lower()]
    
    def _check_suspicious_tld(self, domain: str) -> bool:
        """Check if domain has suspicious TLD"""
        return any(domain.endswith(tld) for tld in self.suspicious_tlds)
    
    def _calculate_levenshtein_distance(self, s1: str, s2: str) -> int:
        """Calculate Levenshtein (edit) distance between two strings"""
        if len(s1) < len(s2):
            return self._calculate_levenshtein_distance(s2, s1)
        
        if len(s2) == 0:
            return len(s1)
        
        previous_row = range(len(s2) + 1)
        for i, c1 in enumerate(s1):
            current_row = [i + 1]
            for j, c2 in enumerate(s2):
                insertions = previous_row[j + 1] + 1
                deletions = current_row[j] + 1
                substitutions = previous_row[j] + (c1 != c2)
                current_row.append(min(insertions, deletions, substitutions))
            previous_row = current_row
        
        return previous_row[-1]
    
    def _normalize_confusables(self, text: str) -> str:
        """Normalize text by replacing confusable characters with their ASCII equivalents"""
        normalized = []
        for char in text.lower():
            normalized.append(CONFUSABLE_CHARS.get(char, char))
        return ''.join(normalized)
    
    def _detect_typosquatting(self, domain: str) -> Optional[Dict[str, Any]]:
        """
        Detect typosquatting attacks by comparing domain to popular domains
        using Levenshtein distance and pattern matching
        """
        # Remove TLD for comparison
        domain_name = domain.split('.')[0] if '.' in domain else domain
        
        best_match = None
        min_distance = float('inf')
        
        for popular in self.popular_domains:
            popular_name = popular.split('.')[0]
            
            # Skip if exact match (it's the real domain)
            if domain == popular:
                return None
            
            # Calculate Levenshtein distance
            distance = self._calculate_levenshtein_distance(domain_name, popular_name)
            
            # Check for very similar domains (potential typosquats)
            if distance <= 2 and distance > 0:  # Within 2 edits but not exact
                if distance < min_distance:
                    min_distance = distance
                    best_match = {
                        'target_domain': popular,
                        'distance': distance,
                        'type': self._identify_typosquat_type(domain_name, popular_name)
                    }
        
        # Also check for number substitutions (e.g., paypa1.com)
        normalized_domain = self._normalize_confusables(domain_name)
        if normalized_domain != domain_name:
            for popular in self.popular_domains:
                popular_name = popular.split('.')[0]
                if normalized_domain == popular_name:
                    return {
                        'target_domain': popular,
                        'distance': 0,
                        'type': 'character_substitution'
                    }
        
        return best_match
    
    def _identify_typosquat_type(self, typo_domain: str, real_domain: str) -> str:
        """Identify the type of typosquatting attack"""
        if len(typo_domain) > len(real_domain):
            return 'character_insertion'
        elif len(typo_domain) < len(real_domain):
            return 'character_omission'
        else:
            # Same length - could be substitution or transposition
            diff_positions = [i for i, (a, b) in enumerate(zip(typo_domain, real_domain)) if a != b]
            if len(diff_positions) == 2 and abs(diff_positions[0] - diff_positions[1]) == 1:
                # Check if it's a character swap
                if (typo_domain[diff_positions[0]] == real_domain[diff_positions[1]] and
                    typo_domain[diff_positions[1]] == real_domain[diff_positions[0]]):
                    return 'character_transposition'
            return 'character_substitution'
    
    def _detect_homograph_attack(self, domain: str) -> Optional[Dict[str, Any]]:
        """
        Detect homograph attacks using confusable Unicode characters
        """
        confusable_found = []
        original_chars = []
        
        for i, char in enumerate(domain):
            if char in CONFUSABLE_CHARS:
                confusable_found.append({
                    'position': i,
                    'original': char,
                    'looks_like': CONFUSABLE_CHARS[char]
                })
                original_chars.append(char)
        
        if confusable_found:
            # Normalize and check against popular domains
            normalized = self._normalize_confusables(domain.split('.')[0])
            matched_brand = None
            
            for popular in self.popular_domains:
                popular_name = popular.split('.')[0]
                if normalized == popular_name:
                    matched_brand = popular
                    break
            
            return {
                'confusable_chars': confusable_found,
                'normalized_domain': normalized,
                'matched_brand': matched_brand,
                'is_mixed_script': self._has_mixed_scripts(domain)
            }
        
        return None
    
    def _has_mixed_scripts(self, text: str) -> bool:
        """Check if text contains mixed Unicode scripts (Latin + Cyrillic, etc.)"""
        has_latin = bool(re.search(r'[a-zA-Z]', text))
        has_cyrillic = bool(re.search(r'[\u0400-\u04FF]', text))
        has_greek = bool(re.search(r'[\u0370-\u03FF]', text))
        
        scripts_found = sum([has_latin, has_cyrillic, has_greek])
        return scripts_found > 1
    
    def _detect_brand_impersonation(self, url: str, domain: str, path: str) -> Optional[Dict[str, Any]]:
        """
        Detect brand impersonation patterns:
        - Brand names in subdomains (paypal.com.malicious.com)
        - Brand names in path with suspicious domain
        - Deceptive URL structures
        """
        impersonation_info = {
            'brand_in_subdomain': [],
            'brand_in_path': [],
            'deceptive_pattern': None
        }
        
        # Check for brand names in subdomains
        domain_parts = domain.split('.')
        if len(domain_parts) > 2:
            subdomains = domain_parts[:-2]
            for subdomain in subdomains:
                for brand in self.brand_names:
                    if brand in subdomain.lower():
                        impersonation_info['brand_in_subdomain'].append({
                            'brand': brand,
                            'subdomain': subdomain
                        })
        
        # Check for brand names in path (except for legitimate domains)
        base_domain = '.'.join(domain_parts[-2:]) if len(domain_parts) >= 2 else domain
        is_legitimate = base_domain in self.popular_domains
        
        if not is_legitimate:
            for brand in self.brand_names:
                if brand in path.lower():
                    impersonation_info['brand_in_path'].append({
                        'brand': brand,
                        'context': 'path'
                    })
                # Also check domain itself for brand name fragments
                if brand in base_domain.lower() and brand not in base_domain.split('.')[0]:
                    impersonation_info['brand_in_path'].append({
                        'brand': brand,
                        'context': 'domain_fragment'
                    })
        
        # Detect deceptive URL patterns
        deceptive_patterns = [
            (r'(secure|login|account|verify|update)[-.]', 'security_keyword_prefix'),
            (r'[-.]com[-.]', 'fake_tld_in_subdomain'),
            (r'(signin|sign-in|log-in|login)\.(php|html|asp)', 'login_page_pattern'),
            (r'@', 'at_symbol_redirect'),
        ]
        
        for pattern, pattern_type in deceptive_patterns:
            if re.search(pattern, url.lower()):
                impersonation_info['deceptive_pattern'] = pattern_type
                break
        
        # Return None if no impersonation detected
        if (not impersonation_info['brand_in_subdomain'] and 
            not impersonation_info['brand_in_path'] and 
            not impersonation_info['deceptive_pattern']):
            return None
        
        return impersonation_info
    
    def _calculate_risk_score(self, features: Dict[str, Any]) -> Tuple[float, List[str]]:
        """
        Calculate a comprehensive risk score based on all URL features
        Returns a value between 0 (safe) and 1 (high risk) plus list of risk factors
        """
        score = 0.0
        risk_factors = []
        
        # === Basic URL Features ===
        
        # URL length (longer URLs are more suspicious)
        if features['url_length'] > 100:
            score += 0.15
            risk_factors.append("Very long URL (>100 chars)")
        elif features['url_length'] > 75:
            score += 0.08
            risk_factors.append("Long URL (>75 chars)")
        
        # HTTPS (lack of secure connection)
        if not features['has_https']:
            score += 0.10
            risk_factors.append("No HTTPS encryption")
            
        # IP address in URL (high risk)
        if features['has_ip_address']:
            score += 0.30
            risk_factors.append("IP address used instead of domain name")
            
        # Suspicious characters
        if features['has_at_symbol']:
            score += 0.25
            risk_factors.append("Contains @ symbol (potential redirect)")
        if features['has_redirect']:
            score += 0.15
            risk_factors.append("Contains redirect pattern (//)")
            
        # Suspicious domain characteristics
        if features['has_hyphen']:
            score += 0.05
            risk_factors.append("Hyphen in domain")
        if features['has_underscore']:
            score += 0.08
            risk_factors.append("Underscore in domain")
            
        # Suspicious path patterns
        if features['has_dot_in_path'] or features['has_double_slash']:
            score += 0.10
            risk_factors.append("Suspicious path pattern")
            
        # Suspicious keywords
        if features['suspicious_keywords']:
            keyword_score = min(0.20, len(features['suspicious_keywords']) * 0.04)
            score += keyword_score
            risk_factors.append(f"Suspicious keywords: {', '.join(features['suspicious_keywords'][:3])}")
            
        # Suspicious TLD
        if features['suspicious_tld']:
            score += 0.15
            risk_factors.append("Suspicious top-level domain")
            
        # Multiple subdomains
        if features['subdomain_count'] > 3:
            score += 0.15
            risk_factors.append(f"Many subdomains ({features['subdomain_count']})")
        elif features['subdomain_count'] > 2:
            score += 0.08
            risk_factors.append(f"Multiple subdomains ({features['subdomain_count']})")
            
        # Port in URL
        if features['has_port']:
            score += 0.10
            risk_factors.append("Non-standard port specified")
        
        # === Advanced Phishing Detection ===
        
        # Punycode domain (internationalized)
        if features['is_punycode']:
            score += 0.20
            risk_factors.append("Internationalized domain name (punycode)")
        
        # Typosquatting detection (HIGH RISK)
        if features['typosquatting_info']:
            typo = features['typosquatting_info']
            if typo['distance'] <= 1:
                score += 0.40
                risk_factors.append(f"TYPOSQUATTING: Very similar to {typo['target_domain']} ({typo['type']})")
            else:
                score += 0.30
                risk_factors.append(f"TYPOSQUATTING: Similar to {typo['target_domain']} ({typo['type']})")
        
        # Homograph attack detection (VERY HIGH RISK)
        if features['homograph_info']:
            homo = features['homograph_info']
            if homo['matched_brand']:
                score += 0.50
                risk_factors.append(f"HOMOGRAPH ATTACK: Uses lookalike characters to impersonate {homo['matched_brand']}")
            elif homo['is_mixed_script']:
                score += 0.35
                risk_factors.append("Mixed Unicode scripts detected (potential homograph attack)")
            else:
                score += 0.25
                risk_factors.append("Contains confusable Unicode characters")
        
        # Brand impersonation detection (HIGH RISK)
        if features['brand_impersonation_info']:
            imp = features['brand_impersonation_info']
            
            if imp['brand_in_subdomain']:
                brands = [b['brand'] for b in imp['brand_in_subdomain']]
                score += 0.35
                risk_factors.append(f"BRAND IMPERSONATION: '{', '.join(brands)}' in subdomain")
            
            if imp['brand_in_path']:
                brands = [b['brand'] for b in imp['brand_in_path']]
                score += 0.20
                risk_factors.append(f"Brand name in URL path: {', '.join(brands)}")
            
            if imp['deceptive_pattern']:
                score += 0.15
                risk_factors.append(f"Deceptive URL pattern: {imp['deceptive_pattern']}")
        
        # Cap the score at 1.0
        final_score = min(1.0, score)
        
        return final_score, risk_factors


# Example usage and testing
if __name__ == "__main__":
    analyzer = URLAnalyzer()
    
    print("=" * 60)
    print("ADVANCED PHISHING URL ANALYZER - TEST SUITE")
    print("=" * 60)
    
    test_urls = [
        # Typosquatting tests
        ("http://paypa1.com/login", "Typosquat (1→l)"),
        ("http://gooogle.com", "Typosquat (extra o)"),
        ("http://amaz0n.com/signin", "Typosquat (0→o)"),
        ("http://microsft.com", "Typosquat (missing o)"),
        ("http://faceb00k.com", "Typosquat (o→0)"),
        
        # Homograph tests
        ("http://pаypal.com", "Homograph (Cyrillic а)"),
        ("http://gооgle.com", "Homograph (Cyrillic о)"),
        
        # Brand impersonation tests
        ("http://paypal.com.malicious.site", "Brand in subdomain"),
        ("http://secure-amazon-login.com", "Brand impersonation"),
        ("http://login.google.verify.com/account", "Brand subdomain"),
        ("http://netflix-support.suspicious.tk", "Brand + suspicious TLD"),
        
        # Legitimate tests (should be low risk)
        ("https://www.google.com", "Legitimate"),
        ("https://www.paypal.com/signin", "Legitimate"),
        ("https://www.amazon.com/dp/product123", "Legitimate"),
        
        # Other suspicious patterns
        ("http://192.168.1.1/login", "IP address"),
        ("http://bit.ly/@paypal.com", "@ symbol redirect"),
    ]
    
    for url, description in test_urls:
        print(f"\n{'─' * 60}")
        print(f"Test: {description}")
        print(f"URL: {url}")
        
        result = analyzer.analyze_url(url)
        
        if 'error' not in result:
            print(f"Risk Score: {result['risk_score']:.2f}")
            
            if result['risk_factors']:
                print("Risk Factors:")
                for factor in result['risk_factors']:
                    print(f"  ⚠️  {factor}")
            
            if result['typosquatting_info']:
                print(f"  🔍 Typosquatting: {result['typosquatting_info']}")
            
            if result['homograph_info']:
                print(f"  🔍 Homograph: {result['homograph_info']}")
            
            if result['brand_impersonation_info']:
                print(f"  🔍 Brand Impersonation: {result['brand_impersonation_info']}")
        else:
            print(f"Error: {result['error']}")
    
    print(f"\n{'=' * 60}")
    print("Test suite complete!")
