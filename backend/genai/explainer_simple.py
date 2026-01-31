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
            # Urgency tactics
            'urgent': 'This message creates a false sense of urgency to pressure you into acting quickly without thinking.',
            'immediately': 'Demands for immediate action are designed to prevent you from verifying the request.',
            'expires': 'Fake deadlines are used to rush you into making poor decisions.',
            'limited time': 'Artificial time pressure is a common manipulation tactic.',
            
            # Verification/action requests
            'verify': 'Legitimate companies rarely ask you to verify account information via email or text.',
            'confirm': 'Unsolicited requests to confirm personal information are suspicious.',
            'click': 'Be cautious of messages asking you to click on suspicious links.',
            'update': 'Legitimate services send security updates through their official apps, not email links.',
            
            # Security/account threats
            'password': 'Never share your password or personal information in response to unsolicited messages.',
            'account': 'Scammers often claim there are problems with your account to trick you into revealing information.',
            'suspended': 'Your account is unlikely to be suspended without prior notice from the official service.',
            'blocked': 'Account blocking notices via email are usually scams - check directly on the official site.',
            'compromised': 'Messages claiming your account is compromised often ARE the actual attack.',
            'unauthorized': 'Fake unauthorized access alerts are designed to create panic.',
            
            # Brand impersonation
            'bank': 'Banks will never ask for sensitive information via email or text messages.',
            'paypal': 'PayPal will never ask you to confirm financial information via email.',
            'amazon': 'Amazon will not ask for your password or payment information via email.',
            'netflix': 'Netflix will never ask for your password or credit card via email.',
            'microsoft': 'Microsoft will not send unsolicited security alerts asking for personal info.',
            'apple': 'Apple ID phishing is common - always verify at apple.com directly.',
            'google': 'Google security alerts should be verified at myaccount.google.com.',
            
            # Prize/reward scams
            'prize': 'Messages claiming you\'ve won a prize you didn\'t enter are almost always scams.',
            'winner': 'Unexpected winning notifications are a classic scam technique.',
            'congratulations': 'Unsolicited congratulations messages are typically phishing attempts.',
            'lottery': 'You cannot win a lottery you never entered.',
            'reward': 'Unexpected reward offers are designed to lure you into providing personal info.',
            
            # Security alerts
            'security': 'Security alerts from legitimate companies come through official channels, not random emails.',
            'alert': 'Fake alerts are designed to make you panic and act without thinking.',
            'warning': 'Threatening warnings are a manipulation tactic to bypass your critical thinking.',
            
            # Financial
            'credit card': 'Never provide credit card information in response to email or text requests.',
            'billing': 'Billing issues should be verified by logging into the official website directly.',
            'payment': 'Payment requests via email should always be verified through official channels.',
            'invoice': 'Fake invoices are commonly used in phishing attacks.',
            'refund': 'Unsolicited refund offers are often used to steal financial information.',
        }
        
        # URL-specific explanations
        self.url_explanations = {
            'typosquatting': 'This URL uses a misspelled version of a legitimate domain name (typosquatting). '
                            'For example, "amaz0n.com" instead of "amazon.com". Always check the spelling carefully.',
            
            'homograph': 'This URL uses lookalike characters from different alphabets (homograph attack). '
                        'Special characters that look like English letters are used to impersonate legitimate sites.',
            
            'brand_subdomain': 'This URL places a trusted brand name in the subdomain to appear legitimate. '
                              'For example, "paypal.com.malicious.site" - the actual domain is "malicious.site".',
            
            'brand_impersonation': 'This URL contains a well-known brand name but is not the official website. '
                                  'Attackers often include brand names to build false trust.',
            
            'suspicious_tld': 'This URL uses a top-level domain commonly associated with phishing. '
                             'Domains like .tk, .ml, .xyz are frequently used for malicious purposes.',
            
            'ip_address': 'This URL uses an IP address instead of a domain name. '
                         'Legitimate websites almost always use proper domain names.',
            
            'long_url': 'Unusually long URLs can be used to hide the true destination. '
                       'Attackers use long paths to push the real domain out of view.',
            
            'no_https': 'This URL does not use HTTPS encryption. '
                       'Legitimate login and payment pages always use HTTPS.',
            
            'punycode': 'This is an international domain name (punycode). While sometimes legitimate, '
                       'punycode domains are often used in phishing to impersonate known brands.',
            
            'at_symbol': 'This URL contains an @ symbol, which can be used to obscure the true destination. '
                        'The browser may ignore everything before the @ symbol.',
            
            'multiple_subdomains': 'Multiple subdomains can be used to make a URL look legitimate. '
                                  'Check the main domain carefully - it\'s the part just before the TLD (.com, .org, etc.).',
        }
        
        # Risk level explanations
        self.risk_level_descriptions = {
            'critical': 'This message shows strong signs of being a phishing attempt. Do not interact with any links or provide any information.',
            'high': 'This message contains multiple phishing indicators. Exercise extreme caution.',
            'medium': 'This message contains some suspicious elements. Verify through official channels before taking action.',
            'low': 'This message has minor suspicious elements. Remain vigilant but it may be legitimate.',
            'minimal': 'This message appears to be legitimate with no significant phishing indicators.'
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

    def generate_explanation(self, text: str, risk_factors: Dict = None, url_analysis: Dict = None) -> str:
        """
        Generate a comprehensive human-readable explanation for a potential phishing attempt
        """
        try:
            text_lower = text.lower()
            explanations = []
            
            # Check for predefined patterns
            matched_explanations = set()
            for keyword, explanation in self.predefined_explanations.items():
                if keyword in text_lower and explanation not in matched_explanations:
                    explanations.append(explanation)
                    matched_explanations.add(explanation)
            
            # Add URL-specific explanations if URL analysis provided
            if url_analysis:
                url_explanations_list = self._generate_url_explanations(url_analysis)
                explanations.extend(url_explanations_list)
            
            # Check for URLs in text
            if 'http' in text_lower or 'www.' in text_lower:
                explanations.append("This message contains links that should be carefully verified before clicking.")
            
            # Check for personal information requests
            personal_info_keywords = ['ssn', 'social security', 'credit card', 'card number', 'cvv', 'pin', 'routing number']
            if any(keyword in text_lower for keyword in personal_info_keywords):
                explanations.append("This message asks for sensitive personal or financial information, which legitimate companies never request via email.")
            
            # Check for threats
            threat_keywords = ['suspend', 'terminate', 'close', 'legal action', 'lawsuit', 'arrest', 'police', 'prosecution']
            if any(keyword in text_lower for keyword in threat_keywords):
                explanations.append("This message uses threats or legal intimidation to scare you into taking immediate action, a common phishing tactic.")
            
            # Check for poor grammar indicators
            if text.count('!!') > 1 or text.count('??') > 0:
                explanations.append("This message contains unusual punctuation, which is often a sign of unprofessional communication.")
            
            # Check for excessive caps
            if len(text) > 20:
                caps_ratio = sum(1 for c in text if c.isupper()) / len(text)
                if caps_ratio > 0.4:
                    explanations.append("This message uses excessive capitalization, a tactic used to create urgency or emphasize fake importance.")
            
            # If no specific patterns found, provide a general explanation
            if not explanations:
                explanations.append("This message shows characteristics commonly found in phishing attempts. Please be cautious and verify the source through official channels.")
            
            # Combine unique explanations (limit to 4 to avoid being too long)
            unique_explanations = list(dict.fromkeys(explanations))
            return ' '.join(unique_explanations[:4])
            
        except Exception as e:
            logger.error(f"Error generating explanation: {str(e)}")
            return "This message contains characteristics commonly found in phishing attempts. Please verify the source before taking any action."

    def _generate_url_explanations(self, url_analysis: Dict) -> List[str]:
        """Generate explanations specific to URL analysis results"""
        explanations = []
        
        # Typosquatting
        if url_analysis.get('typosquatting_info'):
            typo = url_analysis['typosquatting_info']
            explanations.append(
                f"⚠️ TYPOSQUATTING DETECTED: This URL appears to impersonate '{typo['target_domain']}' "
                f"using a misspelled domain name. This is a common phishing technique."
            )
        
        # Homograph attack
        if url_analysis.get('homograph_info'):
            homo = url_analysis['homograph_info']
            if homo.get('matched_brand'):
                explanations.append(
                    f"⚠️ HOMOGRAPH ATTACK DETECTED: This URL uses lookalike characters to impersonate "
                    f"'{homo['matched_brand']}'. Special Unicode characters are being used to trick you."
                )
            elif homo.get('is_mixed_script'):
                explanations.append(
                    "⚠️ This URL contains mixed character sets (different alphabets), which is a "
                    "technique used to create convincing fake domains."
                )
        
        # Brand impersonation
        if url_analysis.get('brand_impersonation_info'):
            imp = url_analysis['brand_impersonation_info']
            if imp.get('brand_in_subdomain'):
                brands = [b['brand'] for b in imp['brand_in_subdomain']]
                explanations.append(
                    f"⚠️ BRAND IMPERSONATION: This URL places '{', '.join(brands)}' in the subdomain "
                    f"to appear legitimate, but the actual domain is different."
                )
            if imp.get('deceptive_pattern'):
                explanations.append(self.url_explanations.get('brand_impersonation', ''))
        
        # Punycode
        if url_analysis.get('is_punycode'):
            explanations.append(self.url_explanations['punycode'])
        
        # IP address
        if url_analysis.get('has_ip_address'):
            explanations.append(self.url_explanations['ip_address'])
        
        # No HTTPS
        if url_analysis.get('has_https') == False:
            explanations.append(self.url_explanations['no_https'])
        
        # Suspicious TLD
        if url_analysis.get('suspicious_tld'):
            explanations.append(self.url_explanations['suspicious_tld'])
        
        # @ symbol
        if url_analysis.get('has_at_symbol'):
            explanations.append(self.url_explanations['at_symbol'])
        
        return explanations

    def get_recommendations(self, risk_level: str, risk_factors: Dict = None, url_analysis: Dict = None) -> List[str]:
        """
        Get comprehensive recommended actions based on risk level and specific factors
        """
        base_recommendations = {
            "critical": [
                "🚫 Do NOT click on any links in this message",
                "🚫 Do NOT download any attachments",
                "🚫 Do NOT provide any personal or financial information",
                "📧 Report this as phishing to your email provider",
                "🗑️ Delete this message immediately",
                "📞 If concerned about your account, contact the company directly using their official website (type it manually) or phone number from a trusted source",
                "🔒 If you already clicked a link or provided information, change your passwords immediately and monitor your accounts"
            ],
            "high": [
                "⚠️ Do not click on any links or download attachments",
                "⚠️ Do not provide any personal or financial information",
                "🔍 Verify the sender by contacting the organization through official channels",
                "📧 Consider reporting this as suspicious to your IT department or email provider",
                "🗑️ Delete the message after verification"
            ],
            "medium": [
                "🔍 Verify the sender's identity through official channels before responding",
                "⚠️ Be cautious with any links - hover to check the actual destination",
                "📱 Contact the supposed sender through a known, trusted method",
                "💭 Ask yourself: Did I expect this message? Does this request make sense?"
            ],
            "low": [
                "👁️ Remain vigilant for suspicious requests",
                "🔍 Verify unexpected messages through official channels",
                "🔒 Keep your security software updated",
                "💭 Trust your instincts - if something feels off, verify it"
            ],
            "minimal": [
                "✓ This message appears to be legitimate",
                "👁️ Continue practicing good security habits",
                "🔍 Always verify requests for sensitive information through official channels"
            ]
        }
        
        recommendations = base_recommendations.get(risk_level.lower(), base_recommendations["medium"]).copy()
        
        # Add specific recommendations based on URL analysis
        if url_analysis:
            if url_analysis.get('typosquatting_info'):
                target = url_analysis['typosquatting_info']['target_domain']
                recommendations.insert(0, f"🔗 If you need to visit {target}, type the address manually in your browser")
            
            if url_analysis.get('homograph_info'):
                recommendations.insert(0, "🔤 This URL uses deceptive characters - do NOT trust the displayed text")
            
            if url_analysis.get('brand_impersonation_info'):
                recommendations.insert(0, "🏢 Visit the official website by typing the address manually, not through this link")
        
        return recommendations

    def get_risk_description(self, risk_level: str) -> str:
        """Get a description of what the risk level means"""
        return self.risk_level_descriptions.get(risk_level.lower(), self.risk_level_descriptions['medium'])

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

    def generate_full_report(self, text: str, classifier_result: Dict = None, url_analysis: Dict = None) -> Dict:
        """
        Generate a comprehensive phishing analysis report
        """
        risk_level = classifier_result.get('risk_level', 'medium') if classifier_result else 'medium'
        
        report = {
            'explanation': self.generate_explanation(text, url_analysis=url_analysis),
            'risk_level': risk_level,
            'risk_description': self.get_risk_description(risk_level),
            'recommendations': self.get_recommendations(risk_level, url_analysis=url_analysis),
            'url_warnings': [],
            'detected_tactics': []
        }
        
        # Add URL-specific warnings
        if url_analysis:
            if url_analysis.get('typosquatting_info'):
                report['url_warnings'].append({
                    'type': 'typosquatting',
                    'severity': 'critical',
                    'details': url_analysis['typosquatting_info']
                })
            
            if url_analysis.get('homograph_info'):
                report['url_warnings'].append({
                    'type': 'homograph_attack',
                    'severity': 'critical',
                    'details': url_analysis['homograph_info']
                })
            
            if url_analysis.get('brand_impersonation_info'):
                report['url_warnings'].append({
                    'type': 'brand_impersonation',
                    'severity': 'high',
                    'details': url_analysis['brand_impersonation_info']
                })
        
        # Detect tactics used
        text_lower = text.lower()
        tactics = []
        if any(word in text_lower for word in ['urgent', 'immediately', 'right now', 'within 24 hours']):
            tactics.append('urgency')
        if any(word in text_lower for word in ['suspended', 'terminated', 'blocked', 'lawsuit', 'arrest']):
            tactics.append('fear/threats')
        if any(word in text_lower for word in ['prize', 'winner', 'congratulations', 'reward', 'free']):
            tactics.append('greed/rewards')
        if any(word in text_lower for word in ['dear customer', 'valued customer', 'dear user']):
            tactics.append('impersonation')
        if any(word in text_lower for word in ['password', 'credit card', 'ssn', 'account number']):
            tactics.append('data_harvesting')
        
        report['detected_tactics'] = tactics
        
        return report


# Example usage
if __name__ == "__main__":
    explainer = PhishingExplainer()
    
    print("=" * 60)
    print("PHISHING EXPLAINER - TEST SUITE")
    print("=" * 60)
    
    # Test explanation generation
    test_cases = [
        "URGENT: Your account will be suspended! Click here to verify now!",
        "Dear valued customer, your PayPal account has been compromised. Update your password at http://paypa1.com/login",
        "Congratulations! You've won $1,000,000! Claim your prize now!",
        "Hi, just checking in to see how you're doing."
    ]
    
    for text in test_cases:
        print(f"\n{'─' * 60}")
        print(f"Text: {text[:70]}{'...' if len(text) > 70 else ''}")
        
        explanation = explainer.generate_explanation(text)
        print(f"Explanation: {explanation}")
        
        # Test with mock URL analysis
        mock_url_analysis = {
            'typosquatting_info': {'target_domain': 'paypal.com', 'distance': 1, 'type': 'character_substitution'},
            'has_https': False,
            'suspicious_tld': True
        } if 'paypa1.com' in text else None
        
        if mock_url_analysis:
            recommendations = explainer.get_recommendations("high", url_analysis=mock_url_analysis)
            print("\nRecommendations:")
            for rec in recommendations[:4]:
                print(f"  {rec}")
    
    print(f"\n{'=' * 60}")
    print("Test suite complete!")
