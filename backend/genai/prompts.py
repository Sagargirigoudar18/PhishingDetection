from typing import Dict, List, Optional

class PromptTemplates:
    """Template prompts for different phishing detection scenarios"""
    
    SYSTEM_PROMPT = """You are a cybersecurity expert specializing in phishing detection. 
    Your task is to analyze messages and explain why they might be phishing attempts in clear, 
    non-technical language that anyone can understand. Focus on the specific indicators that make 
    the message suspicious and provide actionable advice."""
    
    PHISHING_ANALYSIS = """
    Analyze the following message for phishing indicators:
    
    Message: {message}
    Type: {message_type}
    
    Please provide:
    1. A clear explanation of why this message is suspicious (if it is)
    2. The specific phishing techniques being used
    3. What the user should do to stay safe
    
    Keep your response concise and easy to understand for non-technical users.
    """
    
    URL_ANALYSIS = """
    Analyze this URL for phishing indicators:
    
    URL: {url}
    Domain age: {domain_age} days
    Uses HTTPS: {has_https}
    Contains IP address: {has_ip}
    Suspicious keywords: {keywords}
    
    Explain in simple terms why this URL might be dangerous and what precautions the user should take.
    """
    
    EMAIL_ANALYSIS = """
    Analyze this email for phishing indicators:
    
    Subject: {subject}
    Sender: {sender}
    Content: {content}
    
    Look for:
    - Urgency or pressure tactics
    - Requests for personal information
    - Suspicious links or attachments
    - Grammar or spelling errors
    - Unusual sender address
    
    Provide a clear explanation of any red flags found.
    """
    
    SMS_ANALYSIS = """
    Analyze this SMS message for phishing (smishing) indicators:
    
    Message: {message}
    Sender: {sender}
    
    Common SMS phishing tactics to check for:
    - Unexpected prize or lottery winnings
    - Package delivery issues
    - Bank account problems
    - Requests for verification codes
    - Suspicious links
    
    Explain any concerns in simple terms.
    """
    
    @staticmethod
    def get_explanation_prompt(content_type: str, **kwargs) -> str:
        """Get the appropriate prompt based on content type"""
        prompts = {
            'email': PromptTemplates.EMAIL_ANALYSIS,
            'sms': PromptTemplates.SMS_ANALYSIS,
            'whatsapp': PromptTemplates.SMS_ANALYSIS,  # Similar to SMS
            'url': PromptTemplates.URL_ANALYSIS,
            'default': PromptTemplates.PHISHING_ANALYSIS
        }
        
        template = prompts.get(content_type, prompts['default'])
        return template.format(**kwargs)
    
    @staticmethod
    def format_risk_assessment(risk_score: float, risk_factors: List[str]) -> str:
        """Format risk assessment into a clear message"""
        if risk_score >= 0.8:
            risk_level = "HIGH RISK"
            urgency = "This is very dangerous"
        elif risk_score >= 0.5:
            risk_level = "MEDIUM RISK"
            urgency = "This is suspicious"
        else:
            risk_level = "LOW RISK"
            urgency = "This appears safe"
        
        factors_text = ""
        if risk_factors:
            factors_text = f"\n\nWarning signs detected:\n" + "\n".join(f"• {factor}" for factor in risk_factors)
        
        return f"{urgency} ({risk_level}: {risk_score:.0%} confidence){factors_text}"
