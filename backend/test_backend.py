#!/usr/bin/env python3
"""
Simple test script to verify backend functionality
"""
import sys
import os

# Add the backend directory to Python path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

def test_imports():
    """Test if all modules can be imported"""
    print("Testing imports...")
    
    try:
        from api.main import app
        print("✓ Main app imported successfully")
    except Exception as e:
        print(f"✗ Error importing main app: {e}")
        return False
    
    try:
        from ml.classifier_simple import PhishingClassifier
        print("✓ PhishingClassifier imported successfully")
    except Exception as e:
        print(f"✗ Error importing PhishingClassifier: {e}")
        return False
    
    try:
        from features.url_analyzer_simple import URLAnalyzer
        print("✓ URLAnalyzer imported successfully")
    except Exception as e:
        print(f"✗ Error importing URLAnalyzer: {e}")
        return False
    
    try:
        from genai.explainer_simple import PhishingExplainer
        print("✓ PhishingExplainer imported successfully")
    except Exception as e:
        print(f"✗ Error importing PhishingExplainer: {e}")
        return False
    
    return True

def test_classifier():
    """Test the phishing classifier with advanced cases"""
    print("\nTesting classifier...")
    
    try:
        from ml.classifier_simple import PhishingClassifier
        classifier = PhishingClassifier()
        
        # Test with obvious phishing
        phishing_text = "URGENT: Your account will be suspended! Click here to verify your password now!"
        is_phishing, confidence = classifier.predict(phishing_text)
        print(f"✓ Phishing test: {is_phishing} with {confidence:.2f} confidence")
        
        # Test with typosquatting case
        typo_text = "Your account has been compromised. Log in at http://paypa1.com to secure it."
        is_phishing_typo, confidence_typo = classifier.predict(typo_text)
        print(f"✓ Typosquat test: {is_phishing_typo} with {confidence_typo:.2f} confidence")
        
        # Test with normal text
        normal_text = "Hi, just wanted to check in and see how you're doing. Let me know if you need anything."
        is_phishing_normal, confidence_normal = classifier.predict(normal_text)
        print(f"✓ Normal test: {is_phishing_normal} with {confidence_normal:.2f} confidence")
        
        return is_phishing and is_phishing_typo and not is_phishing_normal
    except Exception as e:
        print(f"✗ Error testing classifier: {e}")
        return False

def test_url_analyzer():
    """Test the enhanced URL analyzer"""
    print("\nTesting URL analyzer...")
    
    try:
        from features.url_analyzer_simple import URLAnalyzer
        analyzer = URLAnalyzer()
        
        # Test with suspicious URL
        suspicious_url = "http://secure-login-bank.com/verify-account"
        result = analyzer.analyze_url(suspicious_url)
        print(f"✓ Suspicious URL analysis: {result['risk_score']:.2f} risk score")
        
        # Test with typosquat URL
        typo_url = "http://amaz0n.com/signin"
        result_typo = analyzer.analyze_url(typo_url)
        print(f"✓ Typosquat URL analysis (amaz0n): {result_typo['risk_score']:.2f} risk score")
        if result_typo.get('typosquatting_info'):
             print(f"  Detected impersonation of: {result_typo['typosquatting_info']['target_domain']}")
        
        # Test with safe URL
        safe_url = "https://www.google.com/search"
        result_safe = analyzer.analyze_url(safe_url)
        print(f"✓ Safe URL analysis: {result_safe['risk_score']:.2f} risk score")
        
        return result['risk_score'] > 0.5 and result_typo['risk_score'] > 0.6 and result_safe['risk_score'] < 0.3
    except Exception as e:
        print(f"✗ Error testing URL analyzer: {e}")
        return False

def test_explainer():
    """Test the phishing explainer"""
    print("\nTesting explainer...")
    
    try:
        from genai.explainer_simple import PhishingExplainer
        explainer = PhishingExplainer()
        
        # Test explanation generation
        phishing_text = "URGENT: Verify your account immediately or it will be suspended!"
        explanation = explainer.generate_explanation(phishing_text)
        print(f"✓ Explanation generated: {explanation[:50]}...")
        
        # Test recommendations
        recommendations = explainer.get_recommendations("high")
        print(f"✓ Recommendations: {len(recommendations)} items generated")
        
        return True
    except Exception as e:
        print(f"✗ Error testing explainer: {e}")
        return False

if __name__ == "__main__":
    print("=" * 50)
    print("PhishShield Backend Test Suite")
    print("=" * 50)
    
    all_passed = True
    
    # Run all tests
    tests = [
        test_imports,
        test_classifier,
        test_url_analyzer,
        test_explainer
    ]
    
    for test in tests:
        if not test():
            all_passed = False
    
    print("\n" + "=" * 50)
    if all_passed:
        print("✓ All tests passed! Backend is ready to run.")
        print("\nTo start the server:")
        print("python start.py")
        print("\nAPI will be available at: http://localhost:8000")
        print("API docs at: http://localhost:8000/docs")
    else:
        print("✗ Some tests failed. Please check the errors above.")
    print("=" * 50)
