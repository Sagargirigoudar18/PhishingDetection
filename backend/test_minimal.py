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

def test_functionality():
    """Test if models can be instantiated and work"""
    print("\nTesting functionality...")
    
    try:
        from ml.classifier_simple import PhishingClassifier
        classifier = PhishingClassifier()
        
        # Test prediction
        result = classifier.predict("Your account has been compromised. Click here to secure it!")
        print(f"✓ Classifier test: {result}")
    except Exception as e:
        print(f"✗ Error testing classifier: {e}")
    
    try:
        from features.url_analyzer_simple import URLAnalyzer
        analyzer = URLAnalyzer()
        
        # Test URL analysis
        result = analyzer.analyze_url("http://suspicious-site.com/login")
        print(f"✓ URL Analyzer test: Risk score = {result.get('risk_score', 'N/A')}")
    except Exception as e:
        print(f"✗ Error testing URL analyzer: {e}")
    
    try:
        from genai.explainer_simple import PhishingExplainer
        explainer = PhishingExplainer()
        
        # Test explanation
        result = explainer.generate_explanation("URGENT: Verify your account now!")
        print(f"✓ Explainer test: {result[:50]}...")
    except Exception as e:
        print(f"✗ Error testing explainer: {e}")

if __name__ == "__main__":
    if test_imports():
        test_functionality()
        print("\n✓ All tests passed! The application should work.")
        print("\nTo start the server, run:")
        print("python start.py")
    else:
        print("\n✗ Some tests failed. Please check the errors above.")
