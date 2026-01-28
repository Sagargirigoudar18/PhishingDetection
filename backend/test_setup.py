import sys
import os

# Add the backend directory to Python path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

def test_imports():
    """Test if all modules can be imported"""
    try:
        from api.main import app
        print("✓ Main app imported successfully")
    except Exception as e:
        print(f"✗ Error importing main app: {e}")
        return False
    
    try:
        from ml.classifier import PhishingClassifier
        print("✓ PhishingClassifier imported successfully")
    except Exception as e:
        print(f"✗ Error importing PhishingClassifier: {e}")
        return False
    
    try:
        from features.url_analyzer import URLAnalyzer
        print("✓ URLAnalyzer imported successfully")
    except Exception as e:
        print(f"✗ Error importing URLAnalyzer: {e}")
        return False
    
    try:
        from genai.explainer import PhishingExplainer
        print("✓ PhishingExplainer imported successfully")
    except Exception as e:
        print(f"✗ Error importing PhishingExplainer: {e}")
        return False
    
    return True

def test_models():
    """Test if models can be instantiated"""
    try:
        from ml.classifier import PhishingClassifier
        classifier = PhishingClassifier()
        print("✓ PhishingClassifier instantiated")
    except Exception as e:
        print(f"✗ Error instantiating PhishingClassifier: {e}")
    
    try:
        from features.url_analyzer import URLAnalyzer
        analyzer = URLAnalyzer()
        print("✓ URLAnalyzer instantiated")
    except Exception as e:
        print(f"✗ Error instantiating URLAnalyzer: {e}")
    
    try:
        from genai.explainer import PhishingExplainer
        explainer = PhishingExplainer()
        print("✓ PhishingExplainer instantiated")
    except Exception as e:
        print(f"✗ Error instantiating PhishingExplainer: {e}")

if __name__ == "__main__":
    print("Testing imports...")
    if test_imports():
        print("\nTesting model instantiation...")
        test_models()
        print("\n✓ All tests passed!")
    else:
        print("\n✗ Some tests failed. Please check the errors above.")
