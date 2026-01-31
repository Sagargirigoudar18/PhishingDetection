import uvicorn
import sys
import os
import logging

# Add the backend directory to Python path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

def check_dependencies():
    """Check if required dependencies are available"""
    try:
        import fastapi
        import uvicorn
        import pydantic
        import dotenv
        logger.info("✓ All core dependencies are available")
        return True
    except ImportError as e:
        logger.error(f"✗ Missing dependency: {e}")
        logger.error("Please run: pip install -r requirements.txt")
        return False

def check_imports():
    """Check if all modules can be imported"""
    try:
        from api.main import app
        from ml.classifier_simple import PhishingClassifier
        from features.url_analyzer_simple import URLAnalyzer
        from genai.explainer_simple import PhishingExplainer
        logger.info("✓ All modules imported successfully")
        return True
    except Exception as e:
        logger.error(f"✗ Import error: {e}")
        return False

if __name__ == "__main__":
    print("=" * 60)
    print("🛡️  PhishShield Backend API")
    print("=" * 60)
    
    # Check dependencies
    if not check_dependencies():
        sys.exit(1)
    
    # Check imports
    if not check_imports():
        sys.exit(1)
    
    print("\n🚀 Starting server...")
    print("📖 API Documentation: http://localhost:8000/docs")
    print("📖 API ReDoc: http://localhost:8000/redoc")
    print("🏥 Health Check: http://localhost:8000/health")
    print("\n💡 To test the API:")
    print("   1. Open http://localhost:8000/docs")
    print("   2. Try the POST /api/detect/analyze endpoint")
    print("\n⚠️  Press Ctrl+C to stop the server\n")
    
    try:
        uvicorn.run(
            "api.main:app",
            host="0.0.0.0",
            port=8000,
            reload=True,
            log_level="info"
        )
    except KeyboardInterrupt:
        print("\n👋 Server stopped by user")
    except Exception as e:
        logger.error(f"❌ Failed to start server: {e}")
        sys.exit(1)
