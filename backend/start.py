import uvicorn
import sys
import os

# Add the backend directory to Python path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

if __name__ == "__main__":
    print("Starting PhishShield Backend API...")
    print("API Documentation will be available at: http://localhost:8000/docs")
    print("API ReDoc will be available at: http://localhost:8000/redoc")
    print("\nTo test the API:")
    print("1. Go to http://localhost:8000/docs")
    print("2. Try the POST /api/detect/analyze endpoint")
    print("\nPress Ctrl+C to stop the server\n")
    
    uvicorn.run(
        "api.main:app",
        host="0.0.0.0",
        port=8000,
        reload=True,
        log_level="info"
    )
