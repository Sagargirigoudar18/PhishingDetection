# PhishShield Backend API

## Setup Instructions

### 1. Install Dependencies
```bash
pip install -r requirements.txt
```

### 2. Set Environment Variables
Create a `.env` file in the backend directory:
```env
APP_NAME="PhishShield"
APP_ENV="development"
DEBUG=True
SECRET_KEY="your-secret-key-here-change-in-production"
DATABASE_URL="sqlite:///./phishshield.db"
CORS_ORIGINS="http://localhost:3000,http://localhost:5173"
OPENAI_API_KEY="your-openai-api-key"
```

### 3. Run the Application

#### Option 1: Using the start script
```bash
python start.py
```

#### Option 2: Using uvicorn directly
```bash
uvicorn api.main:app --host 0.0.0.0 --port 8000 --reload
```

### 4. Test the Setup
```bash
python test_setup.py
```

## API Endpoints

### Health Check
- `GET /` - Check if API is running

### Phishing Detection
- `POST /api/detect/analyze` - Analyze content for phishing

Example request:
```json
{
  "content": "Your account has been compromised. Click here to secure it!",
  "content_type": "email"
}
```

## API Documentation
- Swagger UI: http://localhost:8000/docs
- ReDoc: http://localhost:8000/redoc

## Project Structure
```
backend/
├── api/
│   ├── main.py              # FastAPI application
│   └── routes/
│       └── detection.py     # Detection endpoints
├── core/
│   ├── config.py            # Configuration settings
│   └── security.py          # Security utilities
├── ml/
│   ├── classifier.py        # ML phishing classifier
│   └── vector_store.py      # Vector storage for similarity search
├── features/
│   └── url_analyzer.py      # URL analysis features
├── genai/
│   ├── explainer.py         # AI-powered explanation generator
│   └── prompts.py           # Prompt templates
├── requirements.txt         # Python dependencies
├── .env                     # Environment variables
├── start.py                 # Startup script
└── test_setup.py            # Test script
```

## Troubleshooting

### Import Errors
If you encounter import errors, make sure:
1. All `__init__.py` files are present in directories
2. You're running from the backend directory
3. All dependencies are installed

### Database Issues
The application uses SQLite by default. The database file will be created automatically.

### Port Conflicts
If port 8000 is in use, modify the port in the startup command:
```bash
uvicorn api.main:app --host 0.0.0.0 --port 8001 --reload
```
