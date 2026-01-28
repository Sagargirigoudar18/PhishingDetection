import os
from dotenv import load_dotenv

load_dotenv()

class Settings:
    def __init__(self):
        # App settings
        self.APP_NAME = os.getenv("APP_NAME", "PhishShield")
        self.APP_ENV = os.getenv("APP_ENV", "development")
        self.DEBUG = os.getenv("DEBUG", "False").lower() == "true"
        self.SECRET_KEY = os.getenv("SECRET_KEY", "dev-secret-key-change-in-production")
        
        # Database
        self.DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./phishshield.db")
        
        # Security
        self.ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", "1440"))  # 24 hours
        self.ALGORITHM = os.getenv("ALGORITHM", "HS256")
        
        # CORS
        cors_origins = os.getenv("CORS_ORIGINS", "http://localhost:3000,http://localhost:5173")
        self.CORS_ORIGINS = [origin.strip() for origin in cors_origins.split(",")]
        
        # OpenAI
        self.OPENAI_API_KEY = os.getenv("OPENAI_API_KEY", "")

# Create settings instance
settings = Settings()
