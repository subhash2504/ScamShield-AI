import os
from pathlib import Path
from dotenv import load_dotenv

# Base Directories
BACKEND_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = BACKEND_DIR.parent
FRONTEND_DIR = PROJECT_ROOT / "frontend"
DATA_DIR = PROJECT_ROOT / "data"
MODELS_DIR = BACKEND_DIR / "ml" / "models"
DATABASE_DIR = BACKEND_DIR / "database"

# Ensure directories exist safely
try:
    MODELS_DIR.mkdir(parents=True, exist_ok=True)
    DATABASE_DIR.mkdir(parents=True, exist_ok=True)
except OSError:
    pass

# Load .env file if available
dotenv_path = PROJECT_ROOT / ".env"
if dotenv_path.exists():
    load_dotenv(dotenv_path)

# Determine default database path (use /tmp on serverless Vercel)
is_vercel = bool(os.environ.get("VERCEL"))
default_db_path = "/tmp/phishguard.db" if is_vercel else str(DATABASE_DIR / "phishguard.db")

class Config:
    """Base application configuration."""
    SECRET_KEY = os.environ.get("SECRET_KEY", "dev_secret_key_phishguard_ai_2026")
    DATABASE_PATH = os.environ.get("DATABASE_PATH", default_db_path)
    
    # Upload limits (10 MB max)
    MAX_CONTENT_LENGTH = int(os.environ.get("MAX_CONTENT_LENGTH", 10 * 1024 * 1024))
    ALLOWED_IMAGE_EXTENSIONS = {"png", "jpg", "jpeg"}
    ALLOWED_MIME_TYPES = {"image/png", "image/jpeg"}
    
    # Rate Limiting
    RATELIMIT_DEFAULT = os.environ.get("RATELIMIT_DEFAULT", "120 per minute")
    RATELIMIT_STORAGE_URI = os.environ.get("RATELIMIT_STORAGE_URI", "memory://")
    
    # OCR settings
    TESSERACT_CMD = os.environ.get("TESSERACT_CMD", "")
    
    # ML Models
    ML_MODEL_PATH = MODELS_DIR / "phishguard_pipeline.joblib"
    ML_METRICS_PATH = MODELS_DIR / "evaluation_metrics.json"

    # API Keys / Threat Intelligence / LLM
    API_KEY = os.environ.get("API_KEY", "")
    GEMINI_API_KEY = os.environ.get("GEMINI_API_KEY", os.environ.get("API_KEY", ""))
    THREAT_INTEL_API_KEY = os.environ.get("THREAT_INTEL_API_KEY", os.environ.get("API_KEY", ""))


class DevelopmentConfig(Config):
    """Development environment configuration."""
    DEBUG = True
    TESTING = False


class TestingConfig(Config):
    """Testing environment configuration."""
    DEBUG = False
    TESTING = True
    DATABASE_PATH = str(DATABASE_DIR / "test_phishguard.db")
    RATELIMIT_ENABLED = False


class ProductionConfig(Config):
    """Production environment configuration."""
    DEBUG = False
    TESTING = False


config_by_name = {
    "development": DevelopmentConfig,
    "testing": TestingConfig,
    "production": ProductionConfig,
}

def get_config():
    env = os.environ.get("FLASK_ENV", "development").lower()
    return config_by_name.get(env, DevelopmentConfig)
