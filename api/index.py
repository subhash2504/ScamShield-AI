import os
import sys
from pathlib import Path

# Set VERCEL environment flag
os.environ["VERCEL"] = "1"

# Add project root directory to sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from backend.app import create_app

app = create_app()

# Vercel WSGI entry point
# Exports 'app' as the WSGI callable
