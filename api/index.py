import sys
import os
from pathlib import Path

# Add backend directory to Python path for Vercel Serverless Function resolution
backend_dir = Path(__file__).parent.parent / "backend"
sys.path.insert(0, str(backend_dir))

from app.main import app
