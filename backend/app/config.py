import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent.parent
DATA_DIR = BASE_DIR / "data"
SAMPLE_PCAPS_DIR = DATA_DIR / "sample_pcaps"
SYNTHETIC_PCAPS_DIR = DATA_DIR / "synthetic"

PROJECT_NAME = "Email TLS Passive Forensics Framework"
VERSION = "0.1.0"
API_V1_STR = "/api/v1"
