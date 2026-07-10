import os

# -----------------------------
# Application
# -----------------------------

APP_NAME = "Agent Analyst"
APP_VERSION = "1.0.0"
DEBUG = os.getenv("DEBUG", "False").lower() == "true"

# -----------------------------
# Server
# -----------------------------

HOST = os.getenv("HOST", "127.0.0.1")
PORT = int(os.getenv("PORT", 8000))

# -----------------------------
# API
# -----------------------------

API_PREFIX = ""

# -----------------------------
# Tool Configuration
# -----------------------------

AVAILABLE_TOOLS = [
    "trufflehog",
    "gitleaks",
    "secretfinder",
    "linkfinder",
    "jshole",
    "nuclei"
]

# Optional: tool executable paths
TRUFFLEHOG_PATH = os.getenv("TRUFFLEHOG_PATH", "trufflehog")
GITLEAKS_PATH = os.getenv("GITLEAKS_PATH", "gitleaks")
SECRETFINDER_PATH = os.getenv("SECRETFINDER_PATH", "SecretFinder.py")
LINKFINDER_PATH = os.getenv("LINKFINDER_PATH", "linkfinder")
JSHOLE_PATH = os.getenv("JSHOLE_PATH", "jshole")
NUCLEI_PATH = os.getenv("NUCLEI_PATH", "nuclei")

# -----------------------------
# Response Defaults
# -----------------------------

DEFAULT_STATUS = "completed"
DEFAULT_ERROR_STATUS = "error"

# -----------------------------
# Logging
# -----------------------------

LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO")