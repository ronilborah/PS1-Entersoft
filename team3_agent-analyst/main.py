import sys
import os
import logging
from pathlib import Path

# 1. Fix the path so Python finds your 'services' folder
sys.path.append(os.path.abspath(os.path.dirname(__file__)))

# 2. Turn on INFO logs so you can see Ollama's brain working!
logging.basicConfig(level=logging.INFO)

# 3. Load environment variables
from dotenv import load_dotenv
load_dotenv()




# 4. Start the FastAPI app
from fastapi import FastAPI
from routes import router

app = FastAPI(
    title="Agent Analyst",
    version="1.0.0"
)

app.include_router(router)

if __name__ == "__main__":
    import uvicorn

    port = int(os.environ.get("PORT", "8003"))

    uvicorn.run(
        "main:app",
        host="0.0.0.0",
        port=port,
        reload=True,
    )
