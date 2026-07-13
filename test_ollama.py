import os
from dotenv import load_dotenv
from openai import OpenAI

load_dotenv(dotenv_path="/home/kali/agent-mapper/.env")

client = OpenAI(
    base_url=os.getenv("OLLAMA_BASE_URL"),
    api_key=os.getenv("OLLAMA_API_KEY")
)

print("Sending request...")

response = client.chat.completions.create(
    model=os.getenv("OLLAMA_MODEL"),
    messages=[{"role": "user", "content": "Say hello in one sentence."}],
    timeout=60
)

print(response.choices[0].message.content)

