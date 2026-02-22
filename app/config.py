import os
from dotenv import load_dotenv

load_dotenv()

class Config:
    MONGO_URI = os.getenv("MONGO_URI")
    JWT_SECRET_KEY = os.getenv("JWT_SECRET_KEY")

    if not MONGO_URI:
        raise ValueError("❌ MONGO_URI is not set in the .env file")

    if not JWT_SECRET_KEY:
        raise ValueError("❌ JWT_SECRET_KEY is not set in the .env file")
