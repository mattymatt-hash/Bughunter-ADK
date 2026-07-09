from dotenv import load_dotenv
import os

load_dotenv()

APP_NAME = os.getenv("APP_NAME", "BugHunter ADK")
MODEL = os.getenv("MODEL", "gemini-2.5-pro")
GOOGLE_API_KEY = os.getenv("GOOGLE_API_KEY")
DATABASE = os.getenv("DATABASE", "database/bughunter.db")