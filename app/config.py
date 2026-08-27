import os
from dotenv import load_dotenv

load_dotenv()


class Settings:
    PROJECT_NAME: str = "Halyx"
    PROJECT_DESCRIPTION: str = (
        "Runtime Security Gateway for Autonomous AI Agents — "
        "protects against indirect prompt injection and unauthorized tool execution."
    )
    VERSION: str = "0.1.0"
    DEBUG: bool = os.getenv("HALYX_DEBUG", "true").lower() == "true"
    ENV: str = os.getenv("HALYX_ENV", "development")

    CORS_ORIGINS: list[str] = os.getenv("HALYX_CORS_ORIGINS", "*").split(",")


settings = Settings()