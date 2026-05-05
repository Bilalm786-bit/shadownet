"""
ShadowNet — Core Configuration
Loads all settings from environment variables / .env file.
"""

from pydantic_settings import BaseSettings
from pydantic import Field
from typing import List
import json


class Settings(BaseSettings):
    # ─── App ────────────────────────────────────────────
    app_name: str = "ShadowNet"
    app_version: str = "2.0.0"
    debug: bool = True
    secret_key: str = "change-this-to-a-random-64-char-string"
    cors_origins: List[str] = ["http://localhost:5173", "http://localhost:3000"]

    # ─── Database (SQLite dev / PostgreSQL prod) ───────
    database_url: str = "sqlite+aiosqlite:///./shadownet.db"

    # ─── Neo4j ──────────────────────────────────────────
    neo4j_uri: str = "bolt://localhost:7687"
    neo4j_user: str = "neo4j"
    neo4j_password: str = "shadownet_graph_2024"

    # ─── Elasticsearch ──────────────────────────────────
    elasticsearch_url: str = "http://localhost:9200"

    # ─── Redis ──────────────────────────────────────────
    redis_url: str = "redis://localhost:6379/0"

    # ─── MinIO / S3 ─────────────────────────────────────
    minio_endpoint: str = "localhost:9000"
    minio_access_key: str = "shadownet"
    minio_secret_key: str = "shadownet_minio_2024"
    minio_bucket: str = "shadownet-evidence"

    # ─── OpenAI (ChatGPT) ──────────────────────────────
    openai_api_key: str = ""
    openai_model: str = "gpt-4o"

    # ─── OSINT API Keys ─────────────────────────────────
    virustotal_api_key: str = ""
    tavily_api_key: str = ""
    google_search_api_key: str = ""
    google_search_cx: str = ""  # Custom Search Engine ID
    censys_api_id: str = ""
    censys_api_secret: str = ""
    stealth_browser_url: str = ""

    # ─── Cursor Cloud Agents API ────────────────────────
    cursor_api_key: str = ""
    cursor_api_base: str = "https://api.cursor.com"

    # ─── JWT ────────────────────────────────────────────
    jwt_secret_key: str = "change-this-jwt-secret-key"
    jwt_algorithm: str = "HS256"
    jwt_access_token_expire_minutes: int = 30
    jwt_refresh_token_expire_days: int = 7

    model_config = {
        "env_file": ("../.env", ".env", "../../.env"),
        "env_file_encoding": "utf-8",
        "case_sensitive": False,
        "extra": "ignore",
    }


# Singleton settings instance
settings = Settings()
