from typing import List

from decouple import config
from pydantic_settings  import BaseSettings
from pydantic import AnyHttpUrl
from typing import ClassVar
import os


class Settings(BaseSettings):
    ROOT_DIR: ClassVar[str] = os.path.dirname(os.path.abspath(__file__))
    ATTACK_MODEL_PATH: ClassVar[str] = os.path.join(ROOT_DIR, '../util', 'attack_model.pkl')
    ATTACK_SCALER_PATH: ClassVar[str] = os.path.join(ROOT_DIR, '../util', 'attack_scaler.pkl')
    SEVERITY_MODEL_PATH: ClassVar[str] = os.path.join(ROOT_DIR, '../util', 'severity_model.pkl')
    SEVERITY_SCALER_PATH: ClassVar[str] = os.path.join(ROOT_DIR, '../util', 'severity_scaler.pkl')

    API_V1_STR: str = "/api/v1"
    JWT_SECRET_KEY: str = config("JWT_SECRET_KEY", cast=str)
    JWT_REFRESH_SECRET_KEY: str = config("JWT_REFRESH_SECRET_KEY", cast=str)
    ALGORITHM: str = 'HS256'
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 60
    REFRESH_TOKEN_EXPIRE_MINUTES: int = 60 * 24 * 7   # 7 days
    BACKEND_CORS_ORIGINS: List[AnyHttpUrl] = [
        "http://localhost:3000"
    ]
    PROJECT_NAME: str = "CyberGuard AI"
    
    # Database
    MONGO_CONNECTION_STRING: str = config("MONGO_CONNECTION_STRING", cast=str)
    
    class Config:
        case_sensitive = True
        
settings = Settings()
