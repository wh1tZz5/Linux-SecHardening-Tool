from pydantic_settings import BaseSettings
from typing import List, Set
from pydantic import Field


class Settings(BaseSettings):
    # 应用基础配置
    APP_TITLE: str = "SIS·Security Information Systems"
    APP_DESCRIPTION: str = "Linux加固 | SSH连接 | 命令执行 | 安全审计"
    APP_VERSION: str = "v2.0"

    # 跨域配置
    CORS_ALLOW_ORIGINS: List[str] = ["http://localhost:5173", "http://127.0.0.1:5173"]
    CORS_ALLOW_CREDENTIALS: bool = True
    CORS_ALLOW_METHODS: List[str] = ["GET", "POST", "OPTIONS"]
    CORS_ALLOW_HEADERS: List[str] = ["Content-Type", "Authorization"]
    CORS_MAX_AGE: int = 3600

    # SSH 安全配置
    SSH_DEFAULT_PORT: int = 22
    SSH_CONNECT_TIMEOUT: int = 15
    SSH_EXEC_TIMEOUT: int = 30
    SESSION_EXPIRE_SECONDS: int = 600

    # 日志配置
    LOG_LEVEL: str = "INFO"

    # 命令白名单
    SSH_COMMAND_WHITELIST: Set[str] = {"*"}

    model_config = {"case_sensitive": True}

settings = Settings()