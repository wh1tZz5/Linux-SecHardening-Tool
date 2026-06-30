from fastapi.middleware.cors import CORSMiddleware
from fastapi import Request
from fastapi.responses import JSONResponse
from app.core.config import settings
import logging

logging.basicConfig(level=settings.LOG_LEVEL.upper())
logger = logging.getLogger(__name__)

def register_middlewares(app):
    # CORS跨域
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.CORS_ALLOW_ORIGINS,
        allow_credentials=settings.CORS_ALLOW_CREDENTIALS,
        allow_methods=settings.CORS_ALLOW_METHODS,
        allow_headers=settings.CORS_ALLOW_HEADERS,
        max_age=settings.CORS_MAX_AGE,
    )
    # 全局异常
    @app.middleware("http")
    async def global_exception_handler(request: Request, call_next):
        try:
            return await call_next(request)
        except Exception as e:
            logger.error(f"全局异常: {str(e)}")
            return JSONResponse(status_code=500, content={"code": 500, "message": "服务器内部错误"})