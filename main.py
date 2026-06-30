# main.py
import os
from pathlib import Path
from dotenv import load_dotenv

BASE_DIR = Path(__file__).resolve().parent
load_dotenv(BASE_DIR / ".env", override=True)

print("ENV FILE:", BASE_DIR / ".env")
print("DEEPSEEK_MODEL =", os.getenv("DEEPSEEK_MODEL"))
print("HEXSTRIKE_BASE_URL =", os.getenv("HEXSTRIKE_BASE_URL"))



from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse

from app.core.config import settings
from app.core.middleware import register_middlewares

from app.api.v1 import api_router
from app.services.ssh.ssh import ssh_manager





import atexit

print("=== 调试：settings配置 ===")
print("APP_TITLE:", settings.APP_TITLE)
print("APP_DESCRIPTION:", settings.APP_DESCRIPTION)
print("APP_VERSION:", settings.APP_VERSION)
print("=========================")

import time
import json
from app.core.mysql_db import insert_api_log
# 初始化应用
app = FastAPI(
    title=settings.APP_TITLE,
    description=settings.APP_DESCRIPTION,
    version=settings.APP_VERSION
)
# 注册中间件
register_middlewares(app)

app.include_router(api_router)

# 全局参数校验异常处理（
@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError):

    return JSONResponse(
        status_code=422,
        content={
            "code": 422,
            "message": "请求参数格式错误",
            "detail": exc.errors(),
            "request_body": exc.body
        }
    )

# 健康检查
@app.get("/", summary="系统健康检查")
async def root():
    return {"code": 200, "message": "Linux加固平台API服务正常"}

# 进程退出关闭所有SSH连接
@atexit.register
def close_all_ssh():
    for session in list(ssh_manager.sessions.keys()):
        ssh_manager.disconnect(session)

@app.middleware("http")
async def api_log_middleware(request: Request, call_next):
    start_time = time.time()
    client_ip = request.client.host
    method = request.method
    url = str(request.url)
    session_id = None
    request_params = None

    # 尝试获取请求体中的session_id和参数
    try:
        body = await request.json()
        session_id = body.get("session_id")
        request_params = json.dumps(body, ensure_ascii=False)
    except:
        # 处理非JSON请求（如GET/表单）
        request_params = str(request.query_params)

    # 执行请求
    response = await call_next(request)
    duration = round(time.time() - start_time, 3)
    status_code = response.status_code

    # ✅ 写入接口访问日志
    insert_api_log(url, method, session_id, request_params, status_code, duration, client_ip)
    return response
# 放在main.py的最后一行
if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "main:app",
        host="0.0.0.0",
        port=8000,
        reload=True
    )