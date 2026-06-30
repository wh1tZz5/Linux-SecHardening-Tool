# -*- coding: UTF-8 -*-
"""
@Project  ：Linux加固
@File     ：__init__.py
@Author   ：QAQ
@Date     ：2026/5/9 09:26
@Desc     ：

"""
# app/api/v1/__init__.py
from fastapi import APIRouter

# 导入两个子路由
from .ssh import router as ssh_router
from .security import router as security_router
from .poc import router as poc_router
from .ai import router as ai_router


# 创建 v1 版本总路由（统一前缀 /api/v1）
api_router = APIRouter(prefix="/api/v1")

api_router.include_router(ssh_router)
api_router.include_router(security_router)
api_router.include_router(poc_router)
api_router.include_router(ai_router)


# 导出供 main.py 引入
__all__ = ["api_router"]