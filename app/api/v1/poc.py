# -*- coding: UTF-8 -*-

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from typing import Optional, Any

from app.services.poc import poc_manager


router = APIRouter(
    prefix="/poc",
    tags=["漏洞POC探测"]
)


class APIResponse(BaseModel):
    code: int = 200
    message: str = "success"
    data: Optional[Any] = None


class PocRequest(BaseModel):
    session_id: str
    target: Optional[str] = None


@router.post(path="/log4j", summary="Log4j2 RCE 探测", response_model=APIResponse)
async def poc_log4j(req: PocRequest):
    try:
        result = poc_manager.run_log4j(req.session_id, req.target)
        return APIResponse(message="Log4j2 RCE 探测完成", data={"output": result})
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(status_code=500, detail=f"Log4j2 探测失败: {exc}")


@router.post(path="/spring4shell", summary="Spring4Shell 探测", response_model=APIResponse)
async def poc_spring4shell(req: PocRequest):
    try:
        result = poc_manager.run_spring4shell(req.session_id, req.target)
        return APIResponse(message="Spring4Shell 探测完成", data={"output": result})
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(status_code=500, detail=f"Spring4Shell 探测失败: {exc}")


@router.post(path="/fastjson", summary="Fastjson 反序列化探测", response_model=APIResponse)
async def poc_fastjson(req: PocRequest):
    try:
        result = poc_manager.run_fastjson(req.session_id, req.target)
        return APIResponse(message="Fastjson 探测完成", data={"output": result})
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(status_code=500, detail=f"Fastjson 探测失败: {exc}")


@router.post(path="/shiro550", summary="Shiro-550 探测", response_model=APIResponse)
async def poc_shiro550(req: PocRequest):
    try:
        result = poc_manager.run_shiro550(req.session_id, req.target)
        return APIResponse(message="Shiro-550 探测完成", data={"output": result})
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(status_code=500, detail=f"Shiro-550 探测失败: {exc}")


@router.post(path="/nacos", summary="Nacos 未授权探测", response_model=APIResponse)
async def poc_nacos(req: PocRequest):
    try:
        result = poc_manager.run_nacos(req.session_id, req.target)
        return APIResponse(message="Nacos 未授权探测完成", data={"output": result})
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(status_code=500, detail=f"Nacos 探测失败: {exc}")