from typing import Any, Dict, List, Literal

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

from app.services.ai.deepseek_agent import run_tool_agent


router = APIRouter(prefix="/ai", tags=["ai"])


class ChatMessage(BaseModel):
    role: Literal["user", "assistant", "system"]
    content: str = Field(..., min_length=1)


class AIChatRequest(BaseModel):
    model: str = "deepseek-v4-pro"
    messages: List[ChatMessage]


class AIChatResponse(BaseModel):
    code: int
    msg: str
    data: Dict[str, Any]


@router.post("/chat", response_model=AIChatResponse)
def ai_chat(req: AIChatRequest):
    try:
        result = run_tool_agent(
            user_messages=[m.model_dump() for m in req.messages],
            model=req.model,
        )
        return {"code": 0, "msg": "success", "data": result}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))