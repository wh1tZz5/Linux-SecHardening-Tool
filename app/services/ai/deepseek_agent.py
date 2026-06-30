import json
import os
import requests
from typing import Any, Dict, List

from app.services.ai.hexstrike_client import HexStrikeClient

DEEPSEEK_URL = "https://api.deepseek.com/chat/completions"

# 总预算控制
MAX_TOOL_ROUNDS = 8
MAX_TOOL_CALLS_TOTAL = 6

# 单工具重复调用限制
MAX_REPEAT_PER_TOOL = 2


class DeepSeekAgentError(Exception):
    pass


def _deepseek_chat(messages: List[Dict[str, Any]], tools: List[Dict[str, Any]], model: str) -> Dict[str, Any]:
    api_key = os.getenv("DEEPSEEK_API_KEY", "").strip()
    if not api_key:
        raise DeepSeekAgentError("DEEPSEEK_API_KEY 未配置")

    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json",
    }

    payload = {
        "model": model,
        "messages": messages,
        "tools": tools,
        "tool_choice": "auto",
        "stream": False,
        "temperature": 0.2,
    }

    r = requests.post(DEEPSEEK_URL, headers=headers, json=payload, timeout=None)
    r.raise_for_status()
    return r.json()


def run_tool_agent(user_messages: List[Dict[str, str]], model: str | None = None) -> Dict[str, Any]:
    model_name = model or os.getenv("DEEPSEEK_MODEL", "deepseek-v4-pro")
    hexstrike = HexStrikeClient(os.getenv("HEXSTRIKE_BASE_URL", "http://127.0.0.1:8888"), timeout=None)

    tools = [
        {
            "type": "function",
            "function": {
                "name": "hexstrike_health",
                "description": "检查 HexStrike 服务健康状态",
                "parameters": {"type": "object", "properties": {}, "required": []},
            },
        },
        {
            "type": "function",
            "function": {
                "name": "hexstrike_analyze_target",
                "description": "对目标做智能分析",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "target": {"type": "string"},
                        "analysis_type": {"type": "string", "default": "comprehensive"},
                    },
                    "required": ["target"],
                },
            },
        },
        {
            "type": "function",
            "function": {
                "name": "hexstrike_select_tools",
                "description": "根据任务选择工具",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "target": {"type": "string"},
                        "task": {"type": "string"},
                    },
                    "required": ["target", "task"],
                },
            },
        },
        {
            "type": "function",
            "function": {
                "name": "hexstrike_run_command",
                "description": "执行单条安全命令（谨慎）",
                "parameters": {
                    "type": "object",
                    "properties": {"command": {"type": "string"}},
                    "required": ["command"],
                },
            },
        },
    ]

    system_prompt = (
        "你是安全助手。必须先用工具获取事实，不得编造。"
        "重要约束："
        "1) 工具调用总次数最多 6 次；"
        "2) 同一工具不要重复超过 2 次；"
        "3) 一旦获得足够证据，请立刻给最终结论；"
        "4) 若信息不足，明确说明不足点并给最小下一步建议。"
    )

    messages: List[Dict[str, Any]] = [{"role": "system", "content": system_prompt}]
    messages.extend(user_messages)

    tool_calls_total = 0
    tool_call_count: Dict[str, int] = {}

    for _ in range(MAX_TOOL_ROUNDS):
        ds = _deepseek_chat(messages, tools, model_name)
        msg = ds["choices"][0]["message"]
        messages.append(msg)

        tool_calls = msg.get("tool_calls") or []
        if not tool_calls:
            return {
                "output": msg.get("content", ""),
                "model": model_name,
                "provider": "deepseek+hexstrike",
                "tool_calls_used": tool_calls_total,
            }

        for tc in tool_calls:
            if tool_calls_total >= MAX_TOOL_CALLS_TOTAL:
                # 强制收敛
                messages.append(
                    {
                        "role": "system",
                        "content": "工具预算已接近上限，请基于已有结果立即输出最终结论，禁止继续调用工具。",
                    }
                )
                break

            fn = tc["function"]["name"]
            tool_call_count[fn] = tool_call_count.get(fn, 0)

            if tool_call_count[fn] >= MAX_REPEAT_PER_TOOL:
                messages.append(
                    {
                        "role": "tool",
                        "tool_call_id": tc["id"],
                        "name": fn,
                        "content": json.dumps(
                            {"warning": f"{fn} 已达到重复调用上限，请基于现有结果总结"},
                            ensure_ascii=False,
                        ),
                    }
                )
                continue

            tool_call_count[fn] += 1
            tool_calls_total += 1

            args = json.loads(tc["function"].get("arguments", "{}") or "{}")
            try:
                if fn == "hexstrike_health":
                    result = hexstrike.health()
                elif fn == "hexstrike_analyze_target":
                    result = hexstrike.analyze_target(
                        target=args["target"],
                        analysis_type=args.get("analysis_type", "comprehensive"),
                    )
                elif fn == "hexstrike_select_tools":
                    result = hexstrike.select_tools(target=args["target"], task=args["task"])
                elif fn == "hexstrike_run_command":
                    result = hexstrike.run_command(command=args["command"])
                else:
                    result = {"error": f"unknown tool: {fn}"}
            except Exception as e:
                result = {"error": f"{fn} 调用失败: {str(e)}"}

            messages.append(
                {
                    "role": "tool",
                    "tool_call_id": tc["id"],
                    "name": fn,
                    "content": json.dumps(result, ensure_ascii=False),
                }
            )

    return {
        "output": "工具调用轮次达到上限，请缩小任务范围后重试。",
        "model": model_name,
        "provider": "deepseek+hexstrike",
        "tool_calls_used": tool_calls_total,
    }