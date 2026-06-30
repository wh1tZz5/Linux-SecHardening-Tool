from fastapi import APIRouter, HTTPException, WebSocket, WebSocketDisconnect, Request
from pydantic import BaseModel, Field
from app.services.ssh import ssh_manager  # 确保这个导入路径正确
from typing import Optional, Any
import logging
import asyncio

from app.core.mysql_db import insert_ssh_log, update_ssh_disconnect, insert_command_log
import time

logger = logging.getLogger(__name__)
router = APIRouter(
    prefix="/ssh",
    tags=["SSH安全管理"]
)

# 统一响应模型
class APIResponse(BaseModel):
    code: int = 200
    message: str = "success"
    data: Optional[Any] = None

# 请求模型（保留原有）
class SSHConnectRequest(BaseModel):
    host: str = Field(..., min_length=1, description="服务器IP")
    port: int = Field(22, ge=1, le=65535, description="端口")
    username: str = Field(..., min_length=1, description="用户名")
    password: str = Field(..., min_length=1, description="密码")

class SSHDisconnectRequest(BaseModel):
    session_id: str = Field(..., min_length=1, description="会话ID")

# 1. 原有SSH连接接口（完全保留）
@router.get("/", summary="SSH服务健康检查", response_model=APIResponse)
async def ssh_root():
    return APIResponse(message="SSH API 服务正常")

@router.post("/connect", summary="SSH服务器连接", response_model=APIResponse)
async def connect_ssh(data: SSHConnectRequest, request: Request):
    client_ip = request.client.host
    try:
        session_id = ssh_manager.connect(data.host, data.port, data.username, data.password)
        insert_ssh_log(
            session_id=session_id,
            server_ip=data.host,
            server_port=data.port,
            username=data.username,
            client_ip=client_ip,
            status="connected"
        )
        return APIResponse(message="SSH连接成功", data={"session_id": session_id})
    except Exception as e:
        insert_ssh_log(
            session_id="fail_" + str(time.time()),
            server_ip=data.host,
            server_port=data.port,
            username=data.username,
            client_ip=client_ip,
            status="failed",
            error_msg=str(e)
        )
        logger.error(f"SSH连接失败: {data.host} | {str(e)}")
        raise HTTPException(status_code=400, detail=str(e))

@router.post("/disconnect", summary="SSH断开连接", response_model=APIResponse)
async def disconnect_ssh(data: SSHDisconnectRequest):
    ssh_manager.disconnect(data.session_id)

    update_ssh_disconnect(data.session_id)

    return APIResponse(message="SSH连接已关闭")

@router.get("/sessions", summary="获取活跃会话列表",  response_model=APIResponse)
async def get_sessions():
    ssh_manager.clean_expired_sessions()
    return APIResponse(data=ssh_manager.get_all_sessions())

# 🔥 修复版WebSocket（解决连接不上+命令发不出）
@router.websocket("/ws/{session_id}")
async def ssh_websocket(websocket: WebSocket, session_id: str):
    await websocket.accept()
    print(f"✅ WebSocket连接成功，session_id: {session_id}")

    session = ssh_manager.sessions.get(session_id)
    if not session:
        await websocket.close(code=1008, reason="无效会话")
        print("❌ 无效会话，关闭连接")
        return

    channel = session["channel"]
    print(f"✅ 获取到SSH通道: {channel}")

    # 🔥 关键：创建输出数据队列（给日志记录用，不抢channel数据）
    output_queue = asyncio.Queue()
    # 后端→前端（发送命令结果）
    async def send_to_frontend():
        print("📤 发送协程启动")
        while True:
            try:
                if channel.closed:
                    print("❌ SSH通道已关闭，退出发送协程")
                    break
                if channel.recv_ready():
                    data = channel.recv(4096)
                    print(f"📤 收到SSH数据: {len(data)} 字节")
                    await websocket.send_bytes(data)

                    # 写入队列副本，供日志记录读取
                    await output_queue.put(data)

                await asyncio.sleep(0.01)
            except Exception as e:
                print(f"❌ 发送错误: {e}")
                break

    # 🔥 修复：兼容文本+二进制，不报错（解决接收崩溃问题）
    async def recv_from_frontend():
        print("📥 接收协程启动")
        # 输入缓存：存储用户输入的字符，直到按下回车
        input_buffer = b""
        while True:
            try:
                if channel.closed:
                    print("❌ SSH通道已关闭，退出接收协程")
                    break
                # 正确接收方式：先尝试二进制，再尝试文本
                try:
                    data = await websocket.receive_bytes()
                except:
                    text = await websocket.receive_text()
                    data = text.encode()

                print(f"📥 收到前端数据: {len(data)} 字节, 内容: {data!r}")
                # 🔥 关键：用sendall()确保数据完整发送给SSH服务器
                channel.sendall(data)
                print(f"✅ 数据已发送到SSH服务器")

                # ------------------- 【关键逻辑：缓存输入，仅回车时记录日志】 -------------------
                # 1. 处理退格键（\x7f）：删除缓存最后一个字符
                if data == b"\x7f":
                    if input_buffer:
                        input_buffer = input_buffer[:-1]
                    continue  # 退格不记录日志，直接跳过

                # 2. 处理回车/换行符（命令结束标志）
                # 常见换行符：\r、\n、\r\n
                if b"\r" in data or b"\n" in data:
                    # 把当前数据加入缓存，再去掉换行符，得到完整命令
                    input_buffer += data
                    # 解析命令：去掉前后空白、换行符
                    command = input_buffer.decode('utf-8', errors='ignore').strip()
                    # 清空缓存，准备下一条命令
                    input_buffer = b""

                    # 3. 只有非空命令才记录日志（过滤纯回车）
                    if command:
                        print(f"📝 完整命令输入完成：{command!r}")
                        start_time = time.time()
                        output_data = b""
                        # 从队列读取输出（设置超时，避免阻塞）
                        try:
                            while True:
                                chunk = await asyncio.wait_for(output_queue.get(), timeout=0.5)
                                output_data += chunk
                        except asyncio.TimeoutError:
                            pass  # 超时表示没有更多输出了

                        # 计算耗时和解析输出
                        duration = round(time.time() - start_time, 3)
                        output_str = output_data.decode('utf-8', errors='ignore')

                        # ✅ 写入完整日志（包含output和duration）
                        insert_command_log(
                            session_id=session_id,
                            command=command,
                            output=output_str,
                            status="success",
                            duration=duration
                        )
                        print(f"[MySQL] ✅ 终端命令日志写入成功：{command[:20]}... 耗时: {duration}s")
                else:
                    # 4. 非回车字符，加入缓存，等待用户继续输入
                    input_buffer += data

            except Exception as e:
                print(f"❌ 接收/发送错误: {e}")
                # 记录失败日志（如果缓存里有未完成的命令）
                if input_buffer:
                    command = input_buffer.decode('utf-8', errors='ignore').strip()
                    if command:
                        insert_command_log(
                            session_id=session_id,
                            command=command,
                            output=str(e),
                            status="failed",
                            duration=0
                        )
                break

    # 并行运行双向流
    await asyncio.gather(send_to_frontend(), recv_from_frontend())
    print("🔌 WebSocket连接关闭")
    await websocket.close()