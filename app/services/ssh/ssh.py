import uuid
import paramiko
import threading
from datetime import datetime, timedelta
from app.core.config import settings
from app.core.mysql_db import update_ssh_disconnect  # 【改动点1：导入数据库更新函数】
import logging
import time
import re

logger = logging.getLogger(__name__)

class SSHManager:
    _instance = None
    _lock = threading.Lock()

    def __new__(cls):
        with cls._lock:
            if cls._instance is None:
                cls._instance = super().__new__(cls)
                cls._instance.sessions = {}
        return cls._instance

    def __init__(self):
        if not hasattr(self, "sessions"):
            self.sessions = {}
        # 启动后台僵尸会话清理线程（守护线程，不阻塞主程序）】
        self._cleanup_thread = threading.Thread(target=self._cleanup_zombie_sessions, daemon=True)
        self._cleanup_thread.start()

    def _check_command_security(self, command: str) -> bool:
        if "*" in settings.SSH_COMMAND_WHITELIST:
            return True
        else:
            cmd = command.strip().split()[0] if command.strip() else ""
            allowed = cmd in settings.SSH_COMMAND_WHITELIST
            if not allowed:
                logger.warning(f"命令被拦截: {command}")
            return allowed

    def connect(self, host: str, port: int, username: str, password: str):
        try:
            ssh = paramiko.SSHClient()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            ssh.connect(
                hostname=host,
                port=port,
                username=username,
                password=password,
                timeout=10
            )
            channel = ssh.invoke_shell(term='xterm', width=100, height=30)
            channel.settimeout(0)
            session_id = str(uuid.uuid4())
            now = datetime.now()
            expire_time = now + timedelta(seconds=settings.SESSION_EXPIRE_SECONDS)
            self.sessions[session_id] = {
                "ssh": ssh,
                "channel": channel,
                "host": host,
                "username": username,
                "create_time": now.strftime("%Y-%m-%d %H:%M:%S"),
                "expire_time": expire_time.strftime("%Y-%m-%d %H:%M:%S"),
                "last_active": time.time()  # 【改动点3：新增会话最后活跃时间戳】
            }
            logger.info(f"SSH交互式连接成功: {host}")
            return session_id
        except Exception as e:
            logger.error(f"SSH连接失败: {str(e)}")
            raise Exception(f"连接失败: {str(e)}")

    def execute(self, session_id: str, command: str) -> str:
        if session_id not in self.sessions:
            raise Exception("会话不存在")
        self.sessions[session_id]["last_active"] = time.time()
        channel = self.sessions[session_id]["channel"]

        # 1. 清空旧缓冲区，避免脏数据干扰
        while channel.recv_ready():
            channel.recv(4096)

        # 2. 发送命令 + 换行
        channel.send(command + "\n")

        # 3. 循环读取输出，直到无数据
        output = ""
        while True:
            if channel.recv_ready():
                chunk = channel.recv(4096).decode("utf-8", errors="ignore")
                output += chunk
            else:
                time.sleep(0.1)
                if not channel.recv_ready():
                    break

        # 4. 关键清理步骤
        # 过滤颜色/控制字符（改为实例调用静态方法）
        cleaned = self.clean_ansi_escape(output)
        # 按行分割，过滤掉命令本身和提示符
        lines = [line.strip() for line in cleaned.splitlines() if line.strip()]
        # 找到命令执行后的第一行有效输出（跳过命令回显和提示符）
        result = ""
        for line in lines:
            # 过滤掉命令本身（比如hostname命令的回显）和提示符（包含$的行）
            if command in line or "$" in line or "~" in line:
                continue
            result = line
            break

        return result.strip()

    # 修正缩进：作为类的静态方法（核心修复）
    @staticmethod
    def clean_ansi_escape(text: str) -> str:
        """过滤ANSI转义序列（颜色/光标控制字符）"""
        ansi_escape = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')
        return ansi_escape.sub('', text)

    def disconnect(self, session_id: str):
        session = self.sessions.get(session_id)
        if not session:
            return True
        try:
            if "channel" in session:
                session["channel"].close()
            session["ssh"].close()
        except Exception as e:
            logger.warning(f"关闭会话异常: {str(e)}")
        finally:
            self.sessions.pop(session_id, None)
            # 【改动点5：关键！断开时强制更新数据库状态】
            update_ssh_disconnect(session_id)
            logger.info(f"SSH断开: {session_id}")
        return True

    def get_all_sessions(self) -> list:
        with self._lock:
            return [
                {
                    "session_id": sid[:8] + "****",
                    "host": info["host"],
                    "username": info["username"],
                    "create_time": info["create_time"],
                    "expire_time": info["expire_time"],
                }
                for sid, info in self.sessions.items()
            ]

    def clean_expired_sessions(self):
        with self._lock:
            now = datetime.now()
            expired = [
                sid for sid, info in self.sessions.items()
                if now > datetime.strptime(info["expire_time"], "%Y-%m-%d %H:%M:%S")
            ]
            for sid in expired:
                self.disconnect(sid)

    # 【改动点6：新增后台清理僵尸会话方法（优化异常处理）】
    def _cleanup_zombie_sessions(self):
        while True:
            time.sleep(10)  # 每10秒检查一次（可调整）
            with self._lock:
                current_time = time.time()
                zombie_sessions = []
                for session_id, info in list(self.sessions.items()):
                    try:
                        channel = info["channel"]
                        transport = channel.get_transport()
                        # 判断僵尸：SSH通道已断开 或 超过60秒无任何操作
                        if (transport is None or not transport.is_active()) or (current_time - info["last_active"] > 600):
                            zombie_sessions.append(session_id)
                    except Exception as e:
                        logger.warning(f"检查会话 {session_id} 状态异常: {str(e)}")
                        zombie_sessions.append(session_id)
                # 自动断开僵尸会话（触发数据库更新）
                for sid in zombie_sessions:
                    logger.warning(f"清理僵尸SSH会话: {sid}")
                    self.disconnect(sid)


    def execute_full(self, session_id: str, command: str) -> str:
        """在已建立的SSH会话中执行命令，返回输出"""
        if session_id not in self.sessions:
            raise Exception("会话不存在")
        # 【改动点4：刷新会话活跃时间，避免正常会话被误判为僵尸】
        self.sessions[session_id]["last_active"] = time.time()
        channel = self.sessions[session_id]["channel"]
        channel.send(command + "\n")
        output = ""
        while True:
            if channel.recv_ready():
                output += channel.recv(1024).decode("utf-8", errors="ignore")
            else:
                break
        return output



# 实例化（此时类结构正常，线程可正常创建）
ssh_manager = SSHManager()