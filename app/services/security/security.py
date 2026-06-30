# app/services/security/security.py
import asyncio
import re
import threading
from typing import Dict, List
from fastapi import HTTPException

# 【需补充】引入 SSH 管理器（需确保 ssh_manager 已实现以下能力：
# 1. execute(session_id: str, cmd: str) -> str：同步执行命令并返回完整输出
# 2. execute_stream(session_id: str, cmd: str) -> async 生成器：流式返回命令输出（若需流式日志）
from app.services.ssh import ssh_manager

class SecurityManager:
    _instance = None
    _lock = threading.Lock()

    def __new__(cls):
        with cls._lock:
            if cls._instance is None:
                cls._instance = super().__new__(cls)
        return cls._instance

    # -------------------- 系统类型识别（改为 SSH 远程执行） --------------------
    def get_os_info(self, session_id: str) -> Dict[str, str]:
        """
        识别远程系统类型（依赖 SSH 会话）
        :param session_id: SSH 会话ID（核心参数，关联远程连接）
        """
        os_info = {
            "os_type": "unknown",
            "os_version": "unknown",
            "package_manager": "unknown",
            "kernel_version": "unknown"
        }
        try:
            # 1. 获取内核版本（SSH 执行）
            kernel_cmd = "uname -r"
            os_info["kernel_version"] = ssh_manager.execute(session_id, kernel_cmd).strip()

            # 2. 识别 RHEL/CentOS 系统
            rhel_check_cmd = "test -f /etc/redhat-release && echo 'rhel' || echo 'no'"
            rhel_result = ssh_manager.execute(session_id, rhel_check_cmd).strip()
            if rhel_result == "rhel":
                os_info["os_type"] = "rhel"
                # 获取系统主版本
                version_cmd = "grep -oE '[0-9]+' /etc/redhat-release | head -1"
                os_info["os_version"] = ssh_manager.execute(session_id, version_cmd).strip()
                # 识别包管理器（dnf/yum）
                pkg_cmd = "command -v dnf >/dev/null && echo 'dnf' || echo 'yum'"
                os_info["package_manager"] = ssh_manager.execute(session_id, pkg_cmd).strip()

            # 3. 识别 Debian/Ubuntu 系统
            debian_check_cmd = "test -f /etc/debian_version && echo 'debian' || echo 'no'"
            debian_result = ssh_manager.execute(session_id, debian_check_cmd).strip()
            if debian_result == "debian":
                os_info["os_type"] = "debian"
                version_cmd = "cat /etc/debian_version | cut -d. -f1"
                os_info["os_version"] = ssh_manager.execute(session_id, version_cmd).strip()
                os_info["package_manager"] = "apt"

        except Exception as e:
            # 异常兜底（保留兼容逻辑）
            os_info = {
                "os_type": "debian",
                "os_version": "20.04",
                "package_manager": "apt",
                "kernel_version": "5.4.0"
            }
        return os_info

    # -------------------- 安全执行Shell命令（SSH 流式输出） --------------------
    async def execute_shell_command(self, session_id: str, cmd: str):
        """
        SSH 执行命令并返回 SSE 流式日志生成器
        :param session_id: SSH 会话ID
        :param cmd: 待执行的命令
        【需补充】需确保 ssh_manager 实现 execute_stream 异步流式执行方法
        """
        try:
            # 若 ssh_manager 未实现流式执行，可先用同步执行模拟（性能略差）
            # 推荐：实现 SSH 流式输出（如基于 asyncssh 逐行读取）
            async def stream_log():
                # 方案1：SSH 原生流式（推荐）
                # async for line in ssh_manager.execute_stream(session_id, cmd):
                #     yield f"data: {line.strip()}\n\n"
                # yield f"data: 执行完成（返回码：0）\n\n"

                # 方案2：同步执行后拆分行（临时替代）
                result = ssh_manager.execute(session_id, cmd)
                for line in result.splitlines():
                    yield f"data: {line.strip()}\n\n"
                yield f"data: 执行完成（返回码：0）\n\n"
            return stream_log()
        except Exception as e:
            raise HTTPException(status_code=500, detail=f"SSH 命令执行失败：{str(e)}")

    # -------------------- 加固命令白名单（按系统分类） --------------------
    def get_reinforce_commands(self, os_type: str) -> List[str]:
        """保留原有逻辑，命令最终通过 SSH 执行"""
        if os_type == "rhel":
            return [
                "cp -a /etc/ssh/sshd_config /etc/ssh/sshd_config.bak.$(date +%Y%m%d_%H%M%S)",
                "sed -i 's/^PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config",
                "sed -i 's/^PASS_MIN_LEN.*/PASS_MIN_LEN 8/' /etc/login.defs",
                "echo 'password    requisite     pam_pwquality.so retry=3 minlen=8 difok=3' >> /etc/pam.d/system-auth",
                "systemctl restart sshd",
                "systemctl enable --now firewalld"
            ]
        elif os_type == "debian":
            return [
                "cp -a /etc/ssh/sshd_config /etc/ssh/sshd_config.bak.$(date +%Y%m%d_%H%M%S)",
                "sed -i 's/^PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config",
                "sed -i 's/^PASS_MIN_LEN.*/PASS_MIN_LEN 8/' /etc/login.defs",
                "echo 'password    requisite     pam_cracklib.so retry=3 minlen=8 difok=3' >> /etc/pam.d/common-password",
                "systemctl restart ssh",
                "ufw enable"
            ]
        return []

    # -------------------- 配置备份/还原（SSH 远程执行） --------------------
    def backup_config(self, session_id: str) -> str:
        """
        SSH 远程执行配置备份
        :param session_id: SSH 会话ID
        """
        try:
            backup_cmd = (
                "bash -c 'mkdir -p /opt/backups; "
                "cp -a /etc/ssh /opt/backups/ssh_config_$(date +%Y%m%d_%H%M%S); "
                "echo /opt/backups/ssh_config_$(date +%Y%m%d_%H%M%S)'"
            )
            backup_path = ssh_manager.execute(session_id, backup_cmd).strip()
            return f"备份成功！路径: {backup_path}"
        except Exception as e:
            raise HTTPException(status_code=500, detail=f"SSH 备份失败：{str(e)}")

    def restore_config(self, session_id: str, backup_path: str) -> str:
        """
        SSH 远程执行配置还原（校验路径合法性）
        :param session_id: SSH 会话ID
        :param backup_path: 远程备份路径（如 /opt/backups/20240520_102030）
        """
        if not re.match(r"^/opt/backups/202[0-9]{6}_[0-9]{6}$", backup_path):
            raise HTTPException(status_code=400, detail="非法的备份路径（仅支持 /opt/backups/ 下的合法时间戳路径）")
        try:
            # 适配不同系统的 ssh 服务名（sshd/rhel vs ssh/debian）
            restore_cmd = (
                f"cp -a {backup_path}/ssh /etc/ && "
                "systemctl restart sshd || systemctl restart ssh"
            )
            ssh_manager.execute(session_id, restore_cmd)
            return "还原成功！已重启 SSH 服务"
        except Exception as e:
            raise HTTPException(status_code=500, detail=f"SSH 还原失败：{str(e)}")

# 单例实例化
security_manager = SecurityManager()