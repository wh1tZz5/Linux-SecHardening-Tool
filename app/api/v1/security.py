# app/api/v1/security.py
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from app.services.ssh import ssh_manager
from app.core.mysql_db import insert_command_log  # 和 ssh.py 一样导入
import time
from typing import Optional, Any

router = APIRouter(
    prefix="/security",
    tags=["安全检查与加固"]
)

class APIResponse(BaseModel):
    code: int = 200
    message: str = "success"
    data: Optional[Any] = None

class SessionRequest(BaseModel):
    session_id: str

# ------------------- 1. 系统基本信息 -------------------
@router.post("/system-info", summary="系统基本信息检查", response_model=APIResponse)
async def system_info(req: SessionRequest):
    start_time = time.time()
    cmd = """
    TERM=dumb echo "==================== 系统基础信息 ====================" 2>&1 &&
    TERM=dumb hostname 2>&1 && echo -e "\n--- 系统版本 ---" 2>&1 &&
    TERM=dumb cat /etc/os-release 2>&1 && echo -e "\n--- 内核版本 ---" 2>&1 &&
    TERM=dumb uname -r 2>&1 && echo -e "\n--- 系统架构 ---" 2>&1 &&
    TERM=dumb uname -m 2>&1 && echo -e "\n--- IP 地址 ---" 2>&1 &&
    TERM=dumb ip addr | grep inet | grep -v "inet6" | grep -v "127.0.0.1" 2>&1 && echo -e "\n--- CPU 信息 ---" 2>&1 &&
    TERM=dumb cat /proc/cpuinfo | grep 'model name' | cut -f2 -d: | uniq 2>&1 && echo -e "\n--- 内存总量 ---" 2>&1 &&
    TERM=dumb free -h | awk 'NR==2{print $2}' 2>&1 && echo -e "\n--- 磁盘总量 ---" 2>&1 &&
    TERM=dumb df -h --total | grep total | awk '{print $2}' 2>&1 && echo -e "\n--- 运行时间 ---" 2>&1 &&
    TERM=dumb uptime 2>&1 && echo -e "\n--- 系统时间 ---" 2>&1 &&
    TERM=dumb date 2>&1
    """
    try:
        # 调试：打印 ssh_manager 类型
        print("DEBUG: ssh_manager 类型:", type(ssh_manager))
        print("DEBUG: session_id:", req.session_id)
        print("DEBUG: cmd:", cmd[:50])  # 打印前50个字符，避免日志过长

        result = ssh_manager.execute_full(req.session_id, cmd)
        duration = round(time.time() - start_time, 3)
        insert_command_log(
            session_id=req.session_id,
            command="/security/system-info",
            output=result,
            status="success",
            duration=duration
        )
        return APIResponse(data={"output": result})
    except Exception as e:
        duration = round(time.time() - start_time, 3)
        insert_command_log(
            session_id=req.session_id,
            command="/security/system-info",
            output=str(e),
            status="failed",
            duration=duration
        )
        raise HTTPException(status_code=500, detail=f"执行失败：{str(e)}")

# ------------------- 2. 系统资源 -------------------
@router.post("/system-resource", summary="系统资源检查", response_model=APIResponse)
async def system_resource(req: SessionRequest):
    start_time = time.time()
    cmd = """
TERM=dumb echo "==================== 系统资源 ====================" 2>&1 &&
TERM=dumb free -h 2>&1 && echo -e "\n--- 磁盘使用 ---" 2>&1 &&
TERM=dumb df -h 2>&1 && echo -e "\n--- 系统负载 ---" 2>&1 &&
TERM=dumb uptime 2>&1 && echo -e "\n--- TOP5 CPU 进程 ---" 2>&1 &&
TERM=dumb ps auxf | sort -nr -k 3 | head -5 2>&1 && echo -e "\n--- TOP5 内存进程 ---" 2>&1 &&
TERM=dumb ps auxf | sort -nr -k 4 | head -5 2>&1 && echo -e "\n--- 路由表 ---" 2>&1 &&
TERM=dumb ip route show 2>&1 && echo -e "\n--- 监听端口 ---" 2>&1 &&
TERM=dumb ss -tunlp 2>&1
"""
    try:
        result = ssh_manager.execute_full(req.session_id, cmd)
        duration = round(time.time() - start_time, 3)
        insert_command_log(
            session_id=req.session_id,
            command="/security/system-resource",
            output=result,
            status="success",
            duration=duration
        )
        return APIResponse(data={"output": result})
    except Exception as e:
        duration = round(time.time() - start_time, 3)
        insert_command_log(
            session_id=req.session_id,
            command="/security/system-resource",
            output=str(e),
            status="failed",
            duration=duration
        )
        raise HTTPException(status_code=500, detail=f"执行失败：{str(e)}")

# ------------------- 3. 用户权限 -------------------
@router.post("/user-check", summary="用户权限检查", response_model=APIResponse)
async def user_check(req: SessionRequest):
    start_time = time.time()
    cmd = """
TERM=dumb echo "==================== 用户权限 ====================" 2>&1 &&
TERM=dumb cat /etc/passwd 2>&1 && echo -e "\n--- 用户组 ---" 2>&1 &&
TERM=dumb cat /etc/group 2>&1 && echo -e "\n--- 特权用户 ---" 2>&1 &&
TERM=dumb awk -F: '$3==0 {print "特权用户: "$1}' /etc/passwd 2>&1 && echo -e "\n--- 空口令用户 ---" 2>&1 &&
TERM=dumb awk -F: '$2=="" {print "空口令用户: "$1}' /etc/shadow 2>&1 && echo -e "\n--- Sudo 权限 ---" 2>&1 &&
TERM=dumb grep -v "^#" /etc/sudoers | grep -E "ALL\s*=\s*\(ALL" | grep -v "^root" 2>&1 && echo -e "\n--- 高危 SUID 文件 ---" 2>&1 &&
TERM=dumb find / -perm /6000 -type f 2>/dev/null | grep -vE "^/(usr|bin|sbin)/" 2>&1
"""
    try:
        result = ssh_manager.execute_full(req.session_id, cmd)
        duration = round(time.time() - start_time, 3)
        insert_command_log(
            session_id=req.session_id,
            command="/security/user-check",
            output=result,
            status="success",
            duration=duration
        )
        return APIResponse(data={"output": result})
    except Exception as e:
        duration = round(time.time() - start_time, 3)
        insert_command_log(
            session_id=req.session_id,
            command="/security/user-check",
            output=str(e),
            status="failed",
            duration=duration
        )
        raise HTTPException(status_code=500, detail=f"执行失败：{str(e)}")

# ------------------- 4. 身份鉴别 -------------------
@router.post("/auth-check", summary="身份鉴别检查", response_model=APIResponse)
async def auth_check(req: SessionRequest):
    start_time = time.time()
    cmd = """
TERM=dumb echo "==================== 身份鉴别 ====================" 2>&1 &&
TERM=dumb grep -E "^PASS_MIN_LEN|^PASS_MAX_DAYS" /etc/login.defs 2>&1 && echo -e "\n--- 密码复杂度 ---" 2>&1 &&
TERM=dumb grep -i -E "pam_cracklib|pam_pwquality" /etc/pam.d/common-password 2>&1 && echo -e "\n--- 登录锁定 ---" 2>&1 &&
TERM=dumb grep -i -E "pam_tally2|pam_faillock" /etc/pam.d/common-auth 2>&1
"""
    try:
        result = ssh_manager.execute_full(req.session_id, cmd)
        duration = round(time.time() - start_time, 3)
        insert_command_log(
            session_id=req.session_id,
            command="/security/auth-check",
            output=result,
            status="success",
            duration=duration
        )
        return APIResponse(data={"output": result})
    except Exception as e:
        duration = round(time.time() - start_time, 3)
        insert_command_log(
            session_id=req.session_id,
            command="/security/auth-check",
            output=str(e),
            status="failed",
            duration=duration
        )
        raise HTTPException(status_code=500, detail=f"执行失败：{str(e)}")

# ------------------- 5. 安全审计 -------------------
@router.post("/audit-check", summary="安全审计检查", response_model=APIResponse)
async def audit_check(req: SessionRequest):
    start_time = time.time()
    cmd = """
TERM=dumb echo "==================== 安全审计 ====================" 2>&1 &&
TERM=dumb systemctl is-active rsyslog 2>&1 && echo -e "\n--- 审计服务状态 ---" 2>&1 &&
TERM=dumb systemctl is-active auditd 2>&1 && echo -e "\n--- 最近登录 ---" 2>&1 &&
TERM=dumb last | head -20 2>&1 && echo -e "\n--- 失败登录 IP ---" 2>&1 &&
TERM=dumb grep "Failed" /var/log/auth.log 2>/dev/null | awk '{print $(NF-3)}' | sort | uniq -c 2>&1
"""
    try:
        result = ssh_manager.execute_full(req.session_id, cmd)
        duration = round(time.time() - start_time, 3)
        insert_command_log(
            session_id=req.session_id,
            command="/security/audit-check",
            output=result,
            status="success",
            duration=duration
        )
        return APIResponse(data={"output": result})
    except Exception as e:
        duration = round(time.time() - start_time, 3)
        insert_command_log(
            session_id=req.session_id,
            command="/security/audit-check",
            output=str(e),
            status="failed",
            duration=duration
        )
        raise HTTPException(status_code=500, detail=f"执行失败：{str(e)}")

# ------------------- 6. 全量检查 -------------------
@router.post("/full-check", summary="全量安全检查", response_model=APIResponse)
async def full_check(req: SessionRequest):
    start_time = time.time()
    cmd = """
TERM=dumb echo "==================== 全量安全检查 ====================" 2>&1 &&
TERM=dumb hostname 2>&1 && echo -e "\n--- 内核信息 ---" 2>&1 &&
TERM=dumb uname -a 2>&1 && echo -e "\n--- 内存磁盘 ---" 2>&1 &&
TERM=dumb free -h && df -h 2>&1 && echo -e "\n--- 可登录用户 ---" 2>&1 &&
TERM=dumb cat /etc/passwd | grep /bin/bash 2>&1 && echo -e "\n--- SSH 配置 ---" 2>&1 &&
TERM=dumb grep PermitRootLogin /etc/ssh/sshd_config 2>&1 && echo -e "\n--- 密码策略 ---" 2>&1 &&
TERM=dumb grep PASS_MIN_LEN /etc/login.defs 2>&1 && echo -e "\n--- 最近登录 ---" 2>&1 &&
TERM=dumb last | head -10 2>&1
"""
    try:
        result = ssh_manager.execute_full(req.session_id, cmd)
        duration = round(time.time() - start_time, 3)
        insert_command_log(
            session_id=req.session_id,
            command="/security/full-check",
            output=result,
            status="success",
            duration=duration
        )
        return APIResponse(data={"output": result})
    except Exception as e:
        duration = round(time.time() - start_time, 3)
        insert_command_log(
            session_id=req.session_id,
            command="/security/full-check",
            output=str(e),
            status="failed",
            duration=duration
        )
        raise HTTPException(status_code=500, detail=f"执行失败：{str(e)}")

# ------------------- 7. 密码加固 -------------------
@router.post("/reinforce-password", summary="密码策略加固", response_model=APIResponse)
async def reinforce_password(req: SessionRequest):
    start_time = time.time()
    cmd = """
TERM=dumb echo "==================== 密码策略加固 ====================" 2>&1 &&
TERM=dumb sed -i 's/^PASS_MIN_LEN.*/PASS_MIN_LEN 8/' /etc/login.defs 2>&1 &&
TERM=dumb sed -i 's/^PASS_MAX_DAYS.*/PASS_MAX_DAYS 90/' /etc/login.defs 2>&1 &&
TERM=dumb echo "password requisite pam_pwquality.so retry=3 minlen=8 ucredit=-1 lcredit=-1 dcredit=-1 ocredit=-1" >> /etc/pam.d/common-password 2>&1 &&
TERM=dumb echo "✅ 加固完成：密码长度8位+复杂度+90天有效期" 2>&1
"""
    try:
        result = ssh_manager.execute_full(req.session_id, cmd)
        duration = round(time.time() - start_time, 3)
        insert_command_log(
            session_id=req.session_id,
            command="/security/reinforce-password",
            output=result,
            status="success",
            duration=duration
        )
        return APIResponse(data={"output": result})
    except Exception as e:
        duration = round(time.time() - start_time, 3)
        insert_command_log(
            session_id=req.session_id,
            command="/security/reinforce-password",
            output=str(e),
            status="failed",
            duration=duration
        )
        raise HTTPException(status_code=500, detail=f"执行失败：{str(e)}")

# ------------------- 8. SSH加固 -------------------
@router.post("/reinforce-ssh", summary="SSH安全加固", response_model=APIResponse)
async def reinforce_ssh(req: SessionRequest):
    start_time = time.time()
    cmd = """
TERM=dumb echo "==================== SSH加固 ====================" 2>&1 &&
TERM=dumb cp -a /etc/ssh/sshd_config /etc/ssh/sshd_config.bak.$(date +%Y%m%d) 2>&1 &&
TERM=dumb sed -i 's/^PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config 2>&1 &&
TERM=dumb sed -i 's/^PermitEmptyPasswords.*/PermitEmptyPasswords no/' /etc/ssh/sshd_config 2>&1 &&
TERM=dumb sed -i 's/^MaxAuthTries.*/MaxAuthTries 3/' /etc/ssh/sshd_config 2>&1 &&
TERM=dumb systemctl restart sshd 2>&1 &&
TERM=dumb echo "✅ 加固完成：禁止root登录+禁止空密码+最大尝试3次" 2>&1
"""
    try:
        result = ssh_manager.execute_full(req.session_id, cmd)
        duration = round(time.time() - start_time, 3)
        insert_command_log(
            session_id=req.session_id,
            command="/security/reinforce-ssh",
            output=result,
            status="success",
            duration=duration
        )
        return APIResponse(data={"output": result})
    except Exception as e:
        duration = round(time.time() - start_time, 3)
        insert_command_log(
            session_id=req.session_id,
            command="/security/reinforce-ssh",
            output=str(e),
            status="failed",
            duration=duration
        )
        raise HTTPException(status_code=500, detail=f"执行失败：{str(e)}")

# ------------------- 9. 防暴力破解 -------------------
@router.post("/reinforce-brute", summary="防暴力破解加固", response_model=APIResponse)
async def reinforce_brute(req: SessionRequest):
    start_time = time.time()
    cmd = """
TERM=dumb echo "==================== 防暴力破解 ====================" 2>&1 &&
TERM=dumb sed -i '/^auth.*required.*pam_unix.so/i auth required pam_tally2.so deny=3 unlock_time=600' /etc/pam.d/common-auth 2>&1 &&
TERM=dumb sed -i '/^account.*required.*pam_unix.so/i account required pam_tally2.so' /etc/pam.d/common-auth 2>&1 &&
TERM=dumb echo "✅ 加固完成：3次失败锁定10分钟" 2>&1
"""
    try:
        result = ssh_manager.execute_full(req.session_id, cmd)
        duration = round(time.time() - start_time, 3)
        insert_command_log(
            session_id=req.session_id,
            command="/security/reinforce-brute",
            output=result,
            status="success",
            duration=duration
        )
        return APIResponse(data={"output": result})
    except Exception as e:
        duration = round(time.time() - start_time, 3)
        insert_command_log(
            session_id=req.session_id,
            command="/security/reinforce-brute",
            output=str(e),
            status="failed",
            duration=duration
        )
        raise HTTPException(status_code=500, detail=f"执行失败：{str(e)}")

# ------------------- 10. 全量加固 -------------------
@router.post("/full-reinforce", summary="全量安全加固", response_model=APIResponse)
async def full_reinforce(req: SessionRequest):
    start_time = time.time()
    cmd = """
TERM=dumb echo "==================== 全量加固 ====================" 2>&1 &&
TERM=dumb sed -i 's/^PASS_MIN_LEN.*/PASS_MIN_LEN 8/' /etc/login.defs 2>&1 &&
TERM=dumb sed -i 's/^PASS_MAX_DAYS.*/PASS_MAX_DAYS 90/' /etc/login.defs 2>&1 &&
TERM=dumb sed -i 's/^PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config 2>&1 &&
TERM=dumb sed -i 's/^PermitEmptyPasswords.*/PermitEmptyPasswords no/' /etc/ssh/sshd_config 2>&1 &&
TERM=dumb sed -i '/^auth.*required.*pam_unix.so/i auth required pam_tally2.so deny=3 unlock_time=600' /etc/pam.d/common-auth 2>&1 &&
TERM=dumb systemctl restart sshd 2>&1 &&
TERM=dumb echo "✅ 全量加固完成" 2>&1
"""
    try:
        result = ssh_manager.execute_full(req.session_id, cmd)
        duration = round(time.time() - start_time, 3)
        insert_command_log(
            session_id=req.session_id,
            command="/security/full-reinforce",
            output=result,
            status="success",
            duration=duration
        )
        return APIResponse(data={"output": result})
    except Exception as e:
        duration = round(time.time() - start_time, 3)
        insert_command_log(
            session_id=req.session_id,
            command="/security/full-reinforce",
            output=str(e),
            status="failed",
            duration=duration
        )
        raise HTTPException(status_code=500, detail=f"执行失败：{str(e)}")

# ------------------- 11. 配置备份 -------------------
@router.post("/backup-config", summary="配置备份", response_model=APIResponse)
async def backup_config(req: SessionRequest):
    start_time = time.time()
    cmd = """
TERM=dumb echo "==================== 配置备份 ====================" 2>&1 &&
TERM=dumb mkdir -p /tmp/backup 2>&1 &&
TERM=dumb cp -a /etc/ssh /tmp/backup/ssh_config_$(date +%Y%m%d) 2>&1 &&
TERM=dumb cp -a /etc/login.defs /tmp/backup/ 2>&1 &&
TERM=dumb cp -a /etc/pam.d /tmp/backup/ 2>&1 &&
TERM=dumb echo "✅ 备份完成：/tmp/backup/" 2>&1
"""
    try:
        result = ssh_manager.execute_full(req.session_id, cmd)
        duration = round(time.time() - start_time, 3)
        insert_command_log(
            session_id=req.session_id,
            command="/security/backup-config",
            output=result,
            status="success",
            duration=duration
        )
        return APIResponse(data={"output": result})
    except Exception as e:
        duration = round(time.time() - start_time, 3)
        insert_command_log(
            session_id=req.session_id,
            command="/security/backup-config",
            output=str(e),
            status="failed",
            duration=duration
        )
        raise HTTPException(status_code=500, detail=f"执行失败：{str(e)}")


@router.post("/system-stats", summary="获取系统监控数据", response_model=APIResponse)
async def system_stats(req: SessionRequest):
    try:
        # 1. 主机名
        hostname = ssh_manager.execute(req.session_id, "hostname").strip() or "unknown"

        # 2. 系统版本
        os_version = ssh_manager.execute(req.session_id, "lsb_release -d | cut -f2-").strip() or "Kali GNU/Linux Rolling"

        # 3. 内核版本（新增，通用命令，无语言问题）
        kernel = ssh_manager.execute(req.session_id, "uname -r").strip() or "--"

        # 4. 运行时间（新增，强制英文避免中文乱码）
        uptime = ssh_manager.execute(req.session_id, "LANG=C uptime -p").strip() or "--"

        # ====================== CPU ======================
        cpu_usage = ssh_manager.execute(
            req.session_id,
            "grep 'cpu ' /proc/stat | awk '{used=$2+$3+$4; total=used+$5; printf \"%.2f\", used/total*100}'"
        ).strip()
        cpu = f"{cpu_usage}%" if cpu_usage else "0%"

        # ====================== 内存 ======================
        mem_total = ssh_manager.execute(req.session_id, "free -h | awk 'NR==2 {print $2}'").strip() or "--"
        mem_used = ssh_manager.execute(req.session_id, "free -h | awk 'NR==2 {print $3}'").strip() or "--"
        mem_free = ssh_manager.execute(req.session_id, "free -h | awk 'NR==2 {print $4}'").strip() or "--"
        mem_val = ssh_manager.execute(
            req.session_id,
            "free | awk 'NR==2 {used=$3; total=$2; printf \"%.2f\", used/total*100}'"
        ).strip()
        mem = f"{mem_val}%" if mem_val else "0%"

        # ====================== 硬盘 ======================
        disk_total = ssh_manager.execute(req.session_id, "df -h / | awk 'NR==2 {print $2}'").strip() or "--"
        disk_used = ssh_manager.execute(req.session_id, "df -h / | awk 'NR==2 {print $3}'").strip() or "--"
        disk_free = ssh_manager.execute(req.session_id, "df -h / | awk 'NR==2 {print $4}'").strip() or "--"
        disk_percent = ssh_manager.execute(req.session_id, "df / | awk 'NR==2 {print $5}' | tr -d '%'").strip()
        disk = f"{disk_percent}%" if disk_percent else "0%"

        return APIResponse(
            data={
                "hostname": hostname,
                "osVersion": os_version,
                "kernel": kernel,  # 内核版本字段
                "uptime": uptime,  # 运行时间字段
                "cpu": cpu,
                "mem": mem,
                "memUsed": mem_used,
                "memFree": mem_free,
                "memTotal": mem_total,
                "disk": disk,
                "diskUsed": disk_used,
                "diskFree": disk_free,
                "diskTotal": disk_total,
                "status": "正常"
            }
        )
    except Exception as e:
        return APIResponse(code=500, message="获取失败：" + str(e))