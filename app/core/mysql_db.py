# -*- coding: utf-8 -*-
import pymysql
from datetime import datetime
import sys
import re

# 🔥 彻底禁用GBK，强制使用UTF-8编码，解决所有特殊字符问题
sys.modules['pymysql'].charset = 'utf8mb4'
pymysql.charset = 'utf8mb4'

# ===================== 你的MySQL配置（必须使用utf8mb4） =====================
DB_CONFIG = {
    "host": "localhost",
    "port": 3306,
    "user": "root",
    "password": "123456",  # 改成你的密码
    "db": "linux_audit",
    "charset": "utf8mb4",  # 强制UTF-8，支持所有Unicode字符
    "use_unicode": True,
    "connect_timeout": 5
}


# 安全获取连接（永不崩溃）
def _get_conn():
    try:
        conn = pymysql.connect(**DB_CONFIG)
        conn.query("SET NAMES utf8mb4")  # 双重保险
        return conn
    except Exception as e:
        print(f"[MySQL] 连接失败: {str(e)}")
        return None


# ------------------- 1. SSH连接日志（已有） -------------------
def insert_ssh_log(
        session_id,
        server_ip,
        server_port,
        username,
        client_ip,
        status,
        error_msg=None):
    conn = _get_conn()
    if not conn:
        return
    try:
        with conn.cursor() as cursor:
            sql = """
            INSERT INTO ssh_connection_logs 
            (session_id, server_ip, server_port, username, client_ip, status, error_msg)
            VALUES (%s, %s, %s, %s, %s, %s, %s)
            """
            cursor.execute(sql, (
                str(session_id), str(server_ip), int(server_port), str(username),
                str(client_ip), str(status), str(error_msg) if error_msg else None
            ))
        conn.commit()
        print(f"[MySQL] ✅ SSH连接日志写入成功：{session_id}")
    except Exception as e:
        print(f"[MySQL] SSH日志写入失败: {e}")
    finally:
        conn.close()


def update_ssh_disconnect(session_id):
    conn = _get_conn()
    if not conn:
        return
    try:
        with conn.cursor() as cursor:
            sql = """
            UPDATE ssh_connection_logs 
            SET disconnect_time=%s, status=%s WHERE session_id=%s
            """
            cursor.execute(sql, (datetime.now(), "disconnected", str(session_id)))
        conn.commit()
        print(f"[MySQL] ✅ SSH断开日志更新成功：{session_id}")
    except Exception as e:
        print(f"[MySQL] SSH断开日志更新失败: {e}")
    finally:
        conn.close()


# ------------------- 2. 终端命令日志（修复编码问题） -------------------
def insert_command_log(session_id, command, output, status, duration):
    conn = _get_conn()
    if not conn:
        return
    try:
        # 🔥 关键处理：清理输出中的特殊字符，避免编码失败
        # 1. 去掉ANSI颜色转义序列（比如\x1b[36m）
        output = re.sub(r'\x1b\[[0-?]*[ -/]*[@-~]', '', output)
        # 2. 用UTF-8解码，无法识别的字符替换为?，避免报错
        output = output.encode('utf-8', errors='replace').decode('utf-8')
        # 3. 截断超长输出，避免数据库溢出
        command = str(command)[:1000]
        output = output[:5000]

        with conn.cursor() as cursor:
            sql = """
            INSERT INTO terminal_command_logs 
            (session_id, command, output, status, duration)
            VALUES (%s, %s, %s, %s, %s)
            """
            cursor.execute(sql, (
                str(session_id), command, output, str(status), float(duration)
            ))
        conn.commit()
        print(f"[MySQL] ✅ 终端命令日志写入成功：{command[:20]}...")
    except Exception as e:
        print(f"[MySQL] ❌ 终端命令日志写入失败: {e}")
    finally:
        conn.close()


# ------------------- 3. 接口访问日志（新增） -------------------
def insert_api_log(request_url, method, session_id, request_params, status_code, duration, client_ip):
    conn = _get_conn()
    if not conn:
        return
    try:
        # 截断超长参数
        request_params = str(request_params)[:2000] if request_params else ""

        with conn.cursor() as cursor:
            sql = """
            INSERT INTO api_access_logs 
            (request_url, method, session_id, request_params, status_code, duration, client_ip)
            VALUES (%s, %s, %s, %s, %s, %s, %s)
            """
            cursor.execute(sql, (
                str(request_url), str(method), str(session_id) if session_id else None,
                request_params, int(status_code), float(duration), str(client_ip)
            ))
        conn.commit()
        print(f"[MySQL] ✅ 接口访问日志写入成功：{method} {request_url}")
    except Exception as e:
        print(f"[MySQL] ❌ 接口日志写入失败: {e}")
    finally:
        conn.close()