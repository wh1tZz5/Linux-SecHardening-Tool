# -*- coding: UTF-8 -*-
"""
@Project  ：Linux加固
@File     ：poc_manager.py
@Author   ：QAQ
@Date     ：2026/5/24 21:19
@Desc     ：
"""
# app/services/poc/poc_manager.py
class PocManager:
    def run_log4j(self, session_id: str, target: str):
        # 后续补Log4j2探测逻辑
        return f"Log4j2探测：session={session_id}, target={target}"

    def run_spring4shell(self, session_id: str, target: str):
        return f"Spring4Shell探测：session={session_id}, target={target}"

    def run_fastjson(self, session_id: str, target: str):
        return f"Fastjson探测：session={session_id}, target={target}"

    def run_shiro550(self, session_id: str, target: str):
        return f"Shiro550探测：session={session_id}, target={target}"

    def run_nacos(self, session_id: str, target: str):
        return f"Nacos探测：session={session_id}, target={target}"

# 实例化对象（关键！接口层要导入的就是这个）
poc_manager = PocManager()