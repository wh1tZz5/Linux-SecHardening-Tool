import requests
from typing import Any, Dict


class HexStrikeClient:
    def __init__(self, base_url: str, timeout = None):
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout

    def health(self) -> Dict[str, Any]:
        r = requests.get(f"{self.base_url}/health", timeout=self.timeout)
        r.raise_for_status()
        return r.json() if r.content else {"ok": True}

    def analyze_target(self, target: str, analysis_type: str = "comprehensive") -> Dict[str, Any]:
        payload = {"target": target, "analysis_type": analysis_type}
        r = requests.post(
            f"{self.base_url}/api/intelligence/analyze-target",
            json=payload,
            timeout=self.timeout,
        )
        r.raise_for_status()
        return r.json()

    def select_tools(self, target: str, task: str) -> Dict[str, Any]:
        payload = {"target": target, "task": task}
        r = requests.post(
            f"{self.base_url}/api/intelligence/select-tools",
            json=payload,
            timeout=self.timeout,
        )
        r.raise_for_status()
        return r.json()

    def run_command(self, command: str) -> Dict[str, Any]:
        payload = {"command": command}
        r = requests.post(
            f"{self.base_url}/api/command",
            json=payload,
            timeout=self.timeout,
        )
        r.raise_for_status()
        return r.json()