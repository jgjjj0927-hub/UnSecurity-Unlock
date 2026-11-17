import os
import subprocess
import sys
import time
from pathlib import Path

MAIN_EXE_NAME = "UnSecurityUnlock.exe"
GUARD_SLEEP = 3


def _log(msg: str) -> None:
    log_dir = Path(os.getenv("PROGRAMDATA", r"C:\ProgramData")) / "UnSecurityUnlock" / "logs"
    log_dir.mkdir(parents=True, exist_ok=True)
    with open(log_dir / "guard.log", "a", encoding="utf-8") as f:
        f.write(f"{time.strftime('%Y-%m-%d %H:%M:%S')} {msg}\n")


def _main_exe_path() -> Path:
    return Path(sys.executable).parent / MAIN_EXE_NAME


def _is_running(name: str) -> bool:
    try:
        out = subprocess.run(
            ["tasklist", "/FI", f"IMAGENAME eq {name}", "/NH"],
            capture_output=True, text=True, timeout=10
        ).stdout.lower()
        return name.lower() in out
    except Exception:
        return False


def _start_main() -> None:
    exe = _main_exe_path()
    if not exe.exists():
        _log(f"main exe not found: {exe}")
        return
    try:
        subprocess.Popen([str(exe), "--autostart"], creationflags=0x00000008)
        _log(f"main started: {exe}")
    except Exception as e:
        _log(f"start main failed: {e}")


def _ensure_guard_autostart() -> None:
    """Guard тоже прописывается в автозапуск, чтобы пережить перезагрузку."""
    try:
        import winreg
    except ImportError:
        return
    if not (getattr(sys, "frozen", False) or getattr(sys, "__compiled__", False)):
        return
    exe = sys.executable
    try:
        key_path = r"Software\Microsoft\Windows\CurrentVersion\Run"
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, key_path, 0, winreg.KEY_SET_VALUE) as k:
            winreg.SetValueEx(k, "UnSecurityGuard", 0, winreg.REG_SZ, f'"{exe}"')
        _log("guard autostart registered")
    except OSError as e:
        _log(f"guard autostart failed: {e}")


def main() -> None:
    _log("guard started")
    _ensure_guard_autostart()
    while True:
        if not _is_running(MAIN_EXE_NAME):
            _log("main not running, restarting")
            _start_main()
        time.sleep(GUARD_SLEEP)


if __name__ == "__main__":
    main()
