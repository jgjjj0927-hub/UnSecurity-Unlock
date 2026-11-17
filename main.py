import os
import subprocess
import sys
import time
import traceback
from pathlib import Path

from core.logger import logger

GUARD_FLAG = "--guard"
MAIN_FLAG = "--autostart"


# ---------- guard-режим ----------

def guard_log(msg: str) -> None:
    log_dir = Path(os.getenv("PROGRAMDATA", r"C:\ProgramData")) / "UnSecurityUnlock" / "logs"
    log_dir.mkdir(parents=True, exist_ok=True)
    with open(log_dir / "guard.log", "a", encoding="utf-8") as f:
        f.write(f"{time.strftime('%Y-%m-%d %H:%M:%S')} {msg}\n")


def _is_running(name: str) -> bool:
    try:
        out = subprocess.run(
            ["tasklist", "/FI", f"IMAGENAME eq {name}", "/NH"],
            capture_output=True, text=True, timeout=10
        ).stdout.lower()
        return name.lower() in out
    except Exception:
        return False


def _exe_path() -> Path:
    return Path(sys.executable)


def _ensure_guard_autostart() -> None:
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
            winreg.SetValueEx(k, "UnSecurityGuard", 0, winreg.REG_SZ, f'"{exe}" {GUARD_FLAG}')
        guard_log("guard autostart registered")
    except OSError as e:
        guard_log(f"guard autostart failed: {e}")


def guard_loop() -> None:
    """Режим сторожа: следит за основным процессом, перезапускает."""
    guard_log("guard started")
    _ensure_guard_autostart()
    exe_name = _exe_path().name
    while True:
        if not _is_running(exe_name):
            guard_log("main not running, restarting")
            try:
                subprocess.Popen([str(_exe_path()), MAIN_FLAG], creationflags=0x00000008)
            except Exception as e:
                guard_log(f"restart main failed: {e}")
        time.sleep(3)


# ---------- основной режим ----------

def register_autostart():
    try:
        import winreg
    except ImportError:
        return
    if not (getattr(sys, "frozen", False) or getattr(sys, "__compiled__", False)):
        logger.info("skip autostart: not compiled")
        return
    exe = sys.executable
    if not exe.lower().endswith(".exe"):
        return
    try:
        key_path = r"Software\Microsoft\Windows\CurrentVersion\Run"
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, key_path, 0, winreg.KEY_SET_VALUE) as k:
            winreg.SetValueEx(k, "UnSecurityUnlock", 0, winreg.REG_SZ, f'"{exe}" {MAIN_FLAG}')
        logger.info("autostart registered")
    except OSError as e:
        logger.error("autostart failed: %s", e)


def ensure_guard_process() -> None:
    """Поднять копию себя с --guard, если guard не запущен."""
    exe = _exe_path()
    if not exe.exists():
        return
    try:
        out = subprocess.run(
            ["tasklist", "/FI", f"IMAGENAME eq {exe.name}", "/NH"],
            capture_output=True, text=True, timeout=10
        ).stdout.lower()
        # считаем, сколько копий запущено
        count = out.count(exe.name.lower())
        if count < 2:
            subprocess.Popen([str(exe), GUARD_FLAG], creationflags=0x00000008)
            logger.info("guard process spawned")
    except Exception as e:
        logger.error("ensure_guard_process: %s", e)


def autostart_scan():
    from core import scanner, startup
    findings = []
    try:
        entries = startup.get_startup_entries()
        for e in entries:
            cmd = e["command"].strip('"').split(" ")[0]
            if not cmd:
                continue
            if not cmd.lower().endswith((".exe", ".bat", ".cmd", ".ps1", ".vbs", ".js")):
                continue
            reasons = []
            score = 3
            if any(w in cmd.lower() for w in ("temp", "appdata", "programdata", "downloads")):
                reasons.append("Запуск из временной/пользовательской папки")
                score += 2
            if not any(k in e["key"].lower() for k in ("microsoft", "windows")):
                reasons.append("Нестандартный ключ автозапуска")
                score += 1
            findings.append({
                "path": e["command"],
                "name": e["name"],
                "score": score,
                "reasons": "; ".join(reasons) or "Проверить вручную",
            })
    except Exception:
        logger.exception("autostart scan failed")

    try:
        sys32 = scanner.scan_paths([r"C:\Windows\System32"])
        findings.extend(sys32)
    except Exception:
        logger.exception("sys32 scan failed")

    return findings


def main_app() -> None:
    # ---- самозащита ----
    try:
        from core import selfdefense, watchdog
        selfdefense.make_backup()
        selfdefense.backup_master()
        selfdefense.restore_master()
        if not selfdefense.verify_integrity():
            selfdefense.restore_self()
        watchdog.start()
    except Exception:
        logger.exception("selfdefense init failed")

    register_autostart()
    ensure_guard_process()

    is_autostart = MAIN_FLAG in sys.argv

    if is_autostart:
        try:
            findings = autostart_scan()
            if findings:
                from ui.startup_popup import show_startup_alert
                show_startup_alert(findings)
            else:
                logger.info("autostart scan: clean")
        except Exception:
            logger.exception("autostart popup failed")

    try:
        import tkinter  # noqa: F401
        from ui.app import run as run_gui
        run_gui()
    except Exception:
        logger.exception("GUI failed, falling back to CLI")
        try:
            from ui.cli import run as run_cli
            run_cli()
        except Exception:
            logger.exception("CLI failed")


def main() -> None:
    if GUARD_FLAG in sys.argv:
        guard_loop()
    else:
        main_app()


if __name__ == "__main__":
    main()
