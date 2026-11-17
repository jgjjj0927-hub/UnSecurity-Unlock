import sys
import traceback

from core.logger import logger


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
            winreg.SetValueEx(k, "UnSecurityUnlock", 0, winreg.REG_SZ, f'"{exe}" --autostart')
        logger.info("autostart registered")
    except OSError as e:
        logger.error("autostart failed: %s", e)


def autostart_scan():
    """Скан при загрузке Windows. Возвращает список находок."""
    from core import scanner, startup
    findings = []

    # 1. автозапуск
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

    # 2. быстрый скан System32 на подделки
    try:
        sys32 = scanner.scan_paths([r"C:\Windows\System32"])
        findings.extend(sys32)
    except Exception:
        logger.exception("sys32 scan failed")

    return findings


def main():
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

    is_autostart = "--autostart" in sys.argv

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

    # ---- GUI / CLI ----
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


if __name__ == "__main__":
    main()
