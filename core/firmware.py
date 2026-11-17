import hashlib
import subprocess
from pathlib import Path
from typing import Dict, Optional

from .logger import logger


def _run_ps(cmd: str) -> str:
    """Выполнить PowerShell-команду только на чтение. Ничего не меняет."""
    try:
        p = subprocess.run(
            ["powershell", "-NoProfile", "-NonInteractive", "-Command", cmd],
            capture_output=True, text=True, timeout=20
        )
        return (p.stdout or "").strip()
    except Exception as e:
        logger.error("firmware ps failed: %s", e)
        return ""


def get_secure_boot_status() -> str:
    """Только чтение статуса Secure Boot. Ничего не меняет."""
    out = _run_ps("Confirm-SecureBootUEFI")
    low = out.lower()
    if low == "true":
        return "включён"
    if low == "false":
        return "выключен"
    return "неизвестно (возможно Legacy BIOS)"


def get_firmware_type() -> str:
    """UEFI или Legacy BIOS."""
    out = _run_ps(
        "$env:firmware_type; "
        "(Get-ComputerInfo -Property BiosFirmwareType).BiosFirmwareType"
    )
    if "uefi" in out.lower():
        return "UEFI"
    if "bios" in out.lower():
        return "Legacy BIOS"
    return "неизвестно"


def get_tpm_status() -> str:
    """Только чтение TPM. Ничего не меняет."""
    out = _run_ps(
        "(Get-Tpm -ErrorAction SilentlyContinue).TpmPresent"
    )
    if out.lower() == "true":
        return "присутствует"
    if out.lower() == "false":
        return "отсутствует"
    return "неизвестно"


def get_bootloader_hash() -> str:
    """SHA-256 файла загрузчика. Только чтение."""
    candidates = [
        Path(r"C:\Windows\Boot\EFI\bootmgfw.efi"),
        Path(r"C:\EFI\Microsoft\Boot\bootmgfw.efi"),
    ]
    for boot in candidates:
        if boot.exists():
            h = hashlib.sha256()
            try:
                with open(boot, "rb") as f:
                    for chunk in iter(lambda: f.read(65536), b""):
                        h.update(chunk)
                return h.hexdigest()
            except Exception:
                return ""
    return ""


def check_firmware() -> Dict[str, str]:
    """Полная проверка прошивки/загрузки. Только чтение."""
    result = {
        "firmware_type": get_firmware_type(),
        "secure_boot": get_secure_boot_status(),
        "tpm": get_tpm_status(),
        "bootloader_sha256": get_bootloader_hash(),
    }
    logger.info("firmware check: %s", result)
    return result


def firmware_warning() -> Optional[str]:
    """Вернуть предупреждение, если система уязвима. Ничего не меняет."""
    data = check_firmware()
    warnings = []
    if data["secure_boot"] == "выключен":
        warnings.append(
            "Secure Boot выключен. Система уязвима для bootkit-атак "
            "(заражение до загрузки Windows)."
        )
    if data["firmware_type"] == "Legacy BIOS":
        warnings.append(
            "Система загружается в режиме Legacy BIOS. "
            "Рекомендуется включить UEFI + Secure Boot в настройках прошивки вручную."
        )
    if warnings:
        return " ".join(warnings)
    return None
