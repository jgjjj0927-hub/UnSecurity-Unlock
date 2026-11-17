import hashlib
import os
import shutil
import sys
from pathlib import Path
from typing import Optional

from .logger import logger

PROTECT_DIR = Path(os.getenv("PROGRAMDATA", r"C:\ProgramData")) / "UnSecurityUnlock"
BACKUP_DIR = PROTECT_DIR / "backup"
HASH_FILE = PROTECT_DIR / "self.sha256"
BACKUP_DIR.mkdir(parents=True, exist_ok=True)


def current_exe() -> Optional[Path]:
    if getattr(sys, "frozen", False) or getattr(sys, "__compiled__", False):
        return Path(sys.executable)
    return None


def sha256_of(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def make_backup() -> Optional[str]:
    exe = current_exe()
    if not exe or not exe.exists():
        logger.info("selfdefense: not compiled, skip backup")
        return None
    backup = BACKUP_DIR / "unsecurity_core.bin"
    try:
        shutil.copy2(str(exe), str(backup))
        digest = sha256_of(exe)
        HASH_FILE.write_text(digest, encoding="utf-8")
        logger.info("selfdefense: backup created, hash=%s", digest)
        return digest
    except Exception as e:
        logger.error("selfdefense backup failed: %s", e)
        return None


def verify_integrity() -> bool:
    exe = current_exe()
    if not exe or not exe.exists() or not HASH_FILE.exists():
        return True
    try:
        expected = HASH_FILE.read_text(encoding="utf-8").strip()
        actual = sha256_of(exe)
        if expected != actual:
            logger.warning("selfdefense: integrity mismatch!")
            return False
        return True
    except Exception as e:
        logger.error("selfdefense verify failed: %s", e)
        return True


def restore_self() -> bool:
    exe = current_exe()
    backup = BACKUP_DIR / "unsecurity_core.bin"
    if not backup.exists() or exe is None:
        return False
    try:
        if not exe.exists() or not verify_integrity():
            shutil.copy2(str(backup), str(exe))
            logger.info("selfdefense: restored from backup")
            return True
    except Exception as e:
        logger.error("selfdefense restore failed: %s", e)
    return False
