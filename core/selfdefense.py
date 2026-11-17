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

MAIN_BAK = BACKUP_DIR / "main.bak"
GUARD_BAK = BACKUP_DIR / "guard.bak"


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
    try:
        shutil.copy2(str(exe), str(MAIN_BAK))
        shutil.copy2(str(exe), str(GUARD_BAK))
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
    if exe is None:
        return False
    bak = MAIN_BAK if exe.exists() else MAIN_BAK
    if not bak.exists():
        bak = GUARD_BAK
    if not bak.exists():
        return False
    try:
        shutil.copy2(str(bak), str(exe))
        logger.info("selfdefense: restored from backup")
        return True
    except Exception as e:
        logger.error("selfdefense restore failed: %s", e)
    return False


def backup_master() -> None:
    from . import vault
    master = vault.MASTER_FILE
    if master.exists():
        try:
            shutil.copy2(str(master), str(BACKUP_DIR / "master.bak"))
            logger.info("selfdefense: master backed up")
        except Exception as e:
            logger.error("selfdefense master backup failed: %s", e)


def restore_master() -> None:
    from . import vault
    bak = BACKUP_DIR / "master.bak"
    if bak.exists() and not vault.MASTER_FILE.exists():
        try:
            shutil.copy2(str(bak), str(vault.MASTER_FILE))
            logger.info("selfdefense: master restored from backup")
        except Exception as e:
            logger.error("selfdefense master restore failed: %s", e)
