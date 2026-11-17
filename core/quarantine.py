import os
import shutil
import time
from pathlib import Path
from typing import List, Dict

from .logger import logger

QUARANTINE_DIR = Path(os.getenv("PROGRAMDATA", r"C:\ProgramData")) / "UnSecurityUnlock" / "quarantine"
QUARANTINE_DIR.mkdir(parents=True, exist_ok=True)

_ALLOWED_ROOT = str(QUARANTINE_DIR.resolve())


def _safe_quarantine_target(name: str) -> Path:
    dest = (QUARANTINE_DIR / name).resolve()
    if not str(dest).startswith(_ALLOWED_ROOT):
        raise ValueError("path traversal attempt")
    return dest


def quarantine_file(path: str) -> str:
    src = Path(path)
    if not src.exists():
        raise FileNotFoundError(path)

    ts = time.strftime("%Y%m%d_%H%M%S")
    safe_name = f"{ts}_{src.name}.quar"
    dest = _safe_quarantine_target(safe_name)

    try:
        shutil.move(str(src), str(dest))
        logger.info("quarantined %s -> %s", src, dest)
        return str(dest)
    except OSError:
        try:
            shutil.copy2(str(src), str(dest))
            try:
                os.remove(str(src))
            except OSError as e:
                logger.warning("copied but could not delete original: %s", e)
            logger.info("quarantined (copy) %s -> %s", src, dest)
            return str(dest)
        except Exception as e:
            logger.error("quarantine failed for %s: %s", src, e)
            raise


def restore_file(quarantine_name: str, original_path: str) -> str:
    src = _safe_quarantine_target(quarantine_name)
    if not src.exists():
        raise FileNotFoundError(quarantine_name)
    dest = Path(original_path)
    dest.parent.mkdir(parents=True, exist_ok=True)
    shutil.move(str(src), str(dest))
    logger.info("restored %s -> %s", src, dest)
    return str(dest)


def list_quarantine() -> List[Dict]:
    items = []
    for f in QUARANTINE_DIR.iterdir():
        if f.is_file():
            items.append({"name": f.name, "size": f.stat().st_size, "path": str(f)})
    return items
