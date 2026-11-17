import os
import shutil
import time
from pathlib import Path
from typing import List, Dict, Optional

from . import vault
from .logger import logger

QUARANTINE_DIR = vault.VAULT_DIR

_ALLOWED_ROOT = str(QUARANTINE_DIR.resolve())


def _safe_quarantine_target(name: str) -> Path:
    dest = (QUARANTINE_DIR / name).resolve()
    if not str(dest).startswith(_ALLOWED_ROOT):
        raise ValueError("path traversal attempt")
    return dest


def quarantine_file(path: str, password: str) -> str:
    """Зашифровать файл и поместить в карантин."""
    src = Path(path)
    if not src.exists():
        raise FileNotFoundError(path)

    key = vault.get_key(password)
    if key is None:
        raise PermissionError("неверный мастер-пароль")

    ts = time.strftime("%Y%m%d_%H%M%S")
    safe_name = f"{ts}_{src.name}.quar"
    dest = _safe_quarantine_target(safe_name)

    try:
        raw = src.read_bytes()
        blob = vault.encrypt_blob(key, raw)
        dest.write_bytes(blob)
        try:
            os.remove(str(src))
        except OSError as e:
            logger.warning("quarantined but original not deleted: %s", e)
        logger.info("quarantined %s -> %s", src, dest)
        return str(dest)
    except Exception as e:
        logger.error("quarantine failed for %s: %s", src, e)
        raise


def restore_file(quarantine_name: str, original_path: str, password: str) -> str:
    """Расшифровать и восстановить оригинал."""
    src = _safe_quarantine_target(quarantine_name)
    if not src.exists():
        raise FileNotFoundError(quarantine_name)

    key = vault.get_key(password)
    if key is None:
        raise PermissionError("неверный мастер-пароль")

    blob = src.read_bytes()
    raw = vault.decrypt_blob(key, blob)

    dest = Path(original_path)
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_bytes(raw)
    try:
        os.remove(str(src))
    except OSError:
        pass
    logger.info("restored %s -> %s", src, dest)
    return str(dest)


def run_from_quarantine(quarantine_name: str, password: str) -> None:
    """Расшифровать во временную папку, запустить, удалить после."""
    import subprocess
    import tempfile

    src = _safe_quarantine_target(quarantine_name)
    if not src.exists():
        raise FileNotFoundError(quarantine_name)

    key = vault.get_key(password)
    if key is None:
        raise PermissionError("неверный мастер-пароль")

    blob = src.read_bytes()
    raw = vault.decrypt_blob(key, blob)

    # оригинальное имя без временной метки
    base = quarantine_name
    if "_" in base:
        base = base.split("_", 2)[-1]
    if base.endswith(".quar"):
        base = base[:-5]

    tmpdir = Path(tempfile.mkdtemp(prefix="unsec_"))
    tmp_exe = tmpdir / base
    tmp_exe.write_bytes(raw)

    try:
        subprocess.Popen([str(tmp_exe)], cwd=str(tmpdir))
        logger.info("run from quarantine: %s", tmp_exe)
    except Exception as e:
        logger.error("run from quarantine failed: %s", e)
        raise


def list_quarantine() -> List[Dict]:
    items = []
    for f in QUARANTINE_DIR.iterdir():
        if f.is_file() and f.name != ".master":
            items.append({
                "name": f.name,
                "size": f.stat().st_size,
                "path": str(f),
            })
    return items
