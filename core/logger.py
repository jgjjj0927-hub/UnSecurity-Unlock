import logging
import os
from pathlib import Path

LOG_DIR = Path(os.getenv("PROGRAMDATA", r"C:\ProgramData")) / "UnSecurityUnlock" / "logs"
LOG_DIR.mkdir(parents=True, exist_ok=True)

logger = logging.getLogger("unsecurity_unlock")
logger.setLevel(logging.DEBUG)

if not logger.handlers:
    fh = logging.FileHandler(LOG_DIR / "unsecurity_unlock.log", encoding="utf-8")
    fh.setLevel(logging.DEBUG)
    fmt = logging.Formatter("%(asctime)s [%(levelname)s] %(name)s: %(message)s")
    fh.setFormatter(fmt)
    logger.addHandler(fh)
