import os
from pathlib import Path
from typing import Optional, List, Dict

from . import heuristics
from .logger import logger

DEFAULT_ROOTS = [
    r"C:\Windows\System32",
    r"C:\Windows\SysWOW64",
    r"C:\Windows\Media",
    r"C:\Windows\Temp",
    r"C:\Users",
    r"C:\ProgramData",
    r"C:\Program Files",
    r"C:\Program Files (x86)",
    r"C:\Temp",
]

SKIP_DIRS = {
    "$recycle.bin", "system volume information", "winsxs", "servicing",
    "node_modules", ".git", "__pycache__", "cache", "temp",
}

MAX_FILES = 200000


def get_scan_roots() -> List[str]:
    import string
    roots = []
    for letter in string.ascii_uppercase:
        drive = f"{letter}:\\"
        if os.path.exists(drive):
            roots.append(drive)
    for d in DEFAULT_ROOTS:
        if os.path.exists(d):
            roots.append(d)
    seen = set()
    uniq = []
    for r in roots:
        k = r.lower()
        if k not in seen:
            seen.add(k)
            uniq.append(r)
    return uniq


def analyze_file(path: str) -> Optional[Dict]:
    if not os.path.isfile(path):
        return None
    if not heuristics.is_scannable(path):
        return None

    name = Path(path).name
    reasons = []
    score = 0

    if heuristics.is_system_impersonation(name) and not heuristics.is_in_legit_system_dir(path):
        reasons.append("Имя системного файла вне системной папки")
        score += 3

    if heuristics.is_recently_created(path):
        reasons.append("Недавно создан/изменён")
        score += 1

    hits = heuristics.scan_content(path)
    if hits:
        reasons.append("Подозрительное содержимое: " + ", ".join(hits[:3]))
        score += len(hits) * 2

    if score == 0:
        return None

    return {"path": path, "name": name, "score": score, "reasons": reasons}


def scan_paths(roots: List[str], progress_cb=None) -> List[Dict]:
    findings = []
    scanned = 0
    for root in roots:
        if not os.path.exists(root):
            continue
        for dirpath, dirnames, filenames in os.walk(root):
            dirnames[:] = [d for d in dirnames if d.lower() not in SKIP_DIRS]
            if "unsecurityunlock" in dirpath.lower():
                continue
            for fn in filenames:
                full = os.path.join(dirpath, fn)
                scanned += 1
                if scanned > MAX_FILES:
                    logger.warning("scan limit reached: %d files", scanned)
                    return findings
                if progress_cb and scanned % 200 == 0:
                    try:
                        progress_cb(scanned, full)
                    except Exception:
                        pass
                try:
                    res = analyze_file(full)
                except Exception as e:
                    logger.debug("analyze failed for %s: %s", full, e)
                    res = None
                if res:
                    findings.append(res)
    logger.info("scan complete: %d files, %d findings", scanned, len(findings))
    return findings
