import os
import re
import time
from pathlib import Path
from typing import List

SYSTEM_NAME_PATTERNS = [
    r"^svchost\.exe$", r"^lsass\.exe$", r"^csrss\.exe$", r"^winlogon\.exe$",
    r"^services\.exe$", r"^smss\.exe$", r"^wininit\.exe$", r"^explorer\.exe$",
    r"^rundll32\.exe$", r"^taskhostw?\.exe$", r"^dwm\.exe$", r"^spoolsv\.exe$",
    r"^conhost\.exe$", r"^dllhost\.exe$", r"^audiodg\.exe$",
    r"^svch0st\.exe$", r"^scvhost\.exe$", r"^lsas\.exe$", r"^win1ogon\.exe$",
]

LEGIT_SYSTEM_DIRS = [
    r"c:\windows\system32",
    r"c:\windows\syswow64",
    r"c:\windows\winsxs",
    r"c:\windows\servicing",
    r"c:\windows\system32\drivers",
    r"c:\windows\system32\wbem",
]

SUSPICIOUS_STRINGS = [
    "powershell -enc", "powershell -e ", "invoke-expression", "iex(",
    "frombase64string", "downloadstring", "invoke-webrequest",
    "start-process -windowstyle hidden", "-windowstyle hidden",
    "net user /add", "net localgroup administrators",
    "reg add hkcu\\software\\microsoft\\windows\\currentversion\\run",
    "schtasks /create", "bitsadmin /transfer",
    "virtualalloc", "writeprocessmemory", "createremotethread",
    "setwindowshookex", "getasynckeystate", "getkeystate",
    "cryptolocker", "ransom", "encryptfiles",
]

SCAN_EXTENSIONS = {
    ".exe", ".dll", ".bat", ".cmd", ".ps1", ".vbs", ".js", ".jse",
    ".wsf", ".wsh", ".scr", ".pif", ".com", ".hta", ".msi", ".sys",
}

RECENT_THRESHOLD = 7 * 24 * 3600
MAX_CONTENT_READ = 2 * 1024 * 1024


def is_system_impersonation(name: str) -> bool:
    low = name.lower()
    for pat in SYSTEM_NAME_PATTERNS:
        if re.match(pat, low):
            return True
    return False


def is_in_legit_system_dir(path: str) -> bool:
    try:
        low = str(Path(path).resolve()).lower()
    except OSError:
        low = str(path).lower()
    for d in LEGIT_SYSTEM_DIRS:
        if low.startswith(d):
            return True
    return False


def is_recently_created(path: str, threshold: int = RECENT_THRESHOLD) -> bool:
    try:
        st = os.stat(path)
        now = time.time()
        return (now - st.st_ctime) < threshold or (now - st.st_mtime) < threshold
    except OSError:
        return False


def scan_content(path: str) -> List[str]:
    found = []
    try:
        size = os.path.getsize(path)
        if size == 0 or size > MAX_CONTENT_READ:
            return found
        with open(path, "rb") as f:
            raw = f.read()
        text = raw.decode("latin-1", errors="ignore").lower()
        for s in SUSPICIOUS_STRINGS:
            if s in text:
                found.append(s)
    except (OSError, PermissionError):
        pass
    return found


def file_extension(path: str) -> str:
    return Path(path).suffix.lower()


def is_scannable(path: str) -> bool:
    return file_extension(path) in SCAN_EXTENSIONS
