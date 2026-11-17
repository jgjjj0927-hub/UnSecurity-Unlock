import os
import winreg
from pathlib import Path
from typing import List, Dict

RUN_KEYS = [
    (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Run"),
    (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\RunOnce"),
    (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\Run"),
    (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\RunOnce"),
    (winreg.HKEY_LOCAL_MACHINE, r"Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Run"),
]

STARTUP_DIRS = [
    Path(os.getenv("APPDATA", "")) / r"Microsoft\Windows\Start Menu\Programs\Startup",
    Path(os.getenv("PROGRAMDATA", "")) / r"Microsoft\Windows\Start Menu\Programs\Startup",
]


def get_startup_entries() -> List[Dict]:
    entries = []
    for hkey, subkey in RUN_KEYS:
        try:
            with winreg.OpenKey(hkey, subkey, 0, winreg.KEY_READ) as k:
                i = 0
                while True:
                    try:
                        name, value, _ = winreg.EnumValue(k, i)
                        i += 1
                        entries.append({
                            "source": "registry",
                            "key": f"{'HKCU' if hkey == winreg.HKEY_CURRENT_USER else 'HKLM'}\\{subkey}",
                            "name": name,
                            "command": str(value),
                        })
                    except OSError:
                        break
        except OSError:
            continue

    for d in STARTUP_DIRS:
        if d and d.exists():
            try:
                for item in d.iterdir():
                    if item.is_file():
                        entries.append({
                            "source": "folder",
                            "key": str(d),
                            "name": item.name,
                            "command": str(item),
                        })
            except OSError:
                continue

    return entries
