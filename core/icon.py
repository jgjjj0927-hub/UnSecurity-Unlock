import sys
from pathlib import Path
from typing import Optional


def icon_path() -> Optional[Path]:
    """Найти icon-2.ico в dev-режиме, onefile-распаковке или рядом с exe."""
    if hasattr(sys, "_MEIPASS"):
        p = Path(sys._MEIPASS) / "assets" / "icon-2.ico"
        if p.exists():
            return p
    if getattr(sys, "frozen", False) or getattr(sys, "__compiled__", False):
        p = Path(sys.executable).parent / "assets" / "icon-2.ico"
        if p.exists():
            return p
    p = Path(__file__).parent.parent / "assets" / "icon-2.ico"
    if p.exists():
        return p
    return None
