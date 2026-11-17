import subprocess
import sys
from pathlib import Path
import tkinter as tk
from tkinter import ttk


def show_startup_alert(findings: list) -> None:
    """Окно-приветствие при автостарте, если есть находки."""
    if not findings:
        return

    total_score = sum(f["score"] for f in findings)
    danger_pct = min(100, total_score * 10)

    root = tk.Tk()
    root.title("UnSecurity Unlock — привет")
    root.geometry("480x340")
    root.resizable(False, False)
    root.configure(bg="#0a0e14")

    style = ttk.Style(root)
    style.theme_use("clam")
    style.configure("Dark.TLabel", background="#0a0e14", foreground="#7fe8ff", font=("Segoe UI", 11))
    style.configure("Dark.TButton", background="#1f8fff", foreground="white", font=("Segoe UI", 10, "bold"))

    header = tk.Label(root, text="Привет!", bg="#0a0e14", fg="#7fe8ff",
                      font=("Segoe UI", 18, "bold"))
    header.pack(pady=(20, 6))

    msg = tk.Label(
        root,
        text="Антивирусом UnSecurity Unlock\nбыл предотвращён процесс вируса.",
        bg="#0a0e14", fg="#a0d8ff", justify="center", font=("Segoe UI", 11)
    )
    msg.pack(pady=8)

    danger_color = "#ff5050" if danger_pct >= 70 else "#ffb000" if danger_pct >= 40 else "#3fd0ff"
    danger = tk.Label(
        root,
        text=f"Опасность: {danger_pct}%",
        bg="#0a0e14", fg=danger_color,
        font=("Segoe UI", 24, "bold")
    )
    danger.pack(pady=10)

    count = tk.Label(
        root,
        text=f"Найдено: {len(findings)} подозрительных файлов",
        bg="#0a0e14", fg="#a0b0c0", font=("Segoe UI", 10)
    )
    count.pack(pady=4)

    preview = tk.Label(
        root,
        text="\n".join(f["name"] for f in findings[:3]) + ("\n..." if len(findings) > 3 else ""),
        bg="#0a0e14", fg="#607080", font=("Consolas", 9), justify="center"
    )
    preview.pack(pady=4)

    btn_frame = tk.Frame(root, bg="#0a0e14")
    btn_frame.pack(pady=18)

    def open_main():
        root.destroy()
        exe = Path(sys.executable).parent / "UnSecurityUnlock.exe"
        if exe.exists():
            subprocess.Popen([str(exe)], creationflags=0x00000008)

    ttk.Button(btn_frame, text="Открыть UnSecurity Unlock", style="Dark.TButton",
               command=open_main).pack(side="left", padx=8)
    ttk.Button(btn_frame, text="Позже", command=root.destroy).pack(side="left", padx=8)

    root.after(15000, root.destroy)
    root.mainloop()
