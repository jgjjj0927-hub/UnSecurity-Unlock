import tkinter as tk
from tkinter import ttk, messagebox
import threading

from core import scanner, startup, quarantine, defender, firmware
from core.logger import logger


class UnSecurityApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("UnSecurity Unlock")
        self.geometry("1100x650")
        self.minsize(900, 500)

        self.findings = []
        self.startup_findings = []
        self._row_paths = {}

        self._build_ui()

    def _build_ui(self):
        top = ttk.Frame(self, padding=8)
        top.pack(fill="x")

        self.btn_scan_all = ttk.Button(top, text="Сканировать всё", command=self.on_scan_all)
        self.btn_scan_all.pack(side="left", padx=4)

        self.btn_scan_startup = ttk.Button(top, text="Проверить автозапуск", command=self.on_scan_startup)
        self.btn_scan_startup.pack(side="left", padx=4)

        self.btn_quarantine = ttk.Button(top, text="Переместить в карантин", command=self.on_quarantine)
        self.btn_quarantine.pack(side="left", padx=4)

        self.btn_defender = ttk.Button(top, text="Добавить исключения Defender", command=self.on_defender)
        self.btn_defender.pack(side="left", padx=4)

        self.btn_firmware = ttk.Button(top, text="Проверить прошивку", command=self.on_firmware)
        self.btn_firmware.pack(side="left", padx=4)

        self.status_var = tk.StringVar(value="Готов")
        status = ttk.Label(self, textvariable=self.status_var, anchor="w", padding=(8, 2))
        status.pack(fill="x")

        columns = ("score", "name", "path", "reasons")
        self.tree = ttk.Treeview(self, columns=columns, show="headings", height=20)
        self.tree.heading("score", text="Опасность")
        self.tree.heading("name", text="Имя")
        self.tree.heading("path", text="Путь")
        self.tree.heading("reasons", text="Причины")
        self.tree.column("score", width=80, anchor="center")
        self.tree.column("name", width=200)
        self.tree.column("path", width=420)
        self.tree.column("reasons", width=380)

        vsb = ttk.Scrollbar(self, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=vsb.set)
        self.tree.pack(side="left", fill="both", expand=True, padx=(8, 0), pady=8)
        vsb.pack(side="right", fill="y", pady=8)

    def on_scan_all(self):
        self.status_var.set("Сканирование дисков...")
        self._clear_tree()
        threading.Thread(target=self._scan_worker, daemon=True).start()

    def _scan_worker(self):
        roots = scanner.get_scan_roots()
        findings = scanner.scan_paths(roots, progress_cb=self._progress_cb)
        self.findings = findings
        self.after(0, self._populate_tree, findings)
        self.after(0, lambda: self.status_var.set(f"Готово. Найдено: {len(findings)}"))

    def _progress_cb(self, scanned, current):
        self.after(0, lambda: self.status_var.set(f"Просканировано: {scanned} — {current[-60:]}"))

    def on_scan_startup(self):
        self.status_var.set("Проверка автозапуска...")
        self._clear_tree()
        entries = startup.get_startup_entries()
        results = []
        for e in entries:
            cmd = e["command"].strip('"').split(" ")[0]
            if cmd and cmd.lower().endswith((".exe", ".bat", ".cmd", ".ps1", ".vbs", ".js")):
                reasons = []
                if any(w in cmd.lower() for w in ("temp", "appdata", "programdata", "downloads")):
                    reasons.append("Запуск из временной/пользовательской папки")
                results.append({
                    "path": e["command"],
                    "name": e["name"],
                    "score": 5,
                    "reasons": "; ".join(reasons) or "Проверить вручную",
                })
        self.startup_findings = results
        self._populate_tree(results)
        self.status_var.set(f"Автозапуск проверен. Подозрительных: {len(results)}")

    def on_quarantine(self):
        sel = self.tree.selection()
        if not sel:
            messagebox.showinfo("Карантин", "Выберите запись в списке.")
            return
        iid = sel[0]
        path = self._row_paths.get(iid)
        if not path:
            return
        try:
            dest = quarantine.quarantine_file(path)
            messagebox.showinfo("Карантин", f"Перемещено:\n{dest}")
            self.tree.delete(iid)
            self._row_paths.pop(iid, None)
        except Exception as e:
            messagebox.showerror("Ошибка", str(e))

    def on_defender(self):
        res = defender.add_defender_exclusions()
        messagebox.showinfo("Defender", "\n".join(res))

    def on_firmware(self):
        self.status_var.set("Проверка прошивки...")
        try:
            data = firmware.check_firmware()
            warn = firmware.firmware_warning()
            msg = (
                f"Тип прошивки: {data['firmware_type']}\n"
                f"Secure Boot: {data['secure_boot']}\n"
                f"TPM: {data['tpm']}\n"
                f"Загрузчик SHA-256: {data['bootloader_sha256'][:32] or 'не найден'}...\n\n"
            )
            if warn:
                msg += "ПРЕДУПРЕЖДЕНИЕ:\n" + warn
            else:
                msg += "Прошивка настроена безопасно."
            messagebox.showinfo("Проверка прошивки", msg)
            self.status_var.set("Проверка прошивки завершена")
        except Exception as e:
            messagebox.showerror("Ошибка", str(e))

    def _clear_tree(self):
        for i in self.tree.get_children():
            self.tree.delete(i)
        self._row_paths.clear()

    def _populate_tree(self, findings):
        self._clear_tree()
        for f in sorted(findings, key=lambda x: x["score"], reverse=True):
            iid = self.tree.insert("", "end", values=(f["score"], f["name"], f["path"], f["reasons"]))
            self._row_paths[iid] = f["path"]


def run():
    app = UnSecurityApp()
    app.mainloop()
