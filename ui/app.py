import tkinter as tk
from tkinter import ttk, messagebox, simpledialog
import threading

from core import scanner, startup, quarantine, defender, firmware, vault
from core.logger import logger


def ask_master_password(root, create: bool = False) -> str | None:
    """Запросить мастер-пароль. Если create=True — создать новый."""
    if create:
        p1 = simpledialog.askstring("Мастер-пароль", "Задайте мастер-пароль карантина:", show="*", parent=root)
        if not p1:
            return None
        p2 = simpledialog.askstring("Мастер-пароль", "Повторите пароль:", show="*", parent=root)
        if p1 != p2:
            messagebox.showerror("Ошибка", "Пароли не совпадают.")
            return None
        if len(p1) < 6:
            messagebox.showerror("Ошибка", "Минимум 6 символов.")
            return None
        vault.init_master(p1)
        messagebox.showinfo("Карантин", "Мастер-пароль создан. Не забудьте его!")
        return p1
    else:
        p = simpledialog.askstring("Мастер-пароль", "Введите мастер-пароль карантина:", show="*", parent=root)
        if not p:
            return None
        if not vault.verify_master(p):
            messagebox.showerror("Ошибка", "Неверный пароль.")
            return None
        return p


class UnSecurityApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("UnSecurity Unlock")
        self.geometry("1100x680")
        self.minsize(900, 520)

        self.findings = []
        self.startup_findings = []
        self._row_paths = {}
        self._quar_paths = {}

        if not vault.is_initialized():
            ask_master_password(self, create=True)

        self._build_ui()

    def _build_ui(self):
        top = ttk.Frame(self, padding=8)
        top.pack(fill="x")

        ttk.Button(top, text="Сканировать всё", command=self.on_scan_all).pack(side="left", padx=4)
        ttk.Button(top, text="Проверить автозапуск", command=self.on_scan_startup).pack(side="left", padx=4)
        ttk.Button(top, text="Переместить в карантин", command=self.on_quarantine).pack(side="left", padx=4)
        ttk.Button(top, text="Добавить исключения Defender", command=self.on_defender).pack(side="left", padx=4)
        ttk.Button(top, text="Проверить прошивку", command=self.on_firmware).pack(side="left", padx=4)

        self.status_var = tk.StringVar(value="Готов")
        ttk.Label(self, textvariable=self.status_var, anchor="w", padding=(8, 2)).pack(fill="x")

        # Ноутбук: вкладки
        nb = ttk.Notebook(self)
        nb.pack(fill="both", expand=True, padx=8, pady=8)

        # Вкладка 1 — сканер
        scan_tab = ttk.Frame(nb)
        nb.add(scan_tab, text="Сканер")

        columns = ("score", "name", "path", "reasons")
        self.tree = ttk.Treeview(scan_tab, columns=columns, show="headings", height=20)
        self.tree.heading("score", text="Опасность")
        self.tree.heading("name", text="Имя")
        self.tree.heading("path", text="Путь")
        self.tree.heading("reasons", text="Причины")
        self.tree.column("score", width=80, anchor="center")
        self.tree.column("name", width=200)
        self.tree.column("path", width=420)
        self.tree.column("reasons", width=380)
        vsb = ttk.Scrollbar(scan_tab, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=vsb.set)
        self.tree.pack(side="left", fill="both", expand=True)
        vsb.pack(side="right", fill="y")

        # Вкладка 2 — карантин
        quar_tab = ttk.Frame(nb)
        nb.add(quar_tab, text="Карантин")

        q_cols = ("name", "size")
        self.q_tree = ttk.Treeview(quar_tab, columns=q_cols, show="headings", height=20)
        self.q_tree.heading("name", text="Файл в карантине")
        self.q_tree.heading("size", text="Размер")
        self.q_tree.column("name", width=600)
        self.q_tree.column("size", width=120, anchor="center")
        qvsb = ttk.Scrollbar(quar_tab, orient="vertical", command=self.q_tree.yview)
        self.q_tree.configure(yscrollcommand=qvsb.set)
        self.q_tree.pack(side="left", fill="both", expand=True)
        qvsb.pack(side="right", fill="y")

        q_btns = ttk.Frame(quar_tab)
        q_btns.pack(side="bottom", fill="x", pady=4)
        ttk.Button(q_btns, text="Обновить список", command=self.on_refresh_quarantine).pack(side="left", padx=4)
        ttk.Button(q_btns, text="Восстановить", command=self.on_restore).pack(side="left", padx=4)
        ttk.Button(q_btns, text="Запустить (временно)", command=self.on_run_from_quarantine).pack(side="left", padx=4)

        self.on_refresh_quarantine()

    # ---- сканер ----

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
        password = ask_master_password(self)
        if not password:
            return
        try:
            dest = quarantine.quarantine_file(path, password)
            messagebox.showinfo("Карантин", f"Зашифровано и помещено:\n{dest}")
            self.tree.delete(iid)
            self._row_paths.pop(iid, None)
            self.on_refresh_quarantine()
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
            msg += ("ПРЕДУПРЕЖДЕНИЕ:\n" + warn) if warn else "Прошивка настроена безопасно."
            messagebox.showinfo("Проверка прошивки", msg)
            self.status_var.set("Проверка прошивки завершена")
        except Exception as e:
            messagebox.showerror("Ошибка", str(e))

    # ---- карантин ----

    def on_refresh_quarantine(self):
        for i in self.q_tree.get_children():
            self.q_tree.delete(i)
        self._quar_paths.clear()
        for item in quarantine.list_quarantine():
            iid = self.q_tree.insert("", "end", values=(item["name"], item["size"]))
            self._quar_paths[iid] = item["name"]

    def on_restore(self):
        sel = self.q_tree.selection()
        if not sel:
            messagebox.showinfo("Карантин", "Выберите файл.")
            return
        name = self._quar_paths.get(sel[0])
        if not name:
            return
        password = ask_master_password(self)
        if not password:
            return
        # оригинальное имя — убираем префикс даты и .quar
        base = name.split("_", 2)[-1] if "_" in name else name
        if base.endswith(".quar"):
            base = base[:-5]
        target = simpledialog.askstring(
            "Восстановление",
            f"Куда восстановить?\n(по умолчанию: C:\\Temp\\{base})",
            initialvalue=f"C:\\Temp\\{base}",
            parent=self,
        )
        if not target:
            return
        try:
            out = quarantine.restore_file(name, target, password)
            messagebox.showinfo("Карантин", f"Восстановлено:\n{out}")
            self.on_refresh_quarantine()
        except Exception as e:
            messagebox.showerror("Ошибка", str(e))

    def on_run_from_quarantine(self):
        sel = self.q_tree.selection()
        if not sel:
            messagebox.showinfo("Карантин", "Выберите файл.")
            return
        name = self._quar_paths.get(sel[0])
        if not name:
            return
        password = ask_master_password(self)
        if not password:
            return
        if not messagebox.askyesno("Запуск", "Расшифровать и запустить? Это опасно."):
            return
        try:
            quarantine.run_from_quarantine(name, password)
            messagebox.showinfo("Карантин", "Запущено. Процесс работает.")
        except Exception as e:
            messagebox.showerror("Ошибка", str(e))

    # ---- helpers ----

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
