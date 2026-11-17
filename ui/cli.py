import getpass
from core import scanner, startup, quarantine, defender, firmware, vault


def _ask_password() -> str | None:
    p = getpass.getpass("Мастер-пароль карантина: ")
    if not vault.verify_master(p):
        print("Неверный пароль.")
        return None
    return p


def run():
    print("=" * 60)
    print(" UnSecurity Unlock — консольный режим")
    print("=" * 60)

    if not vault.is_initialized():
        p1 = getpass.getpass("Задайте мастер-пароль карантина: ")
        p2 = getpass.getpass("Повторите: ")
        if p1 != p2 or len(p1) < 6:
            print("Пароли не совпадают или короче 6 символов. Выход.")
            return
        vault.init_master(p1)
        print("Мастер-пароль создан.")

    while True:
        print("\nМеню:")
        print(" 1 — Сканировать всё")
        print(" 2 — Проверить автозапуск")
        print(" 3 — Карантин: список")
        print(" 4 — Карантин: восстановить")
        print(" 5 — Карантин: запустить")
        print(" 6 — Defender: исключения")
        print(" 7 — Проверить прошивку")
        print(" 0 — Выход")
        try:
            choice = input("> ").strip()
        except (EOFError, KeyboardInterrupt):
            break

        if choice == "1":
            roots = scanner.get_scan_roots()
            print(f"Сканирую {len(roots)} корней...")
            findings = scanner.scan_paths(roots, progress_cb=lambda n, p: print(f"  [{n}] {p[-60:]}"))
            for f in findings:
                print(f"[{f['score']}] {f['name']} — {f['path']}")
                print(f"   причины: {f['reasons']}")
            if not findings:
                print("Чисто.")
        elif choice == "2":
            for e in startup.get_startup_entries():
                print(f"{e['name']} -> {e['command']} ({e['key']})")
        elif choice == "3":
            for q in quarantine.list_quarantine():
                print(f"{q['name']}  {q['size']} bytes")
        elif choice == "4":
            name = input("Имя файла в карантине: ").strip()
            target = input("Куда восстановить: ").strip()
            pwd = _ask_password()
            if pwd:
                try:
                    print("Восстановлено:", quarantine.restore_file(name, target, pwd))
                except Exception as e:
                    print("Ошибка:", e)
        elif choice == "5":
            name = input("Имя файла в карантине: ").strip()
            pwd = _ask_password()
            if pwd:
                try:
                    quarantine.run_from_quarantine(name, pwd)
                    print("Запущено.")
                except Exception as e:
                    print("Ошибка:", e)
        elif choice == "6":
            try:
                print("\n".join(defender.add_defender_exclusions()))
            except Exception as e:
                print("Ошибка:", e)
        elif choice == "7":
            try:
                data = firmware.check_firmware()
                for k, v in data.items():
                    print(f"{k}: {v}")
                warn = firmware.firmware_warning()
                if warn:
                    print("ПРЕДУПРЕЖДЕНИЕ:", warn)
            except Exception as e:
                print("Ошибка:", e)
        elif choice == "0":
            break
