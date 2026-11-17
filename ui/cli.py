from core import scanner, startup, quarantine, defender, firmware


def run():
    print("=" * 60)
    print(" UnSecurity Unlock — консольный режим")
    print("=" * 60)
    while True:
        print("\nМеню:")
        print(" 1 — Сканировать всё")
        print(" 2 — Проверить автозапуск")
        print(" 3 — Карантин: список")
        print(" 4 — Defender: исключения")
        print(" 5 — Проверить прошивку")
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
            try:
                print("\n".join(defender.add_defender_exclusions()))
            except Exception as e:
                print(f"Ошибка: {e}")
        elif choice == "5":
            try:
                data = firmware.check_firmware()
                for k, v in data.items():
                    print(f"{k}: {v}")
                warn = firmware.firmware_warning()
                if warn:
                    print("ПРЕДУПРЕЖДЕНИЕ:", warn)
            except Exception as e:
                print(f"Ошибка: {e}")
        elif choice == "0":
            break
