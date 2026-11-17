@echo off
setlocal

echo === UnSecurity Unlock build (nuitka) ===

python -m pip install --upgrade nuitka zstandard pywin32 cryptography

echo.
echo --- build single exe ---
python -m nuitka ^
  --standalone ^
  --onefile ^
  --enable-plugin=tk-inter ^
  --windows-console-mode=disable ^
  --windows-icon-from-ico=assets\icon-2.ico ^
  --include-data-dir=assets=assets ^
  --output-filename=UnSecurityUnlock.exe ^
  --assume-yes-for-downloads ^
  --remove-output ^
  --output-dir=dist ^
  main.py

echo.
echo Готово: dist\UnSecurityUnlock.exe
pause
