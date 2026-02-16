@echo off
echo Initializing WinRE network...
wpeinit

set URL=https://raw.githubusercontent.com/JrPetersonjr/SnakeInMyBoot/master/fix.ps1
set OUT=X:\fix.ps1

echo Downloading repair script...
curl -L -o "%OUT%" "%URL%" >nul 2>&1
if errorlevel 1 (
  powershell -NoProfile -ExecutionPolicy Bypass -Command ^
    "Invoke-WebRequest -UseBasicParsing -Uri '%URL%' -OutFile '%OUT%'"
)

if not exist "%OUT%" (
  echo Failed to download repair script.
  pause
  exit /b 1
)

echo Running repair script...
powershell -NoProfile -ExecutionPolicy Bypass -File "%OUT%"
echo Done. You may now reboot.
pause
