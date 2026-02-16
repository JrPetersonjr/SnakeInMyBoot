@echo off
setlocal EnableExtensions EnableDelayedExpansion

title RootFix Recovery Assistant
color 0A

set USBROOT=%~d0\RootFix
set LOCAL_SCRIPT=%USBROOT%\fix.ps1
set LOGDIR=%USBROOT%\logs
set URL=https://raw.githubusercontent.com/JrPetersonjr/SnakeInMyBoot/master/fix.ps1
set HASHURL=https://raw.githubusercontent.com/JrPetersonjr/SnakeInMyBoot/master/fix.ps1.sha256
set STAGE=X:\fix.ps1
set STAGEHASH=X:\fix.ps1.sha256
set SCRIPT_TO_RUN=%LOCAL_SCRIPT%
set PS_MODE=auto
set UPDATE_MODE=local

set LOGFILE=%LOGDIR%\bootstrap-%DATE:~10,4%%DATE:~4,2%%DATE:~7,2%-%TIME:~0,2%%TIME:~3,2%%TIME:~6,2%.log
set LOGFILE=%LOGFILE: =0%
if not exist "%LOGDIR%" mkdir "%LOGDIR%"

echo [%DATE% %TIME%] Starting bootstrap > "%LOGFILE%"
echo Local script: %LOCAL_SCRIPT%>> "%LOGFILE%"

if not exist "%LOCAL_SCRIPT%" (
  echo Local script is missing at %LOCAL_SCRIPT%>> "%LOGFILE%"
  echo Local script missing. Cannot continue safely.
  echo See log: %LOGFILE%
  pause
  exit /b 1
)

if /I "%~1"=="update" set UPDATE_MODE=update
if /I "%~1"=="menu" goto MENU
if /I "%~1"=="kb" set PS_MODE=kb
if /I "%~1"=="full" set PS_MODE=full
if /I "%~1"=="boot" set PS_MODE=boot
if /I "%~1"=="repair" set PS_MODE=repair
if /I "%~1"=="auto" set PS_MODE=auto
if not "%~1"=="" goto RUN

:MENU
cls
echo ============================================
echo          ROOTFIX RECOVERY ASSISTANT
echo ============================================
echo.
echo Choose one option:
echo.
echo   1. Recommended: Auto repair (local script)
echo   2. Auto repair + check for verified online update
echo   3. KB5077181 rollback check + disable updates
echo   4. Full repair (all actions)
echo   5. Boot repair only
echo   6. Cache reset + DISM/SFC only
echo   7. Exit
echo.
set /p CHOICE=Enter 1-7 and press Enter: 

if "%CHOICE%"=="1" (set PS_MODE=auto&set UPDATE_MODE=local&goto RUN)
if "%CHOICE%"=="2" (set PS_MODE=auto&set UPDATE_MODE=update&goto RUN)
if "%CHOICE%"=="3" (set PS_MODE=kb&set UPDATE_MODE=local&goto RUN)
if "%CHOICE%"=="4" (set PS_MODE=full&set UPDATE_MODE=local&goto RUN)
if "%CHOICE%"=="5" (set PS_MODE=boot&set UPDATE_MODE=local&goto RUN)
if "%CHOICE%"=="6" (set PS_MODE=repair&set UPDATE_MODE=local&goto RUN)
if "%CHOICE%"=="7" exit /b 0

echo Invalid choice.
timeout /t 2 >nul
goto MENU

:RUN
echo Mode: %PS_MODE% >> "%LOGFILE%"
echo Update mode: %UPDATE_MODE% >> "%LOGFILE%"

if /I "%UPDATE_MODE%"=="update" (
  echo Initializing WinRE network for update check...
  wpeinit >> "%LOGFILE%" 2>&1

  echo Downloading latest hosted script and checksum...
  curl -L -o "%STAGE%" "%URL%" >> "%LOGFILE%" 2>&1
  if errorlevel 1 (
    powershell -NoProfile -ExecutionPolicy RemoteSigned -Command "Invoke-WebRequest -UseBasicParsing -Uri '%URL%' -OutFile '%STAGE%'" >> "%LOGFILE%" 2>&1
  )

  curl -L -o "%STAGEHASH%" "%HASHURL%" >> "%LOGFILE%" 2>&1
  if errorlevel 1 (
    powershell -NoProfile -ExecutionPolicy RemoteSigned -Command "Invoke-WebRequest -UseBasicParsing -Uri '%HASHURL%' -OutFile '%STAGEHASH%'" >> "%LOGFILE%" 2>&1
  )

  if exist "%STAGE%" if exist "%STAGEHASH%" (
    for /f %%H in ('powershell -NoProfile -Command "(Get-FileHash -Algorithm SHA256 '%STAGE%').Hash"') do set DLHASH=%%H
    for /f "tokens=1" %%H in ('type "%STAGEHASH%"') do set EXPHASH=%%H

    echo Downloaded hash: !DLHASH!>> "%LOGFILE%"
    echo Expected hash: !EXPHASH!>> "%LOGFILE%"

    if /I "!DLHASH!"=="!EXPHASH!" (
      set SCRIPT_TO_RUN=%STAGE%
      echo Remote script hash verified. Using downloaded script.>> "%LOGFILE%"
    ) else (
      echo Hash mismatch on downloaded script. Using local fallback.>> "%LOGFILE%"
    )
  ) else (
    echo Download/update check incomplete. Using local fallback.>> "%LOGFILE%"
  )
) else (
  echo Local-first mode selected. Skipping network update check.>> "%LOGFILE%"
)

echo Running repair script: %SCRIPT_TO_RUN% >> "%LOGFILE%"
powershell -NoProfile -ExecutionPolicy RemoteSigned -File "%SCRIPT_TO_RUN%" -Mode "%PS_MODE%" -LogRoot "%LOGDIR%" >> "%LOGFILE%" 2>&1
set EXITCODE=%ERRORLEVEL%

echo [%DATE% %TIME%] Repair script exit code: %EXITCODE%>> "%LOGFILE%"
if not "%EXITCODE%"=="0" (
  echo Repair completed with warnings/errors. See log:
  echo %LOGFILE%
  pause
  exit /b %EXITCODE%
)

echo Done. You may now reboot.
echo Log file: %LOGFILE%
pause
exit /b 0
