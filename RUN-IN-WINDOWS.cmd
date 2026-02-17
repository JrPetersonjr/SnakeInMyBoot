@echo off
setlocal

:: Relaunch elevated if needed
net session >nul 2>&1
if not %errorlevel%==0 (
  powershell -NoProfile -Command "Start-Process -FilePath '%~f0' -Verb RunAs"
  exit /b
)

title RootFix Windows Update Guard
color 0B

:MENU
cls
echo ============================================
echo        ROOTFIX WINDOWS UPDATE GUARD
echo ============================================
echo.
echo  1. Prep update safely (recommended)
echo  2. Disable auto updates
echo  3. Re-enable normal auto updates
echo  4. Exit
echo.
set /p CH=Enter 1-4 and press Enter: 

if "%CH%"=="1" powershell -NoProfile -ExecutionPolicy RemoteSigned -File "%~dp0windows_update_guard.ps1" -Mode prep-update & goto END
if "%CH%"=="2" powershell -NoProfile -ExecutionPolicy RemoteSigned -File "%~dp0windows_update_guard.ps1" -Mode disable-auto & goto END
if "%CH%"=="3" powershell -NoProfile -ExecutionPolicy RemoteSigned -File "%~dp0windows_update_guard.ps1" -Mode enable-auto & goto END
if "%CH%"=="4" exit /b 0

echo Invalid choice.
timeout /t 2 >nul
goto MENU

:END
echo.
echo Done.
pause
exit /b 0
