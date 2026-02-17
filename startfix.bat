@echo off
setlocal

if exist "%~dp0fixme.bat" (
  call "%~dp0fixme.bat" %*
  exit /b %ERRORLEVEL%
)

echo RootFix launcher not found at "%~dp0fixme.bat".
echo If your USB letter changed, run RUN-ROOTFIX.cmd instead.
pause
exit /b 1
