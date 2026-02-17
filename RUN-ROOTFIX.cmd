@echo off
setlocal
for %%D in (D E F G H I J K L M N O P Q R S T U V W Y Z) do (
  if exist "%%D:\RootFix\fixme.bat" (
    echo Launching RootFix from %%D:\RootFix\fixme.bat
    call "%%D:\RootFix\fixme.bat"
    exit /b %ERRORLEVEL%
  )
)
echo RootFix not found on USB letters D: through Z:.
pause
exit /b 1
