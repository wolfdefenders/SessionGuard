@echo off
setlocal
title SessionGuard - Build Windows EXE
cd /d "%~dp0"

echo ===============================================
echo  SessionGuard - one-click EXE builder
echo ===============================================
echo.
echo  [NOTE] YE SCRIPT OPTIONAL HAI - SIRF DEVELOPERS KE LIYE!
echo.
echo  SessionGuard.exe PEHLE SE BANI HUI IS FOLDER MEIN MOJOOD HAI.
echo  Tool chalane ke liye sirf SessionGuard.exe double-click karein.
echo  Ye script tool ko dobara banata hai - iske liye PC par Python
echo  (python.org se, "Add to PATH" ke sath) aur internet zaroori hai.
echo.
choice /C YN /N /M "Kya aap waqai rebuild karna chahte hain? (Y=Yes, N=No): "
if errorlevel 2 exit /b 0
echo.

set PYCMD=
where python >nul 2>nul && set PYCMD=python
if "%PYCMD%"=="" (
  where py >nul 2>nul && set PYCMD=py -3
)
if "%PYCMD%"=="" (
  echo [X] Python not found. Install Python 3.8+ from https://python.org
  echo     and tick "Add Python to PATH" during setup, then re-run this file.
  pause
  exit /b 1
)

echo [1/3] Installing requests + PyInstaller...
%PYCMD% -m pip install --upgrade pip
%PYCMD% -m pip install requests pyinstaller
if errorlevel 1 (
  echo [X] pip install failed - check your internet connection.
  pause
  exit /b 1
)

echo.
echo [2/3] Building SessionGuard.exe (onefile, windowed)...
%PYCMD% -m PyInstaller --noconfirm --clean --onefile --windowed ^
    --name SessionGuard --icon icon.ico --version-file version.txt ^
    SessionGuard_GUI.py
if errorlevel 1 (
  echo [X] Build failed. Read the messages above.
  pause
  exit /b 1
)

echo.
echo [3/3] Copying EXE to this folder...
if not exist dist\SessionGuard.exe (
  echo [X] dist\SessionGuard.exe missing.
  pause
  exit /b 1
)
copy /y dist\SessionGuard.exe SessionGuard.exe >nul
echo.
echo ===============================================
echo  DONE: SessionGuard.exe is ready in this folder
echo ===============================================
pause
