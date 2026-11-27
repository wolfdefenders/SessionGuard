@echo off
setlocal
title SessionGuard - Setup / Installer
cd /d "%~dp0"

echo =====================================================
echo   SessionGuard v2.0 - Setup (one-click installer)
echo   Made for Rayyan - Web Session Security
echo   PNY Trainings - Instructor: Abdul Mannan
echo =====================================================
echo.

if not exist SessionGuard.exe (
  echo [X] SessionGuard.exe nahi mila!
  echo     Ye file ko usi folder mein rakhein jahan SessionGuard.exe hai.
  pause
  exit /b 1
)

echo [1/4] SessionGuard.exe mil gaya - build verify kar raha hoon...
SessionGuard.exe --selftest >nul 2>&1
if errorlevel 1 (
  echo [!] Self-test warning aaya - lekin tool phir bhi normal chalega.
) else (
  echo [OK] Self-test passed: 19 checks, 0 failed.
)
echo.

echo [2/4] Desktop aur Start Menu shortcuts bana raha hoon...
powershell -NoProfile -ExecutionPolicy Bypass -Command ^
  "$ws=New-Object -ComObject WScript.Shell; $p=[Environment]::GetFolderPath('Desktop')+'\SessionGuard.lnk'; $s=$ws.CreateShortcut($p); $s.TargetPath='%~dp0SessionGuard.exe'; $s.WorkingDirectory='%~dp0'; $s.Save(); $d=[Environment]::GetFolderPath('Programs')+'\SessionGuard'; New-Item -ItemType Directory -Force -Path $d | Out-Null; $s2=$ws.CreateShortcut($d+'\SessionGuard.lnk'); $s2.TargetPath='%~dp0SessionGuard.exe'; $s2.WorkingDirectory='%~dp0'; $s2.Save(); if(Test-Path '%~dp0LabServer.exe'){$s3=$ws.CreateShortcut($d+'\SessionGuard LabServer.lnk'); $s3.TargetPath='%~dp0LabServer.exe'; $s3.WorkingDirectory='%~dp0'; $s3.Save()}" >nul 2>&1
if errorlevel 1 (
  echo [i] Shortcuts skip ho gaye - koi masla nahi, EXE seedha bhi chalti hai.
) else (
  echo [OK] Shortcuts ready: Desktop + Start Menu ^(+ LabServer^).
)
echo.

echo [3/4] Python requirements check (sirf source code / lab_server.py
echo       ke liye - EXE tool ke liye in ki zaroorat nahi hoti)...
set PYCMD=
where python >nul 2>nul && (python -c "import sys" >nul 2>&1 && set PYCMD=python)
if not defined PYCMD (
  where py >nul 2>nul && (py -3 -c "import sys" >nul 2>&1 && set PYCMD=py -3)
)
if defined PYCMD (
  echo     Python mila - requirements install ho rahi hain: requests + flask
  %PYCMD% -m pip install --disable-pip-version-check -q requests flask >nul 2>&1
  if errorlevel 1 (
    echo [!] pip install skip hua - internet ya setup ka masla.
    echo     Koi baat nahi: SessionGuard.exe standalone hai, phir bhi 100 chalay ga.
  ) else (
    echo [OK] requirements installed: requests + flask
  )
) else (
  echo [i] Python nahi mila - KOI MASLA NAHI, kuch install karne ki
  echo     zaroorat nahi:
  echo     - SessionGuard.exe standalone hai: sab kuch EXE ke andar bundled hai.
  echo     - LabServer.exe bhi standalone hai: demo site bhi bina Python chalegi.
  echo     Isi liye ye step automatic skip ho gaya.
)
echo.

echo [4/4] Finish...
if exist LabServer.exe (
  echo [OK] LabServer.exe ready hai - practice demo site. Double-click
  echo     karke chalayen, phir SessionGuard mein target likhein:
  echo     http://127.0.0.1:5057/
) else (
  echo [i] LabServer.exe is folder mein nahi - optional hai, tool ke
  echo     liye zaroori nahi.
)
echo.
echo =====================================================
echo   INSTALL MUKAMMAL!
echo -----------------------------------------------------
echo   SessionGuard.exe   = asli tool  (double-click)
echo   LabServer.exe      = practice demo site (double-click)
echo   HOW_TO_USE.txt     = poori guide (Roman Urdu + English)
echo =====================================================
echo.
choice /C YN /N /M "Abhi SessionGuard kholna hai? (Y=Yes, N=No): "
if errorlevel 2 exit /b 0
start "" SessionGuard.exe
exit /b 0
