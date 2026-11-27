@echo off
setlocal
title SessionGuard
cd /d "%~dp0"

if exist SessionGuard.exe (
  start "" SessionGuard.exe
  exit /b 0
)

set PYCMD=
where python >nul 2>nul && set PYCMD=python
if "%PYCMD%"=="" (
  where py >nul 2>nul && set PYCMD=py -3
)
if "%PYCMD%"=="" (
  echo Python not found. Install Python 3.8+ from https://python.org
  echo with "Add Python to PATH", or double-click Build_EXE.bat first.
  pause
  exit /b 1
)

%PYCMD% -m pip install -q requests 2>nul
start "" %PYCMD% SessionGuard_GUI.py
