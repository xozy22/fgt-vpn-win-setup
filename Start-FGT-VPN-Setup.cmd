@echo off
REM Startet FGT-VPN-Setup.ps1 unabhaengig von der Execution Policy (nur fuer diesen Aufruf).
title FGT-VPN Setup
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0FGT-VPN-Setup.ps1" %*
