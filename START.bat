@echo off
title ThreatVault web app
cd /d "%~dp0"
if not exist node_modules\lucide-static (
  echo Installing new packages for the redesigned UI...
  call npm install
)
echo Starting ThreatVault at http://localhost:3000  (close this window to stop it)
start "" http://localhost:3000
call npm start
pause
