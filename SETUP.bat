@echo off
title ThreatVault one click setup
cd /d "%~dp0"
echo ============================================================
echo   ThreatVault setup: database, sample logs and web app
echo ============================================================
echo.

where node >nul 2>nul
if errorlevel 1 (
  echo [X] Node.js is not installed. Install it from https://nodejs.org then run SETUP.bat again.
  pause
  exit /b 1
)
where sqlplus >nul 2>nul
if errorlevel 1 (
  echo [X] SQL*Plus not found. Is Oracle installed and running?
  pause
  exit /b 1
)
echo [OK] Node.js and SQL*Plus found.

if not exist C:\threatvault_dump mkdir C:\threatvault_dump
echo [OK] Folder C:\threatvault_dump ready.
echo.

set /p SYS_PWD=Type your Oracle SYSTEM password and press Enter: 

REM Oracle 21c Enterprise uses ORCL service
set TV_SERVICE=orclpdb
echo exit | sqlplus -L -S system/%SYS_PWD%@localhost:1521/%TV_SERVICE% >nul
if not errorlevel 1 goto found

echo.
echo [X] Could not log in as SYSTEM.
echo     1. Check that the password is right.
echo     2. Open Services and start OracleServiceFREE or OracleServiceXE, and the TNS Listener.
echo     3. Run lsnrctl status and look for the database name.
pause
exit /b 1

:found
set TV_CONN=localhost:1521/%TV_SERVICE%
echo [OK] Using database service %TV_SERVICE%
echo [OK] SYSTEM login works.

REM Settings for the web app (this file is never uploaded to GitHub)
> .env echo DB_USER=tv_central
>> .env echo DB_PASSWORD=tvpass123
>> .env echo DB_CONNECT=%TV_CONN%
>> .env echo SITE_PASSWORD=tvpass123
>> .env echo PORT=3000
>> .env echo SESSION_SECRET=threatvault%RANDOM%%RANDOM%%RANDOM%

echo.
echo ===== Step 1 of 4: installing Node packages =====
call npm install
if errorlevel 1 (
  echo [X] npm install failed.
  pause
  exit /b 1
)

echo.
echo ===== Step 2 of 4: creating the Oracle database =====
REM The SYSTEM password is written only while the database is being created
> sql\config.sql echo DEFINE conn   = %TV_CONN%
>> sql\config.sql echo DEFINE pwd    = tvpass123
>> sql\config.sql echo DEFINE syspwd = %SYS_PWD%
>> sql\config.sql echo DEFINE dpdir  = C:\threatvault_dump
> scripts\config.bat echo @echo off
>> scripts\config.bat echo set TV_CONN=%TV_CONN%
>> scripts\config.bat echo set TV_PWD=tvpass123
>> scripts\config.bat echo set SYS_PWD=%SYS_PWD%

cd sql
echo exit | sqlplus -L system/%SYS_PWD%@%TV_CONN% @install.sql
cd ..

REM Remove the SYSTEM password again, so it never goes to GitHub
> sql\config.sql echo DEFINE conn   = %TV_CONN%
>> sql\config.sql echo DEFINE pwd    = tvpass123
>> sql\config.sql echo DEFINE syspwd = YOUR_SYSTEM_PASSWORD
>> sql\config.sql echo DEFINE dpdir  = C:\threatvault_dump
> scripts\config.bat echo @echo off
>> scripts\config.bat echo set TV_CONN=%TV_CONN%
>> scripts\config.bat echo set TV_PWD=tvpass123
>> scripts\config.bat echo set SYS_PWD=YOUR_SYSTEM_PASSWORD

REM Check that the database was really created
echo exit | sqlplus -L -S tv_central/tvpass123@%TV_CONN% >nul
if errorlevel 1 goto dbfail
echo [OK] ThreatVault database created.

echo.
echo ===== Step 3 of 4: generating and loading sample logs =====
call npm run generate
where sqlldr >nul 2>nul
if errorlevel 1 (
  echo sqlldr not found, loading with Node.js instead...
  call npm run load
) else (
  call scripts\load_logs.bat
  cd /d "%~dp0"
)

echo.
echo ===== Step 4 of 4: checking everything =====
call npm run check

echo.
echo ============================================================
echo   Setup finished. Double click START.bat to open the website.
echo   Login: admin / admin123
echo ============================================================
pause
exit /b 0

:dbfail
echo.
echo [X] The ThreatVault database was not created.
echo     Scroll up and look for lines that start with ORA or PLS.
echo     Send a screenshot of those lines to get help.
pause
exit /b 1