@echo off
REM Creates all ThreatVault users, tables, types, package, views and audit policy.
call "%~dp0config.bat"
cd /d "%~dp0..\sql"
echo Installing ThreatVault into %TV_CONN% ...
sqlplus system/%SYS_PWD%@%TV_CONN% @install.sql
