@echo off
REM Lab 5: Data Pump IMPORT. Restores one site's LOG_EVENT table from its dump file.
REM Usage: import_logs.bat KHI
call "%~dp0config.bat"
if "%1"=="" (
  echo Usage: import_logs.bat KHI   ^(or LHR, ISB^)
  exit /b 1
)
impdp tv_%1/%TV_PWD%@%TV_CONN% tables=log_event directory=tv_dir dumpfile=%1_logs.dmp logfile=%1_import.log table_exists_action=replace
