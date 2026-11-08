@echo off
REM Lab 5: Data Pump EXPORT of each site's LOG_EVENT table.
REM Dump files go to the folder of directory TV_DIR (dpdir in sql\config.sql).
call "%~dp0config.bat"
for %%S in (KHI LHR ISB) do (
  echo ===== Exporting %%S =====
  expdp tv_%%S/%TV_PWD%@%TV_CONN% tables=log_event directory=tv_dir dumpfile=%%S_logs.dmp logfile=%%S_export.log reuse_dumpfiles=yes
)
