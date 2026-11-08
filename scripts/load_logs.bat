@echo off
REM Loads data\logs_KHI.csv, logs_LHR.csv, logs_ISB.csv into each site with SQL*Loader,
REM then runs attack detection and refreshes the dashboard summary.
call "%~dp0config.bat"
cd /d "%~dp0.."
if not exist data\logs_KHI.csv (
  echo No CSV files found. Run: npm run generate
  exit /b 1
)
for %%S in (KHI LHR ISB) do (
  echo.
  echo ===== Loading site %%S =====
  sqlldr userid=tv_%%S/%TV_PWD%@%TV_CONN% control=sql\loader\log_event.ctl data=data\logs_%%S.csv log=data\load_%%S.log bad=data\load_%%S.bad
)
echo.
echo ===== Running detection and refreshing summary =====
cd sql
sqlplus -s tv_central/%TV_PWD%@%TV_CONN% @after_load.sql
