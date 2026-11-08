-- ============================================================
-- SQL*Loader control file (Labs 3 and 4: data extraction and loading)
-- Loads one site CSV into that site's LOG_EVENT table.
-- Used by scripts\load_logs.bat, for example:
--   sqlldr userid=tv_khi/tvpass123@localhost:1521/XEPDB1 control=sql\loader\log_event.ctl data=data\logs_KHI.csv
-- ============================================================
OPTIONS (SKIP=1, ROWS=5000, ERRORS=100)
LOAD DATA
CHARACTERSET UTF8
APPEND
INTO TABLE log_event
FIELDS TERMINATED BY ',' OPTIONALLY ENCLOSED BY '"'
TRAILING NULLCOLS
(
  site_code,
  event_time  DATE "YYYY-MM-DD HH24:MI:SS",
  asset_id,
  src_ip,
  src_country,
  dst_port,
  event_type,
  action,
  username,
  detail
)
