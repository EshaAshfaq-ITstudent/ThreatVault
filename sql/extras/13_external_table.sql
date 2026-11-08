-- ============================================================
-- 13 External table (Labs 3 and 4: data extraction), run as tv_khi
-- Before running: copy data\logs_KHI.csv into the folder set as dpdir
-- in config.sql (default C:\threatvault_dump).
-- An external table lets you query a CSV file with SQL without loading it.
-- ============================================================

BEGIN
  EXECUTE IMMEDIATE 'DROP TABLE log_event_ext';
EXCEPTION WHEN OTHERS THEN NULL;
END;
/

CREATE TABLE log_event_ext (
  site_code   VARCHAR2(3),
  event_time  VARCHAR2(19),
  asset_id    NUMBER,
  src_ip      VARCHAR2(15),
  src_country VARCHAR2(40),
  dst_port    NUMBER,
  event_type  VARCHAR2(20),
  action      VARCHAR2(10),
  username    VARCHAR2(40),
  detail      VARCHAR2(200)
)
ORGANIZATION EXTERNAL (
  TYPE ORACLE_LOADER
  DEFAULT DIRECTORY tv_dir
  ACCESS PARAMETERS (
    RECORDS DELIMITED BY NEWLINE
    SKIP 1
    FIELDS TERMINATED BY ',' OPTIONALLY ENCLOSED BY '"'
    MISSING FIELD VALUES ARE NULL
  )
  LOCATION ('logs_KHI.csv')
)
REJECT LIMIT UNLIMITED;

PROMPT ===== Query the CSV file directly =====
SELECT event_type, COUNT(*) AS rows_in_file
FROM   log_event_ext
GROUP  BY event_type
ORDER  BY 2 DESC;

PROMPT To load from the external table instead of SQL*Loader:
PROMPT INSERT INTO log_event (site_code, event_time, asset_id, src_ip, src_country, dst_port, event_type, action, username, detail)
PROMPT SELECT site_code, TO_DATE(event_time,'YYYY-MM-DD HH24:MI:SS'), asset_id, src_ip, src_country, dst_port, event_type, action, username, detail FROM log_event_ext;
