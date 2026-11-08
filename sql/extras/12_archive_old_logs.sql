-- ============================================================
-- 12 Archive old logs (Labs 5 and 7), run as a site user
-- Step 1: export old logs with Data Pump first:  scripts\export_logs.bat
-- Step 2: run this script to drop the partition of an old day.
--         Dropping a partition is instant, no matter how many rows it has.
-- ============================================================
SET VERIFY OFF
ACCEPT old_day CHAR PROMPT 'Day to drop (YYYY-MM-DD): '

SELECT COUNT(*) AS rows_to_remove
FROM   log_event PARTITION FOR (TO_DATE('&old_day', 'YYYY-MM-DD'));

ALTER TABLE log_event DROP PARTITION FOR (TO_DATE('&old_day', 'YYYY-MM-DD')) UPDATE INDEXES;

PROMPT Partition dropped. Use scripts\import_logs.bat to bring the data back if needed.
