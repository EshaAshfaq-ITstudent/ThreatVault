-- ============================================================
-- 11 Partition demo (Lab 7), run as a site user, for example:
--   sqlplus tv_khi/tvpass123@localhost:1521/XEPDB1 @extras/11_partition_demo.sql
-- ============================================================
SET LINESIZE 200
SET PAGESIZE 100

PROMPT ===== Partitions created automatically (one per day) =====
SELECT partition_name, partition_position, num_rows
FROM   user_tab_partitions
WHERE  table_name = 'LOG_EVENT'
ORDER  BY partition_position;

PROMPT ===== Rows in each day =====
SELECT TRUNC(event_time) AS day, COUNT(*) AS rows_in_day
FROM   log_event
GROUP  BY TRUNC(event_time)
ORDER  BY 1;

PROMPT ===== Partition pruning: query for ONE day reads ONE partition =====
EXPLAIN PLAN FOR
SELECT COUNT(*) FROM log_event
WHERE  event_time >= TRUNC(SYSDATE) AND event_time < TRUNC(SYSDATE) + 1;

SELECT * FROM TABLE(DBMS_XPLAN.DISPLAY(NULL, NULL, 'BASIC +PARTITION'));
PROMPT Look at Pstart and Pstop: they point to a single partition.

PROMPT ===== Read one partition directly by date =====
SELECT COUNT(*) AS today_rows
FROM   log_event PARTITION FOR (TRUNC(SYSDATE));
