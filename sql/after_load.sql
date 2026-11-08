-- ============================================================
-- Run after loading the logs (as tv_central):
--   sqlplus tv_central/tvpass123@localhost:1521/XEPDB1 @after_load.sql
-- Finds attacks in the last 30 days and refreshes the dashboard summary.
-- ============================================================
SET SERVEROUTPUT ON
DECLARE
  v_new NUMBER;
BEGIN
  v_new := pkg_soc.run_detection(TRUNC(SYSDATE) - 30, TRUNC(SYSDATE) + 1);
  DBMS_OUTPUT.PUT_LINE('Incidents created: ' || v_new);
  pkg_soc.refresh_summary;
  DBMS_OUTPUT.PUT_LINE('Materialized view refreshed.');
END;
/
EXIT
