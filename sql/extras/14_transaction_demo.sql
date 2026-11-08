-- ============================================================
-- 14 Transaction demo (Lab 13), run as tv_central
-- Shows that a failed close_incident leaves NOTHING half saved.
-- ============================================================
SET SERVEROUTPUT ON
SET VERIFY OFF
ACCEPT inc NUMBER PROMPT 'Incident id to test with: '

PROMPT Before:
SELECT i.ticket_no, i.status FROM incidents i WHERE i.incident_id = &inc;
SELECT COUNT(*) AS actions_before FROM response_action WHERE incident_id = &inc;

PROMPT Calling close_incident with p_simulate_err = Y ...
BEGIN
  pkg_soc.close_incident(&inc, 1, 'Test close', 'Y', 'Y');
EXCEPTION
  WHEN OTHERS THEN
    DBMS_OUTPUT.PUT_LINE('Error caught: ' || SQLERRM);
END;
/

PROMPT After (status and action count must be the same as before):
SELECT i.ticket_no, i.status FROM incidents i WHERE i.incident_id = &inc;
SELECT COUNT(*) AS actions_after FROM response_action WHERE incident_id = &inc;
