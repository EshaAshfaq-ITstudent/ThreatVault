-- ============================================================
-- 06 Audit triggers (Lab 14: application level auditing)
-- app_user = name of the person logged into the web app.
-- The web app sends it as CLIENT_IDENTIFIER on every database call.
-- ============================================================

CREATE OR REPLACE TRIGGER trg_incidents_audit
AFTER INSERT OR UPDATE OR DELETE ON incidents
FOR EACH ROW
DECLARE
  v_action VARCHAR2(10);
  v_old    VARCHAR2(400);
  v_new    VARCHAR2(400);
BEGIN
  -- INSERTING / UPDATING / DELETING can only be used in PL/SQL, not inside SQL
  IF INSERTING THEN
    v_action := 'INSERT';
  ELSIF UPDATING THEN
    v_action := 'UPDATE';
  ELSE
    v_action := 'DELETE';
  END IF;
  IF NOT INSERTING THEN
    v_old := 'status=' || :OLD.status || ', analyst=' || :OLD.analyst_id;
  END IF;
  IF NOT DELETING THEN
    v_new := 'status=' || :NEW.status || ', analyst=' || :NEW.analyst_id;
  END IF;
  INSERT INTO audit_log (table_name, action, record_id, old_value, new_value, app_user)
  VALUES ('INCIDENTS', v_action, NVL(:NEW.ticket_no, :OLD.ticket_no), v_old, v_new,
          SYS_CONTEXT('USERENV', 'CLIENT_IDENTIFIER'));
END;
/

CREATE OR REPLACE TRIGGER trg_blocklist_audit
AFTER INSERT OR DELETE ON blocklist
FOR EACH ROW
DECLARE
  v_action VARCHAR2(10);
BEGIN
  IF INSERTING THEN
    v_action := 'INSERT';
  ELSE
    v_action := 'DELETE';
  END IF;
  INSERT INTO audit_log (table_name, action, record_id, old_value, new_value, app_user)
  VALUES ('BLOCKLIST', v_action, NVL(:NEW.ip, :OLD.ip), :OLD.reason, :NEW.reason,
          SYS_CONTEXT('USERENV', 'CLIENT_IDENTIFIER'));
END;
/

CREATE OR REPLACE TRIGGER trg_rule_audit
AFTER UPDATE ON detection_rule
FOR EACH ROW
BEGIN
  INSERT INTO audit_log (table_name, action, record_id, old_value, new_value, app_user)
  VALUES ('DETECTION_RULE', 'UPDATE', TO_CHAR(:NEW.rule_id),
          'threshold=' || :OLD.threshold || ', active=' || :OLD.active,
          'threshold=' || :NEW.threshold || ', active=' || :NEW.active,
          SYS_CONTEXT('USERENV', 'CLIENT_IDENTIFIER'));
END;
/
