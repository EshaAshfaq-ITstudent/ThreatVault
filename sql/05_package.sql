-- ============================================================
-- 05 Package PKG_SOC (Lab 9: packages, Lab 13: transactions)
-- Every action of the web app goes through this package.
-- ============================================================

CREATE OR REPLACE PACKAGE pkg_soc AS

  -- custom error numbers used by the package
  c_err_not_found   CONSTANT NUMBER := -20010;
  c_err_closed      CONSTANT NUMBER := -20011;
  c_err_simulated   CONSTANT NUMBER := -20099;

  FUNCTION open_incident (
    p_type        VARCHAR2,
    p_rule_id     NUMBER,
    p_site        VARCHAR2,
    p_asset_id    NUMBER,
    p_ip          VARCHAR2,
    p_severity    VARCHAR2,
    p_first_seen  DATE,
    p_extra_text  VARCHAR2 DEFAULT NULL,
    p_extra_num   NUMBER   DEFAULT NULL
  ) RETURN NUMBER;

  PROCEDURE assign_analyst (p_incident_id NUMBER, p_analyst_id NUMBER);

  PROCEDURE add_action (p_incident_id NUMBER, p_analyst_id NUMBER, p_text VARCHAR2);

  PROCEDURE block_ip (p_ip VARCHAR2, p_reason VARCHAR2, p_analyst_id NUMBER);

  PROCEDURE unblock_ip (p_ip VARCHAR2);

  PROCEDURE close_incident (
    p_incident_id  NUMBER,
    p_analyst_id   NUMBER,
    p_action_text  VARCHAR2,
    p_block_ip     VARCHAR2 DEFAULT 'N',
    p_simulate_err VARCHAR2 DEFAULT 'N'
  );

  FUNCTION run_detection (p_from DATE, p_to DATE) RETURN NUMBER;

  PROCEDURE sync_rules;

  PROCEDURE refresh_summary;

  FUNCTION open_incident_count RETURN NUMBER;

  FUNCTION is_blocked (p_ip VARCHAR2) RETURN VARCHAR2;

END pkg_soc;
/

CREATE OR REPLACE PACKAGE BODY pkg_soc AS

  -- ---------- private helpers (not in the spec, so hidden from outside) ----------

  PROCEDURE log_action (p_incident_id NUMBER, p_analyst_id NUMBER, p_text VARCHAR2) IS
  BEGIN
    INSERT INTO response_action (incident_id, analyst_id, action_text)
    VALUES (p_incident_id, p_analyst_id, SUBSTR(p_text, 1, 400));
  END;

  -- Inserts into the central blocklist and REPLICATES the row to every site.
  -- No COMMIT here, so the caller decides (one distributed transaction).
  PROCEDURE do_block (p_ip VARCHAR2, p_reason VARCHAR2, p_analyst_id NUMBER) IS
  BEGIN
    INSERT INTO blocklist (ip, reason, added_by, added_on)
    VALUES (p_ip, SUBSTR(p_reason, 1, 200), p_analyst_id, SYSDATE);

    INSERT INTO blocklist_copy@khi_link (ip, reason, added_on, synced_at)
    VALUES (p_ip, SUBSTR(p_reason, 1, 200), SYSDATE, SYSDATE);
    INSERT INTO blocklist_copy@lhr_link (ip, reason, added_on, synced_at)
    VALUES (p_ip, SUBSTR(p_reason, 1, 200), SYSDATE, SYSDATE);
    INSERT INTO blocklist_copy@isb_link (ip, reason, added_on, synced_at)
    VALUES (p_ip, SUBSTR(p_reason, 1, 200), SYSDATE, SYSDATE);
  END;

  -- ---------- public procedures and functions ----------

  FUNCTION is_blocked (p_ip VARCHAR2) RETURN VARCHAR2 IS
    v_count NUMBER;
  BEGIN
    SELECT COUNT(*) INTO v_count FROM blocklist WHERE ip = p_ip;
    RETURN CASE WHEN v_count > 0 THEN 'Y' ELSE 'N' END;
  END;

  FUNCTION open_incident_count RETURN NUMBER IS
    v_count NUMBER;
  BEGIN
    SELECT COUNT(*) INTO v_count FROM incidents i WHERE i.status <> 'CLOSED';
    RETURN v_count;
  END;

  FUNCTION open_incident (
    p_type        VARCHAR2,
    p_rule_id     NUMBER,
    p_site        VARCHAR2,
    p_asset_id    NUMBER,
    p_ip          VARCHAR2,
    p_severity    VARCHAR2,
    p_first_seen  DATE,
    p_extra_text  VARCHAR2 DEFAULT NULL,
    p_extra_num   NUMBER   DEFAULT NULL
  ) RETURN NUMBER IS
    v_id     NUMBER := incident_seq.NEXTVAL;
    v_ticket VARCHAR2(20) := incident_t.new_ticket_no(p_type, v_id);   -- static method
  BEGIN
    -- The subtype constructor decides which kind of incident is stored
    CASE p_type
      WHEN 'BRUTEFORCE' THEN
        INSERT INTO incidents VALUES (bruteforce_t(v_id, v_ticket, p_rule_id, p_site, p_asset_id,
          p_ip, p_severity, 'OPEN', NULL, p_first_seen, SYSDATE, NULL, p_extra_num));
      WHEN 'DDOS' THEN
        INSERT INTO incidents VALUES (ddos_t(v_id, v_ticket, p_rule_id, p_site, p_asset_id,
          p_ip, p_severity, 'OPEN', NULL, p_first_seen, SYSDATE, NULL, p_extra_num));
      WHEN 'MALWARE' THEN
        INSERT INTO incidents VALUES (malware_t(v_id, v_ticket, p_rule_id, p_site, p_asset_id,
          p_ip, p_severity, 'OPEN', NULL, p_first_seen, SYSDATE, NULL, p_extra_text));
      WHEN 'PHISHING' THEN
        INSERT INTO incidents VALUES (phishing_t(v_id, v_ticket, p_rule_id, p_site, p_asset_id,
          p_ip, p_severity, 'OPEN', NULL, p_first_seen, SYSDATE, NULL, p_extra_text));
      ELSE
        RAISE_APPLICATION_ERROR(c_err_not_found, 'Unknown incident type ' || p_type);
    END CASE;

    log_action(v_id, NULL, 'Incident opened automatically by rule ' || p_rule_id);
    RETURN v_id;
  END;

  PROCEDURE assign_analyst (p_incident_id NUMBER, p_analyst_id NUMBER) IS
    v_name analyst.full_name%TYPE;
  BEGIN
    SELECT full_name INTO v_name FROM analyst WHERE analyst_id = p_analyst_id;

    UPDATE incidents i
    SET    i.analyst_id = p_analyst_id,
           i.status     = 'ASSIGNED'
    WHERE  i.incident_id = p_incident_id
    AND    i.status <> 'CLOSED';

    IF SQL%ROWCOUNT = 0 THEN
      RAISE_APPLICATION_ERROR(c_err_closed, 'Incident not found or already closed');
    END IF;

    log_action(p_incident_id, p_analyst_id, 'Assigned to ' || v_name);
    COMMIT;
  EXCEPTION
    WHEN NO_DATA_FOUND THEN
      RAISE_APPLICATION_ERROR(c_err_not_found, 'Analyst ' || p_analyst_id || ' does not exist');
  END;

  PROCEDURE add_action (p_incident_id NUMBER, p_analyst_id NUMBER, p_text VARCHAR2) IS
  BEGIN
    log_action(p_incident_id, p_analyst_id, p_text);
    COMMIT;
  END;

  PROCEDURE block_ip (p_ip VARCHAR2, p_reason VARCHAR2, p_analyst_id NUMBER) IS
  BEGIN
    do_block(p_ip, p_reason, p_analyst_id);
    COMMIT;   -- commits central + 3 site inserts together (distributed transaction)
  EXCEPTION
    WHEN DUP_VAL_ON_INDEX THEN
      ROLLBACK;
      RAISE_APPLICATION_ERROR(c_err_closed, 'IP ' || p_ip || ' is already blocked');
  END;

  PROCEDURE unblock_ip (p_ip VARCHAR2) IS
  BEGIN
    DELETE FROM blocklist WHERE ip = p_ip;
    DELETE FROM blocklist_copy@khi_link WHERE ip = p_ip;
    DELETE FROM blocklist_copy@lhr_link WHERE ip = p_ip;
    DELETE FROM blocklist_copy@isb_link WHERE ip = p_ip;
    COMMIT;
  END;

  -- Lab 13: one unit of work. Either ALL steps are saved or NONE.
  PROCEDURE close_incident (
    p_incident_id  NUMBER,
    p_analyst_id   NUMBER,
    p_action_text  VARCHAR2,
    p_block_ip     VARCHAR2 DEFAULT 'N',
    p_simulate_err VARCHAR2 DEFAULT 'N'
  ) IS
    v_status  VARCHAR2(12);
    v_ip      VARCHAR2(15);
    v_ticket  VARCHAR2(20);
  BEGIN
    SAVEPOINT before_close;

    SELECT i.status, i.src_ip, i.ticket_no
    INTO   v_status, v_ip, v_ticket
    FROM   incidents i
    WHERE  i.incident_id = p_incident_id
    FOR UPDATE;

    IF v_status = 'CLOSED' THEN
      RAISE_APPLICATION_ERROR(c_err_closed, 'Incident ' || v_ticket || ' is already closed');
    END IF;

    -- step 1: record what the analyst did
    log_action(p_incident_id, p_analyst_id, NVL(p_action_text, 'Incident closed'));

    -- step 2: block the attacker everywhere (central + all sites)
    IF p_block_ip = 'Y' AND is_blocked(v_ip) = 'N' THEN
      do_block(v_ip, 'Blocked while closing ' || v_ticket, p_analyst_id);
    END IF;

    -- step 3: close the incident
    UPDATE incidents i
    SET    i.status     = 'CLOSED',
           i.closed_at  = SYSDATE,
           i.analyst_id = NVL(i.analyst_id, p_analyst_id)
    WHERE  i.incident_id = p_incident_id;

    -- demo switch: fail at the very end to prove ROLLBACK undoes steps 1, 2 and 3
    IF p_simulate_err = 'Y' THEN
      RAISE_APPLICATION_ERROR(c_err_simulated,
        'Simulated failure. ROLLBACK TO before_close undid the action, the block and the close.');
    END IF;

    COMMIT;
  EXCEPTION
    WHEN NO_DATA_FOUND THEN
      ROLLBACK TO before_close;
      RAISE_APPLICATION_ERROR(c_err_not_found, 'Incident ' || p_incident_id || ' does not exist');
    WHEN OTHERS THEN
      ROLLBACK TO before_close;
      RAISE;
  END;

  -- Reads all sites through ALL_LOG_EVENTS and opens incidents for every rule hit.
  -- A hit = one source IP crossing the rule threshold inside one hour.
  FUNCTION run_detection (p_from DATE, p_to DATE) RETURN NUMBER IS
    v_created NUMBER := 0;
    v_id      NUMBER;
    v_exists  NUMBER;
  BEGIN
    FOR r IN (SELECT * FROM detection_rule WHERE active = 'Y' ORDER BY rule_id) LOOP
      FOR h IN (
        SELECT site_code, src_ip,
               TRUNC(event_time, 'HH24') AS hour_slot,
               MIN(asset_id)             AS asset_id,
               MAX(detail)               AS detail,
               COUNT(*)                  AS hits
        FROM   all_log_events
        WHERE  event_type = r.event_type
        AND    event_time >= p_from
        AND    event_time <  p_to
        GROUP  BY site_code, src_ip, TRUNC(event_time, 'HH24')
        HAVING COUNT(*) >= r.threshold
      ) LOOP
        SELECT COUNT(*) INTO v_exists
        FROM   incidents i
        WHERE  i.rule_id = r.rule_id
        AND    i.site_code = h.site_code
        AND    i.src_ip = h.src_ip
        AND    i.first_seen = h.hour_slot;

        IF v_exists = 0 THEN
          v_id := open_incident(r.incident_type, r.rule_id, h.site_code, h.asset_id,
                                h.src_ip, r.severity, h.hour_slot, h.detail, h.hits);
          v_created := v_created + 1;
        END IF;
      END LOOP;
    END LOOP;

    COMMIT;
    RETURN v_created;
  END;

  -- Lab 2: replication of DETECTION_RULE to every site
  PROCEDURE sync_rules IS
  BEGIN
    DELETE FROM rule_copy@khi_link;
    DELETE FROM rule_copy@lhr_link;
    DELETE FROM rule_copy@isb_link;

    INSERT INTO rule_copy@khi_link
      SELECT rule_id, rule_name, event_type, threshold, severity, incident_type, SYSDATE
      FROM detection_rule;
    INSERT INTO rule_copy@lhr_link
      SELECT rule_id, rule_name, event_type, threshold, severity, incident_type, SYSDATE
      FROM detection_rule;
    INSERT INTO rule_copy@isb_link
      SELECT rule_id, rule_name, event_type, threshold, severity, incident_type, SYSDATE
      FROM detection_rule;
    COMMIT;
  END;

  -- Lab 7: refresh the materialized view used by the dashboard
  PROCEDURE refresh_summary IS
  BEGIN
    DBMS_MVIEW.REFRESH('MV_DAILY_ATTACKS', 'C');
  END;

END pkg_soc;
/

SHOW ERRORS PACKAGE BODY pkg_soc
