-- ============================================================
-- 10 Seed data (schema tv_central)
-- Web app logins:
--   admin    / admin123    (ADMIN)
--   esha     / analyst123  (ANALYST)
--   maham    / analyst123  (ANALYST)
--   mujtaba  / analyst123  (ANALYST)
-- ============================================================

INSERT INTO site VALUES ('KHI', 'Karachi Head Office', 'Karachi',   'KHI_LINK');
INSERT INTO site VALUES ('LHR', 'Lahore Branch',       'Lahore',    'LHR_LINK');
INSERT INTO site VALUES ('ISB', 'Islamabad Branch',    'Islamabad', 'ISB_LINK');

-- 20 assets per site. Ids: KHI 101 to 120, LHR 201 to 220, ISB 301 to 320
DECLARE
  TYPE t_list IS TABLE OF VARCHAR2(20);
  v_types  t_list := t_list('WEB_SERVER','DB_SERVER','MAIL_SERVER','FIREWALL','WORKSTATION');
  v_sites  t_list := t_list('KHI','LHR','ISB');
  v_type   VARCHAR2(20);
BEGIN
  FOR s IN 1 .. v_sites.COUNT LOOP
    FOR n IN 1 .. 20 LOOP
      v_type := v_types(MOD(n - 1, 5) + 1);
      INSERT INTO asset (asset_id, site_code, hostname, ip_address, asset_type, criticality)
      VALUES (s * 100 + n,
              v_sites(s),
              LOWER(v_sites(s)) || '-' || LOWER(REPLACE(v_type, '_SERVER', '')) || '-' || LPAD(n, 2, '0'),
              '10.' || s || '.0.' || n,
              v_type,
              CASE v_type
                WHEN 'DB_SERVER'   THEN 5
                WHEN 'FIREWALL'    THEN 5
                WHEN 'WEB_SERVER'  THEN 4
                WHEN 'MAIL_SERVER' THEN 3
                ELSE 2
              END);
    END LOOP;
  END LOOP;
END;
/

INSERT INTO analyst VALUES (1, 'Esha Ashfaq', 'MORNING', '02-235232-002@student.bahria.edu.pk', 'Y');
INSERT INTO analyst VALUES (2, 'Maham Imran', 'EVENING', '02-235232-030@student.bahria.edu.pk', 'Y');
INSERT INTO analyst VALUES (3, 'Mujtaba',     'NIGHT',   '02-235232-048@student.bahria.edu.pk', 'Y');
INSERT INTO analyst VALUES (4, 'SOC Admin',   'MORNING', 'admin@threatvault.local',             'Y');

INSERT INTO app_user (username, password_hash, role, analyst_id) VALUES
  ('admin',   '$2b$10$U1c3wtOoXaffAD6frtM2S.QAEti0zzEZisiwG6YuGDtvXNM5wd3ES', 'ADMIN',   4);
INSERT INTO app_user (username, password_hash, role, analyst_id) VALUES
  ('esha',    '$2b$10$LRPwVnkH2/veq84u70ReNud0ZVK8DpCz6yPibS62eWUjrO36WeoN2', 'ANALYST', 1);
INSERT INTO app_user (username, password_hash, role, analyst_id) VALUES
  ('maham',   '$2b$10$LRPwVnkH2/veq84u70ReNud0ZVK8DpCz6yPibS62eWUjrO36WeoN2', 'ANALYST', 2);
INSERT INTO app_user (username, password_hash, role, analyst_id) VALUES
  ('mujtaba', '$2b$10$LRPwVnkH2/veq84u70ReNud0ZVK8DpCz6yPibS62eWUjrO36WeoN2', 'ANALYST', 3);

-- Detection rules: threshold = events from one IP inside one hour
INSERT INTO detection_rule VALUES (1, 'Brute force login',   'LOGIN_FAIL',    20,  'HIGH',     'BRUTEFORCE', 'Y');
INSERT INTO detection_rule VALUES (2, 'Web flood (DDoS)',    'HTTP_REQ',      300, 'CRITICAL', 'DDOS',       'Y');
INSERT INTO detection_rule VALUES (3, 'Malware alert',       'MALWARE_ALERT', 1,   'CRITICAL', 'MALWARE',    'Y');
INSERT INTO detection_rule VALUES (4, 'Phishing link click', 'PHISH_CLICK',   1,   'MEDIUM',   'PHISHING',   'Y');

COMMIT;

-- Copy the rules to every site (replication)
EXEC pkg_soc.sync_rules

PROMPT Seed data loaded.
