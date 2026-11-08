-- ============================================================
-- 02 Central tables (schema tv_central)
-- ============================================================

CREATE TABLE site (
  site_code  VARCHAR2(3) PRIMARY KEY,
  site_name  VARCHAR2(50) NOT NULL,
  city       VARCHAR2(30) NOT NULL,
  db_link    VARCHAR2(30) NOT NULL
);

CREATE TABLE asset (
  asset_id     NUMBER PRIMARY KEY,
  site_code    VARCHAR2(3) NOT NULL REFERENCES site(site_code),
  hostname     VARCHAR2(40) NOT NULL,
  ip_address   VARCHAR2(15) NOT NULL,
  asset_type   VARCHAR2(20) NOT NULL,
  criticality  NUMBER(1) NOT NULL CHECK (criticality BETWEEN 1 AND 5)
);

CREATE TABLE analyst (
  analyst_id  NUMBER PRIMARY KEY,
  full_name   VARCHAR2(60) NOT NULL,
  shift       VARCHAR2(10) CHECK (shift IN ('MORNING','EVENING','NIGHT')),
  email       VARCHAR2(80),
  active      CHAR(1) DEFAULT 'Y' CHECK (active IN ('Y','N'))
);

CREATE TABLE app_user (
  username       VARCHAR2(30) PRIMARY KEY,
  password_hash  VARCHAR2(100) NOT NULL,
  role           VARCHAR2(10) NOT NULL CHECK (role IN ('ADMIN','ANALYST')),
  analyst_id     NUMBER REFERENCES analyst(analyst_id),
  created_at     DATE DEFAULT SYSDATE
);

CREATE TABLE detection_rule (
  rule_id        NUMBER PRIMARY KEY,
  rule_name      VARCHAR2(60) NOT NULL,
  event_type     VARCHAR2(20) NOT NULL,
  threshold      NUMBER NOT NULL,
  severity       VARCHAR2(10) NOT NULL CHECK (severity IN ('LOW','MEDIUM','HIGH','CRITICAL')),
  incident_type  VARCHAR2(12) NOT NULL CHECK (incident_type IN ('PHISHING','MALWARE','BRUTEFORCE','DDOS')),
  active         CHAR(1) DEFAULT 'Y' CHECK (active IN ('Y','N'))
);

CREATE TABLE blocklist (
  ip        VARCHAR2(15) PRIMARY KEY,
  reason    VARCHAR2(200),
  added_by  NUMBER REFERENCES analyst(analyst_id),
  added_on  DATE DEFAULT SYSDATE
);

CREATE TABLE response_action (
  action_id    NUMBER GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  incident_id  NUMBER NOT NULL,
  analyst_id   NUMBER REFERENCES analyst(analyst_id),
  action_text  VARCHAR2(400) NOT NULL,
  action_time  DATE DEFAULT SYSDATE
);

-- Lab 14: application level audit trail (filled by triggers in 06_triggers.sql)
CREATE TABLE audit_log (
  log_id      NUMBER GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  table_name  VARCHAR2(30),
  action      VARCHAR2(10),
  record_id   VARCHAR2(40),
  old_value   VARCHAR2(400),
  new_value   VARCHAR2(400),
  db_user     VARCHAR2(30) DEFAULT USER,
  app_user    VARCHAR2(64),
  log_time    TIMESTAMP DEFAULT SYSTIMESTAMP
);

CREATE SEQUENCE incident_seq START WITH 1 INCREMENT BY 1;
