-- ============================================================
-- 03 Object types (Labs 10, 11, 12)
--
--  incident_t      NOT INSTANTIABLE, NOT FINAL supertype (abstraction)
--    risk_score()              abstract method, every subtype must override it
--    risk_score(p_criticality) OVERLOADED version (same name, different parameters)
--    severity_weight, sla_hours, is_overdue   normal member methods
--    type_name, details        overridden by subtypes
--    new_ticket_no             STATIC method (called on the type, not on an object)
--  phishing_t, malware_t, bruteforce_t, ddos_t   subtypes (inheritance)
--  incidents       object table that stores all four subtypes together
-- ============================================================

CREATE OR REPLACE TYPE incident_t AS OBJECT (
  incident_id  NUMBER,
  ticket_no    VARCHAR2(20),
  rule_id      NUMBER,
  site_code    VARCHAR2(3),
  asset_id     NUMBER,
  src_ip       VARCHAR2(15),
  severity     VARCHAR2(10),
  status       VARCHAR2(12),
  analyst_id   NUMBER,
  first_seen   DATE,
  opened_at    DATE,
  closed_at    DATE,
  NOT INSTANTIABLE MEMBER FUNCTION risk_score RETURN NUMBER,
  MEMBER FUNCTION risk_score (p_criticality NUMBER) RETURN NUMBER,
  MEMBER FUNCTION severity_weight RETURN NUMBER,
  MEMBER FUNCTION sla_hours RETURN NUMBER,
  MEMBER FUNCTION is_overdue RETURN VARCHAR2,
  MEMBER FUNCTION type_name RETURN VARCHAR2,
  MEMBER FUNCTION details RETURN VARCHAR2,
  STATIC FUNCTION new_ticket_no (p_type VARCHAR2, p_id NUMBER) RETURN VARCHAR2
) NOT INSTANTIABLE NOT FINAL;
/

CREATE OR REPLACE TYPE BODY incident_t AS

  -- Overloaded: base risk adjusted by how important the attacked asset is (1 to 5)
  MEMBER FUNCTION risk_score (p_criticality NUMBER) RETURN NUMBER IS
  BEGIN
    RETURN LEAST(100, ROUND(SELF.risk_score() * (1 + NVL(p_criticality, 1) / 10), 1));
  END;

  MEMBER FUNCTION severity_weight RETURN NUMBER IS
  BEGIN
    RETURN CASE SELF.severity
             WHEN 'CRITICAL' THEN 4
             WHEN 'HIGH'     THEN 3
             WHEN 'MEDIUM'   THEN 2
             ELSE 1
           END;
  END;

  -- Hours allowed to close the incident (service level)
  MEMBER FUNCTION sla_hours RETURN NUMBER IS
  BEGIN
    RETURN CASE SELF.severity
             WHEN 'CRITICAL' THEN 4
             WHEN 'HIGH'     THEN 8
             WHEN 'MEDIUM'   THEN 24
             ELSE 72
           END;
  END;

  MEMBER FUNCTION is_overdue RETURN VARCHAR2 IS
  BEGIN
    IF SELF.status <> 'CLOSED' AND (SYSDATE - SELF.opened_at) * 24 > SELF.sla_hours() THEN
      RETURN 'YES';
    END IF;
    RETURN 'NO';
  END;

  MEMBER FUNCTION type_name RETURN VARCHAR2 IS
  BEGIN
    RETURN 'GENERIC';
  END;

  MEMBER FUNCTION details RETURN VARCHAR2 IS
  BEGIN
    RETURN 'Source IP ' || SELF.src_ip;
  END;

  STATIC FUNCTION new_ticket_no (p_type VARCHAR2, p_id NUMBER) RETURN VARCHAR2 IS
  BEGIN
    RETURN SUBSTR(p_type, 1, 2) || TO_CHAR(SYSDATE, 'YYMMDD') || LPAD(p_id, 5, '0');
  END;

END;
/

-- ---------------- Subtypes ----------------

CREATE OR REPLACE TYPE phishing_t UNDER incident_t (
  sender_email VARCHAR2(80),
  OVERRIDING MEMBER FUNCTION risk_score RETURN NUMBER,
  OVERRIDING MEMBER FUNCTION type_name RETURN VARCHAR2,
  OVERRIDING MEMBER FUNCTION details RETURN VARCHAR2
);
/
CREATE OR REPLACE TYPE BODY phishing_t AS
  OVERRIDING MEMBER FUNCTION risk_score RETURN NUMBER IS
  BEGIN
    -- a user clicked a phishing link: medium base risk
    RETURN 15 + 10 * SELF.severity_weight();
  END;
  OVERRIDING MEMBER FUNCTION type_name RETURN VARCHAR2 IS
  BEGIN
    RETURN 'PHISHING';
  END;
  OVERRIDING MEMBER FUNCTION details RETURN VARCHAR2 IS
  BEGIN
    RETURN 'Phishing link clicked, sender ' || NVL(SELF.sender_email, 'unknown');
  END;
END;
/

CREATE OR REPLACE TYPE malware_t UNDER incident_t (
  file_hash VARCHAR2(80),
  OVERRIDING MEMBER FUNCTION risk_score RETURN NUMBER,
  OVERRIDING MEMBER FUNCTION type_name RETURN VARCHAR2,
  OVERRIDING MEMBER FUNCTION details RETURN VARCHAR2
);
/
CREATE OR REPLACE TYPE BODY malware_t AS
  OVERRIDING MEMBER FUNCTION risk_score RETURN NUMBER IS
  BEGIN
    -- malware on a machine is always serious
    RETURN 25 + 15 * SELF.severity_weight();
  END;
  OVERRIDING MEMBER FUNCTION type_name RETURN VARCHAR2 IS
  BEGIN
    RETURN 'MALWARE';
  END;
  OVERRIDING MEMBER FUNCTION details RETURN VARCHAR2 IS
  BEGIN
    RETURN 'Malware detected, file hash ' || NVL(SELF.file_hash, 'unknown');
  END;
END;
/

CREATE OR REPLACE TYPE bruteforce_t UNDER incident_t (
  failed_attempts NUMBER,
  OVERRIDING MEMBER FUNCTION risk_score RETURN NUMBER,
  OVERRIDING MEMBER FUNCTION type_name RETURN VARCHAR2,
  OVERRIDING MEMBER FUNCTION details RETURN VARCHAR2
);
/
CREATE OR REPLACE TYPE BODY bruteforce_t AS
  OVERRIDING MEMBER FUNCTION risk_score RETURN NUMBER IS
  BEGIN
    -- more failed attempts = higher risk
    RETURN LEAST(100, 8 * SELF.severity_weight() + ROUND(NVL(SELF.failed_attempts, 0) / 2));
  END;
  OVERRIDING MEMBER FUNCTION type_name RETURN VARCHAR2 IS
  BEGIN
    RETURN 'BRUTEFORCE';
  END;
  OVERRIDING MEMBER FUNCTION details RETURN VARCHAR2 IS
  BEGIN
    RETURN NVL(SELF.failed_attempts, 0) || ' failed logins in one hour from ' || SELF.src_ip;
  END;
END;
/

CREATE OR REPLACE TYPE ddos_t UNDER incident_t (
  peak_requests NUMBER,
  OVERRIDING MEMBER FUNCTION risk_score RETURN NUMBER,
  OVERRIDING MEMBER FUNCTION type_name RETURN VARCHAR2,
  OVERRIDING MEMBER FUNCTION details RETURN VARCHAR2
);
/
CREATE OR REPLACE TYPE BODY ddos_t AS
  OVERRIDING MEMBER FUNCTION risk_score RETURN NUMBER IS
  BEGIN
    -- more requests per hour = higher risk
    RETURN LEAST(100, 12 * SELF.severity_weight() + ROUND(NVL(SELF.peak_requests, 0) / 25));
  END;
  OVERRIDING MEMBER FUNCTION type_name RETURN VARCHAR2 IS
  BEGIN
    RETURN 'DDOS';
  END;
  OVERRIDING MEMBER FUNCTION details RETURN VARCHAR2 IS
  BEGIN
    RETURN NVL(SELF.peak_requests, 0) || ' web requests in one hour from ' || SELF.src_ip;
  END;
END;
/

-- Object table: one table holds every kind of incident (substitutable rows)
CREATE TABLE incidents OF incident_t (
  CONSTRAINT incidents_pk PRIMARY KEY (incident_id),
  CONSTRAINT incidents_status_ck CHECK (status IN ('OPEN','ASSIGNED','CLOSED')),
  CONSTRAINT incidents_sev_ck CHECK (severity IN ('LOW','MEDIUM','HIGH','CRITICAL'))
);

CREATE INDEX incidents_ip_ix ON incidents (src_ip);
