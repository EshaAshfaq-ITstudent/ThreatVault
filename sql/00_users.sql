-- ============================================================
-- 00 Users and privileges (run as SYSTEM)
-- One user per site simulates a distributed database:
--   tv_khi, tv_lhr, tv_isb = site databases (fragments)
--   tv_central             = head office (incidents, reports, web app)
-- ============================================================

-- Remove old audit policy and users so the script can be re-run
BEGIN
  EXECUTE IMMEDIATE 'NOAUDIT POLICY tv_evidence_policy';
EXCEPTION WHEN OTHERS THEN NULL;
END;
/
BEGIN
  EXECUTE IMMEDIATE 'DROP AUDIT POLICY tv_evidence_policy';
EXCEPTION WHEN OTHERS THEN NULL;
END;
/
BEGIN
  FOR u IN (SELECT username FROM dba_users
            WHERE username IN ('TV_CENTRAL','TV_KHI','TV_LHR','TV_ISB')) LOOP
    EXECUTE IMMEDIATE 'DROP USER ' || u.username || ' CASCADE';
  END LOOP;
END;
/

CREATE USER tv_central IDENTIFIED BY &pwd DEFAULT TABLESPACE users QUOTA UNLIMITED ON users;
CREATE USER tv_khi     IDENTIFIED BY &pwd DEFAULT TABLESPACE users QUOTA UNLIMITED ON users;
CREATE USER tv_lhr     IDENTIFIED BY &pwd DEFAULT TABLESPACE users QUOTA UNLIMITED ON users;
CREATE USER tv_isb     IDENTIFIED BY &pwd DEFAULT TABLESPACE users QUOTA UNLIMITED ON users;

-- Central schema: everything the head office needs
GRANT CREATE SESSION, CREATE TABLE, CREATE VIEW, CREATE MATERIALIZED VIEW,
      CREATE PROCEDURE, CREATE TYPE, CREATE TRIGGER, CREATE SEQUENCE,
      CREATE DATABASE LINK, CREATE SYNONYM TO tv_central;
GRANT AUDIT_VIEWER TO tv_central;

-- Site schemas: tables, triggers and procedures for their own fragment
GRANT CREATE SESSION, CREATE TABLE, CREATE VIEW, CREATE PROCEDURE,
      CREATE TRIGGER, CREATE SEQUENCE TO tv_khi, tv_lhr, tv_isb;

-- Directory for Data Pump export/import and the external table
CREATE OR REPLACE DIRECTORY tv_dir AS '&dpdir';
GRANT READ, WRITE ON DIRECTORY tv_dir TO tv_central, tv_khi, tv_lhr, tv_isb;
GRANT DATAPUMP_EXP_FULL_DATABASE, DATAPUMP_IMP_FULL_DATABASE TO tv_central;
