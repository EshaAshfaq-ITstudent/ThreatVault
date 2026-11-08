-- ============================================================
-- ThreatVault full install
-- Run from the sql folder:
--   cd threatvault\sql
--   sqlplus system/<your_system_password>@localhost:1521/XEPDB1 @install.sql
-- ============================================================
SET ECHO OFF
SET VERIFY OFF
SET FEEDBACK ON
SET SERVEROUTPUT ON
SET SQLBLANKLINES ON
SET DEFINE ON
@@config.sql

PROMPT ===== Step 0: users, privileges, directory (as SYSTEM) =====
@@00_users.sql

PROMPT ===== Step 1: site fragments (Karachi, Lahore, Islamabad) =====
CONNECT tv_khi/&pwd@&conn
@@01_site_schema.sql KHI
CONNECT tv_lhr/&pwd@&conn
@@01_site_schema.sql LHR
CONNECT tv_isb/&pwd@&conn
@@01_site_schema.sql ISB

PROMPT ===== Step 2: central schema =====
CONNECT tv_central/&pwd@&conn
@@02_central_tables.sql
@@03_object_types.sql
@@04_links_and_views.sql
@@05_package.sql
@@06_triggers.sql
@@07_mview.sql
@@10_seed_data.sql

PROMPT ===== Step 3: database auditing (as SYSTEM) =====
CONNECT system/&syspwd@&conn
@@09_audit_policy.sql

PROMPT
PROMPT ThreatVault installed. Next: generate and load sample logs (see README).
