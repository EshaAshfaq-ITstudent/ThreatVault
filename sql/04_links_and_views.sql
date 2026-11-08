-- ============================================================
-- 04 Database links and global views (Lab 2: distributed database)
-- The central schema reaches every site through a database link.
-- ALL_LOG_EVENTS joins the three fragments back together (UNION ALL),
-- so the head office sees one global table.
-- ============================================================

CREATE DATABASE LINK khi_link CONNECT TO tv_khi IDENTIFIED BY &pwd USING '&conn';
CREATE DATABASE LINK lhr_link CONNECT TO tv_lhr IDENTIFIED BY &pwd USING '&conn';
CREATE DATABASE LINK isb_link CONNECT TO tv_isb IDENTIFIED BY &pwd USING '&conn';

-- Location transparency: short names for remote tables
CREATE OR REPLACE SYNONYM khi_logs FOR log_event@khi_link;
CREATE OR REPLACE SYNONYM lhr_logs FOR log_event@lhr_link;
CREATE OR REPLACE SYNONYM isb_logs FOR log_event@isb_link;

-- Reconstruction of the fragmented table
CREATE OR REPLACE VIEW all_log_events AS
  SELECT event_id, site_code, event_time, asset_id, src_ip, src_country,
         dst_port, event_type, action, username, detail
  FROM   log_event@khi_link
  UNION ALL
  SELECT event_id, site_code, event_time, asset_id, src_ip, src_country,
         dst_port, event_type, action, username, detail
  FROM   log_event@lhr_link
  UNION ALL
  SELECT event_id, site_code, event_time, asset_id, src_ip, src_country,
         dst_port, event_type, action, username, detail
  FROM   log_event@isb_link;

-- Site audit tables in one place (used by the Audit page)
CREATE OR REPLACE VIEW all_log_change_audit AS
  SELECT 'KHI' site_code, a.* FROM log_change_audit@khi_link a
  UNION ALL
  SELECT 'LHR', a.* FROM log_change_audit@lhr_link a
  UNION ALL
  SELECT 'ISB', a.* FROM log_change_audit@isb_link a;
