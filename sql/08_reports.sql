-- ============================================================
-- 08 Reports for the demo (run as tv_central)
--   sqlplus tv_central/tvpass123@localhost:1521/XEPDB1 @08_reports.sql
-- The same queries run on the Reports page of the web app.
-- ============================================================
SET LINESIZE 200
SET PAGESIZE 100
COLUMN site_code FORMAT A6
COLUMN src_country FORMAT A15
COLUMN event_type FORMAT A14
COLUMN severity FORMAT A10
COLUMN type FORMAT A12

PROMPT ===== Lab 1: INTERSECT, IPs that attacked BOTH Karachi and Lahore =====
SELECT src_ip FROM khi_logs WHERE event_type = 'LOGIN_FAIL'
INTERSECT
SELECT src_ip FROM lhr_logs WHERE event_type = 'LOGIN_FAIL';

PROMPT ===== Lab 1: MINUS, attackers with incidents that are NOT blocked yet =====
SELECT i.src_ip FROM incidents i
MINUS
SELECT ip FROM blocklist;

PROMPT ===== Lab 1: UNION, every suspicious IP seen at any site (no duplicates) =====
SELECT COUNT(*) AS unique_suspicious_ips FROM (
  SELECT src_ip FROM khi_logs WHERE event_type IN ('LOGIN_FAIL','PORT_SCAN','FW_BLOCK')
  UNION
  SELECT src_ip FROM lhr_logs WHERE event_type IN ('LOGIN_FAIL','PORT_SCAN','FW_BLOCK')
  UNION
  SELECT src_ip FROM isb_logs WHERE event_type IN ('LOGIN_FAIL','PORT_SCAN','FW_BLOCK')
);

PROMPT ===== Lab 6: ROLLUP, incidents per site and severity with subtotals =====
SELECT DECODE(GROUPING(i.site_code), 1, 'ALL', i.site_code) AS site_code,
       DECODE(GROUPING(i.severity), 1, 'ALL', i.severity)   AS severity,
       COUNT(*) AS incidents
FROM   incidents i
GROUP  BY ROLLUP (i.site_code, i.severity)
ORDER  BY 1, 2;

PROMPT ===== Lab 6: CUBE, suspicious events by country and event type =====
SELECT DECODE(GROUPING(src_country), 1, 'ALL', src_country) AS src_country,
       DECODE(GROUPING(event_type), 1, 'ALL', event_type)   AS event_type,
       SUM(event_count) AS events
FROM   mv_daily_attacks
WHERE  event_type IN ('LOGIN_FAIL','PORT_SCAN','FW_BLOCK','MALWARE_ALERT','PHISH_CLICK')
GROUP  BY CUBE (src_country, event_type)
ORDER  BY 3 DESC
FETCH FIRST 25 ROWS ONLY;

PROMPT ===== Lab 6: GROUPING SETS, totals per site and per day only =====
SELECT site_code, attack_day, SUM(event_count) AS events
FROM   mv_daily_attacks
GROUP  BY GROUPING SETS ((site_code), (attack_day))
ORDER  BY site_code NULLS LAST, attack_day;

PROMPT ===== Labs 10 to 12: methods on the object table =====
SELECT i.ticket_no,
       i.type_name()                AS type,
       i.severity,
       i.risk_score()               AS base_risk,
       i.risk_score(a.criticality)  AS asset_risk,
       i.sla_hours()                AS sla_hours,
       i.is_overdue()               AS overdue
FROM   incidents i JOIN asset a ON a.asset_id = i.asset_id
ORDER  BY asset_risk DESC
FETCH FIRST 15 ROWS ONLY;

PROMPT ===== TREAT: read an attribute that only the subtype has =====
SELECT i.ticket_no,
       TREAT(VALUE(i) AS bruteforce_t).failed_attempts AS failed_attempts
FROM   incidents i
WHERE  VALUE(i) IS OF (bruteforce_t);
