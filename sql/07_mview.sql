-- ============================================================
-- 07 Materialized view (Lab 7)
-- Daily summary of all events from all sites, stored ready to use.
-- The dashboard reads this instead of scanning every log row.
-- Refresh: EXEC pkg_soc.refresh_summary   (or the Admin page button)
-- ============================================================

CREATE MATERIALIZED VIEW mv_daily_attacks
BUILD IMMEDIATE
REFRESH COMPLETE ON DEMAND
AS
SELECT site_code,
       TRUNC(event_time)     AS attack_day,
       event_type,
       src_country,
       COUNT(*)              AS event_count,
       COUNT(DISTINCT src_ip) AS unique_ips
FROM   all_log_events
GROUP  BY site_code, TRUNC(event_time), event_type, src_country;
