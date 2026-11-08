// Reports shown on the Reports page. Each one shows a course concept.
// The SQL text is displayed on the page so the teacher can see it.
const SUSPICIOUS = `('LOGIN_FAIL','PORT_SCAN','FW_BLOCK','MALWARE_ALERT','PHISH_CLICK')`;

module.exports = [
  {
    key: 'intersect',
    lab: 'Lab 1: Set operators',
    title: 'Attackers seen at ALL three sites (INTERSECT)',
    explain: 'IPs that tried brute force logins in Karachi, Lahore and Islamabad. One attacker hitting every office is a strong sign of a planned attack.',
    sql: `SELECT src_ip FROM khi_logs WHERE event_type = 'LOGIN_FAIL'
INTERSECT
SELECT src_ip FROM lhr_logs WHERE event_type = 'LOGIN_FAIL'
INTERSECT
SELECT src_ip FROM isb_logs WHERE event_type = 'LOGIN_FAIL'`,
  },
  {
    key: 'minus',
    lab: 'Lab 1: Set operators',
    title: 'Attackers with incidents that are NOT blocked yet (MINUS)',
    explain: 'Every IP that caused an incident, minus the IPs already in the blocklist. This is the to do list for the SOC team.',
    sql: `SELECT i.src_ip FROM incidents i
MINUS
SELECT ip FROM blocklist`,
  },
  {
    key: 'union',
    lab: 'Lab 1: Set operators',
    title: 'Port scanners from every site (UNION)',
    explain: 'UNION joins the three fragments and removes duplicate IPs.',
    sql: `SELECT src_ip, src_country FROM khi_logs WHERE event_type = 'PORT_SCAN'
UNION
SELECT src_ip, src_country FROM lhr_logs WHERE event_type = 'PORT_SCAN'
UNION
SELECT src_ip, src_country FROM isb_logs WHERE event_type = 'PORT_SCAN'`,
  },
  {
    key: 'rollup',
    lab: 'Lab 6: Summarized data',
    title: 'Incidents per site and severity with subtotals (ROLLUP)',
    explain: 'ROLLUP adds a subtotal for each site and one grand total row (shown as ALL).',
    sql: `SELECT DECODE(GROUPING(i.site_code), 1, 'ALL', i.site_code) AS site,
       DECODE(GROUPING(i.severity), 1, 'ALL', i.severity)   AS severity,
       COUNT(*) AS incidents
FROM   incidents i
GROUP  BY ROLLUP (i.site_code, i.severity)
ORDER  BY 1, 2`,
  },
  {
    key: 'cube',
    lab: 'Lab 6: Summarized data',
    title: 'Suspicious events by country and event type (CUBE)',
    explain: 'CUBE gives totals for every combination: per country, per event type, and both together. Reads the materialized view, not the raw logs.',
    sql: `SELECT DECODE(GROUPING(src_country), 1, 'ALL', src_country) AS country,
       DECODE(GROUPING(event_type), 1, 'ALL', event_type)   AS event_type,
       SUM(event_count) AS events
FROM   mv_daily_attacks
WHERE  event_type IN ${SUSPICIOUS}
GROUP  BY CUBE (src_country, event_type)
ORDER  BY 3 DESC
FETCH FIRST 30 ROWS ONLY`,
  },
  {
    key: 'grouping_sets',
    lab: 'Lab 6: Summarized data',
    title: 'Events per site and per day (GROUPING SETS)',
    explain: 'GROUPING SETS gives only the groups we ask for: one total per site and one total per day.',
    sql: `SELECT site_code, attack_day, SUM(event_count) AS events
FROM   mv_daily_attacks
GROUP  BY GROUPING SETS ((site_code), (attack_day))
ORDER  BY site_code NULLS LAST, attack_day`,
  },
  {
    key: 'methods',
    lab: 'Labs 10 to 12: Objects',
    title: 'Risk score from member methods (overloading and overriding)',
    explain: 'risk_score() is overridden in every subtype. risk_score(criticality) is the overloaded version that also uses how important the asset is.',
    sql: `SELECT i.ticket_no,
       i.type_name()               AS type,
       i.severity,
       i.risk_score()              AS base_risk,
       a.criticality,
       i.risk_score(a.criticality) AS asset_risk,
       i.sla_hours()               AS sla_hours,
       i.is_overdue()              AS overdue
FROM   incidents i JOIN asset a ON a.asset_id = i.asset_id
ORDER  BY asset_risk DESC
FETCH FIRST 25 ROWS ONLY`,
  },
  {
    key: 'treat',
    lab: 'Labs 10 to 12: Objects',
    title: 'Subtype attributes with TREAT and IS OF',
    explain: 'failed_attempts exists only in bruteforce_t, so TREAT is used to read it from the shared object table.',
    sql: `SELECT i.ticket_no, i.src_ip, i.site_code,
       TREAT(VALUE(i) AS bruteforce_t).failed_attempts AS failed_attempts
FROM   incidents i
WHERE  VALUE(i) IS OF (bruteforce_t)
ORDER  BY failed_attempts DESC`,
  },
  {
    key: 'fragments',
    lab: 'Lab 2: Fragmentation',
    title: 'Rows stored in each fragment',
    explain: 'Each site keeps only its own rows. The union of all fragments is the global ALL_LOG_EVENTS view.',
    sql: `SELECT 'KHI' AS site, COUNT(*) AS rows_in_fragment FROM khi_logs
UNION ALL
SELECT 'LHR', COUNT(*) FROM lhr_logs
UNION ALL
SELECT 'ISB', COUNT(*) FROM isb_logs`,
  },
];
