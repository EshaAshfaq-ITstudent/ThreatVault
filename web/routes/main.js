const express = require('express');
const db = require('../db');
const reports = require('../reports');
const { wrap } = require('./middleware');

const router = express.Router();
const SUSPICIOUS = ['LOGIN_FAIL', 'PORT_SCAN', 'FW_BLOCK', 'MALWARE_ALERT', 'PHISH_CLICK'];
const SUSP_SQL = `('${SUSPICIOUS.join("','")}')`;
const EVENT_TYPES = ['LOGIN_OK', 'LOGIN_FAIL', 'HTTP_REQ', 'FW_BLOCK', 'PORT_SCAN', 'MALWARE_ALERT', 'PHISH_CLICK'];
const SITE_SOURCE = { KHI: 'khi_logs', LHR: 'lhr_logs', ISB: 'isb_logs' };

// ---------------- Dashboard ----------------
router.get('/', wrap(async (req, res) => {
  const u = req.session.user.username;
  const kpi = await db.one(`
    SELECT (SELECT COUNT(*) FROM incidents i WHERE i.status <> 'CLOSED') AS open_incidents,
           (SELECT COUNT(*) FROM incidents i WHERE i.status <> 'CLOSED' AND i.severity = 'CRITICAL') AS critical_open,
           (SELECT COUNT(*) FROM incidents i WHERE i.status <> 'CLOSED' AND i.is_overdue() = 'YES') AS overdue,
           (SELECT COUNT(*) FROM blocklist) AS blocked,
           (SELECT NVL(SUM(event_count), 0) FROM mv_daily_attacks) AS total_events,
           (SELECT NVL(SUM(event_count), 0) FROM mv_daily_attacks WHERE event_type IN ${SUSP_SQL}) AS suspicious_events
    FROM dual`, {}, u);

  const mv = await db.one(`SELECT last_refresh_date FROM user_mviews WHERE mview_name = 'MV_DAILY_ATTACKS'`, {}, u);

  const trend = await db.query(`
    SELECT attack_day, event_type, SUM(event_count) AS c
    FROM mv_daily_attacks
    WHERE event_type IN ${SUSP_SQL}
    GROUP BY attack_day, event_type
    ORDER BY attack_day`, {}, u);

  const countries = await db.query(`
    SELECT src_country, SUM(event_count) AS c
    FROM mv_daily_attacks
    WHERE event_type IN ${SUSP_SQL} AND src_country <> 'Pakistan'
    GROUP BY src_country ORDER BY c DESC FETCH FIRST 8 ROWS ONLY`, {}, u);

  const byType = await db.query(`
    SELECT t, COUNT(*) AS c FROM (SELECT i.type_name() AS t FROM incidents i) GROUP BY t ORDER BY t`, {}, u);

  const bySite = await db.query(`
    SELECT site_code, SUM(event_count) AS c FROM mv_daily_attacks
    WHERE event_type IN ${SUSP_SQL} GROUP BY site_code ORDER BY site_code`, {}, u);

  const siteEvents = await db.query(`
    SELECT site_code, SUM(event_count) AS events FROM mv_daily_attacks
    WHERE event_type IN ${SUSP_SQL} GROUP BY site_code`, {}, u);
  const siteOpen = await db.query(`
    SELECT i.site_code, COUNT(*) AS open_count FROM incidents i
    WHERE i.status <> 'CLOSED' GROUP BY i.site_code`, {}, u);
  const siteStats = {};
  ['KHI', 'LHR', 'ISB'].forEach((s) => {
    const e = siteEvents.find((r) => r.site_code === s);
    const o = siteOpen.find((r) => r.site_code === s);
    siteStats[s] = { events: e ? e.events : 0, open: o ? o.open_count : 0 };
  });

  // Hour by day heat map of suspicious events (reads the fragments through ALL_LOG_EVENTS)
  const heatRows = await db.query(`
    SELECT TRUNC(event_time) AS d, TO_NUMBER(TO_CHAR(event_time, 'HH24')) AS h, COUNT(*) AS c
    FROM all_log_events
    WHERE event_type IN ${SUSP_SQL} AND event_time >= TRUNC(SYSDATE) - 13
    GROUP BY TRUNC(event_time), TO_NUMBER(TO_CHAR(event_time, 'HH24'))`, {}, u);
  const heatDays = [...new Set(heatRows.map((r) => res.locals.fmtDay(r.d)))].sort();
  const heat = {
    days: heatDays,
    max: Math.max(1, ...heatRows.map((r) => r.c)),
    cell: {},
  };
  heatRows.forEach((r) => { heat.cell[`${res.locals.fmtDay(r.d)}|${r.h}`] = r.c; });

  const origins = (await db.query(`
    SELECT src_country AS country, SUM(event_count) AS cnt
    FROM mv_daily_attacks
    WHERE event_type IN ${SUSP_SQL} AND src_country <> 'Pakistan'
    GROUP BY src_country ORDER BY cnt DESC FETCH FIRST 10 ROWS ONLY`, {}, u)).map((r) => ({ country: r.country, count: r.cnt }));

  const recent = await db.query(`
    SELECT i.incident_id, i.ticket_no, i.type_name() AS type_name, i.site_code, i.src_ip,
           i.severity, i.status, i.opened_at
    FROM incidents i ORDER BY i.opened_at DESC, i.incident_id DESC FETCH FIRST 8 ROWS ONLY`, {}, u);

  // Build chart data
  const days = [...new Set(trend.map((r) => res.locals.fmtDay(r.attack_day)))];
  const series = SUSPICIOUS.map((t) => ({
    label: t,
    data: days.map((d) => {
      const row = trend.find((r) => r.event_type === t && res.locals.fmtDay(r.attack_day) === d);
      return row ? row.c : 0;
    }),
  }));
  const chart = {
    trend: { labels: days, series },
    countries: { labels: countries.map((r) => r.src_country), data: countries.map((r) => r.c) },
    byType: { labels: byType.map((r) => r.t), data: byType.map((r) => r.c) },
    bySite: { labels: bySite.map((r) => r.site_code), data: bySite.map((r) => r.c) },
  };

  res.render('dashboard', { title: 'Dashboard', kpi, mv, recent, chart, siteStats, heat, origins });
}));

// ---------------- Logs (partition pruning demo) ----------------
router.get('/logs', wrap(async (req, res) => {
  const u = req.session.user.username;
  const days = await db.query(`SELECT DISTINCT attack_day FROM mv_daily_attacks ORDER BY attack_day DESC`, {}, u);
  const dayList = days.map((r) => res.locals.fmtDay(r.attack_day));

  const f = {
    site: SITE_SOURCE[req.query.site] ? req.query.site : '',
    day: /^\d{4}-\d{2}-\d{2}$/.test(req.query.day || '') ? req.query.day : (dayList[0] || res.locals.fmtDay(new Date())),
    type: EVENT_TYPES.includes(req.query.type) ? req.query.type : '',
    ip: (req.query.ip || '').trim().slice(0, 15),
    page: Math.max(1, parseInt(req.query.page || '1', 10) || 1),
  };
  const source = f.site ? SITE_SOURCE[f.site] : 'all_log_events';
  const binds = { d: f.day };
  let where = `l.event_time >= TO_DATE(:d, 'YYYY-MM-DD') AND l.event_time < TO_DATE(:d, 'YYYY-MM-DD') + 1`;
  if (f.type) { where += ' AND l.event_type = :t'; binds.t = f.type; }
  if (f.ip) { where += ' AND l.src_ip = :ip'; binds.ip = f.ip; }

  const total = (await db.one(`SELECT COUNT(*) AS c FROM ${source} l WHERE ${where}`, binds, u)).c;
  const pageSize = 50;
  const rows = await db.query(`
    SELECT l.event_id, l.site_code, l.event_time, l.asset_id, l.src_ip, l.src_country, l.dst_port,
           l.event_type, l.action, l.username, l.detail,
           CASE WHEN EXISTS (SELECT 1 FROM blocklist b WHERE b.ip = l.src_ip) THEN 'Y' ELSE 'N' END AS blocked
    FROM ${source} l
    WHERE ${where}
    ORDER BY l.event_time DESC, l.event_id DESC
    OFFSET ${(f.page - 1) * pageSize} ROWS FETCH NEXT ${pageSize} ROWS ONLY`, binds, u);

  res.render('logs', {
    title: 'Logs', f, rows, total, pageSize, dayList, eventTypes: EVENT_TYPES,
    source: f.site ? `${source}  (synonym for log_event@${f.site.toLowerCase()}_link)` : 'all_log_events  (UNION ALL of the three site fragments)',
  });
}));

// ---------------- Reports ----------------
router.get('/reports', wrap(async (req, res) => {
  const report = reports.find((r) => r.key === req.query.r) || reports[0];
  let rows = [];
  let error = null;
  try {
    rows = await db.query(report.sql, {}, req.session.user.username);
  } catch (e) {
    error = db.cleanError(e);
  }
  res.render('reports', { title: 'Reports', reports, report, rows, error });
}));

// ---------------- Audit ----------------
router.get('/audit', wrap(async (req, res) => {
  const u = req.session.user.username;
  const appLog = await db.query(`
    SELECT log_id, table_name, action, record_id, old_value, new_value, db_user, app_user,
           CAST(log_time AS DATE) AS log_time
    FROM audit_log ORDER BY log_id DESC FETCH FIRST 100 ROWS ONLY`, {}, u);

  let siteLog = [];
  let siteError = null;
  try {
    siteLog = await db.query(`
      SELECT site_code, event_id, src_ip, event_time, change_type, db_user, os_user,
             CAST(changed_at AS DATE) AS changed_at
      FROM all_log_change_audit ORDER BY changed_at DESC FETCH FIRST 50 ROWS ONLY`, {}, u);
  } catch (e) { siteError = db.cleanError(e); }

  let unified = [];
  let unifiedError = null;
  try {
    unified = await db.query(`
      SELECT CAST(event_timestamp AS DATE) AS event_time, dbusername, action_name,
             object_schema, object_name, unified_audit_policies
      FROM unified_audit_trail
      WHERE object_schema IN ('TV_KHI','TV_LHR','TV_ISB','TV_CENTRAL')
      ORDER BY event_timestamp DESC FETCH FIRST 50 ROWS ONLY`, {}, u);
  } catch (e) { unifiedError = db.cleanError(e); }

  res.render('audit', { title: 'Audit', appLog, siteLog, siteError, unified, unifiedError });
}));

// ---------------- Course concepts map ----------------
router.get('/concepts', (req, res) => res.render('concepts', { title: 'Course Concepts' }));

module.exports = router;
