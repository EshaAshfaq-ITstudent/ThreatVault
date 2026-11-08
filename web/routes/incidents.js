const express = require('express');
const db = require('../db');
const { wrap, requireAdmin, flash } = require('./middleware');

const router = express.Router();
const TYPES = ['BRUTEFORCE', 'DDOS', 'MALWARE', 'PHISHING'];
const STATUSES = ['OPEN', 'ASSIGNED', 'CLOSED'];
const SITES = ['KHI', 'LHR', 'ISB'];
const SITE_SOURCE = { KHI: 'khi_logs', LHR: 'lhr_logs', ISB: 'isb_logs' };
const IP_RE = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/;

// ---------------- Incident list ----------------
router.get('/incidents', wrap(async (req, res) => {
  const f = {
    status: STATUSES.includes(req.query.status) ? req.query.status : (req.query.status === 'ALL' ? 'ALL' : 'ACTIVE'),
    type: TYPES.includes(req.query.type) ? req.query.type : '',
    site: SITES.includes(req.query.site) ? req.query.site : '',
    q: (req.query.q || '').trim().slice(0, 20),
  };
  const binds = {};
  const where = ['1 = 1'];
  if (f.status === 'ACTIVE') where.push(`i.status <> 'CLOSED'`);
  else if (f.status !== 'ALL') { where.push('i.status = :st'); binds.st = f.status; }
  if (f.type) { where.push('i.type_name() = :ty'); binds.ty = f.type; }
  if (f.site) { where.push('i.site_code = :si'); binds.si = f.site; }
  if (f.q) { where.push('(i.src_ip = :q OR i.ticket_no = UPPER(:q))'); binds.q = f.q; }

  const rows = await db.query(`
    SELECT i.incident_id, i.ticket_no, i.type_name() AS type_name, i.site_code, i.src_ip,
           i.severity, i.status, i.risk_score(a.criticality) AS risk, i.is_overdue() AS overdue,
           an.full_name AS analyst, i.first_seen, i.opened_at
    FROM incidents i
    JOIN asset a ON a.asset_id = i.asset_id
    LEFT JOIN analyst an ON an.analyst_id = i.analyst_id
    WHERE ${where.join(' AND ')}
    ORDER BY CASE i.status WHEN 'CLOSED' THEN 1 ELSE 0 END, risk DESC, i.opened_at DESC
    FETCH FIRST 300 ROWS ONLY`, binds, req.session.user.username);

  res.render('incidents', { title: 'Incidents', rows, f, TYPES, STATUSES, SITES });
}));

// ---------------- Incident detail ----------------
router.get('/incidents/:id', wrap(async (req, res, next) => {
  const u = req.session.user.username;
  const id = Number(req.params.id);
  if (!Number.isInteger(id)) return next();
  const inc = await db.one(`
    SELECT i.incident_id, i.ticket_no, i.type_name() AS type_name, i.details() AS details,
           i.site_code, i.asset_id, a.hostname, a.asset_type, a.criticality,
           i.src_ip, i.severity, i.status,
           i.risk_score() AS base_risk, i.risk_score(a.criticality) AS risk,
           i.sla_hours() AS sla_hours, i.is_overdue() AS overdue,
           i.first_seen, i.opened_at, i.closed_at, i.analyst_id, an.full_name AS analyst_name,
           r.rule_name, r.threshold, pkg_soc.is_blocked(i.src_ip) AS blocked
    FROM incidents i
    JOIN asset a ON a.asset_id = i.asset_id
    LEFT JOIN analyst an ON an.analyst_id = i.analyst_id
    LEFT JOIN detection_rule r ON r.rule_id = i.rule_id
    WHERE i.incident_id = :id`, { id }, u);
  if (!inc) return next();

  const actions = await db.query(`
    SELECT ra.action_time, ra.action_text, an.full_name
    FROM response_action ra LEFT JOIN analyst an ON an.analyst_id = ra.analyst_id
    WHERE ra.incident_id = :id ORDER BY ra.action_id`, { id }, u);

  const analysts = await db.query(`SELECT analyst_id, full_name, shift FROM analyst WHERE active = 'Y' ORDER BY analyst_id`, {}, u);

  // Evidence: the log rows from that hour, read straight from the site fragment
  const evidence = await db.query(`
    SELECT event_time, event_type, action, dst_port, username, detail
    FROM ${SITE_SOURCE[inc.site_code]}
    WHERE src_ip = :ip AND event_time >= :fs AND event_time < :fs + 1/24
    ORDER BY event_time FETCH FIRST 30 ROWS ONLY`, { ip: inc.src_ip, fs: inc.first_seen }, u);

  res.render('incident', { title: inc.ticket_no, inc, actions, analysts, evidence });
}));

router.post('/incidents/:id/assign', wrap(async (req, res) => {
  const id = Number(req.params.id);
  try {
    await db.run(`BEGIN pkg_soc.assign_analyst(:id, :a); END;`,
      { id, a: Number(req.body.analyst_id) }, req.session.user.username);
    flash(req, 'ok', 'Analyst assigned.');
  } catch (e) { flash(req, 'error', db.cleanError(e)); }
  res.redirect(`/incidents/${id}`);
}));

router.post('/incidents/:id/note', wrap(async (req, res) => {
  const id = Number(req.params.id);
  const text = (req.body.text || '').trim();
  if (!text) { flash(req, 'error', 'Write a note first.'); return res.redirect(`/incidents/${id}`); }
  try {
    await db.run(`BEGIN pkg_soc.add_action(:id, :a, :t); END;`,
      { id, a: req.session.user.analystId, t: text.slice(0, 400) }, req.session.user.username);
    flash(req, 'ok', 'Note added.');
  } catch (e) { flash(req, 'error', db.cleanError(e)); }
  res.redirect(`/incidents/${id}`);
}));

router.post('/incidents/:id/close', wrap(async (req, res) => {
  const id = Number(req.params.id);
  try {
    await db.run(`BEGIN pkg_soc.close_incident(:id, :a, :t, :b, :s); END;`, {
      id,
      a: req.session.user.analystId,
      t: (req.body.text || 'Incident closed').slice(0, 400),
      b: req.body.block === 'Y' ? 'Y' : 'N',
      s: req.body.simulate === 'Y' ? 'Y' : 'N',
    }, req.session.user.username);
    flash(req, 'ok', 'Incident closed in one transaction.');
  } catch (e) {
    flash(req, 'error', db.cleanError(e));
  }
  res.redirect(`/incidents/${id}`);
}));

// ---------------- Blocklist ----------------
router.get('/blocklist', wrap(async (req, res) => {
  const u = req.session.user.username;
  const rows = await db.query(`
    SELECT b.ip, b.reason, b.added_on, an.full_name AS added_by,
           (SELECT COUNT(*) FROM incidents i WHERE i.src_ip = b.ip) AS incidents
    FROM blocklist b LEFT JOIN analyst an ON an.analyst_id = b.added_by
    ORDER BY b.added_on DESC`, {}, u);
  const rep = await db.one(`
    SELECT (SELECT COUNT(*) FROM blocklist)                AS central,
           (SELECT COUNT(*) FROM blocklist_copy@khi_link)  AS khi,
           (SELECT COUNT(*) FROM blocklist_copy@lhr_link)  AS lhr,
           (SELECT COUNT(*) FROM blocklist_copy@isb_link)  AS isb
    FROM dual`, {}, u);
  res.render('blocklist', { title: 'Blocklist', rows, rep, ipPrefill: req.query.ip || '' });
}));

router.post('/blocklist', wrap(async (req, res) => {
  const ip = (req.body.ip || '').trim();
  const m = ip.match(IP_RE);
  if (!m || m.slice(1).some((p) => Number(p) > 255)) {
    flash(req, 'error', 'Enter a valid IPv4 address, for example 45.12.8.9');
    return res.redirect('/blocklist');
  }
  try {
    await db.run(`BEGIN pkg_soc.block_ip(:ip, :r, :a); END;`,
      { ip, r: (req.body.reason || 'Blocked manually').slice(0, 200), a: req.session.user.analystId },
      req.session.user.username);
    flash(req, 'ok', `${ip} blocked at central and replicated to all 3 sites.`);
  } catch (e) { flash(req, 'error', db.cleanError(e)); }
  res.redirect('/blocklist');
}));

router.post('/blocklist/remove', requireAdmin, wrap(async (req, res) => {
  try {
    await db.run(`BEGIN pkg_soc.unblock_ip(:ip); END;`, { ip: req.body.ip }, req.session.user.username);
    flash(req, 'ok', `${req.body.ip} removed from all sites.`);
  } catch (e) { flash(req, 'error', db.cleanError(e)); }
  res.redirect('/blocklist');
}));

module.exports = router;
