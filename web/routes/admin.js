const express = require('express');
const bcrypt = require('bcryptjs');
const db = require('../db');
const { wrap, requireAdmin, flash } = require('./middleware');

const router = express.Router();
router.use('/admin', requireAdmin);

router.get('/admin', wrap(async (req, res) => {
  const u = req.session.user.username;
  const rules = await db.query(`SELECT * FROM detection_rule ORDER BY rule_id`, {}, u);
  const users = await db.query(`
    SELECT u.username, u.role, a.full_name, u.created_at
    FROM app_user u LEFT JOIN analyst a ON a.analyst_id = u.analyst_id ORDER BY u.username`, {}, u);
  const analysts = await db.query(`SELECT analyst_id, full_name FROM analyst ORDER BY analyst_id`, {}, u);

  // Partitions in each site, read from the remote data dictionary through the links
  const partitions = await db.query(`
    SELECT 'KHI' AS site, COUNT(*) AS partitions FROM user_tab_partitions@khi_link WHERE table_name = 'LOG_EVENT'
    UNION ALL
    SELECT 'LHR', COUNT(*) FROM user_tab_partitions@lhr_link WHERE table_name = 'LOG_EVENT'
    UNION ALL
    SELECT 'ISB', COUNT(*) FROM user_tab_partitions@isb_link WHERE table_name = 'LOG_EVENT'`, {}, u);

  const perDay = await db.query(`
    SELECT attack_day,
           SUM(CASE WHEN site_code = 'KHI' THEN event_count ELSE 0 END) AS khi,
           SUM(CASE WHEN site_code = 'LHR' THEN event_count ELSE 0 END) AS lhr,
           SUM(CASE WHEN site_code = 'ISB' THEN event_count ELSE 0 END) AS isb
    FROM mv_daily_attacks GROUP BY attack_day ORDER BY attack_day DESC`, {}, u);

  const ruleRep = await db.one(`
    SELECT (SELECT COUNT(*) FROM detection_rule)              AS central,
           (SELECT COUNT(*) FROM rule_copy@khi_link)          AS khi,
           (SELECT COUNT(*) FROM rule_copy@lhr_link)          AS lhr,
           (SELECT COUNT(*) FROM rule_copy@isb_link)          AS isb,
           (SELECT MAX(synced_at) FROM rule_copy@khi_link)    AS synced_at
    FROM dual`, {}, u);

  const mv = await db.one(`SELECT last_refresh_date FROM user_mviews WHERE mview_name = 'MV_DAILY_ATTACKS'`, {}, u);

  res.render('admin', { title: 'Admin', rules, users, analysts, partitions, perDay, ruleRep, mv });
}));

router.post('/admin/detect', wrap(async (req, res) => {
  const days = Math.min(365, Math.max(1, parseInt(req.body.days || '30', 10) || 30));
  try {
    const r = await db.run(
      `BEGIN :n := pkg_soc.run_detection(TRUNC(SYSDATE) - :d, TRUNC(SYSDATE) + 1); END;`,
      { n: { dir: db.oracledb.BIND_OUT, type: db.oracledb.NUMBER }, d: days },
      req.session.user.username);
    flash(req, 'ok', `Detection finished. New incidents: ${r.outBinds.n}`);
  } catch (e) { flash(req, 'error', db.cleanError(e)); }
  res.redirect('/admin');
}));

router.post('/admin/refresh', wrap(async (req, res) => {
  try {
    await db.run(`BEGIN pkg_soc.refresh_summary; END;`, {}, req.session.user.username);
    flash(req, 'ok', 'Materialized view MV_DAILY_ATTACKS refreshed.');
  } catch (e) { flash(req, 'error', db.cleanError(e)); }
  res.redirect('/admin');
}));

router.post('/admin/sync', wrap(async (req, res) => {
  try {
    await db.run(`BEGIN pkg_soc.sync_rules; END;`, {}, req.session.user.username);
    flash(req, 'ok', 'Rules replicated to all three sites.');
  } catch (e) { flash(req, 'error', db.cleanError(e)); }
  res.redirect('/admin');
}));

router.post('/admin/rules/:id', wrap(async (req, res) => {
  const threshold = Math.max(1, parseInt(req.body.threshold, 10) || 1);
  const active = req.body.active === 'Y' ? 'Y' : 'N';
  try {
    await db.run(`UPDATE detection_rule SET threshold = :t, active = :a WHERE rule_id = :id`,
      { t: threshold, a: active, id: Number(req.params.id) }, req.session.user.username);
    await db.run(`BEGIN pkg_soc.sync_rules; END;`, {}, req.session.user.username);
    flash(req, 'ok', 'Rule saved, audited and replicated to all sites.');
  } catch (e) { flash(req, 'error', db.cleanError(e)); }
  res.redirect('/admin');
}));

// Audit demo: an "insider" deletes one log row at a site. The deletion is caught
// by the site trigger (LOG_CHANGE_AUDIT) and by the unified audit policy.
router.post('/admin/tamper', wrap(async (req, res) => {
  const site = { KHI: 'khi_logs', LHR: 'lhr_logs', ISB: 'isb_logs' }[req.body.site] || 'khi_logs';
  try {
    const r = await db.run(
      `DELETE FROM ${site} WHERE event_id = (SELECT MIN(event_id) FROM ${site} WHERE event_type = 'LOGIN_FAIL')`,
      {}, req.session.user.username);
    flash(req, 'ok', `${r.rowsAffected} log row deleted from ${site}. Now open the Audit page to see it recorded.`);
  } catch (e) { flash(req, 'error', db.cleanError(e)); }
  res.redirect('/admin');
}));

router.post('/admin/users', wrap(async (req, res) => {
  const username = (req.body.username || '').trim().toLowerCase();
  const password = req.body.password || '';
  const role = req.body.role === 'ADMIN' ? 'ADMIN' : 'ANALYST';
  if (!/^[a-z0-9_.]{3,30}$/.test(username) || password.length < 6) {
    flash(req, 'error', 'Username: 3 to 30 letters or numbers. Password: at least 6 characters.');
    return res.redirect('/admin');
  }
  try {
    await db.run(`INSERT INTO app_user (username, password_hash, role, analyst_id) VALUES (:u, :p, :r, :a)`, {
      u: username, p: bcrypt.hashSync(password, 10), r: role, a: req.body.analyst_id ? Number(req.body.analyst_id) : null,
    }, req.session.user.username);
    flash(req, 'ok', `User ${username} created.`);
  } catch (e) { flash(req, 'error', db.cleanError(e)); }
  res.redirect('/admin');
}));

module.exports = router;
