// Quick test: can Node.js reach Oracle and is ThreatVault installed?
// Usage: npm run check
require('dotenv').config();
const oracledb = require('oracledb');

(async () => {
  const cfg = {
    user: process.env.DB_USER || 'tv_central',
    password: process.env.DB_PASSWORD || 'tvpass123',
    connectString: process.env.DB_CONNECT || 'localhost:1521/XEPDB1',
  };
  try {
    const conn = await oracledb.getConnection(cfg);
    const v = await conn.execute(`SELECT banner_full FROM v$version`).catch(() => ({ rows: [['(version hidden)']] }));
    console.log('Connected to:', v.rows[0][0]);
    const checks = [
      ['Sites', 'SELECT COUNT(*) FROM site'],
      ['Assets', 'SELECT COUNT(*) FROM asset'],
      ['Rules', 'SELECT COUNT(*) FROM detection_rule'],
      ['Logs (all sites, via DB links)', 'SELECT COUNT(*) FROM all_log_events'],
      ['Incidents', 'SELECT COUNT(*) FROM incidents'],
    ];
    for (const [name, sql] of checks) {
      try {
        const r = await conn.execute(sql);
        console.log(`  ${name.padEnd(32)} ${r.rows[0][0]}`);
      } catch (e) {
        console.log(`  ${name.padEnd(32)} ERROR ${e.message}`);
      }
    }
    await conn.close();
  } catch (e) {
    console.error('Could not connect:', e.message);
    console.error('Check that Oracle is running and that .env has the right password and DB_CONNECT.');
    process.exit(1);
  }
})();
