// ============================================================
// Node.js loader (backup option if sqlldr is not on your PATH)
// Loads data/logs_<SITE>.csv into each site's LOG_EVENT table,
// then runs detection and refreshes the materialized view.
// Usage: npm run load
// The main method for the lab is SQL*Loader: scripts\load_logs.bat
// ============================================================
require('dotenv').config();
const fs = require('fs');
const path = require('path');
const oracledb = require('oracledb');

const CONNECT = process.env.DB_CONNECT || 'localhost:1521/XEPDB1';
const SITE_PWD = process.env.SITE_PASSWORD || 'tvpass123';
const SITES = ['KHI', 'LHR', 'ISB'];
const BATCH = 5000;

// Splits one CSV line, respecting "quoted, values"
function parseLine(line) {
  const out = [];
  let cur = '';
  let q = false;
  for (let i = 0; i < line.length; i++) {
    const c = line[i];
    if (q) {
      if (c === '"' && line[i + 1] === '"') { cur += '"'; i++; }
      else if (c === '"') q = false;
      else cur += c;
    } else if (c === '"') q = true;
    else if (c === ',') { out.push(cur); cur = ''; }
    else cur += c;
  }
  out.push(cur);
  return out;
}

async function loadSite(site) {
  const file = path.join(__dirname, '..', 'data', `logs_${site}.csv`);
  if (!fs.existsSync(file)) throw new Error(`${file} not found. Run: npm run generate`);
  const lines = fs.readFileSync(file, 'utf8').split(/\r?\n/).slice(1).filter(Boolean);
  const conn = await oracledb.getConnection({ user: `tv_${site.toLowerCase()}`, password: SITE_PWD, connectString: CONNECT });
  const sql = `INSERT INTO log_event (site_code, event_time, asset_id, src_ip, src_country, dst_port,
                 event_type, action, username, detail)
               VALUES (:1, TO_DATE(:2, 'YYYY-MM-DD HH24:MI:SS'), :3, :4, :5, :6, :7, :8, :9, :10)`;
  const opts = {
    autoCommit: false,
    bindDefs: [
      { type: oracledb.STRING, maxSize: 3 }, { type: oracledb.STRING, maxSize: 19 },
      { type: oracledb.NUMBER }, { type: oracledb.STRING, maxSize: 15 },
      { type: oracledb.STRING, maxSize: 40 }, { type: oracledb.NUMBER },
      { type: oracledb.STRING, maxSize: 20 }, { type: oracledb.STRING, maxSize: 10 },
      { type: oracledb.STRING, maxSize: 40 }, { type: oracledb.STRING, maxSize: 200 },
    ],
  };
  let done = 0;
  for (let i = 0; i < lines.length; i += BATCH) {
    const rows = lines.slice(i, i + BATCH).map((l) => {
      const v = parseLine(l);
      return [v[0], v[1], Number(v[2]), v[3], v[4] || null, v[5] ? Number(v[5]) : null,
              v[6], v[7] || null, v[8] || null, v[9] || null];
    });
    await conn.executeMany(sql, rows, opts);
    done += rows.length;
    process.stdout.write(`\r  ${site}: ${done}/${lines.length} rows`);
  }
  await conn.commit();
  await conn.close();
  console.log('');
}

async function main() {
  for (const s of SITES) await loadSite(s);

  console.log('Running detection and refreshing the dashboard summary...');
  const conn = await oracledb.getConnection({
    user: process.env.DB_USER || 'tv_central',
    password: process.env.DB_PASSWORD || 'tvpass123',
    connectString: CONNECT,
  });
  const r = await conn.execute(
    `BEGIN :n := pkg_soc.run_detection(TRUNC(SYSDATE) - 30, TRUNC(SYSDATE) + 1); pkg_soc.refresh_summary; END;`,
    { n: { dir: oracledb.BIND_OUT, type: oracledb.NUMBER } }
  );
  console.log(`Incidents created: ${r.outBinds.n}`);
  await conn.close();
  console.log('Done. Start the web app with: npm start');
}

main().catch((e) => { console.error('\nLoad failed:', e.message); process.exit(1); });
