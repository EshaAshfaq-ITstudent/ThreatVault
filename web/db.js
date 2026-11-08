// Oracle connection pool and small helpers.
// The app always connects as tv_central. The logged in username is sent as
// CLIENT_IDENTIFIER so the audit triggers can record who did what.
const oracledb = require('oracledb');

oracledb.outFormat = oracledb.OUT_FORMAT_OBJECT;
oracledb.fetchAsString = [oracledb.CLOB];

let pool = null;

async function getPool() {
  if (pool) return pool;
  pool = await oracledb.createPool({
    user: process.env.DB_USER || 'tv_central',
    password: process.env.DB_PASSWORD || 'tvpass123',
    connectString: process.env.DB_CONNECT || 'localhost:1521/XEPDB1',
    poolMin: 1,
    poolMax: 8,
    poolIncrement: 1,
  });
  return pool;
}

// Oracle returns UPPERCASE column names; make them lowercase for the templates
function lowerKeys(rows) {
  return (rows || []).map((r) => {
    const o = {};
    for (const k of Object.keys(r)) o[k.toLowerCase()] = r[k];
    return o;
  });
}

async function withConn(user, fn) {
  const conn = await (await getPool()).getConnection();
  try {
    conn.clientId = user || 'system';
    return await fn(conn);
  } finally {
    await conn.close();
  }
}

// SELECT: returns an array of row objects
function query(sql, binds = {}, user) {
  return withConn(user, async (conn) => lowerKeys((await conn.execute(sql, binds)).rows));
}

// SELECT one row (or null)
async function one(sql, binds = {}, user) {
  const rows = await query(sql, binds, user);
  return rows[0] || null;
}

// DML or PL/SQL call, committed automatically
function run(sql, binds = {}, user) {
  return withConn(user, (conn) => conn.execute(sql, binds, { autoCommit: true }));
}

// Turns "ORA-20011: Incident already closed\nORA-06512: at ..." into a clean message
function cleanError(err) {
  const msg = (err && err.message) || String(err);
  const first = msg.split('\n')[0];
  return first.replace(/^ORA-20\d{3}: /, '');
}

async function close() {
  if (pool) await pool.close(5);
}

module.exports = { oracledb, query, one, run, cleanError, close, getPool };
