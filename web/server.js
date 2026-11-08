// ============================================================
// ThreatVault web dashboard
// Start: npm start   then open http://localhost:3000
// ============================================================
const path = require('path');
require('dotenv').config({ path: path.join(__dirname, '..', '.env') });

const express = require('express');
const session = require('express-session');
const db = require('./db');
const { requireLogin } = require('./routes/middleware');
const visuals = require('./visuals');

const app = express();
const PORT = process.env.PORT || 3000;

app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));
app.use(express.static(path.join(__dirname, 'public')));
// Chart.js served locally so charts work without internet
app.get('/vendor/chart.umd.js', (req, res) => res.sendFile(path.join(__dirname, '..', 'node_modules', 'chart.js', 'dist', 'chart.umd.js')));
app.use(express.urlencoded({ extended: false }));
app.use(session({
  secret: process.env.SESSION_SECRET || 'threatvault-dev-secret',
  resave: false,
  saveUninitialized: false,
  cookie: { maxAge: 8 * 60 * 60 * 1000 },
}));

// Values every page can use
const pad = (n) => String(n).padStart(2, '0');
app.use((req, res, next) => {
  res.locals.user = req.session.user || null;
  res.locals.flash = req.session.flash || null;
  delete req.session.flash;
  res.locals.path = req.path;
  res.locals.fmt = (d) => (d instanceof Date
    ? `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())} ${pad(d.getHours())}:${pad(d.getMinutes())}`
    : (d == null ? '' : String(d)));
  res.locals.fmtDay = (d) => (d instanceof Date
    ? `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}` : (d == null ? '' : String(d)));
  res.locals.icon = visuals.icon;
  res.locals.attackMap = visuals.attackMap;
  res.locals.siteMap = visuals.siteMap;
  res.locals.num = (n) => (n == null ? '0' : Number(n).toLocaleString('en-US'));
  next();
});

app.use(require('./routes/auth'));
app.use(requireLogin);
app.use(require('./routes/main'));
app.use(require('./routes/incidents'));
app.use(require('./routes/admin'));

app.use((req, res) => res.status(404).render('error', { title: 'Not found', message: 'This page does not exist.' }));

// Any error (for example Oracle not running) shows a friendly page
app.use((err, req, res, _next) => {
  console.error(err);
  const msg = db.cleanError(err);
  const hint = /NJS-|ORA-12541|ORA-12514|ORA-01017|ECONNREFUSED/.test(msg)
    ? 'Check that Oracle XE is running, that you ran sql/install.sql, and that .env has the right DB_CONNECT and password.'
    : null;
  res.status(500).render('error', { title: 'Something went wrong', message: msg, hint });
});

app.listen(PORT, () => {
  console.log(`ThreatVault running at http://localhost:${PORT}`);
  db.getPool()
    .then(() => console.log('Connected to Oracle as', process.env.DB_USER || 'tv_central'))
    .catch((e) => console.error('Oracle connection failed:', e.message));
});

process.on('SIGINT', async () => { await db.close(); process.exit(0); });
