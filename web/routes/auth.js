const express = require('express');
const bcrypt = require('bcryptjs');
const db = require('../db');

// Sample attack origins for the login illustration
const LOGIN_ORIGINS = [
  { country: 'China', count: 900 }, { country: 'Russia', count: 760 }, { country: 'Iran', count: 520 },
  { country: 'Brazil', count: 380 }, { country: 'Vietnam', count: 340 }, { country: 'Romania', count: 260 },
  { country: 'North Korea', count: 240 },
];
const { wrap } = require('./middleware');

const router = express.Router();

router.get('/login', (req, res) => {
  if (req.session.user) return res.redirect('/');
  res.render('login', { origins: LOGIN_ORIGINS, title: 'Login', error: null, username: '' });
});

router.post('/login', wrap(async (req, res) => {
  const username = (req.body.username || '').trim().toLowerCase();
  const password = req.body.password || '';
  let row = null;
  try {
    row = await db.one(
      `SELECT u.username, u.password_hash, u.role, u.analyst_id, a.full_name
       FROM app_user u LEFT JOIN analyst a ON a.analyst_id = u.analyst_id
       WHERE u.username = :u`, { u: username }, username);
  } catch (e) {
    return res.render('login', { origins: LOGIN_ORIGINS, title: 'Login', error: 'Database not reachable: ' + db.cleanError(e), username });
  }
  if (!row || !bcrypt.compareSync(password, row.password_hash)) {
    return res.render('login', { origins: LOGIN_ORIGINS, title: 'Login', error: 'Wrong username or password.', username });
  }
  req.session.user = {
    username: row.username,
    role: row.role,
    analystId: row.analyst_id,
    name: row.full_name || row.username,
  };
  res.redirect('/');
}));

router.get('/logout', (req, res) => {
  req.session.destroy(() => res.redirect('/login'));
});

module.exports = router;
