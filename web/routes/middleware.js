// Small helpers shared by all route files

// Lets async route functions send errors to the error page
const wrap = (fn) => (req, res, next) => Promise.resolve(fn(req, res, next)).catch(next);

function requireLogin(req, res, next) {
  if (req.session.user) return next();
  return res.redirect('/login');
}

function requireAdmin(req, res, next) {
  if (req.session.user && req.session.user.role === 'ADMIN') return next();
  req.session.flash = { type: 'error', text: 'Only an admin can do that.' };
  return res.redirect('/');
}

function flash(req, type, text) {
  req.session.flash = { type, text };
}

module.exports = { wrap, requireLogin, requireAdmin, flash };
