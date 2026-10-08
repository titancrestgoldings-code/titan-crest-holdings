const express = require('express');
const session = require('express-session');
const bcrypt = require('bcryptjs');
const Database = require('better-sqlite3');
const path = require('path');

const app = express();
const db = new Database('/tmp/titancrest.db');

//db.pragma('journal_mode = WAL');

db.exec(`
CREATE TABLE IF NOT EXISTS users(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL,
  email TEXT UNIQUE NOT NULL,
  password_hash TEXT NOT NULL,
  role TEXT NOT NULL DEFAULT 'investor',
  created_at TEXT DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS holdings(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER UNIQUE NOT NULL,
  stocks_gbp REAL NOT NULL DEFAULT 0,
  shares_gbp REAL NOT NULL DEFAULT 0,
  updated_at TEXT DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY(user_id) REFERENCES users(id)
);

CREATE TABLE IF NOT EXISTS balance_audit(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL,
  admin_id INTEGER NOT NULL,
  old_stocks_gbp REAL NOT NULL,
  new_stocks_gbp REAL NOT NULL,
  old_shares_gbp REAL NOT NULL,
  new_shares_gbp REAL NOT NULL,
  reason TEXT NOT NULL,
  created_at TEXT DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY(user_id) REFERENCES users(id),
  FOREIGN KEY(admin_id) REFERENCES users(id)
);
`);

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

app.use(session({
  secret: process.env.SESSION_SECRET || 'CHANGE_THIS_BEFORE_DEPLOYING',
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    sameSite: 'lax',
    secure: process.env.NODE_ENV === 'production'
  }
}));

app.use(express.static(path.join(__dirname, 'public')));

app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'index.html'));
});

function auth(req, res, next) {
  if (!req.session.userId) {
    return res.status(401).json({ error: 'Please log in.' });
  }
  next();
}

function adminOnly(req, res, next) {
  if (!req.session.userId) {
    return res.status(401).json({ error: 'Please log in.' });
  }

  const user = db
    .prepare('SELECT id, name, email, role FROM users WHERE id = ?')
    .get(req.session.userId);

  if (!user || user.role !== 'admin') {
    return res.status(403).json({ error: 'Admin access required.' });
  }

  req.admin = user;
  next();
}

function getUser(id) {
  return db
    .prepare('SELECT id, name, email, role, created_at FROM users WHERE id = ?')
    .get(id);
}

/* Register */
app.post('/api/register', (req, res) => {
  const { name, email, password } = req.body;

  if (!name || !email || !password || password.length < 8) {
    return res.status(400).json({
      error: 'Name, email and a password of at least 8 characters are required.'
    });
  }

  try {
    const hash = bcrypt.hashSync(password, 12);

    const info = db.prepare(`
      INSERT INTO users(name, email, password_hash)
      VALUES (?, ?, ?)
    `).run(name.trim(), email.trim().toLowerCase(), hash);

    db.prepare(`
      INSERT INTO holdings(user_id, stocks_gbp, shares_gbp)
      VALUES (?, 0, 0)
    `).run(info.lastInsertRowid);

    req.session.userId = info.lastInsertRowid;

    res.json({
      ok: true,
      user: getUser(req.session.userId)
    });
  } catch (e) {
    res.status(400).json({
      error: 'An account with that email may already exist.'
    });
  }
});

/* Login */
app.post('/api/login', (req, res) => {
  const email = String(req.body.email || '').trim().toLowerCase();
  const password = String(req.body.password || '');

  const row = db
    .prepare('SELECT * FROM users WHERE email = ?')
    .get(email);

  if (!row || !bcrypt.compareSync(password, row.password_hash)) {
    return res.status(401).json({ error: 'Invalid email or password.' });
  }

  req.session.userId = row.id;

  res.json({
    ok: true,
    user: getUser(row.id)
  });
});

/* Logout */
app.post('/api/logout', (req, res) => {
  req.session.destroy(() => {
    res.json({ ok: true });
  });
});

/* Current customer */
app.get('/api/me', auth, (req, res) => {
  const user = getUser(req.session.userId);

  const holdings = db
    .prepare(`
      SELECT stocks_gbp, shares_gbp, updated_at
      FROM holdings
      WHERE user_id = ?
    `)
    .get(req.session.userId);

  res.json({
    user,
    holdings: holdings || {
      stocks_gbp: 0,
      shares_gbp: 0
    }
  });
});

/* Admin: list customers */
app.get('/api/admin/customers', adminOnly, (req, res) => {
  const customers = db.prepare(`
    SELECT
      u.id,
      u.name,
      u.email,
      u.created_at,
      COALESCE(h.stocks_gbp, 0) AS stocks_gbp,
      COALESCE(h.shares_gbp, 0) AS shares_gbp
    FROM users u
    LEFT JOIN holdings h ON h.user_id = u.id
    WHERE u.role != 'admin'
    ORDER BY u.created_at DESC
  `).all();

  res.json({ customers });
});

/* Admin: update customer holdings */
app.put('/api/admin/customers/:id/holdings', adminOnly, (req, res) => {
  const userId = Number(req.params.id);
  const stocks = Number(req.body.stocks_gbp);
  const shares = Number(req.body.shares_gbp);
  const reason = String(req.body.reason || '').trim();

  if (!Number.isFinite(stocks) || stocks < 0 ||
      !Number.isFinite(shares) || shares < 0) {
    return res.status(400).json({
      error: 'Stocks and shares must be valid non-negative amounts.'
    });
  }

  if (!reason) {
    return res.status(400).json({
      error: 'A reason is required for every balance adjustment.'
    });
  }

  const customer = getUser(userId);

  if (!customer || customer.role === 'admin') {
    return res.status(404).json({
      error: 'Customer not found.'
    });
  }

  const old = db.prepare(`
    SELECT stocks_gbp, shares_gbp
    FROM holdings
    WHERE user_id = ?
  `).get(userId) || {
    stocks_gbp: 0,
    shares_gbp: 0
  };

  const update = db.transaction(() => {
    db.prepare(`
      INSERT INTO holdings(user_id, stocks_gbp, shares_gbp)
      VALUES (?, ?, ?)
      ON CONFLICT(user_id) DO UPDATE SET
        stocks_gbp = excluded.stocks_gbp,
        shares_gbp = excluded.shares_gbp,
        updated_at = CURRENT_TIMESTAMP
    `).run(userId, stocks, shares);

    db.prepare(`
      INSERT INTO balance_audit(
        user_id,
        admin_id,
        old_stocks_gbp,
        new_stocks_gbp,
        old_shares_gbp,
        new_shares_gbp,
        reason
      )
      VALUES (?, ?, ?, ?, ?, ?, ?)
    `).run(
      userId,
      req.admin.id,
      old.stocks_gbp,
      stocks,
      old.shares_gbp,
      shares,
      reason
    );
  });

  update();

  res.json({
    ok: true,
    customer: getUser(userId),
    holdings: {
      stocks_gbp: stocks,
      shares_gbp: shares
    }
  });
});

/* Admin: adjustment history */
app.get('/api/admin/audit', adminOnly, (req, res) => {
  const records = db.prepare(`
    SELECT
      a.*,
      u.name AS customer_name,
      u.email AS customer_email,
      admin.name AS admin_name
    FROM balance_audit a
    JOIN users u ON u.id = a.user_id
    JOIN users admin ON admin.id = a.admin_id
    ORDER BY a.created_at DESC
  `).all();

  res.json({ records });
});

/*
  Set an administrator using the ADMIN_EMAIL environment variable.
  Example:
  ADMIN_EMAIL=your-email@example.com
*/
if (process.env.ADMIN_EMAIL) {
  db.prepare(`
    UPDATE users
    SET role = 'admin'
    WHERE email = ?
  `).run(process.env.ADMIN_EMAIL.trim().toLowerCase());
}

const PORT = process.env.PORT || 3000;

app.listen(PORT, () => {
  console.log(`Titan Crest portal running on port ${PORT}`);
});
