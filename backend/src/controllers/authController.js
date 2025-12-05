const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { db } = require('../config/database');
const { failedAttempts } = require('../middleware/bruteForceDefence');

const login = async (req, res) => {
  const ip = req.ip || "unknown";
  failedAttempts[ip] = failedAttempts[ip] || 0;

  const { username, password } = req.body;

  const query = `SELECT * FROM users WHERE username = ?`;

  db.query(query, [username], async (err, results) => {
    if (err) {
      return res.status(500).json({ error: 'Error en el servidor' });
    }

    if (results.length === 0) {
      failedAttempts[ip]++;
      return res.status(401).json({ error: 'Credenciales inválidas' });
    }

    const user = results[0];
    const isValidPassword = await bcrypt.compare(password, user.password);

    if (!isValidPassword) {
      failedAttempts[ip]++;
      return res.status(401).json({ error: 'Credenciales inválidas' });
    }

    failedAttempts[ip] = 0;

    const token = jwt.sign(
      { id: user.id, username: user.username },
      process.env.JWT_SECRET || 'supersecret123'
    );

    return res.json({ token, username: user.username });
  });
};
const register = (req, res) => {
  return res.status(501).json({ error: 'Not implemented' });
};

const verifyToken = (req, res) => {
  return res.status(501).json({ error: 'Not implemented' });
};

const checkUsername = (req, res) => {
  try {
    const ip = req.ip || 'unknown';
    const username = req.body && req.body.username;

    if (!username || typeof username !== 'string' || !/^[a-zA-Z0-9_]{3,30}$/.test(username)) {
      if (username && (username.includes("'") || username.includes('--') || /sleep/i.test(username))) {
        console.warn('Posible intento de SQLi en checkUsername', { ip, username });
      }

      return res.json({ exists: false });
    }

    const query = 'SELECT COUNT(*) as count FROM users WHERE username = ?';
    db.query(query, [username], (err, results) => {
      if (err) {
        console.error('DB error in checkUsername:', err);
        return res.json({ exists: false });
      }

      const count = (results && results[0] && (results[0].count || results[0].COUNT || results[0].count === 0))
        ? Number(results[0].count || results[0].COUNT || 0)
        : 0;

      const delay = Math.floor(Math.random() * 100) + 50;
      setTimeout(() => res.json({ exists: count > 0 }), delay);
    });
  } catch (error) {
    console.error('Unexpected error in checkUsername:', error);
    return res.json({ exists: false });
  }
};

module.exports = {
  login,
  register,
  verifyToken,
  checkUsername
};