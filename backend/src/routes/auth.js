const express = require('express');
const router = express.Router();

const { login, register, verifyToken, checkUsername } = require('../controllers/authController');
const {
  bruteForceLimiter,
  bruteForceDelay,
  bruteForceCaptcha,
  resetFailedAttempts,
  resetRateLimit,
  recordAttempt
} = require('../middleware/bruteForceDefence');

// Resetear intentos al iniciar la app
router.use((req, res, next) => {
  if (!req.app.__brute_reset_done) {
    resetFailedAttempts();
    resetRateLimit();
    req.app.__brute_reset_done = true;
  }
  next();
});

// Rutas de autenticación
router.post('/login', recordAttempt, bruteForceLimiter, bruteForceDelay, bruteForceCaptcha, login);
router.post('/register', register);
router.post('/auth/verify', verifyToken);
router.post('/check-username', recordAttempt, bruteForceLimiter, bruteForceDelay, checkUsername);

module.exports = router;
