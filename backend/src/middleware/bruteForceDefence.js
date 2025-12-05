const failedAttempts = {};
const attemptCounts = {};

// Registrar intento
function recordAttempt(req, res, next) {
  const ip = req.ip;
  attemptCounts[ip] = (attemptCounts[ip] || 0) + 1;
  next();
}

// Limitar intentos: máximo 5
function bruteForceLimiter(req, res, next) {
  const ip = req.ip;
  const attempts = attemptCounts[ip] || 0;

  if (attempts > 5) {
    return res.status(429).json({ error: 'Too many requests' });
  }

  next();
}

// Delay progresivo por intentos fallidos
async function bruteForceDelay(req, res, next) {
  const ip = req.ip;
  const attempts = attemptCounts[ip] || 0;

  if (attempts > 1) {
    const delay = Math.min(300 * Math.pow(2, attempts - 2), 8000);
    await new Promise(resolve => setTimeout(resolve, delay));
  }

  next();
}

// CAPTCHA después de 3 intentos fallidos
function bruteForceCaptcha(req, res, next) {
  const ip = req.ip;
  const attempts = attemptCounts[ip] || failedAttempts[ip] || 0;

  if (attempts > 3 && !req.body.captcha) {
    return res.status(400).json({ error: "Se requiere verificación captcha" });
  }

  next();
}

// Resetear intentos fallidos
function resetFailedAttempts() {
  for (const k in failedAttempts) delete failedAttempts[k];
  for (const k in attemptCounts) delete attemptCounts[k];
}

// Resetear rate limit
function resetRateLimit() {
  for (const k in attemptCounts) delete attemptCounts[k];
}

module.exports = {
  bruteForceLimiter,
  bruteForceDelay,
  bruteForceCaptcha,
  failedAttempts,
  recordAttempt,
  resetFailedAttempts,
  resetRateLimit
};
