const csrf =require("csurf");
const csrfProteccion=csrf();

const ALLOWED_ORIGIN = new Set([
  "http://localhost:5173",
  "http://localhost:3000",
  "http://localhost",
]);; 

function errorCsrf(err, req, res, next) {
  if (err && err.code === 'EBADCSRFTOKEN') {
    return res.status(403).json({ error: 'CSRF token inválido o faltante' });
  }
  next(err);
}

function validateOrigin(req, res, next) {
    const origin = req.get("origin") || req.get("referer");
  if (origin && ![...ALLOWED_ORIGIN].some((o) => origin.startsWith(o))) {
    return res.status(403).json({ error: "Invalid Origin" });
  }
  next();
}

module.exports = { errorCsrf, validateOrigin , csrfProteccion};