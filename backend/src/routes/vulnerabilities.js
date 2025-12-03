const express = require('express');
const router = express.Router();
const vulnerabilityController = require('../controllers/vulnerabilityController');
const { uploadMiddleware, uploadFile } = require('../controllers/uploadController');
const { errorCsrf, validateOrigin , csrfProteccion} = require("../middleware/errorCsrf")
// Command Injection
router.post('/ping', vulnerabilityController.ping);

// CSRF - Transferencia
router.get("/csrf-token", csrfProteccion, (req, res) => {
  const token = req.csrfToken();
  res.cookie("CSRF-TOKEN", token, {
    sameSite: "strict",
    httpOnly: false,
    secure: false,
  });
  return res.status(200).json({ csrfToken: token });
});

router.post('/transfer', validateOrigin,csrfProteccion,vulnerabilityController.transfer);

// Local File Inclusion
router.get('/file', vulnerabilityController.readFile);

// File Upload
router.post('/upload', uploadMiddleware, uploadFile);

module.exports = router;

router.use(errorCsrf);
