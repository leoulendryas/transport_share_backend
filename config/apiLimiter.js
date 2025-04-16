const rateLimit = require('express-rate-limit');

const apiLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 mins
  max: 100,
  standardHeaders: true, // send rate limit info in headers
  legacyHeaders: false,  // disable legacy headers
});

module.exports = apiLimiter;
