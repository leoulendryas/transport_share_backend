const rateLimit = require('express-rate-limit');

const apiLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 10, // limit each IP to 10 requests per windowMs
  message: {
    error: 'Too many requests, please try again in 15 minutes',
  },
  standardHeaders: true,
  legacyHeaders: false,
});

module.exports = apiLimiter;
