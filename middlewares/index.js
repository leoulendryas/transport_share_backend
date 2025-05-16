const jwt = require('jsonwebtoken');
const rateLimit = require('express-rate-limit');
const NodeCache = require('node-cache');
require('dotenv').config();

const cache = new NodeCache({ stdTTL: 300 }); // 5 minute TTL

// Rate limiting configurations
const createAccountLimiter = rateLimit({
  windowMs: 60 * 60 * 1000,
  max: 5,
  message: 'Too many accounts created from this IP, please try again after an hour'
});

const apiLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
  message: 'Too many requests, please try again later.'
});

const messageLimiter = rateLimit({
  windowMs: 1 * 60 * 1000,
  max: 30,
  message: 'Too many messages, please slow down'
});

const authenticate = (req, res, next) => {
  const authHeader = req.headers.authorization;
  if (!authHeader) return res.status(401).json({ error: 'Authorization header missing' });
  
  const token = authHeader.split(' ')[1];
  jwt.verify(token, process.env.JWT_SECRET, (err, decoded) => {
    if (err) return res.status(403).json({ error: 'Invalid or expired token' });
    req.user = decoded;
    next();
  });
};

const validateCoordinates = (req, res, next) => {
  const { from, to } = req.body;
  if (from.lat < -90 || from.lat > 90 || from.lng < -180 || from.lng > 180 ||
      to.lat < -90 || to.lat > 90 || to.lng < -180 || to.lng > 180) {
    return res.status(400).json({ error: 'Invalid coordinates' });
  }
  next();
};

const validateCoordinatesForPrice = (req, res, next) => {
  const { from, to } = req.body;

  // Validate coordinate structure
  if (!from?.lat || !from?.lng || !to?.lat || !to?.lng) {
    return res.status(400).json({ error: "Invalid coordinate format" });
  }

  // Validate Ethiopia boundaries
  const ETH_BOUNDS = {
    latMin: 3.397, latMax: 14.894,
    lngMin: 32.997, lngMax: 47.989
  };

  const validateRange = (val, min, max, name) => {
    if (val < min || val > max) {
      throw new Error(`${name} coordinate out of Ethiopian range`);
    }
  };  

  try {
    validateRange(from.lat, ETH_BOUNDS.latMin, ETH_BOUNDS.latMax, "From latitude");
    validateRange(from.lng, ETH_BOUNDS.lngMin, ETH_BOUNDS.lngMax, "From longitude");
    validateRange(to.lat, ETH_BOUNDS.latMin, ETH_BOUNDS.latMax, "To latitude");
    validateRange(to.lng, ETH_BOUNDS.lngMin, ETH_BOUNDS.lngMax, "To longitude");
    next();
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
};

const paginate = (req, res, next) => {
  req.query.page = Math.max(1, parseInt(req.query.page) || 1);
  req.query.limit = Math.min(100, Math.max(1, parseInt(req.query.limit))) || 20;
  next();
};

module.exports = {
  cache,
  createAccountLimiter,
  apiLimiter,
  messageLimiter,
  authenticate,
  validateCoordinates,
  validateCoordinatesForPrice,
  paginate
};