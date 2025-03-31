const express = require('express');
const { query } = require('../config/database');
const { cache } = require('../middlewares');

const router = express.Router();

router.get('/', async (req, res) => {
  const cacheKey = 'all_companies';
  let companies = cache.get(cacheKey);
  
  if (!companies) {
    const result = await query('SELECT * FROM ride_companies');
    companies = result.rows;
    cache.set(cacheKey, companies);
  }
  
  res.json(companies);
});

module.exports = router;