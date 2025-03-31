const express = require('express');
const { query } = require('../config/database');
const { authenticate } = require('../middlewares');

const router = express.Router();

router.get('/', authenticate, async (req, res) => {
  try {
    const user = await query(
      `SELECT id, email, created_at 
       FROM users WHERE id = $1`,
      [req.user.id]
    );
    
    const rides = await query(
      `SELECT r.id, r.from_address, r.to_address, r.departure_time, ur.is_driver
       FROM rides r JOIN user_rides ur ON r.id = ur.ride_id
       WHERE ur.user_id = $1 AND r.departure_time > NOW()`,
      [req.user.id]
    );
    
    res.json({
      user: user.rows[0],
      upcomingRides: rides.rows
    });
  } catch (error) {
    res.status(500).json({ error: 'Failed to fetch profile' });
  }
});

module.exports = router;