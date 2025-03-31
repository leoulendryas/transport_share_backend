const express = require('express');
const { query } = require('../config/database');
const { authenticate } = require('../middlewares');

const router = express.Router();

router.post('/', authenticate, async (req, res) => {
  try {
    const { rideId, latitude, longitude } = req.body;
    if (!rideId || !latitude || !longitude) {
      return res.status(400).json({ error: 'Missing required fields' });
    }

    const result = await query(
      `INSERT INTO sos_alerts 
       (user_id, ride_id, location) 
       VALUES ($1, $2, $3) 
       RETURNING *`,
      [req.user.id, rideId, `${latitude},${longitude}`]
    );
    
    // TODO: Implement emergency notification logic
    res.json(result.rows[0]);
  } catch (error) {
    res.status(500).json({ error: 'Failed to send SOS' });
  }
});

module.exports = router;