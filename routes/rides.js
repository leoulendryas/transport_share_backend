const express = require('express');
const { pool, query } = require('../config/database');
const { rideConnections } = require('../config/websocket');
const { authenticate, validateCoordinates, paginate, cache } = require('../middlewares');

const router = express.Router();

router.post('/', authenticate, validateCoordinates, async (req, res) => {
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const { from, to, seats, departure_time, from_address, to_address, companies } = req.body;

    const requiredFields = ['from', 'to', 'seats'];
    for (const field of requiredFields) {
      if (!req.body[field]) throw new Error(`Missing required field: ${field}`);
    }

    if (seats < 1 || seats > 8) {
      throw new Error('Seats must be between 1 and 8');
    }

    if (departure_time && new Date(departure_time) < new Date()) {
      throw new Error('Departure time must be in the future');
    }

    const rideResult = await client.query(
      `INSERT INTO rides 
       (driver_id, from_location, from_address, to_location, to_address, 
        total_seats, seats_available, departure_time)
       VALUES ($1, ST_SetSRID(ST_MakePoint($2, $3), 4326), $4, 
              ST_SetSRID(ST_MakePoint($5, $6), 4326), $7, $8, $9, $10)
       RETURNING *`,
      [
        req.user.id,
        from.lng, from.lat,
        from_address,
        to.lng, to.lat,
        to_address,
        seats + 1,
        seats,
        departure_time || null
      ]
    );

    for (const companyId of companies || []) {
      const companyCheck = await client.query(
        'SELECT id FROM ride_companies WHERE id = $1', 
        [companyId]
      );
      
      if (companyCheck.rowCount === 0) {
        throw new Error(`Company with ID ${companyId} does not exist`);
      }
    
      await client.query(
        'INSERT INTO ride_company_mapping (ride_id, company_id) VALUES ($1, $2)',
        [rideResult.rows[0].id, companyId]
      );
    }

    await client.query(
      'INSERT INTO user_rides (user_id, ride_id, is_driver) VALUES ($1, $2, true)',
      [req.user.id, rideResult.rows[0].id]
    );

    await client.query('COMMIT');
    res.status(201).json(rideResult.rows[0]);
  } catch (error) {
    await client.query('ROLLBACK');
    res.status(400).json({ error: error.message });
  } finally {
    client.release();
  }
});

router.get('/', paginate, async (req, res) => {
  const client = await pool.connect();
  try {
    const { from_lat, from_lng, to_lat, to_lng, radius = 5000, company_id } = req.query;
    const offset = (req.query.page - 1) * req.query.limit;

    if (!from_lat || !from_lng || !to_lat || !to_lng) {
      return res.status(400).json({ error: 'Missing required location parameters' });
    }

    const cacheKey = `rides_${from_lat}_${from_lng}_${to_lat}_${to_lng}_${radius}_${company_id || 'all'}_${req.query.page}_${req.query.limit}`;
    const cached = cache.get(cacheKey);
    if (cached) return res.json(cached);

    let queryText = `
      SELECT 
        r.*,
        u.email as driver_email,
        COUNT(ur.user_id) as participants,
        ST_X(r.from_location::geometry) as from_lng,
        ST_Y(r.from_location::geometry) as from_lat,
        ST_X(r.to_location::geometry) as to_lng,
        ST_Y(r.to_location::geometry) as to_lat,
        ARRAY_AGG(rc.company_id) as company_ids
      FROM rides r
      JOIN users u ON r.driver_id = u.id
      LEFT JOIN user_rides ur ON r.id = ur.ride_id
      LEFT JOIN ride_company_mapping rc ON r.id = rc.ride_id
      WHERE r.status = 'active'
        AND ST_DWithin(r.from_location::geography, ST_SetSRID(ST_MakePoint($1, $2), 4326)::geography, $3)
        AND ST_DWithin(r.to_location::geography, ST_SetSRID(ST_MakePoint($4, $5), 4326)::geography, $3)
    `;

    const params = [from_lng, from_lat, radius, to_lng, to_lat];

    if (company_id) {
      queryText += ` AND rc.company_id = $${params.length + 1}`;
      params.push(company_id);
    }

    queryText += `
      GROUP BY r.id, u.email
      ORDER BY r.departure_time ASC
      LIMIT $${params.length + 1} OFFSET $${params.length + 2}
    `;

    params.push(req.query.limit, offset);

    const result = await client.query(queryText, params);
    const countResult = await client.query(
      `SELECT COUNT(*) as total FROM rides r
       WHERE r.status = 'active'
         AND ST_DWithin(r.from_location::geography, ST_SetSRID(ST_MakePoint($1, $2), 4326)::geography, $3)
         AND ST_DWithin(r.to_location::geography, ST_SetSRID(ST_MakePoint($4, $5), 4326)::geography, $3)`,
      [from_lng, from_lat, radius, to_lng, to_lat]
    );

    const response = {
      results: result.rows,
      pagination: {
        page: req.query.page,
        limit: req.query.limit,
        total: parseInt(countResult.rows[0].total, 10)
      }
    };

    cache.set(cacheKey, response);
    res.json(response);
  } catch (error) {
    res.status(500).json({ error: 'Failed to fetch rides' });
  } finally {
    client.release();
  }
});

router.get('/:id', authenticate, async (req, res) => {
  const client = await pool.connect();
  try {
    const rideId = req.params.id;
    const userId = req.user.id;

    // Get ride details
    const rideResult = await client.query(
      `SELECT 
        r.*,
        u.email as driver_email,
        ST_X(r.from_location::geometry) as from_lng,
        ST_Y(r.from_location::geometry) as from_lat,
        ST_X(r.to_location::geometry) as to_lng,
        ST_Y(r.to_location::geometry) as to_lat,
        ARRAY_AGG(rc.company_id) as company_ids,
        EXISTS(SELECT 1 FROM user_rides WHERE ride_id = r.id AND user_id = $2) as is_participant,
        (r.driver_id = $2) as is_driver
      FROM rides r
      JOIN users u ON r.driver_id = u.id
      LEFT JOIN ride_company_mapping rc ON r.id = rc.ride_id
      WHERE r.id = $1
      GROUP BY r.id, u.email`,
      [rideId, userId]
    );

    if (rideResult.rows.length === 0) {
      return res.status(404).json({ error: 'Ride not found' });
    }

    // Get participants
    const participantsResult = await client.query(
      `SELECT 
        u.id, u.email, 
        (ur.user_id = r.driver_id) as is_driver
      FROM user_rides ur
      JOIN users u ON ur.user_id = u.id
      JOIN rides r ON ur.ride_id = r.id
      WHERE ur.ride_id = $1`,
      [rideId]
    );

    const response = {
      ...rideResult.rows[0],
      participants: participantsResult.rows,
      // Include participation status for current user
      current_user: {
        is_participant: rideResult.rows[0].is_participant,
        is_driver: rideResult.rows[0].is_driver
      }
    };

    res.json(response);
  } catch (error) {
    res.status(500).json({ error: 'Failed to fetch ride details' });
  } finally {
    client.release();
  }
});

router.get('/user/active-rides', authenticate, paginate, async (req, res) => {
  const client = await pool.connect();
  try {
    const userId = req.user.id;
    const offset = (req.query.page - 1) * req.query.limit;

    const queryText = `
      SELECT 
        r.*,
        u.email as driver_email,
        COUNT(ur.user_id) as participants,
        ST_X(r.from_location::geometry) as from_lng,
        ST_Y(r.from_location::geometry) as from_lat,
        ST_X(r.to_location::geometry) as to_lng,
        ST_Y(r.to_location::geometry) as to_lat,
        ARRAY_AGG(rc.company_id) as company_ids,
        MAX(CASE WHEN ur.user_id = $1 THEN ur.is_driver ELSE false END) as is_driver
      FROM rides r
      JOIN users u ON r.driver_id = u.id
      LEFT JOIN user_rides ur ON r.id = ur.ride_id
      LEFT JOIN ride_company_mapping rc ON r.id = rc.ride_id
      WHERE r.id IN (
        SELECT ride_id FROM user_rides WHERE user_id = $1
      )
        AND r.status = 'active'
        AND (r.departure_time IS NULL OR r.departure_time > NOW())
      GROUP BY r.id, u.email
      ORDER BY r.departure_time ASC
      LIMIT $2 OFFSET $3
    `;

    const result = await client.query(queryText, [userId, req.query.limit, offset]);

    const countResult = await client.query(
      `SELECT COUNT(DISTINCT r.id) as total 
       FROM rides r
       JOIN user_rides ur ON r.id = ur.ride_id
       WHERE ur.user_id = $1
         AND r.status = 'active'
         AND (r.departure_time IS NULL OR r.departure_time > NOW())`,
      [userId]
    );

    const response = {
      results: result.rows,
      pagination: {
        page: req.query.page,
        limit: req.query.limit,
        total: parseInt(countResult.rows[0].total, 10)
      }
    };

    res.json(response);
  } catch (error) {
    res.status(500).json({ error: 'Failed to fetch user rides' });
  } finally {
    client.release();
  }
});

router.get('/:id/check-participation', authenticate, async (req, res) => {
  try {
    const rideId = req.params.id;
    const userId = req.user.id;

    const result = await query(
      `SELECT 
        EXISTS(SELECT 1 FROM user_rides WHERE ride_id = $1 AND user_id = $2) as is_participant,
        EXISTS(SELECT 1 FROM rides WHERE id = $1 AND driver_id = $2) as is_driver
      `,
      [rideId, userId]
    );

    res.json({
      isParticipant: result.rows[0].is_participant,
      isDriver: result.rows[0].is_driver
    });
  } catch (error) {
    res.status(500).json({ error: 'Failed to check participation' });
  }
});

router.post('/:id/join', authenticate, async (req, res) => {
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const rideId = req.params.id;
    const userId = req.user.id;

    // Check if user already joined
    const existingCheck = await client.query(
      'SELECT 1 FROM user_rides WHERE user_id = $1 AND ride_id = $2',
      [userId, rideId]
    );
    
    if (existingCheck.rows.length > 0) {
      throw new Error('User already joined this ride');
    }

    // Get ride details with existence check
    const ride = await client.query(
      `SELECT status, seats_available, departure_time 
       FROM rides WHERE id = $1 FOR UPDATE`,
      [rideId]
    );

    if (ride.rows.length === 0) {
      throw new Error('Ride not found');
    }

    const rideData = ride.rows[0];

    // Validate ride conditions
    if (rideData.departure_time && new Date(rideData.departure_time) < new Date()) {
      throw new Error('Cannot join a ride that has already departed');
    }

    if (rideData.status !== 'active') {
      throw new Error('Ride is not active');
    }

    if (rideData.seats_available < 1) {
      throw new Error('Ride is full');
    }

    // Update seats
    await client.query(
      'UPDATE rides SET seats_available = seats_available - 1 WHERE id = $1',
      [rideId]
    );

    // Create user-ride association
    await client.query(
      'INSERT INTO user_rides (user_id, ride_id) VALUES ($1, $2)',
      [userId, rideId]
    );

    // Mark as full if no seats left
    if (rideData.seats_available - 1 === 0) {
      await client.query(
        'UPDATE rides SET status = \'full\' WHERE id = $1',
        [rideId]
      );
    }

    await client.query('COMMIT');
    
    // Notify WebSocket clients
    const clients = rideConnections.get(rideId);
    if (clients) {
      clients.forEach(client => {
        if (client.readyState === WebSocket.OPEN) {
          client.send(JSON.stringify({
            type: 'participant_joined',
            user_id: userId,
            ride_id: rideId,
            timestamp: new Date().toISOString()
          }));
        }
      });
    }

    res.json({ message: 'Successfully joined ride' });
  } catch (error) {
    await client.query('ROLLBACK');
    res.status(400).json({ error: error.message });
  } finally {
    client.release();
  }
});

router.post('/:id/leave', authenticate, async (req, res) => {
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const rideId = req.params.id;
    const userId = req.user.id;

    const userRideCheck = await client.query(
      `SELECT is_driver FROM user_rides 
       WHERE user_id = $1 AND ride_id = $2`,
      [userId, rideId]
    );

    if (userRideCheck.rows.length === 0) {
      throw new Error('User is not part of this ride');
    }

    if (userRideCheck.rows[0].is_driver) {
      throw new Error('Drivers cannot leave their own ride. Use cancel instead.');
    }

    await client.query(
      'DELETE FROM user_rides WHERE user_id = $1 AND ride_id = $2',
      [userId, rideId]
    );

    await client.query(
      'UPDATE rides SET seats_available = seats_available + 1 WHERE id = $1',
      [rideId]
    );

    await client.query(
      `UPDATE rides SET status = 'active' 
       WHERE id = $1 AND status = 'full' AND seats_available > 0`,
      [rideId]
    );

    await client.query('COMMIT');
    
    const clients = rideConnections.get(rideId);
    if (clients) {
      clients.forEach(client => {
        if (client.readyState === WebSocket.OPEN) {
          client.send(JSON.stringify({
            type: 'participant_left',
            user_id: userId,
            ride_id: rideId,
            timestamp: new Date().toISOString()
          }));
        }
      });
    }

    res.json({ message: 'Successfully left the ride' });
  } catch (error) {
    await client.query('ROLLBACK');
    res.status(400).json({ error: error.message });
  } finally {
    client.release();
  }
});

router.post('/:id/cancel', authenticate, async (req, res) => {
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const rideId = req.params.id;
    
    const rideCheck = await client.query(
      `SELECT 1 FROM rides 
       WHERE id = $1 AND driver_id = $2`,
      [rideId, req.user.id]
    );
    
    if (rideCheck.rows.length === 0) {
      throw new Error('Only the driver can cancel this ride');
    }
    
    await client.query(
      `UPDATE rides SET status = 'cancelled' 
       WHERE id = $1 RETURNING *`,
      [rideId]
    );
    
    const participants = await client.query(
      `SELECT user_id FROM user_rides 
       WHERE ride_id = $1 AND user_id != $2`,
      [rideId, req.user.id]
    );
    
    await client.query('COMMIT');
    
    const clients = rideConnections.get(rideId);
    if (clients) {
      clients.forEach(client => {
        if (client.readyState === WebSocket.OPEN) {
          client.send(JSON.stringify({
            type: 'ride_cancelled',
            ride_id: rideId,
            timestamp: new Date().toISOString()
          }));
        }
      });
    }
    
    res.json({ message: 'Ride cancelled successfully' });
  } catch (error) {
    await client.query('ROLLBACK');
    res.status(400).json({ error: error.message });
  } finally {
    client.release();
  }
});

module.exports = router;