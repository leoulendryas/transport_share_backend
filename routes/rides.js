const express = require('express');
const { pool, query } = require('../config/database');
const { rideConnections } = require('../config/websocket');
const { authenticate, validateCoordinates, validateCoordinatesForPrice, paginate, cache } = require('../middlewares');
const cron = require('node-cron');
const axios = require('axios');
const WebSocket = require('ws');

const router = express.Router();

async function getRouteDistanceAndDuration({ from, to }) {
  try {
    if (
      !from || !to ||
      typeof from.lat !== 'number' || typeof from.lng !== 'number' ||
      typeof to.lat !== 'number' || typeof to.lng !== 'number'
    ) {
      throw new Error('Invalid coordinate format. Expected {lat: number, lng: number}');
    }

    const apiKey = process.env.GEBETA_API_KEY;
    if (!apiKey) throw new Error('Gebeta Maps API key not configured');

    const url = new URL('https://mapapi.gebeta.app/api/route/direction/');
    url.searchParams.append('origin', `${from.lat},${from.lng}`);
    url.searchParams.append('destination', `${to.lat},${to.lng}`);
    url.searchParams.append('apiKey', apiKey);
    url.searchParams.append('instruction', '0');

    const response = await axios.get(url.toString(), {
      timeout: 5000,
      headers: { 'Accept': 'application/json' },
      validateStatus: (status) => status < 500
    });

    // Log the actual response for debugging
    console.log('Gebeta API Response:', JSON.stringify(response.data, null, 2));

    // Handle Gebeta-specific error responses
    if (response.data?.status_code && response.data.status_code !== 200) {
      const errorCode = response.data.status_code;
      const errorMessages = {
        404: 'No route found between locations',
        401: 'Invalid or expired API key',
        422: 'Invalid input parameters'
      };
      throw new Error(errorMessages[errorCode] || `Routing failed (${errorCode})`);
    }

    // Extract distance and duration from the actual response structure
    const totalDistance = response.data.totalDistance;
    const timeTaken = response.data.timetaken;

    // Validate the values
    if (typeof totalDistance !== 'number' || typeof timeTaken !== 'number') {
      throw new Error('Invalid route data in response');
    }

    return {
      distance: totalDistance,  // in meters
      duration: timeTaken       // in seconds
    };

  } catch (error) {
    console.error('Gebeta Maps Error:', error.message);
    
    // Enhanced error details
    let errorMessage = error.message;
    if (error.response) {
      errorMessage += ` | Status: ${error.response.status}`;
      if (error.response.data) {
        errorMessage += ` | Data: ${JSON.stringify(error.response.data)}`;
      }
    }
    
    throw new Error(`Routing failed: ${errorMessage}`);
  }
}

function isValidEthiopianLocation({ lat, lng }) {
  const latMin = 3.4;
  const latMax = 14.9;
  const lngMin = 32.9;
  const lngMax = 48.0;

  return lat >= latMin && lat <= latMax && lng >= lngMin && lng <= lngMax;
}

// Enhanced price calculation with real-world factors
function calculatePriceRange(distanceMeters, durationSeconds, seats) {
  const BASE_RATE = 19.5; // ETB per km
  const TIME_RATE = 3; // ETB per minute
  const FUEL_PRICE = 122.53; // ETB per liter
  const FUEL_EFFICIENCY = 12.3; // km per liter
  const SERVICE_FEE_RATE = 0.15;
  const SEAT_UTILIZATION_FACTOR = 0.7;
  
  const distanceKm = distanceMeters / 1000;
  const durationMinutes = durationSeconds / 60;
  
  // Base calculation
  const distanceCost = distanceKm * BASE_RATE;
  const timeCost = durationMinutes * TIME_RATE;
  
  // Fuel cost calculation
  const fuelCost = (distanceKm / FUEL_EFFICIENCY) * FUEL_PRICE;
  
  // Total cost components
  const operationalCost = fuelCost + (distanceCost * 0.3);
  const serviceFee = (distanceCost + timeCost) * SERVICE_FEE_RATE;
  
  // Per-seat pricing
  const basePricePerSeat = (distanceCost + timeCost + operationalCost + serviceFee) / 
                          (seats * SEAT_UTILIZATION_FACTOR);
  
  // Dynamic pricing range
  return {
    minPrice: basePricePerSeat * 0.85,
    maxPrice: basePricePerSeat * 1.25,
    basePricePerSeat
  };
}

// Route handler with improved validation
router.post('/calculate-price', authenticate, validateCoordinatesForPrice, async (req, res) => {
  try {
    const { from, to, seats = 1 } = req.body;

    // Validate seats
    if (!Number.isInteger(seats) || seats < 1 || seats > 8) {
      return res.status(400).json({ error: 'Invalid seat count (1-8)' });
    }

    // Enhanced location validation
    if (!isValidEthiopianLocation(from) || !isValidEthiopianLocation(to)) {
      return res.status(400).json({ error: 'Both locations must be within Ethiopia' });
    }

    // Get route data
    const { distance, duration } = await getRouteDistanceAndDuration({ from, to });

    // Validate route metrics
    if (distance < 100 || duration < 10) {
      return res.status(400).json({ error: 'Route too short for pricing' });
    }

    // Calculate pricing
    const { minPrice, maxPrice, basePricePerSeat } = calculatePriceRange(
      distance, 
      duration, 
      seats
    );

    // Format response
    res.json({
      min_price: minPrice.toFixed(2),
      max_price: maxPrice.toFixed(2),
      base_price: basePricePerSeat.toFixed(2),
      distance: (distance / 1000).toFixed(1),
      duration: Math.ceil(duration / 60)
    });

  } catch (error) {
    console.error(`Pricing Error: ${error.message}`);
    res.status(400).json({ error: error.message });
  }
});

async function cancelRide(rideId) {
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    
    const rideCheck = await client.query(
      `SELECT id FROM rides WHERE id = $1 AND status = 'active' FOR UPDATE`,
      [rideId]
    );
    
    if (rideCheck.rowCount === 0) throw new Error('Ride not found or not active');
    
    // Cancel the ride
    await client.query(
      `UPDATE rides SET status = 'cancelled' WHERE id = $1`,
      [rideId]
    );

    // Delete all associated messages
    await client.query(
      `DELETE FROM messages WHERE ride_id = $1`,
      [rideId]
    );

    await client.query('COMMIT');
    
    // Notify WebSocket clients
    const clients = rideConnections.get(rideId);
    if (clients) {
      clients.forEach(wsClient => {
        if (wsClient.readyState === WebSocket.OPEN) {
          wsClient.send(JSON.stringify({
            type: 'ride_cancelled',
            ride_id: rideId,
            timestamp: new Date().toISOString()
          }));
          // Notify about message clearance
          wsClient.send(JSON.stringify({
            type: 'messages_cleared',
            ride_id: rideId,
            timestamp: new Date().toISOString()
          }));
        }
      });
    }
    
    return true;
  } catch (error) {
    await client.query('ROLLBACK');
    console.error(`Failed to cancel ride ${rideId}:`, error);
    return false;
  } finally {
    client.release();
  }
}

cron.schedule('0 * * * *', async () => {
  const client = await pool.connect();
  try {
    console.log('Checking for rides to cancel automatically...');
    
    const { rows } = await client.query(
      `SELECT id FROM rides 
       WHERE status = 'active' 
       AND created_at < NOW() - INTERVAL '24 HOURS'`
    );
    
    console.log(`Found ${rows.length} rides to cancel.`);
    
    for (const ride of rows) {
      await cancelRide(ride.id);
    }
  } catch (error) {
    console.error('Error during automatic ride cancellation:', error);
  } finally {
    client.release();
  }
});

router.post('/', authenticate, validateCoordinates, async (req, res) => {
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const {
      from, to, seats, departure_time, price_per_seat,
      from_address, to_address, companies,
      plate_number, color, brand_name
    } = req.body;

    const requiredFields = ['from', 'to', 'seats', 'plate_number', 'color', 'brand_name', 'price_per_seat'];
    for (const field of requiredFields) {
      if (!req.body[field]) throw new Error(`Missing required field: ${field}`);
    }

    if (seats < 1 || seats > 8) {
      throw new Error('Seats must be between 1 and 8');
    }

    if (departure_time && new Date(departure_time) < new Date()) {
      throw new Error('Departure time must be in the future');
    }

    const { distance, duration } = await getRouteDistanceAndDuration({ from, to });
    const { minPrice, maxPrice } = calculatePriceRange(distance, duration, seats);
    if (price_per_seat < minPrice || price_per_seat > maxPrice) {
      throw new Error(`Price must be between $${minPrice.toFixed(2)} and $${maxPrice.toFixed(2)}`);
    }

    const rideResult = await client.query(
      `INSERT INTO rides 
       (driver_id, from_location, from_address, to_location, to_address, 
        total_seats, seats_available, departure_time, created_at,
        plate_number, color, brand_name, price_per_seat)
       VALUES ($1, ST_SetSRID(ST_MakePoint($2, $3), 4326), $4, 
               ST_SetSRID(ST_MakePoint($5, $6), 4326), $7, 
               $8, $9, $10, NOW(), $11, $12, $13, $14)
       RETURNING *`,
      [
        req.user.id,
        from.lng, from.lat,
        from_address,
        to.lng, to.lat,
        to_address,
        seats + 1,
        seats,
        departure_time || null,
        plate_number,
        color,
        brand_name,
        price_per_seat
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
        r.id,
        r.driver_id,
        r.price_per_seat,
        r.from_location,
        r.from_address,
        r.to_location,
        r.to_address,
        r.total_seats,
        r.seats_available,
        r.departure_time,
        r.status,
        r.created_at,
        r.plate_number,
        r.color,
        r.brand_name,
        u.email as driver_email,
        (
          SELECT json_agg(data) FROM (
            SELECT json_build_object(
              'id', u2.id,
              'email', u2.email,
              'first_name', u2.first_name,
              'last_name', u2.last_name,
              'phone_number', u2.phone_number,
              'age', u2.age,
              'gender', u2.gender,
              'created_at', u2.created_at,
              'profile_image_url', u2.profile_image_url,
              'is_driver', ur.is_driver
            ) as data
            FROM user_rides ur
            JOIN users u2 ON ur.user_id = u2.id
            WHERE ur.ride_id = r.id
          ) as participant_data
        ) as participants,
        ST_X(r.from_location::geometry) as from_lng,
        ST_Y(r.from_location::geometry) as from_lat,
        ST_X(r.to_location::geometry) as to_lng,
        ST_Y(r.to_location::geometry) as to_lat,
        ARRAY_AGG(rc.company_id) as company_ids
      FROM rides r
      JOIN users u ON r.driver_id = u.id
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

    const parsedRides = result.rows.map(ride => ({
      ...ride,
      // Override from_lat/from_lng and to_lat/to_lng with parsed values to ensure consistency
      from_lat: parseLocation(ride.from_location)?.lat,
      from_lng: parseLocation(ride.from_location)?.lng,
      to_lat: parseLocation(ride.to_location)?.lat,
      to_lng: parseLocation(ride.to_location)?.lng,
      participants: (ride.participants || []).filter(p => p && p.id) // Filter nulls & invalids
    }));

    const countParams = [from_lng, from_lat, radius, to_lng, to_lat];
    let countQuery = `
      SELECT COUNT(*) as total 
      FROM rides r
      WHERE r.status = 'active'
        AND ST_DWithin(r.from_location::geography, ST_SetSRID(ST_MakePoint($1, $2), 4326)::geography, $3)
        AND ST_DWithin(r.to_location::geography, ST_SetSRID(ST_MakePoint($4, $5), 4326)::geography, $3)
    `;

    if (company_id) {
      countQuery += ` AND EXISTS (
        SELECT 1 FROM ride_company_mapping rc WHERE rc.ride_id = r.id AND rc.company_id = $6
      )`;
      countParams.push(company_id);
    }

    const countResult = await client.query(countQuery, countParams);

    const response = {
      results: parsedRides,
      pagination: {
        page: parseInt(req.query.page, 10),
        limit: parseInt(req.query.limit, 10),
        total: parseInt(countResult.rows[0].total, 10)
      }
    };

    cache.set(cacheKey, response);
    res.json(response);

  } catch (error) {
    console.error('Error fetching rides:', error);
    res.status(500).json({ error: 'Failed to fetch rides', details: error.message });
  } finally {
    client.release();
  }
});

router.get('/:id', authenticate, async (req, res) => {
  const client = await pool.connect();
  try {
    const rideId = req.params.id;
    const userId = req.user.id;

    const rideResult = await client.query(
      `SELECT 
        r.*,
        (
          SELECT json_agg(
            json_build_object(
              'id', u.id,
              'email', u.email,
              'first_name', u.first_name,
              'last_name', u.last_name,
              'phone_number', u.phone_number,
              'age', u.age,
              'gender', u.gender,
              'created_at', u.created_at,
              'profile_image_url', u.profile_image_url,
              'is_driver', ur.is_driver
            )
          )
          FROM user_rides ur
          JOIN users u ON ur.user_id = u.id
          WHERE ur.ride_id = r.id
        ) as participants,
        EXISTS(SELECT 1 FROM user_rides WHERE ride_id = r.id AND user_id = $2) as is_participant,
        (r.driver_id = $2) as is_driver
      FROM rides r
      WHERE r.id = $1`,
      [rideId, userId]
    );

    if (rideResult.rows.length === 0) {
      return res.status(404).json({ error: 'Ride not found' });
    }

    const rideData = rideResult.rows[0];

    const fromLocation = parseLocation(rideData.from_location);
    const toLocation = parseLocation(rideData.to_location);

    const response = {
      ...rideData,
      participants: rideData.participants?.filter(p => p.id !== null) || [],
      from_lat: fromLocation?.lat,
      from_lng: fromLocation?.lng,
      to_lat: toLocation?.lat,
      to_lng: toLocation?.lng,
      current_user: {
        is_participant: rideData.is_participant,
        is_driver: rideData.is_driver
      }
    };

    res.json(response);
  } catch (error) {
    console.error('Error fetching ride details:', error);
    res.status(500).json({ error: 'Failed to fetch ride details' });
  } finally {
    client.release();
  }
});

// Add this helper function
function parseLocation(location) {
  if (!location) return null;
  try {
    const matches = location.match(/[-+]?[0-9]*\.?[0-9]+/g);
    if (matches && matches.length >= 2) {
      return { lng: parseFloat(matches[0]), lat: parseFloat(matches[1]) };
    }
    return null;
  } catch (e) {
    console.error('Error parsing location:', e);
    return null;
  }
}

router.get('/user/active-rides', authenticate, paginate, async (req, res) => {
  const client = await pool.connect();
  try {
    const userId = req.user.id;
    const offset = (req.query.page - 1) * req.query.limit;

    const queryText = `
      SELECT DISTINCT ON (r.id)
        r.id,
        r.driver_id,
        r.price_per_seat,
        r.from_location,
        r.from_address,
        r.to_location,
        r.to_address,
        r.total_seats,
        r.seats_available,
        r.departure_time,
        r.status,
        r.created_at,
        r.plate_number,
        r.color,
        r.brand_name,
        u.email as driver_email,
        (
          SELECT json_agg(
            json_build_object(
              'id', u2.id,
              'email', u2.email,
              'first_name', u2.first_name,
              'last_name', u2.last_name,
              'phone_number', u2.phone_number,
              'age', u2.age,
              'gender', u2.gender,
              'created_at', u2.created_at,
              'profile_image_url', u2.profile_image_url,
              'is_driver', ur.is_driver
            )
          )
          FROM user_rides ur
          JOIN users u2 ON ur.user_id = u2.id
          WHERE ur.ride_id = r.id
        ) as participants,
        ST_X(r.from_location::geometry) as from_lng,
        ST_Y(r.from_location::geometry) as from_lat,
        ST_X(r.to_location::geometry) as to_lng,
        ST_Y(r.to_location::geometry) as to_lat,
        (SELECT ARRAY_AGG(company_id) FROM ride_company_mapping WHERE ride_id = r.id) as company_ids,
        (SELECT is_driver FROM user_rides WHERE user_id = $1 AND ride_id = r.id) as is_driver
      FROM rides r
      JOIN users u ON r.driver_id = u.id
      JOIN user_rides ur ON r.id = ur.ride_id
      WHERE ur.user_id = $1
        AND r.status IN ('active', 'full')
        AND (r.departure_time IS NULL OR r.departure_time > NOW())
      ORDER BY r.id, r.departure_time ASC
      LIMIT $2 OFFSET $3
    `;

    const result = await client.query(queryText, [userId, req.query.limit, offset]);

    const parsedRides = result.rows.map(ride => ({
      ...ride,
      from_lat: parseLocation(ride.from_location)?.lat,
      from_lng: parseLocation(ride.from_location)?.lng,
      to_lat: parseLocation(ride.to_location)?.lat,
      to_lng: parseLocation(ride.to_location)?.lng,
      participants: ride.participants || []
    }));

    const countResult = await client.query(
      `SELECT COUNT(DISTINCT r.id) as total 
       FROM rides r
       JOIN user_rides ur ON r.id = ur.ride_id
       WHERE ur.user_id = $1
         AND r.status IN ('active', 'full')
         AND (r.departure_time IS NULL OR r.departure_time > NOW())`,
      [userId]
    );

    const response = {
      results: parsedRides,
      pagination: {
        page: req.query.page,
        limit: req.query.limit,
        total: parseInt(countResult.rows[0].total, 10)
      }
    };

    res.json(response);
  } catch (error) {
    console.error('Error in /user/active-rides:', error);
    res.status(500).json({ error: 'Failed to fetch user rides', details: error.message });
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
      return res.status(403).json({ error: 'Only the driver can cancel this ride' });
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

    const success = await cancelRide(rideId);
    if (!success) throw new Error('Failed to cancel ride');
    
    res.json({ message: 'Ride cancelled successfully' });
  } catch (error) {
    await client.query('ROLLBACK');
    res.status(400).json({ error: error.message });
  } finally {
    client.release();
  }
});

router.post('/:id/remove-user', authenticate, async (req, res) => {
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const rideId = req.params.id;
    const userIdToRemove = req.body.userId;
    const driverId = req.user.id;

    // Verify ride exists and requester is driver
    const rideCheck = await client.query(
      'SELECT driver_id, status FROM rides WHERE id = $1',
      [rideId]
    );
    if (rideCheck.rows.length === 0) {
      return res.status(404).json({ error: 'Ride not found' });
    }
    if (rideCheck.rows[0].driver_id !== driverId) {
      return res.status(403).json({ error: 'Only the driver can remove users' });
    }

    // Prevent modifying completed/cancelled rides
    if (['completed', 'cancelled'].includes(rideCheck.rows[0].status)) {
      return res.status(400).json({ error: 'Cannot modify completed/cancelled ride' });
    }

    // Verify user exists in ride and is not driver
    const userCheck = await client.query(
      `SELECT 1 FROM user_rides 
       WHERE ride_id = $1 AND user_id = $2 AND is_driver = false`,
      [rideId, userIdToRemove]
    );
    if (userCheck.rows.length === 0) {
      return res.status(404).json({ error: 'User not found in ride or is driver' });
    }

    // Remove user from ride
    await client.query(
      'DELETE FROM user_rides WHERE ride_id = $1 AND user_id = $2',
      [rideId, userIdToRemove]
    );

    // Update available seats
    await client.query(
      'UPDATE rides SET seats_available = seats_available + 1 WHERE id = $1',
      [rideId]
    );

    // Re-activate ride if it was full
    await client.query(
      `UPDATE rides SET status = 'active' 
       WHERE id = $1 AND status = 'full'`,
      [rideId]
    );

    await client.query('COMMIT');

    // Notify participants via WebSocket
    const clients = rideConnections.get(rideId);
    if (clients) {
      clients.forEach(client => {
        if (client.readyState === WebSocket.OPEN) {
          client.send(JSON.stringify({
            type: 'user_removed',
            ride_id: rideId,
            user_id: userIdToRemove,
            timestamp: new Date().toISOString()
          }));
        }
      });
    }

    res.json({ message: 'User removed successfully' });
  } catch (error) {
    await client.query('ROLLBACK');
    res.status(500).json({ error: error.message });
  } finally {
    client.release();
  }
});

// Endpoint to update ride status (ongoing/completed)
router.put('/:id/status', authenticate, async (req, res) => {
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const rideId = req.params.id;
    const { status } = req.body;
    const userId = req.user.id;

    // Validate new status
    if (!['ongoing', 'completed'].includes(status)) {
      return res.status(400).json({ error: 'Invalid status' });
    }

    // Verify user is part of the ride
    const participantCheck = await client.query(
      `SELECT 1 FROM user_rides WHERE ride_id = $1 AND user_id = $2`,
      [rideId, userId]
    );
    if (participantCheck.rows.length === 0) {
      return res.status(403).json({ error: 'User not part of this ride' });
    }

    // Get current ride status with lock
    const rideResult = await client.query(
      'SELECT status, driver_id FROM rides WHERE id = $1 FOR UPDATE',
      [rideId]
    );
    if (rideResult.rows.length === 0) {
      return res.status(404).json({ error: 'Ride not found' });
    }

    const currentStatus = rideResult.rows[0].status;
    const isDriver = rideResult.rows[0].driver_id === userId;

    // Validate status transitions
    if (status === 'ongoing') {
      if (!isDriver) {
        return res.status(403).json({ error: 'Only driver can start the ride' });
      }
      if (!['active', 'full'].includes(currentStatus)) {
        return res.status(400).json({ error: 'Ride must be active/full to start' });
      }
    } else if (status === 'completed') {
      if (currentStatus !== 'ongoing') {
        return res.status(400).json({ error: 'Ride must be ongoing to complete' });
      }
    }

    // Update ride status
    await client.query(
      'UPDATE rides SET status = $1 WHERE id = $2',
      [status, rideId]
    );

    await client.query('COMMIT');

    // Notify participants via WebSocket
    const clients = rideConnections.get(rideId);
    if (clients) {
      clients.forEach(client => {
        if (client.readyState === WebSocket.OPEN) {
          client.send(JSON.stringify({
            type: 'status_update',
            ride_id: rideId,
            new_status: status,
            timestamp: new Date().toISOString()
          }));
        }
      });
    }

    res.json({ message: 'Ride status updated successfully' });
  } catch (error) {
    await client.query('ROLLBACK');
    res.status(500).json({ error: error.message });
  } finally {
    client.release();
  }
});

module.exports = router;