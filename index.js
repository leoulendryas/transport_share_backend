const express = require('express');
const bodyParser = require('body-parser');
const cors = require('cors');
const { Pool } = require('pg');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const WebSocket = require('ws');
const http = require('http');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
require('dotenv').config();

const app = express();
app.use(helmet());
app.use(cors());
app.use(bodyParser.json());

const server = http.createServer(app);
const wss = new WebSocket.Server({ server, path: '/ws' });

// Database pool
const pool = new Pool({
  user: process.env.DB_USER,
  host: process.env.DB_HOST,
  database: process.env.DB_NAME,
  password: process.env.DB_PASSWORD,
  port: process.env.DB_PORT,
  ssl: process.env.DB_SSL ? { rejectUnauthorized: false } : false
});

// Rate limiting
const apiLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
  message: 'Too many requests, please try again later.'
});

// WebSocket connections map
const rideConnections = new Map();

// Auth middleware
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

// WebSocket authentication
wss.on('connection', async (ws, req) => {
  try {
    // Extract token and rideId from the WebSocket URL
    const token = new URL(req.url, `ws://${req.headers.host}`).searchParams.get('token');
    const rideId = new URL(req.url, `ws://${req.headers.host}`).searchParams.get('rideId');
    
    console.log(`New WebSocket connection: rideId=${rideId}, token=${token}`);

    // Verify the JWT token
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    const userCheck = await pool.query('SELECT id FROM users WHERE id = $1', [decoded.id]);
    if (!userCheck.rows[0]) throw new Error('Invalid user');
    
    // Check if the user has access to the ride
    const rideAccess = await pool.query(
      'SELECT 1 FROM user_rides WHERE user_id = $1 AND ride_id = $2',
      [decoded.id, rideId]
    );
    if (!rideAccess.rows[0]) throw new Error('Access denied');

    // Add the WebSocket connection to the ride's connection pool
    if (!rideConnections.has(rideId)) {
      rideConnections.set(rideId, new Set());
    }
    const clients = rideConnections.get(rideId);
    clients.add(ws);

    console.log(`User ${decoded.id} connected to ride ${rideId}`);

    // Handle incoming messages
    ws.on('message', async (message) => {
      try {
        const { content } = JSON.parse(message);
        console.log(`Received message from user ${decoded.id}: ${content}`);

        // Insert the message into the database
        const result = await pool.query(
          'INSERT INTO messages (ride_id, user_id, content) VALUES ($1, $2, $3) RETURNING *',
          [rideId, decoded.id, content]
        );

        // Broadcast the message to all connected clients
        clients.forEach(client => {
          if (client.readyState === WebSocket.OPEN) {
            client.send(JSON.stringify({
              id: result.rows[0].id,
              user_id: decoded.id,
              content,
              created_at: result.rows[0].created_at
            }));
          }
        });
      } catch (error) {
        console.error('WebSocket error:', error);
      }
    });

    // Handle WebSocket connection close
    ws.on('close', () => {
      console.log(`User ${decoded.id} disconnected from ride ${rideId}`);
      clients.delete(ws);
      if (clients.size === 0) {
        rideConnections.delete(rideId);
      }
    });

  } catch (error) {
    console.error('WebSocket connection error:', error);
    ws.close(1008, error.message);
  }
});

// Routes
app.post('/register', apiLimiter, async (req, res) => {
  try {
    const { email, password } = req.body;

    // Validate required fields
    if (!email || !password) {
      return res.status(400).json({ error: 'Email and password are required' });
    }

    const hashedPassword = await bcrypt.hash(password, 12); // Ensure password and salt rounds are provided

    const result = await pool.query(
      'INSERT INTO users (email, password_hash) VALUES ($1, $2) RETURNING id, email',
      [email, hashedPassword],
    );

    const token = jwt.sign({ id: result.rows[0].id }, process.env.JWT_SECRET, {
      expiresIn: '1h',
    });

    res.status(201).json({ user: result.rows[0], token });
  } catch (error) {
    console.error('Registration error:', error);
    res.status(400).json({ error: 'Registration failed' });
  }
});

app.post('/login', apiLimiter, async (req, res) => {
  try {
    const { email, password } = req.body;
    const user = await pool.query('SELECT * FROM users WHERE email = $1', [email]);

    if (!user.rows[0] || !(await bcrypt.compare(password, user.rows[0].password_hash))) {
      console.error('Invalid credentials for email:', email);
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    const token = jwt.sign({ id: user.rows[0].id }, process.env.JWT_SECRET, {
      expiresIn: '1h',
    });

    res.json({ user: user.rows[0], token });
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ error: 'Login failed' });
  }
});

// Ride endpoints
app.post('/rides', authenticate, async (req, res) => {
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const { from, to, seats, departure_time, from_address, to_address, companies } = req.body;

    const rideResult = await client.query(
      `INSERT INTO rides 
      (driver_id, from_location, from_address, to_location, to_address, 
       total_seats, seats_available, departure_time)
      VALUES ($1, ST_Point($2, $3), $4, ST_Point($5, $6), $7, $8, $9, $10)
      RETURNING *`,
      [
        req.user.id,
        from.lng, from.lat,
        from_address,
        to.lng, to.lat,
        to_address,
        seats + 1,
        seats,
        departure_time
      ]
    );

    // Insert ride-sharing companies
    for (const companyId of companies) {
      await client.query(
        'INSERT INTO ride_companies (ride_id, company_id) VALUES ($1, $2)',
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

app.post('/rides/:id/join', authenticate, async (req, res) => {
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const rideId = req.params.id;
    const userId = req.user.id;

    // Fetch the ride and lock the row for update
    const ride = await client.query(
      'SELECT * FROM rides WHERE id = $1 FOR UPDATE',
      [rideId]
    );

    // Check if the ride is active and has available seats
    if (ride.rows[0].status !== 'active') {
      throw new Error('Ride is not active');
    }
    if (ride.rows[0].seats_available < 1) {
      throw new Error('Ride is full');
    }

    // Decrease the available seats
    await client.query(
      'UPDATE rides SET seats_available = seats_available - 1 WHERE id = $1',
      [rideId]
    );

    // Add the user to the ride
    await client.query(
      'INSERT INTO user_rides (user_id, ride_id) VALUES ($1, $2)',
      [userId, rideId]
    );

    // Update the ride status to "full" if no seats are left
    if (ride.rows[0].seats_available - 1 === 0) {
      await client.query(
        'UPDATE rides SET status = \'full\' WHERE id = $1',
        [rideId]
      );
    }

    await client.query('COMMIT');
    res.json({ message: 'Successfully joined ride' });
  } catch (error) {
    await client.query('ROLLBACK');
    res.status(400).json({ error: error.message });
  } finally {
    client.release();
  }
});

app.post('/rides', authenticate, async (req, res) => {
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const { from, to, seats, departure_time, from_address, to_address, companies } = req.body;

    // Insert the ride
    const rideResult = await client.query(
      `INSERT INTO rides 
      (driver_id, from_location, from_address, to_location, to_address, 
       total_seats, seats_available, departure_time)
      VALUES ($1, ST_SetSRID(ST_MakePoint($2, $3), 4326), $4, ST_SetSRID(ST_MakePoint($5, $6), 4326), $7, $8, $9, $10)
      RETURNING *`,
      [
        req.user.id,
        from.lng, from.lat,
        from_address,
        to.lng, to.lat,
        to_address,
        seats + 1,
        seats,
        departure_time
      ]
    );

    // Insert ride-sharing companies
    for (const companyId of companies) {
      await client.query(
        'INSERT INTO ride_companies_junction (ride_id, company_id) VALUES ($1, $2)',
        [rideResult.rows[0].id, companyId]
      );
    }

    // Add the driver to the ride
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

app.get('/rides', async (req, res) => {
  const client = await pool.connect();
  try {
    const { from_lat, from_lng, to_lat, to_lng, radius = 5000, page = 1, limit = 20, company_id } = req.query;
    const offset = (page - 1) * limit;

    if (!from_lat || !from_lng || !to_lat || !to_lng) {
      return res.status(400).json({ error: 'Missing required location parameters' });
    }

    let query = `
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
      LEFT JOIN ride_companies_junction rc ON r.id = rc.ride_id
      WHERE r.status = 'active'
        AND ST_DWithin(r.from_location::geography, ST_SetSRID(ST_MakePoint($1, $2), 4326)::geography, $3)
        AND ST_DWithin(r.to_location::geography, ST_SetSRID(ST_MakePoint($4, $5), 4326)::geography, $3)
    `;

    const values = [
      parseFloat(from_lng), parseFloat(from_lat),
      parseInt(radius, 10),
      parseFloat(to_lng), parseFloat(to_lat),
      parseInt(limit, 10), parseInt(offset, 10)
    ];

    // Add company filter if provided
    if (company_id) {
      query += ` AND rc.company_id = $8`;
      values.push(parseInt(company_id, 10));
    }

    query += `
      GROUP BY r.id, u.email
      ORDER BY r.departure_time ASC
      LIMIT $6 OFFSET $7
    `;

    const result = await client.query(query, values);

    res.json({
      results: result.rows,
      pagination: { page: Number(page), limit: Number(limit), total: result.rowCount }
    });

  } catch (error) {
    console.error("Error fetching rides:", error);
    res.status(500).json({ error: 'Failed to fetch rides' });
  } finally {
    client.release();
  }
});

// SOS Endpoint
app.post('/sos', authenticate, async (req, res) => {
  try {
    const { rideId, latitude, longitude } = req.body;
    const result = await pool.query(
      `INSERT INTO sos_alerts 
      (user_id, ride_id, location) 
      VALUES ($1, $2, $3) 
      RETURNING *`,
      [req.user.id, rideId, `${latitude},${longitude}`]
    );
    
    // Implement emergency notification logic here
    console.log(`SOS Alert: Ride ${rideId} - User ${req.user.id}`);
    res.json(result.rows[0]);
  } catch (error) {
    res.status(500).json({ error: 'Failed to send SOS' });
  }
});

// Chat Endpoints
app.get('/rides/:id/messages', async (req, res) => {
  try {
    const rideId = req.params.id;

    // Validate rideId
    if (!rideId || isNaN(rideId)) {
      return res.status(400).json({ error: 'Invalid rideId' });
    }

    // Fetch messages
    const result = await pool.query(
      `SELECT m.*, u.email 
       FROM messages m
       JOIN users u ON m.user_id = u.id
       WHERE ride_id = $1 
       ORDER BY created_at ASC`,
      [rideId]
    );

    // If no messages are found, return an empty array
    if (result.rows.length === 0) {
      return res.json([]);
    }

    res.json(result.rows);
  } catch (error) {
    console.error('Error fetching messages:', error);
    res.status(500).json({ error: 'Failed to fetch messages' });
  }
});

// Send Message Endpoint
app.post('/rides/:id/messages', authenticate, async (req, res) => {
  try {
    const { content } = req.body;
    const rideId = req.params.id;
    const userId = req.user.id;

    // Validate required fields
    if (!content) {
      return res.status(400).json({ error: 'Message content is required' });
    }

    // Insert the message into the database
    const result = await pool.query(
      `INSERT INTO messages (ride_id, user_id, content) 
       VALUES ($1, $2, $3) 
       RETURNING *`,
      [rideId, userId, content]
    );

    // Broadcast the message to all connected WebSocket clients for this ride
    const clients = rideConnections.get(rideId);
    if (clients) {
      clients.forEach(client => {
        if (client.readyState === WebSocket.OPEN) {
          client.send(JSON.stringify({
            id: result.rows[0].id,
            user_id: userId,
            content,
            timestamp: result.rows[0].timestamp
          }));
        }
      });
    }

    // Return the created message
    res.json(result.rows[0]);
  } catch (error) {
    console.error('Error sending message:', error);
    res.status(500).json({ error: 'Failed to send message' });
  }
});

// Check if the user is a participant in a ride
app.get('/rides/:rideId/participants', authenticate, async (req, res) => {
  try {
    const rideId = req.params.rideId;
    const userId = req.user.id;

    // Check if the user is a participant in the ride
    const participantCheck = await pool.query(
      `SELECT 1 
       FROM user_rides 
       WHERE user_id = $1 AND ride_id = $2`,
      [userId, rideId]
    );

    // If the user is a participant, return true; otherwise, return false
    const isParticipant = participantCheck.rows.length > 0;

    res.status(200).json({ isParticipant });
  } catch (error) {
    console.error('Error checking participation:', error);
    res.status(500).json({ error: 'Failed to check participation' });
  }
});

// Start Server
const PORT = process.env.PORT || 5000;
server.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});