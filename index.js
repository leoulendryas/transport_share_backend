const express = require('express');
const bodyParser = require('body-parser');
const cors = require('cors');
const { Pool } = require('pg'); // PostgreSQL
const admin = require('firebase-admin'); // Firebase Admin for Auth
const WebSocket = require('ws');
const http = require('http');

const app = express();
app.use(cors());
app.use(bodyParser.json());
const server = http.createServer(app);
const wss = new WebSocket.Server({ server });

// PostgreSQL connection
const pool = new Pool({
  user: 'postgres',
  host: 'localhost',
  database: 'postgres',
  password: 'SscAAiTUnity',
  port: 5432,
});

// Initialize Firebase Admin (for authentication)
const serviceAccount = require('./transport-sharing-app-firebase-adminsdk-fbsvc-a12a2e53e9.json');
admin.initializeApp({
  credential: admin.credential.cert(serviceAccount),
});

// WebSocket connection handler
wss.on('connection', (ws) => {
  console.log('New client connected');

  // Handle incoming messages from clients
  ws.on('message', async (message) => {
    const { ride_id, sender, message: text } = JSON.parse(message);

    try {
      // Save message to PostgreSQL
      const result = await pool.query(
        'INSERT INTO chats (ride_id, sender, message) VALUES ($1, $2, $3) RETURNING *',
        [ride_id, sender, text]
      );

      // Broadcast the new message to all connected clients
      wss.clients.forEach((client) => {
        if (client.readyState === WebSocket.OPEN) {
          client.send(JSON.stringify(result.rows[0]));
        }
      });
    } catch (error) {
      console.error('Error saving message:', error);
    }
  });

  // Handle client disconnection
  ws.on('close', () => {
    console.log('Client disconnected');
  });
});

// Middleware to validate Firebase ID tokens
const authenticate = async (req, res, next) => {
  const idToken = req.headers.authorization?.split('Bearer ')[1];
  if (!idToken) {
    return res.status(401).json({ error: 'Unauthorized' });
  }

  try {
    const decodedToken = await admin.auth().verifyIdToken(idToken);
    req.user = decodedToken;
    next();
  } catch (error) {
    console.error('Error verifying token:', error);
    res.status(401).json({ error: 'Unauthorized' });
  }
};

// Create a ride
app.post('/create-ride', authenticate, async (req, res) => {
  const { from, to, seats, time } = req.body;

  const ride = {
    from,
    to,
    seats,
    time, // Time is passed as a string
    createdAt: new Date(),
  };

  try {
    const rideRef = await admin.firestore().collection('rides').add(ride);
    res.status(201).json({ message: 'Ride created successfully!', rideId: rideRef.id });
  } catch (error) {
    console.error('Error creating ride:', error);
    res.status(500).json({ error: 'Failed to create ride' });
  }
});

// Get all rides
app.get('/rides', async (req, res) => {
  try {
    const ridesSnapshot = await admin.firestore().collection('rides').get();
    const rides = ridesSnapshot.docs.map((doc) => ({ id: doc.id, ...doc.data() }));
    res.status(200).json(rides);
  } catch (error) {
    console.error('Error fetching rides:', error);
    res.status(500).json({ error: 'Failed to fetch rides' });
  }
});

// Search rides
app.get('/search-rides', async (req, res) => {
  const { from, to, time } = req.query;

  try {
    let query = admin.firestore().collection('rides');

    if (from) query = query.where('from', '==', from);
    if (to) query = query.where('to', '==', to);
    if (time) query = query.where('time', '==', time); // Compare as string

    const ridesSnapshot = await query.get();
    const rides = ridesSnapshot.docs.map((doc) => ({ id: doc.id, ...doc.data() }));

    res.status(200).json(rides);
  } catch (error) {
    console.error('Error searching rides:', error);
    res.status(500).json({ error: 'Failed to search rides' });
  }
});

// Send SOS alert
app.post('/send-sos', authenticate, async (req, res) => {
  const { latitude, longitude } = req.body;

  try {
    // Save SOS alert to PostgreSQL
    const result = await pool.query(
      'INSERT INTO sos_alerts (user_id, location) VALUES ($1, $2) RETURNING *',
      [req.user.uid, `${latitude}, ${longitude}`]
    );

    // Send SMS via Ethio Telecom SMS Gateway (pseudo-code)
    // await sendSMS(`SOS! User at ${latitude}, ${longitude}`);

    res.status(201).json({ message: 'SOS alert sent successfully!', sosId: result.rows[0].id });
  } catch (error) {
    console.error('Error sending SOS:', error);
    res.status(500).json({ error: 'Failed to send SOS' });
  }
});

// Send chat message
app.post('/send-message', authenticate, async (req, res) => {
  const { ride_id, sender, message } = req.body;

  try {
    // Save message to PostgreSQL
    const result = await pool.query(
      'INSERT INTO chats (ride_id, sender, message) VALUES ($1, $2, $3) RETURNING *',
      [ride_id, sender, message]
    );

    res.status(201).json({ message: 'Message sent successfully!', messageId: result.rows[0].id });
  } catch (error) {
    console.error('Error sending message:', error);
    res.status(500).json({ error: 'Failed to send message' });
  }
});

// Get chat messages
app.get('/get-messages', async (req, res) => {
  const { ride_id } = req.query;

  try {
    const result = await pool.query(
      'SELECT * FROM chats WHERE ride_id = $1 ORDER BY timestamp ASC',
      [ride_id]
    );
    res.status(200).json(result.rows);
  } catch (error) {
    console.error('Error fetching messages:', error);
    res.status(500).json({ error: 'Failed to fetch messages' });
  }
});

// Health check
app.get('/health', (req, res) => {
  res.status(200).json({ status: 'OK' });
});

const PORT = process.env.PORT || 5000;
server.listen(PORT, () => console.log(`Server running on port ${PORT}`));