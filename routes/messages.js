const express = require('express');
const { query } = require('../config/database');
const { authenticate, messageLimiter } = require('../middlewares');
const { rideConnections } = require('../config/websocket');

const router = express.Router();

router.get('/rides/:id/messages', async (req, res) => {
  try {
    const rideId = req.params.id;
    if (!rideId || isNaN(rideId)) {
      return res.status(400).json({ error: 'Invalid rideId' });
    }

    const result = await query(
      `SELECT m.*, u.email 
       FROM messages m
       JOIN users u ON m.user_id = u.id
       WHERE ride_id = $1 
       ORDER BY created_at ASC`,
      [rideId]
    );

    res.json(result.rows);
  } catch (error) {
    res.status(500).json({ error: 'Failed to fetch messages' });
  }
});

router.post('/rides/:id/messages', authenticate, messageLimiter, async (req, res) => {
  try {
    const { content } = req.body;
    const rideId = req.params.id;
    const userId = req.user.id;

    if (!content) {
      return res.status(400).json({ error: 'Message content is required' });
    }

    const result = await query(
      `INSERT INTO messages (ride_id, user_id, content) 
       VALUES ($1, $2, $3) 
       RETURNING *`,
      [rideId, userId, content]
    );

    const clients = rideConnections.get(rideId);
    if (clients) {
      clients.forEach(client => {
        if (client.readyState === WebSocket.OPEN) {
          client.send(JSON.stringify({
            id: result.rows[0].id,
            user_id: userId,
            content,
            timestamp: result.rows[0].created_at
          }));
        }
      });
    }

    res.json(result.rows[0]);
  } catch (error) {
    res.status(500).json({ error: 'Failed to send message' });
  }
});

module.exports = router;