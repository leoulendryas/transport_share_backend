const express = require('express');
const { query } = require('../config/database');
const { authenticate, messageLimiter } = require('../middlewares');
const { broadcastMessage, rideConnections } = require('../config/websocket');
const validator = require('validator');
const { MAX_MESSAGE_LENGTH } = require('../config/constants');

const router = express.Router();

// Enhanced message validation
function isValidMessage(content) {
  return typeof content === 'string' && 
         content.trim().length > 0 && 
         content.length <= MAX_MESSAGE_LENGTH &&
         !validator.contains(content, ['<script>', '</script>']);
}

// Get message history with pagination
router.get('/rides/:id/messages', authenticate, async (req, res) => {
  try {
    const rideId = parseInt(req.params.id);
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 50;
    const offset = (page - 1) * limit;

    const rideCheck = await query(
      'SELECT status FROM rides WHERE id = $1',
      [rideId]
    );
    
    if (rideCheck.rows.length === 0) {
      return res.status(404).json({ 
        error: 'Ride not found',
        details: 'The specified ride does not exist'
      });
    }

    if (rideCheck.rows[0].status === 'cancelled') {
      return res.json({
        messages: [],
        pagination: {
          page: 1,
          limit: 50,
          total: 0,
          totalPages: 0
        }
      });
    }

    if (isNaN(rideId)) {
      return res.status(400).json({ 
        error: 'Invalid rideId',
        details: 'rideId must be a valid number'
      });
    }

    // Verify ride access
    const rideAccess = await query(
      'SELECT 1 FROM user_rides WHERE user_id = $1 AND ride_id = $2',
      [req.user.id, rideId]
    );
    
    if (!rideAccess.rows[0]) {
      return res.status(403).json({ 
        error: 'Access denied',
        details: 'You are not a participant in this ride'
      });
    }

    // Get messages with pagination
    const messagesResult = await query(
      `SELECT m.*, u.email 
       FROM messages m
       JOIN users u ON m.user_id = u.id
       WHERE ride_id = $1 
       ORDER BY created_at DESC
       LIMIT $2 OFFSET $3`,
      [rideId, limit, offset]
    );

    // Get total count for pagination metadata
    const countResult = await query(
      'SELECT COUNT(*) FROM messages WHERE ride_id = $1',
      [rideId]
    );

    res.json({
      messages: messagesResult.rows.reverse(), // Reverse to maintain chronological order
      pagination: {
        page,
        limit,
        total: parseInt(countResult.rows[0].count),
        totalPages: Math.ceil(countResult.rows[0].count / limit)
      }
    });
  } catch (error) {
    console.error('Failed to fetch messages:', error);
    res.status(500).json({ 
      error: 'Failed to fetch messages',
      details: process.env.NODE_ENV === 'development' ? error.message : undefined
    });
  }
});

// Send new message
router.post('/rides/:id/messages', authenticate, messageLimiter, async (req, res) => {
  try {
    const { content } = req.body;
    const rideId = parseInt(req.params.id);
    const userId = req.user.id;

    const rideCheck = await query(
      'SELECT status FROM rides WHERE id = $1',
      [rideId]
    );
    
    if (rideCheck.rows.length === 0) {
      return res.status(404).json({ 
        error: 'Ride not found',
        details: 'The specified ride does not exist'
      });
    }
    
    if (rideCheck.rows[0].status === 'cancelled') {
      return res.status(400).json({ 
        error: 'Ride canceled',
        details: 'Cannot send messages in a canceled ride'
      });
    }

    if (isNaN(rideId)) {
      return res.status(400).json({ 
        error: 'Invalid rideId',
        details: 'rideId must be a valid number'
      });
    }

    if (!isValidMessage(content)) {
      return res.status(400).json({ 
        error: 'Invalid message content',
        details: `Message must be 1-${MAX_MESSAGE_LENGTH} characters and not contain scripts`
      });
    }

    // Verify ride access
    const rideAccess = await query(
      'SELECT 1 FROM user_rides WHERE user_id = $1 AND ride_id = $2',
      [userId, rideId]
    );
    
    if (!rideAccess.rows[0]) {
      return res.status(403).json({ 
        error: 'Access denied',
        details: 'You are not a participant in this ride'
      });
    }

    // Sanitize content
    const sanitizedContent = validator.escape(content.trim());

    const result = await query(
      `INSERT INTO messages (ride_id, user_id, content) 
       VALUES ($1, $2, $3) 
       RETURNING *, (SELECT email FROM users WHERE id = $2) as user_email`,
      [rideId, userId, sanitizedContent]
    );

    const newMessage = {
      type: 'message',
      id: result.rows[0].id.toString(),  // Ensure string type for consistency with WS
      userId: userId.toString(),         // Ensure string type
      userEmail: result.rows[0].user_email,
      content: sanitizedContent,
      timestamp: result.rows[0].created_at.toISOString(),
      fromHttp: true
    };

    // Only broadcast if there are active WS connections
    if (rideConnections.has(rideId)) {
      await broadcastMessage(rideId, newMessage);
    }

    res.status(201).json(newMessage);
  } catch (error) {
    console.error('Failed to send message:', error);
    res.status(500).json({ 
      error: 'Failed to send message',
      details: process.env.NODE_ENV === 'development' ? error.message : undefined
    });
  }
});

module.exports = router;