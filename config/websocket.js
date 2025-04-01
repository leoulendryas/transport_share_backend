const WebSocket = require('ws');
const { query } = require('./database');
const jwt = require('jsonwebtoken');
const zlib = require('zlib');
const util = require('util');
const deflate = util.promisify(zlib.deflate);
require('dotenv').config();

// Constants
const PING_INTERVAL = 25000;
const HEARTBEAT_TIMEOUT = 30000;
const RATE_LIMIT = 30; // messages per minute
const MESSAGE_HISTORY_BATCH_SIZE = 50;
const MAX_MESSAGE_LENGTH = 500;

const rideConnections = new Map();
const userConnections = new Map();
const wsMessageCount = new Map();

// Helper function to broadcast messages to all clients in a ride
async function broadcastMessage(rideId, message) {
  const clients = rideConnections.get(rideId);
  if (!clients) return;

  const messageString = JSON.stringify(message);
  
  for (const client of clients) {
    try {
      if (client.readyState === WebSocket.OPEN) {
        client.send(messageString);
      }
    } catch (error) {
      console.error('Broadcast error:', error);
    }
  }
}

function isValidMessage(content) {
  return typeof content === 'string' && 
         content.trim().length > 0 && 
         content.length <= MAX_MESSAGE_LENGTH;
}

const setupWebSocket = (server) => {
  const wss = new WebSocket.Server({ 
    server, 
    path: '/ws',
    perMessageDeflate: {
      zlibDeflateOptions: {
        chunkSize: 1024,
        memLevel: 7,
        level: 3
      },
      clientNoContextTakeover: true,
      serverNoContextTakeover: true
    }
  });

  // Ping all clients periodically
  const interval = setInterval(() => {
    wss.clients.forEach((ws) => {
      if (!ws.isAlive) {
        console.log('Terminating unresponsive connection');
        return ws.terminate();
      }
      ws.isAlive = false;
      try {
        ws.ping();
      } catch (error) {
        console.error('Ping error:', error);
      }
    });
  }, PING_INTERVAL);

  wss.on('connection', async (ws, req) => {
    ws.isAlive = true;
    let rideId, userId;
    let heartbeatTimeout;

    const resetHeartbeat = () => {
      clearTimeout(heartbeatTimeout);
      heartbeatTimeout = setTimeout(() => {
        console.log('Heartbeat timeout, terminating connection');
        ws.terminate();
      }, HEARTBEAT_TIMEOUT);
    };

    resetHeartbeat();

    try {
      // Validate origin if in production
      if (process.env.NODE_ENV === 'production') {
        const origin = req.headers.origin;
        if (!origin || !origin.includes(process.env.ALLOWED_ORIGIN)) {
          throw new Error('Invalid origin');
        }
      }

      // Parse token and rideId from URL
      const url = new URL(req.url, `ws://${req.headers.host}`);
      const token = url.searchParams.get('token');
      rideId = url.searchParams.get('rideId');
      
      if (!token || !rideId) {
        throw new Error('Authentication required');
      }

      // Verify JWT token
      const decoded = jwt.verify(token, process.env.JWT_SECRET);
      userId = decoded.id;

      // Verify user exists
      const userCheck = await query('SELECT id, email FROM users WHERE id = $1', [userId]);
      if (!userCheck.rows[0]) {
        throw new Error('Invalid user');
      }
      
      // Verify ride access
      const rideAccess = await query(
        'SELECT 1 FROM user_rides WHERE user_id = $1 AND ride_id = $2',
        [userId, rideId]
      );
      if (!rideAccess.rows[0]) {
        throw new Error('Access denied');
      }

      // Initialize connection tracking
      if (!rideConnections.has(rideId)) {
        rideConnections.set(rideId, new Set());
      }
      rideConnections.get(rideId).add(ws);

      if (!userConnections.has(userId)) {
        userConnections.set(userId, new Set());
      }
      userConnections.get(userId).add(ws);

      // Send message history in batches
      const messageHistory = await query(
        `SELECT m.*, u.email 
         FROM messages m
         JOIN users u ON m.user_id = u.id
         WHERE ride_id = $1 
         ORDER BY created_at ASC`,
        [rideId]
      );

      // Split history into batches
      const batches = [];
      for (let i = 0; i < messageHistory.rows.length; i += MESSAGE_HISTORY_BATCH_SIZE) {
        batches.push(messageHistory.rows.slice(i, i + MESSAGE_HISTORY_BATCH_SIZE));
      }

      for (const [index, batch] of batches.entries()) {
        ws.send(JSON.stringify({
          type: 'history',
          messages: batch,
          isLastBatch: index === batches.length - 1
        }));
      }

      // Message handler
      ws.on('message', async (message) => {
        try {
          resetHeartbeat();
          
          const data = JSON.parse(message);
          
          // Handle ping/pong
          if (data.type === 'ping') {
            return ws.pong();
          }
          
          // Handle new messages
          if (data.type === 'message') {
            // Rate limiting
            const now = Date.now();
            const userCounts = wsMessageCount.get(userId) || [];
            const recentCounts = userCounts.filter(t => now - t < 60000);
            
            if (recentCounts.length >= RATE_LIMIT) {
              console.log(`Rate limit exceeded for user ${userId}`);
              return ws.close(1008, 'Rate limit exceeded');
            }
            
            wsMessageCount.set(userId, [...recentCounts, now]);
            
            // Validate message
            if (!isValidMessage(data.content)) {
              throw new Error(`Message content must be 1-${MAX_MESSAGE_LENGTH} characters`);
            }
            
            // Sanitize message content
            const sanitizedContent = data.content.replace(/</g, '&lt;').replace(/>/g, '&gt;');
            
            // Insert message if not from HTTP
            if (!data.fromHttp) {
              const result = await query(
                'INSERT INTO messages (ride_id, user_id, content) VALUES ($1, $2, $3) RETURNING *',
                [rideId, userId, sanitizedContent]
              );
              
              await broadcastMessage(rideId, {
                type: 'message',
                id: result.rows[0].id,
                userId,
                userEmail: userCheck.rows[0].email,
                content: sanitizedContent,
                timestamp: result.rows[0].created_at.toISOString()
              });
            }
          }
        } catch (error) {
          console.error('WebSocket message error:', error);
          ws.send(JSON.stringify({
            type: 'error',
            message: error.message
          }));
        }
      });

      ws.on('pong', () => {
        ws.isAlive = true;
        resetHeartbeat();
      });

      // Cleanup on close
      ws.on('close', () => {
        clearTimeout(heartbeatTimeout);
        
        // Remove from ride connections
        const rideClients = rideConnections.get(rideId);
        if (rideClients) {
          rideClients.delete(ws);
          if (rideClients.size === 0) {
            rideConnections.delete(rideId);
          }
        }
        
        // Remove from user connections
        if (userId) {
          const userWsSet = userConnections.get(userId);
          if (userWsSet) {
            userWsSet.delete(ws);
            if (userWsSet.size === 0) {
              userConnections.delete(userId);
              wsMessageCount.delete(userId);
            }
          }
        }
      });

    } catch (error) {
      console.error('WebSocket connection error:', error);
      ws.close(1008, error.message);
    }
  });

  return {
    wss,
    rideConnections,
    userConnections,
    broadcastMessage,
    cleanup: () => clearInterval(interval)
  };
};

module.exports = {
  setupWebSocket,
  rideConnections,
  userConnections,
  broadcastMessage
};