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

  const interval = setInterval(() => {
    wss.clients.forEach((ws) => {
      if (!ws.isAlive) return ws.terminate();
      ws.isAlive = false;
      ws.send(JSON.stringify({ type: 'ping', timestamp: Date.now() }));
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
      const token = new URL(req.url, `ws://${req.headers.host}`).searchParams.get('token');
      const rideIdParam = new URL(req.url, `ws://${req.headers.host}`).searchParams.get('rideId');

      // Parse token and rideId from URL
      if (!token || !rideIdParam) {
        throw new Error('Authentication required');
      }

      const decoded = jwt.verify(token, process.env.JWT_SECRET);
      const userCheck = await query('SELECT id FROM users WHERE id = $1', [decoded.id]);
      if (!userCheck.rows[0]) throw new Error('Invalid user');
      userId = decoded.id;

      // Initialize connection tracking for the ride
      if (!rideConnections.has(rideIdParam)) {
        rideConnections.set(rideIdParam, new Set());
      }
      const clients = rideConnections.get(rideIdParam);
      clients.add(ws);

      // Initialize user connection tracking
      if (!userConnections.has(userId)) {
        userConnections.set(userId, new Set());
      }
      userConnections.get(userId).add(ws);

      // Notify other clients of the new connection
      broadcastMessage(rideIdParam, {
        type: 'user_connected',
        userId: userId,
        action: '+'
      });

      // Message history logic (same as before)
      const messageHistory = await query(
        `SELECT m.*, u.email 
         FROM messages m
         JOIN users u ON m.user_id = u.id
         WHERE ride_id = $1 
         ORDER BY created_at ASC`,
        [rideIdParam]
      );
      // Send message history logic (same as before)
      
      ws.on('message', async (message) => {
        try {
          resetHeartbeat();
          const data = JSON.parse(message);

          if (data.type === 'ping') {
            ws.send(JSON.stringify({ type: 'pong', timestamp: data.timestamp }));
            return;
          }

          if (data.type === 'message') {
            const result = await query(
              'INSERT INTO messages (ride_id, user_id, content) VALUES ($1, $2, $3) RETURNING *',
              [rideIdParam, decoded.id, data.content]
            );

            // Broadcast the message to all other clients
            broadcastMessage(rideIdParam, {
              type: 'message',
              content: data.content,
              userId: decoded.id,
              timestamp: result.rows[0].created_at.toISOString()
            });
          }
        } catch (error) {
          ws.send(JSON.stringify({ 
            type: 'error',
            message: error.message 
          }));
        }
      });

      ws.on('close', () => {
        // Remove from ride connections
        const rideClients = rideConnections.get(rideIdParam);
        if (rideClients) {
          rideClients.delete(ws);
          // Notify other clients of the removed connection
          broadcastMessage(rideIdParam, {
            type: 'user_disconnected',
            userId: userId,
            action: '-'
          });

          if (rideClients.size === 0) {
            rideConnections.delete(rideIdParam);
          }
        }

        // Remove from user connections
        if (userConnections.has(userId)) {
          const userWsSet = userConnections.get(userId);
          userWsSet.delete(ws);
          if (userWsSet.size === 0) {
            userConnections.delete(userId);
            wsMessageCount.delete(userId);
          }
        }
      });

    } catch (error) {
      ws.send(JSON.stringify({ 
        type: 'error',
        message: error.message 
      }));
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

module.exports = setupWebSocket;
