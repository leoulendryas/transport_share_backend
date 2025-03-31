const WebSocket = require('ws');
const { query } = require('./database');
const jwt = require('jsonwebtoken');
require('dotenv').config();

const rideConnections = new Map();

const setupWebSocket = (server) => {
  const wss = new WebSocket.Server({ server, path: '/ws' });

  // Ping all clients every 30 seconds
  const interval = setInterval(() => {
    wss.clients.forEach((ws) => {
      if (!ws.isAlive) return ws.terminate();
      ws.isAlive = false;
      ws.send(JSON.stringify({ type: 'ping', timestamp: Date.now() }));
    });
  }, 25000);

  wss.on('connection', async (ws, req) => {
    ws.isAlive = true;
    ws.on('pong', () => { ws.isAlive = true; });

    try {
      const token = new URL(req.url, `ws://${req.headers.host}`).searchParams.get('token');
      const rideId = new URL(req.url, `ws://${req.headers.host}`).searchParams.get('rideId');
      
      const decoded = jwt.verify(token, process.env.JWT_SECRET);
      const userCheck = await query('SELECT id FROM users WHERE id = $1', [decoded.id]);
      if (!userCheck.rows[0]) throw new Error('Invalid user');
      
      const rideAccess = await query(
        'SELECT 1 FROM user_rides WHERE user_id = $1 AND ride_id = $2',
        [decoded.id, rideId]
      );
      if (!rideAccess.rows[0]) throw new Error('Access denied');

      if (!rideConnections.has(rideId)) {
        rideConnections.set(rideId, new Set());
      }
      const clients = rideConnections.get(rideId);
      clients.add(ws);

      ws.on('message', async (message) => {
        try {
          const data = JSON.parse(message);
          
          if (data.type === 'ping') {
            ws.send(JSON.stringify({ type: 'pong', timestamp: data.timestamp }));
            return;
          }
          
          const result = await query(
            'INSERT INTO messages (ride_id, user_id, content) VALUES ($1, $2, $3) RETURNING *',
            [rideId, decoded.id, data.content]
          );
      
          clients.forEach(client => {
            if (client.readyState === WebSocket.OPEN) {
              client.send(JSON.stringify({
                type: 'message',
                id: result.rows[0].id,
                userId: decoded.id,
                content: data.content,
                timestamp: result.rows[0].created_at.toISOString()
              }));
            }
          });
        } catch (error) {
          ws.send(JSON.stringify({ 
            type: 'error',
            message: error.message 
          }));
        }
      });

      ws.on('close', () => {
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

  return {
    wss,
    rideConnections,
    cleanup: () => clearInterval(interval)
  };
};

module.exports = setupWebSocket;