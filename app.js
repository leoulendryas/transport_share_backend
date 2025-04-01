const express = require('express');
const bodyParser = require('body-parser');
const cors = require('cors');
const helmet = require('helmet');
const http = require('http');
const { pool } = require('./config/database');
const { authenticate } = require('./middlewares');
const { setupWebSocket, rideConnections } = require('./config/websocket');
require('dotenv').config();

const app = express();

// Middleware
app.use(helmet());
app.use(cors());
app.use(bodyParser.json());

// Create HTTP server
const server = http.createServer(app);

// Setup WebSocket
const { wss, cleanup: cleanupWebSocket } = setupWebSocket(server);

// Routes
app.use('/auth', require('./routes/auth'));
app.use('/rides', require('./routes/rides'));
app.use('/messages', require('./routes/messages'));
app.use('/profile', require('./routes/profile'));
app.use('/companies', require('./routes/companies'));
app.use('/sos', require('./routes/sos'));

// Error handling
app.use((err, req, res, next) => {
  console.error('Unhandled error:', err);
  
  if (err instanceof SyntaxError && err.status === 400 && 'body' in err) {
    return res.status(400).json({ error: 'Invalid JSON' });
  }
  
  res.status(500).json({ 
    error: 'Internal server error',
    ...(process.env.NODE_ENV === 'development' && { details: err.message })
  });
});

// Server configuration
const PORT = process.env.PORT || 5000;

// Start server
const startServer = () => {
  server.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
  });
};

// Cleanup
const cleanup = async () => {
  try {
    cleanupWebSocket();
    server.close();
    await pool.end();
    console.log('Server and database connections closed gracefully');
  } catch (err) {
    console.error('Error during cleanup:', err);
    process.exit(1);
  }
};

process.on('SIGTERM', cleanup);
process.on('SIGINT', cleanup);

// Export for testing and potential module use
module.exports = {
  app,
  server,
  wss,
  PORT,
  startServer,
  cleanup
};

// Start the server if not in test environment
if (process.env.NODE_ENV !== 'test') {
  startServer();
}