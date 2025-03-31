const express = require('express');
const bodyParser = require('body-parser');
const cors = require('cors');
const helmet = require('helmet');
const http = require('http');
const { pool } = require('./config/database');
const setupWebSocket = require('./config/websocket');
const { authenticate } = require('./middlewares');
require('dotenv').config();

const app = express();
app.use(helmet());
app.use(cors());
app.use(bodyParser.json());

// Create HTTP server and WebSocket server
const server = http.createServer(app);
const { wss, cleanup: cleanupWebSocket } = setupWebSocket(server);

// Import routes
const authRoutes = require('./routes/auth');
const rideRoutes = require('./routes/rides');
const messageRoutes = require('./routes/messages');
const profileRoutes = require('./routes/profile');
const companyRoutes = require('./routes/companies');
const sosRoutes = require('./routes/sos');

// Use routes
app.use('/auth', authRoutes);
app.use('/rides', rideRoutes);
app.use('/messages', messageRoutes);
app.use('/profile', profileRoutes);
app.use('/companies', companyRoutes);
app.use('/sos', sosRoutes);

// Error handling middleware
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

// Start Server
const PORT = process.env.PORT || 5000;
server.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});

// Cleanup on server close
process.on('SIGTERM', () => {
  cleanupWebSocket();
  server.close();
  pool.end();
});

module.exports = app;