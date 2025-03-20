const express = require('express');
const bodyParser = require('body-parser');
const cors = require('cors');
const admin = require('firebase-admin');

const app = express();
app.use(cors());
app.use(bodyParser.json());

// Initialize Firebase Admin SDK
const serviceAccount = require('./transport-sharing-app-firebase-adminsdk-fbsvc-a12a2e53e9.json');
admin.initializeApp({
  credential: admin.credential.cert(serviceAccount),
});

// Example API endpoint
app.post('/create-ride', async (req, res) => {
  const { from, to, seats, time } = req.body;

  const ride = {
    from,
    to,
    seats,
    time,
    createdAt: new Date()
  };

  await admin.firestore().collection('rides').add(ride);
  res.status(201).json({ message: 'Ride created successfully!' });
});

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

app.post('/signup', async (req, res) => {
  const { email, password } = req.body;

  try {
    const userRecord = await admin.auth().createUser({
      email,
      password,
    });

    res.status(201).json({
      message: 'User created successfully!',
      user: {
        uid: userRecord.uid,
        email: userRecord.email,
      },
    });
  } catch (error) {
    console.error('Error creating user:', error);
    res.status(400).json({ error: error.message });
  }
});

app.post('/login', async (req, res) => {
  const { email, password } = req.body;

  try {
    const userRecord = await admin.auth().getUserByEmail(email);

    // Verify password (this is a simplified example; use Firebase Auth SDK for real apps)
    const user = await admin.auth().signInWithEmailAndPassword(email, password);

    res.status(200).json({
      message: 'Login successful!',
      user: {
        uid: userRecord.uid,
        email: userRecord.email,
      },
    });
  } catch (error) {
    console.error('Error logging in:', error);
    res.status(400).json({ error: error.message });
  }
});

app.get('/health', (req, res) => {
  res.status(200).json({ status: 'OK' });
});

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));