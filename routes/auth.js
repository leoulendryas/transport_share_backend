const express = require('express');
const router = express.Router();
const twilio = require('twilio');
const speakeasy = require('speakeasy');
const bcrypt = require('bcrypt');
const crypto = require('crypto');
const jwt = require('jsonwebtoken');
const multer = require('multer');
const path = require('path');
const { query } = require('../config/database');
const transporter = require('../config/nodemailer');
const createAccountLimiter = require('../config/createAccountLimiter');
const apiLimiter = require('../config/apiLimiter');

const client = twilio(process.env.TWILIO_ACCOUNT_SID, process.env.TWILIO_AUTH_TOKEN);

// Configure multer for ID image uploads
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, 'uploads/ids/');
  },
  filename: (req, file, cb) => {
    const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1e9);
    cb(null, `id-${uniqueSuffix}${path.extname(file.originalname)}`);
  }
});
const upload = multer({ storage });

// Authentication middleware
const authenticateUser = async (req, res, next) => {
  const authHeader = req.headers.authorization;
  if (!authHeader) return res.status(401).json({ error: 'Authorization header missing' });
  
  const token = authHeader.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'Access token missing' });

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    const user = await query('SELECT * FROM users WHERE id = $1', [decoded.id]);
    if (!user.rows[0]) return res.status(401).json({ error: 'User not found' });
    
    req.user = user.rows[0];
    next();
  } catch (error) {
    console.error('Authentication error:', error);
    res.status(401).json({ error: 'Invalid access token' });
  }
};

// Authorization middleware for ID verification
const requireIdVerification = (req, res, next) => {
  if (!req.user.id_verified) {
    return res.status(403).json({ error: 'ID verification required' });
  }
  next();
};

// Token generation helper
const generateTokens = (userId) => ({
  accessToken: jwt.sign({ id: userId }, process.env.JWT_SECRET, { expiresIn: '1h' }),
  refreshToken: jwt.sign({ id: userId }, process.env.JWT_REFRESH_SECRET)
});

// Registration endpoint
router.post('/register', createAccountLimiter, async (req, res) => {
  try {
    const { first_name, last_name, email, phone_number, password, age, gender } = req.body;

    if (!first_name || !last_name) {
      return res.status(400).json({ error: 'First and last name are required' });
    }

    const existingUser = await query(
      'SELECT * FROM users WHERE email = $1 OR phone_number = $2',
      [email, phone_number]
    );

    if (existingUser.rows[0]) {
      return res.status(400).json({ error: 'Email or phone already registered' });
    }

    const hashedPassword = await bcrypt.hash(password, 12);
    let verificationToken = null;
    let otpHash = null;
    let otpExpiry = null;

    if (email) {
      verificationToken = crypto.randomBytes(32).toString('hex');
    }

    if (phone_number) {
      const otpCode = speakeasy.totp({
        secret: speakeasy.generateSecret().base32,
        digits: 6
      });
      otpHash = await bcrypt.hash(otpCode, 12);
      otpExpiry = new Date(Date.now() + 5 * 60 * 1000);

      await client.messages.create({
        body: `Your verification code: ${otpCode}`,
        from: process.env.TWILIO_PHONE_NUMBER,
        to: phone_number
      });
    }

    const result = await query(
      `INSERT INTO users 
      (first_name, last_name, email, phone_number, password_hash, 
       verification_token, otp_hash, otp_expiry, age, gender) 
      VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
      RETURNING id, first_name, last_name, email, phone_number, age, gender`,
      [first_name, last_name, email, phone_number, hashedPassword, 
       verificationToken, otpHash, otpExpiry, age || null, gender || null]
    );

    const { accessToken, refreshToken } = generateTokens(result.rows[0].id);
    await query('UPDATE users SET refresh_token = $1 WHERE id = $2', [refreshToken, result.rows[0].id]);

    if (email) {
      const verificationLink = `${process.env.BASE_URL}/auth/verify-email?token=${verificationToken}`;
      await transporter.sendMail({
        to: email,
        subject: 'Verify Your Email Address',
        html: `Click <a href="${verificationLink}">here</a> to verify your email`
      });
    }

    res.status(201).json({
      access_token: accessToken,
      refresh_token: refreshToken,
      expires_in: 3600,
      user: result.rows[0]
    });

  } catch (error) {
    console.error('Registration Error:', error);
    res.status(500).json({ error: 'Registration failed' });
  }
});

// Email verification endpoint
router.get('/verify-email', async (req, res) => {
  try {
    const { token } = req.query;
    if (!token) return res.status(400).json({ error: 'Token is required' });

    const user = await query(
      `UPDATE users SET email_verified = true, verification_token = NULL 
       WHERE verification_token = $1 RETURNING *`,
      [token]
    );

    if (!user.rows[0]) {
      return res.status(400).json({ error: 'Invalid or expired verification token' });
    }

    const { accessToken, refreshToken } = generateTokens(user.rows[0].id);
    await query('UPDATE users SET refresh_token = $1 WHERE id = $2', [refreshToken, user.rows[0].id]);

    res.json({
      access_token: accessToken,
      refresh_token: refreshToken,
      expires_in: 3600,
      user: user.rows[0],
    });

  } catch (error) {
    console.error('Email Verification Error:', error);
    res.status(500).json({ error: 'Email verification failed' });
  }
});

// Phone verification endpoint
router.post('/verify-phone', async (req, res) => {
  try {
    const { phone_number, otp } = req.body;
    const user = await query('SELECT * FROM users WHERE phone_number = $1', [phone_number]);

    if (!user.rows[0]) return res.status(404).json({ error: 'User not found' });

    const isValid = await bcrypt.compare(otp, user.rows[0].otp_hash);
    const isExpired = new Date() > new Date(user.rows[0].otp_expiry);

    if (!isValid || isExpired) {
      return res.status(401).json({ error: isExpired ? 'OTP expired' : 'Invalid OTP' });
    }

    await query('UPDATE users SET phone_verified = true WHERE id = $1', [user.rows[0].id]);

    const { accessToken, refreshToken } = generateTokens(user.rows[0].id);
    await query('UPDATE users SET refresh_token = $1 WHERE id = $2', [refreshToken, user.rows[0].id]);

    res.json({
      access_token: accessToken,
      refresh_token: refreshToken,
      expires_in: 3600,
      user: user.rows[0]
    });

  } catch (error) {
    console.error('Phone Verification Error:', error);
    res.status(500).json({ error: 'Verification failed' });
  }
});

// Password login endpoint
router.post('/login', apiLimiter, async (req, res) => {
  try {
    const { email, phone_number, password } = req.body;
    let user;

    if (email) {
      user = await query('SELECT * FROM users WHERE email = $1', [email]);
      if (!user.rows[0]?.email_verified) {
        return res.status(401).json({ error: 'Email not verified' });
      }
    } else if (phone_number) {
      user = await query('SELECT * FROM users WHERE phone_number = $1', [phone_number]);
      if (!user.rows[0]?.phone_verified) {
        return res.status(401).json({ error: 'Phone not verified' });
      }
    }

    if (!user?.rows[0] || !(await bcrypt.compare(password, user.rows[0].password_hash))) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    const { accessToken, refreshToken } = generateTokens(user.rows[0].id);
    await query('UPDATE users SET refresh_token = $1 WHERE id = $2', [refreshToken, user.rows[0].id]);

    res.json({
      access_token: accessToken,
      refresh_token: refreshToken,
      expires_in: 3600,
      user: user.rows[0]
    });

  } catch (error) {
    console.error('Login Error:', error);
    res.status(500).json({ error: 'Login failed' });
  }
});

// OTP login endpoint
router.post('/login-otp', apiLimiter, async (req, res) => {
  try {
    const { phone_number, otp } = req.body;
    const user = await query('SELECT * FROM users WHERE phone_number = $1', [phone_number]);

    if (!user.rows[0] || !(await bcrypt.compare(otp, user.rows[0].otp_hash))) {
      return res.status(401).json({ error: 'Invalid OTP' });
    }

    const { accessToken, refreshToken } = generateTokens(user.rows[0].id);
    await query('UPDATE users SET refresh_token = $1 WHERE id = $2', [refreshToken, user.rows[0].id]);

    res.json({
      access_token: accessToken,
      refresh_token: refreshToken,
      expires_in: 3600,
      user: user.rows[0]
    });

  } catch (error) {
    console.error('OTP Login Error:', error);
    res.status(500).json({ error: 'Login failed' });
  }
});

// Refresh token endpoint
router.post('/refresh', async (req, res) => {
  try {
    const { refresh_token } = req.body;
    if (!refresh_token) return res.status(400).json({ error: 'Refresh token required' });

    const decoded = jwt.verify(refresh_token, process.env.JWT_REFRESH_SECRET);
    const user = await query(
      'SELECT * FROM users WHERE id = $1 AND refresh_token = $2',
      [decoded.id, refresh_token]
    );

    if (!user.rows[0]) return res.status(401).json({ error: 'Invalid refresh token' });

    const { accessToken, refreshToken } = generateTokens(user.rows[0].id);
    await query('UPDATE users SET refresh_token = $1 WHERE id = $2', [refreshToken, user.rows[0].id]);

    res.json({
      access_token: accessToken,
      refresh_token: refreshToken,
      expires_in: 3600
    });

  } catch (error) {
    console.error('Refresh Error:', error);
    res.status(401).json({ error: 'Invalid refresh token' });
  }
});

// Logout endpoint
router.post('/logout', async (req, res) => {
  try {
    const authHeader = req.headers.authorization;
    if (!authHeader) return res.status(400).json({ error: 'Authorization header required' });

    const token = authHeader.split(' ')[1];
    if (!token) return res.status(400).json({ error: 'Access token required' });

    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    await query('UPDATE users SET refresh_token = NULL WHERE id = $1', [decoded.id]);

    res.clearCookie('refreshToken', { httpOnly: true, secure: true, sameSite: 'Strict' });
    res.sendStatus(204);

  } catch (error) {
    console.error('Logout Error:', error);
    res.status(500).json({ error: 'Logout failed' });
  }
});

// OTP request endpoint
router.post('/request-otp', apiLimiter, async (req, res) => {
  try {
    const { phone_number } = req.body;
    const user = await query('SELECT * FROM users WHERE phone_number = $1', [phone_number]);

    if (!user.rows[0]) return res.status(404).json({ error: 'User not found' });

    const otpCode = speakeasy.totp({
      secret: speakeasy.generateSecret().base32,
      digits: 6
    });

    await client.messages.create({
      body: `Your login OTP: ${otpCode}`,
      from: process.env.TWILIO_PHONE_NUMBER,
      to: phone_number
    });

    const otpHash = await bcrypt.hash(otpCode, 12);
    const otpExpiry = new Date(Date.now() + 5 * 60 * 1000);

    await query(
      'UPDATE users SET otp_hash = $1, otp_expiry = $2 WHERE phone_number = $3',
      [otpHash, otpExpiry, phone_number]
    );

    res.json({ message: 'OTP sent successfully' });

  } catch (error) {
    console.error('OTP Request Error:', error);
    res.status(500).json({ error: 'Failed to send OTP' });
  }
});

// Resend verification email endpoint
router.post('/resend-verification', async (req, res) => {
  try {
    const { email } = req.body;
    const user = await query('SELECT * FROM users WHERE email = $1', [email]);
    if (!user.rows[0]) return res.status(404).json({ error: 'User not found' });

    const verificationToken = crypto.randomBytes(32).toString('hex');
    await query(
      'UPDATE users SET verification_token = $1 WHERE id = $2',
      [verificationToken, user.rows[0].id]
    );

    const verificationLink = `${process.env.BASE_URL}/auth/verify-email?token=${verificationToken}`;
    await transporter.sendMail({
      to: email,
      subject: 'Verify Your Email',
      html: `Click <a href="${verificationLink}">here</a> to verify your email`
    });

    res.json({ message: 'Verification email resent' });

  } catch (error) {
    console.error('Resend Error:', error);
    res.status(500).json({ error: 'Failed to resend verification' });
  }
});

// ID Verification Endpoint
router.post('/verify-identity', 
  authenticateUser,
  upload.single('id_image'),
  async (req, res) => {
    try {
      const { name, age, gender, id_type } = req.body;
      const userId = req.user.id;

      if (!name || !age || !gender || !id_type || !req.file) {
        return res.status(400).json({ error: 'All fields and ID image are required' });
      }

      const idImageUrl = `/ids/${req.file.filename}`;
      await query(
        `UPDATE users 
        SET name = $1, age = $2, gender = $3, id_image_url = $4, id_verified = FALSE 
        WHERE id = $5`,
        [name, age, gender, idImageUrl, userId]
      );

      res.status(201).json({ 
        message: 'ID verification submitted for review',
        verification_status: 'pending'
      });

    } catch (error) {
      console.error('ID Verification Error:', error);
      res.status(500).json({ error: 'ID verification submission failed' });
    }
  }
);

// Admin Verification Approval Endpoint
router.post('/admin/verify-id', 
  authenticateUser,
  async (req, res) => {
    try {
      const { userId } = req.body;      
      await query('UPDATE users SET id_verified = TRUE WHERE id = $1', [userId]);
      res.json({ message: 'ID verification approved' });
    } catch (error) {
      res.status(500).json({ error: 'Verification approval failed' });
    }
  }
);

// Protected Ride Posting Endpoint
router.post('/rides',
  authenticateUser,
  requireIdVerification,
  async (req, res) => {
    try {
      res.json({ message: 'Ride posted successfully' });
    } catch (error) {
      res.status(500).json({ error: 'Failed to post ride' });
    }
  }
);

module.exports = router;