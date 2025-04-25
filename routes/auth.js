const express = require('express');
const router = express.Router();
const twilio = require('twilio');
const speakeasy = require('speakeasy');
const bcrypt = require('bcrypt');
const crypto = require('crypto');
const jwt = require('jsonwebtoken');
const { query } = require('../config/database');
const transporter = require('../config/nodemailer');
const createAccountLimiter = require('../config/createAccountLimiter');
const apiLimiter = require('../config/apiLimiter');

const client = twilio(process.env.TWILIO_ACCOUNT_SID, process.env.TWILIO_AUTH_TOKEN);

// Token generation helper
const generateTokens = (userId) => ({
  accessToken: jwt.sign({ id: userId }, process.env.JWT_SECRET, { expiresIn: '1h' }),
  refreshToken: jwt.sign({ id: userId }, process.env.JWT_REFRESH_SECRET) // Refresh token with no expiry
});

// Registration endpoint
router.post('/register', createAccountLimiter, async (req, res) => {
  try {
    const { first_name, last_name, email, phone_number, password } = req.body;

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
      (first_name, last_name, email, phone_number, password_hash, verification_token, otp_hash, otp_expiry) 
      VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
      RETURNING id, first_name, last_name, email, phone_number`,
      [first_name, last_name, email, phone_number, hashedPassword, verificationToken, otpHash, otpExpiry]
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
    if (!token) {
      return res.status(400).json({ error: 'Token is required' });
    }

    // Verify the token and update the user's email verification status
    const user = await query(
      `UPDATE users SET email_verified = true, verification_token = NULL 
       WHERE verification_token = $1 RETURNING *`,
      [token]
    );

    if (!user.rows[0]) {
      return res.status(400).json({ error: 'Invalid or expired verification token' });
    }

    // Generate access and refresh tokens
    const { accessToken, refreshToken } = generateTokens(user.rows[0].id);

    // Save the refresh token in the database
    await query('UPDATE users SET refresh_token = $1 WHERE id = $2', [refreshToken, user.rows[0].id]);

    // Send the response with the tokens
    res.json({
      access_token: accessToken,
      refresh_token: refreshToken,
      expires_in: 3600, // Token expiry time in seconds
      user: user.rows[0],
    });

  } catch (error) {
    console.error('Email Verification Error:', error);
    res.status(500).json({ error: 'Email verification failed due to a server error' });
  }
});

// Phone verification endpoint
router.post('/verify-phone', async (req, res) => {
  try {
    const { phone_number, otp } = req.body;
    const user = await query('SELECT * FROM users WHERE phone_number = $1', [phone_number]);

    if (!user.rows[0]) {
      return res.status(404).json({ error: 'User not found' });
    }

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

    if (!user.rows[0] || !(await bcrypt.compare(otp, user.rows[0].otp_hash)) ||
      new Date() > new Date(user.rows[0].otp_expiry)) {
      return res.status(401).json({ error: 'Invalid or expired OTP' });
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
// Refresh token endpoint
router.post('/refresh', async (req, res) => {
  try {
    const { refresh_token } = req.body;

    if (!refresh_token) {
      return res.status(400).json({ error: 'Refresh token is required' });
    }

    // Verify the refresh token
    const decoded = jwt.verify(refresh_token, process.env.JWT_REFRESH_SECRET);

    // Find the user using the ID from the decoded token
    const user = await query(
      'SELECT * FROM users WHERE id = $1 AND refresh_token = $2',
      [decoded.id, refresh_token]
    );

    if (!user.rows[0]) {
      return res.status(401).json({ error: 'Invalid refresh token' });
    }

    // Generate new access and refresh tokens
    const { accessToken, refreshToken } = generateTokens(user.rows[0].id);

    // Update the refresh token in the database
    await query('UPDATE users SET refresh_token = $1 WHERE id = $2', [refreshToken, user.rows[0].id]);

    // Respond with the new tokens
    res.json({
      access_token: accessToken,
      refresh_token: refreshToken,
      expires_in: 3600  // Access token expires in 1 hour
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
    if (!authHeader) {
      return res.status(400).json({ error: 'Authorization header required' });
    }

    // Extract token from the Authorization header (Bearer token)
    const token = authHeader.split(' ')[1];

    if (!token) {
      return res.status(400).json({ error: 'Access token is required' });
    }

    // Verify the access token
    const decoded = jwt.verify(token, process.env.JWT_SECRET);

    // Remove refresh token from the database for this user
    await query('UPDATE users SET refresh_token = NULL WHERE id = $1', [decoded.id]);

    // Optionally, if you're using cookies, clear the refresh token cookie here as well:
    res.clearCookie('refreshToken', { httpOnly: true, secure: true, sameSite: 'Strict' });

    // Send a response indicating successful logout
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

    if (!user.rows[0]) {
      return res.status(404).json({ error: 'User not found' });
    }

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
    
    if (!user.rows[0]) {
      return res.status(404).json({ error: 'User not found' });
    }

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

    res.json({ message: 'Verification email resent successfully' });

  } catch (error) {
    console.error('Resend Error:', error);
    res.status(500).json({ error: 'Failed to resend verification' });
  }
});

module.exports = router;