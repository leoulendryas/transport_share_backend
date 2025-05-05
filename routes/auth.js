const express = require('express');
const router = express.Router();
const twilio = require('twilio');
const speakeasy = require('speakeasy');
const bcrypt = require('bcrypt');
const crypto = require('crypto');
const jwt = require('jsonwebtoken');
const multer = require('multer');
const path = require('path');
const transporter = require('../config/nodemailer');
const createAccountLimiter = require('../config/createAccountLimiter');
const apiLimiter = require('../config/apiLimiter');
const { body, query: validateQuery, validationResult } = require('express-validator');
const { query: dbQuery, pool } = require('../config/database');

const client = twilio(process.env.TWILIO_ACCOUNT_SID, process.env.TWILIO_AUTH_TOKEN);

const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, 'uploads/ids/');
  },
  filename: (req, file, cb) => {
    const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1e9);
    cb(null, `id-${uniqueSuffix}${path.extname(file.originalname)}`);
  }
});

const fileFilter = (req, file, cb) => {
  const allowedTypes = ['image/jpeg', 'image/png', 'application/pdf'];
  allowedTypes.includes(file.mimetype) ? cb(null, true) : cb(new Error('Invalid file type'));
};

const upload = multer({
  storage,
  fileFilter,
  limits: { fileSize: 5 * 1024 * 1024 }
});

const authenticateUser = async (req, res, next) => {
  try {
    const authHeader = req.headers.authorization;
    if (!authHeader) return res.status(401).json({ error: 'Authorization header missing' });
    
    const token = authHeader.split(' ')[1];
    if (!token) return res.status(401).json({ error: 'Access token missing' });

    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    const user = await dbQuery('SELECT * FROM users WHERE id = $1', [decoded.id]);
    
    if (!user.rows[0]) return res.status(401).json({ error: 'User not found' });
    if (user.rows[0].banned) return res.status(403).json({ error: 'Account suspended' });
    
    req.user = user.rows[0];
    next();
  } catch (error) {
    res.status(401).json({ error: 'Invalid access token' });
  }
};

const isAdmin = (req, res, next) => {
  req.user?.is_admin ? next() : res.status(403).json({ error: 'Admin access required' });
};

const generateTokens = (userId) => ({
  accessToken: jwt.sign({ id: userId }, process.env.JWT_SECRET, { expiresIn: '1h' }),
  refreshToken: jwt.sign(
    { id: userId }, 
    process.env.JWT_REFRESH_SECRET, 
    { expiresIn: process.env.JWT_REFRESH_EXPIRY || '7d' }
  )
});

router.post('/register', [
  createAccountLimiter,
  body('first_name').notEmpty().trim().escape(),
  body('last_name').notEmpty().trim().escape(),
  body('password').isLength({ min: 8 }),
  body().custom(body => {
    if (!body.email && !body.phone_number) throw new Error('Either email or phone must be provided');
    if (body.email && body.phone_number) throw new Error('Cannot provide both email and phone');
    return true;
  }),
  body('email').if(body => body.email).isEmail().normalizeEmail(),
  body('phone_number').if(body => body.phone_number).isMobilePhone()
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });

  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const { first_name, last_name, email, phone_number, password, age, gender } = req.body;

    const credential = email || phone_number;
    const checkField = email ? 'email' : 'phone_number';
    const existingUser = await client.query(
      `SELECT * FROM users WHERE ${checkField} = $1 FOR UPDATE`,
      [credential]
    );

    if (existingUser.rows[0]) {
      return res.status(400).json({ 
        error: `${checkField.replace('_', ' ')} already registered`
      });
    }

    const hashedPassword = await bcrypt.hash(password, 12);
    const verificationToken = crypto.randomBytes(32).toString('hex');
    const otpSecret = speakeasy.generateSecret().base32;
    const otpCode = speakeasy.totp({ secret: otpSecret, digits: 6 });

    const result = await client.query(
      `INSERT INTO users 
      (first_name, last_name, email, phone_number, password_hash, 
       verification_token, otp_secret, age, gender) 
      VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
      RETURNING id, first_name, last_name, email, phone_number, age, gender`,
      [
        first_name, 
        last_name, 
        email || null, 
        phone_number || null, 
        hashedPassword,
        verificationToken,
        otpSecret,
        age || null, 
        gender || null
      ]
    );

    if (phone_number) {
      await client.messages.create({
        body: `Your verification code: ${otpCode}`,
        from: process.env.TWILIO_PHONE_NUMBER,
        to: phone_number
      });
    } else if (email) {
      const verificationLink = `${process.env.BASE_URL}/auth/verify-email?token=${verificationToken}`;
      await transporter.sendMail({
        to: email,
        subject: 'Verify Your Email Address',
        html: `
          <div style="background-color: #F7F9F9; padding: 40px; font-family: Arial, sans-serif; color: #004F2D; text-align: center;">
            <div style="max-width: 600px; margin: auto; border: 2px solid #004F2D; border-radius: 12px; padding: 30px;">
              <h1 style="color: #004F2D;">Welcome to Transport Sharing!</h1>
              <p style="font-size: 16px; margin-bottom: 30px;">
                You're almost there! Please verify your email to activate your account.
              </p>
              <a href="${verificationLink}" 
                 style="display: inline-block; background-color: #004F2D; color: #F7F9F9; padding: 15px 30px; 
                        border-radius: 8px; text-decoration: none; font-size: 16px; font-weight: bold;">
                Verify Email
              </a>
              <p style="margin-top: 30px; font-size: 14px; color: #555;">
                If you did not sign up, please ignore this message.
              </p>
            </div>
          </div>
        `
      });
    }
    
    await client.query('COMMIT');
    res.status(201).json({ 
      message: `Registration successful. Check your ${email ? 'email' : 'phone'} for verification.`,
      methodUsed: email ? 'email' : 'phone'
    });    
  } catch (error) {
    await client.query('ROLLBACK');
    res.status(500).json({ 
      error: error.code === '23514' 
        ? 'Must provide email or phone' 
        : 'Registration failed' 
    });
  } finally {
    client.release();
  }
});

router.get('/verify-email', [
  validateQuery('token')
    .isLength({ min: 64, max: 64 })
    .withMessage('Invalid verification token format')
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });

  try {
    const { token } = req.query;
    const user = await dbQuery(
      `UPDATE users SET email_verified = true, verification_token = NULL 
       WHERE verification_token = $1 RETURNING *`,
      [token]
    );

    if (!user.rows[0]) {
      return res.status(400).json({ error: 'Invalid or expired verification token' });
    }

    const { accessToken, refreshToken } = generateTokens(user.rows[0].id);
    await dbQuery('UPDATE users SET refresh_token = $1 WHERE id = $2', [refreshToken, user.rows[0].id]);

    res.json({
      message: 'Email verified successfully',
      verified: true,
      access_token: accessToken,
      refresh_token: refreshToken,
      user: user.rows[0]
    });
  } catch (error) {
    res.status(500).json({ error: 'Email verification failed' });
  }
});

router.post('/verify-phone', [
  body('phone_number').isMobilePhone(),
  body('otp').isLength({ min: 6, max: 6 })
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });

  try {
    const { phone_number, otp } = req.body;
    const user = await dbQuery('SELECT * FROM users WHERE phone_number = $1', [phone_number]);

    if (!user.rows[0]) return res.status(404).json({ error: 'User not found' });

    const isValid = speakeasy.totp.verify({
      secret: user.rows[0].otp_secret,
      encoding: 'base32',
      token: otp,
      window: 2
    });

    if (!isValid) return res.status(401).json({ error: 'Invalid OTP' });

    await dbQuery('UPDATE users SET phone_verified = true WHERE id = $1', [user.rows[0].id]);
    
    const { accessToken, refreshToken } = generateTokens(user.rows[0].id);
    await dbQuery('UPDATE users SET refresh_token = $1 WHERE id = $2', [refreshToken, user.rows[0].id]);

    res.json({
      access_token: accessToken,
      refresh_token: refreshToken,
      expires_in: 3600,
      user: user.rows[0]
    });
  } catch (error) {
    res.status(500).json({ error: 'Verification failed' });
  }
});

router.post('/login', [
  apiLimiter,
  body('email').optional().isEmail(),
  body('phone_number').optional().isMobilePhone(),
  body('password').notEmpty()
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });

  try {
    const { email, phone_number, password } = req.body;
    let user;

    if (email) {
      user = await dbQuery('SELECT * FROM users WHERE email = $1', [email]);
      if (!user.rows[0]?.email_verified) {
        return res.status(401).json({ error: 'Email not verified' });
      }
    } else if (phone_number) {
      user = await dbQuery('SELECT * FROM users WHERE phone_number = $1', [phone_number]);
      if (!user.rows[0]?.phone_verified) {
        return res.status(401).json({ error: 'Phone not verified' });
      }
    }

    if (!user?.rows[0] || !(await bcrypt.compare(password, user.rows[0].password_hash))) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    const { accessToken, refreshToken } = generateTokens(user.rows[0].id);
    await dbQuery('UPDATE users SET refresh_token = $1 WHERE id = $2', [refreshToken, user.rows[0].id]);

    res.json({
      access_token: accessToken,
      refresh_token: refreshToken,
      expires_in: 3600,
      user: user.rows[0]
    });
  } catch (error) {
    res.status(500).json({ error: 'Login failed' });
  }
});

router.post('/login-otp', [
  apiLimiter,
  body('phone_number').isMobilePhone(),
  body('otp').isLength({ min: 6, max: 6 })
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });

  try {
    const { phone_number, otp } = req.body;
    const user = await dbQuery('SELECT * FROM users WHERE phone_number = $1', [phone_number]);

    if (!user.rows[0]) return res.status(404).json({ error: 'User not found' });

    const isValid = speakeasy.totp.verify({
      secret: user.rows[0].otp_secret,
      encoding: 'base32',
      token: otp,
      window: 2
    });

    if (!isValid) return res.status(401).json({ error: 'Invalid OTP' });

    const { accessToken, refreshToken } = generateTokens(user.rows[0].id);
    await dbQuery('UPDATE users SET refresh_token = $1 WHERE id = $2', [refreshToken, user.rows[0].id]);

    res.json({
      access_token: accessToken,
      refresh_token: refreshToken,
      expires_in: 3600,
      user: user.rows[0]
    });
  } catch (error) {
    res.status(500).json({ error: 'Login failed' });
  }
});

router.post('/refresh', [
  body('refresh_token').notEmpty()
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });

  try {
    const { refresh_token } = req.body;
    const decoded = jwt.verify(refresh_token, process.env.JWT_REFRESH_SECRET);
    const user = await dbQuery(
      'SELECT * FROM users WHERE id = $1 AND refresh_token = $2',
      [decoded.id, refresh_token]
    );

    if (!user.rows[0]) return res.status(401).json({ error: 'Invalid refresh token' });

    const { accessToken, refreshToken } = generateTokens(user.rows[0].id);
    await dbQuery('UPDATE users SET refresh_token = $1 WHERE id = $2', [refreshToken, user.rows[0].id]);

    res.json({
      access_token: accessToken,
      refresh_token: refreshToken,
      expires_in: 3600
    });
  } catch (error) {
    res.status(401).json({ error: 'Invalid refresh token' });
  }
});

router.post('/logout', authenticateUser, async (req, res) => {
  try {
    await dbQuery('UPDATE users SET refresh_token = NULL WHERE id = $1', [req.user.id]);
    res.clearCookie('refreshToken', { httpOnly: true, secure: true, sameSite: 'Strict' });
    res.sendStatus(204);
  } catch (error) {
    res.status(500).json({ error: 'Logout failed' });
  }
});

router.post('/request-otp', [
  apiLimiter,
  body('phone_number').isMobilePhone()
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });

  try {
    const { phone_number } = req.body;
    const user = await dbQuery('SELECT * FROM users WHERE phone_number = $1', [phone_number]);

    if (!user.rows[0]) return res.status(404).json({ error: 'User not found' });

    const otpCode = speakeasy.totp({
      secret: user.rows[0].otp_secret,
      digits: 6
    });

    await client.messages.create({
      body: `Your login OTP: ${otpCode}`,
      from: process.env.TWILIO_PHONE_NUMBER,
      to: phone_number
    });

    res.json({ message: 'OTP sent successfully' });
  } catch (error) {
    res.status(500).json({ error: 'Failed to send OTP' });
  }
});

router.post('/resend-verification', [
  body('email').isEmail()
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });

  try {
    const { email } = req.body;
    const user = await dbQuery('SELECT * FROM users WHERE email = $1', [email]);
    if (!user.rows[0]) return res.status(404).json({ error: 'User not found' });

    const verificationToken = crypto.randomBytes(32).toString('hex');
    await dbQuery(
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
    res.status(500).json({ error: 'Failed to resend verification' });
  }
});

router.post('/verify-identity', 
  authenticateUser,
  upload.single('id_image'),
  [
    body('name').notEmpty(),
    body('age').isInt({ min: 18 }),
    body('gender').isIn(['male', 'female', 'other']),
    body('id_type').notEmpty()
  ],
  async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });

    try {
      const { name, age, gender, id_type } = req.body;
      const idImageUrl = `/ids/${req.file.filename}`;

      await dbQuery(
        `UPDATE users 
        SET name = $1, age = $2, gender = $3, id_image_url = $4, id_verified = FALSE 
        WHERE id = $5`,
        [name, age, gender, idImageUrl, req.user.id]
      );

      res.status(201).json({ 
        message: 'ID verification submitted for review',
        verification_status: 'pending'
      });
    } catch (error) {
      res.status(500).json({ error: 'ID verification submission failed' });
    }
  }
);

router.post('/admin/verify-id', 
  authenticateUser,
  isAdmin,
  [
    body('userId').isInt()
  ],
  async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });

    try {
      const { userId } = req.body;      
      await dbQuery('UPDATE users SET id_verified = TRUE WHERE id = $1', [userId]);
      res.json({ message: 'ID verification approved' });
    } catch (error) {
      res.status(500).json({ error: 'Verification approval failed' });
    }
  }
);

router.post('/rides',
  authenticateUser,
  [
    body('destination').notEmpty(),
    body('departure_time').isISO8601()
  ],
  async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });

    try {
      res.json({ message: 'Ride posted successfully' });
    } catch (error) {
      res.status(500).json({ error: 'Failed to post ride' });
    }
  }
);

module.exports = router;