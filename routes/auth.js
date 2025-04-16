const express = require('express');
const router = express.Router();
const twilio = require('twilio');
const speakeasy = require('speakeasy');
const client = twilio(process.env.TWILIO_ACCOUNT_SID, process.env.TWILIO_AUTH_TOKEN);
const createAccountLimiter = require('../config/createAccountLimiter');
const apiLimiter = require('../config/apiLimiter');

// Add to registration endpoint
router.post('/register', createAccountLimiter, async (req, res) => {
  try {
    const { first_name, last_name, email, phone_number, password } = req.body;
    
    if (!first_name || !last_name) {
      return res.status(400).json({ error: 'First and last name are required' });
    }

    if (!email && !phone_number) {
      return res.status(400).json({ error: 'Email or phone number is required' });
    }

    // Check existing user
    const existingUser = await query(
      'SELECT * FROM users WHERE email = $1 OR phone_number = $2',
      [email, phone_number]
    );

    if (existingUser.rows[0]) {
      return res.status(400).json({ error: 'Email or phone already registered' });
    }

    // Prepare verification data
    let verificationToken, otpCode, otpHash, otpExpiry;
    const hashedPassword = await bcrypt.hash(password, 12);

    if (email) {
      verificationToken = crypto.randomBytes(32).toString('hex');
    }

    if (phone_number) {
      otpCode = speakeasy.totp({
        secret: speakeasy.generateSecret().base32,
        digits: 6
      });
      otpHash = await bcrypt.hash(otpCode, 12);
      otpExpiry = new Date(Date.now() + 5 * 60000); // 5 minutes
      
      // Send SMS
      await client.messages.create({
        body: `Your verification code: ${otpCode}`,
        from: process.env.TWILIO_PHONE_NUMBER,
        to: phone_number
      });
    }

    // Insert user
    const result = await query(
      `INSERT INTO users 
      (first_name, last_name, email, phone_number, password_hash, 
       verification_token, otp_hash, otp_expiry) 
      VALUES ($1, $2, $3, $4, $5, $6, $7, $8) 
      RETURNING id, email, phone_number`,
      [first_name, last_name, email, phone_number, hashedPassword, 
       verificationToken, otpHash, otpExpiry]
    );

    // Send email verification if email exists
    if (email) {
      const verificationLink = `${process.env.BASE_URL}/auth/verify-email?token=${verificationToken}`;
      await transporter.sendMail({
        to: email,
        subject: 'Verify Your Email',
        html: `Click <a href="${verificationLink}">here</a> to verify your email`
      });
    }

    res.status(201).json({ 
      message: 'Registration successful. Check your email/phone for verification.' 
    });

  } catch (error) {
    res.status(400).json({ error: 'Registration failed' });
  }
});

// New OTP verification endpoint
router.post('/verify-phone', async (req, res) => {
  try {
    const { phone_number, otp } = req.body;
    const user = await query(
      'SELECT * FROM users WHERE phone_number = $1',
      [phone_number]
    );

    if (!user.rows[0] || !(await bcrypt.compare(otp, user.rows[0].otp_hash))) {
      return res.status(401).json({ error: 'Invalid OTP' });
    }

    if (new Date() > user.rows[0].otp_expiry) {
      return res.status(401).json({ error: 'OTP expired' });
    }

    await query(
      'UPDATE users SET phone_verified = true WHERE phone_number = $1',
      [phone_number]
    );

    res.json({ message: 'Phone verified successfully!' });
  } catch (error) {
    res.status(500).json({ error: 'Verification failed' });
  }
});

// Updated login endpoint
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

    if (!user.rows[0] || !(await bcrypt.compare(password, user.rows[0].password_hash))) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    const token = jwt.sign({ id: user.rows[0].id }, process.env.JWT_SECRET, {
      expiresIn: '1d',
    });

    res.json({ user: user.rows[0], token });
  } catch (error) {
    res.status(500).json({ error: 'Login failed' });
  }
});

// OTP Login Flow
router.post('/request-otp', apiLimiter, async (req, res) => {
  try {
    const { phone_number } = req.body;
    const user = await query(
      'SELECT * FROM users WHERE phone_number = $1',
      [phone_number]
    );

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
    await query(
      'UPDATE users SET otp_hash = $1, otp_expiry = $2 WHERE phone_number = $3',
      [otpHash, new Date(Date.now() + 300000), phone_number]
    );

    res.json({ message: 'OTP sent successfully' });
  } catch (error) {
    res.status(500).json({ error: 'Failed to send OTP' });
  }
});

router.post('/login-otp', apiLimiter, async (req, res) => {
  try {
    const { phone_number, otp } = req.body;
    const user = await query(
      'SELECT * FROM users WHERE phone_number = $1',
      [phone_number]
    );

    if (!user.rows[0] || 
        !(await bcrypt.compare(otp, user.rows[0].otp_hash)) ||
        new Date() > user.rows[0].otp_expiry) {
      return res.status(401).json({ error: 'Invalid OTP' });
    }

    const token = jwt.sign({ id: user.rows[0].id }, process.env.JWT_SECRET, {
      expiresIn: '1d',
    });

    res.json({ user: user.rows[0], token });
  } catch (error) {
    res.status(500).json({ error: 'Login failed' });
  }
});


module.exports = router;