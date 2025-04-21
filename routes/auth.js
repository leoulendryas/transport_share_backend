const express = require('express');
const router = express.Router();
const twilio = require('twilio');
const speakeasy = require('speakeasy');
const bcrypt = require('bcrypt');
const crypto = require('crypto');
const jwt = require('jsonwebtoken');
const { query } = require('../config/database'); // adjust this path to your DB config
const transporter = require('../config/nodemailer'); // adjust this path to your nodemailer config
const createAccountLimiter = require('../config/createAccountLimiter');
const apiLimiter = require('../config/apiLimiter');

const client = twilio(process.env.TWILIO_ACCOUNT_SID, process.env.TWILIO_AUTH_TOKEN);

// Register endpoint
router.post('/register', createAccountLimiter, async (req, res) => {
  try {
    const { first_name, last_name, email, phone_number, password } = req.body;

    if (!first_name || !last_name) {
      return res.status(400).json({ error: 'First and last name are required' });
    }

    if (!email && !phone_number) {
      return res.status(400).json({ error: 'Email or phone number is required' });
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
    let otpCode = null;
    let otpHash = null;
    let otpExpiry = null;

    if (email) {
      verificationToken = crypto.randomBytes(32).toString('hex');
    }

    if (phone_number) {
      otpCode = speakeasy.totp({
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
      RETURNING id, email, phone_number`,
      [
        first_name,
        last_name,
        email,
        phone_number,
        hashedPassword,
        verificationToken,
        otpHash,
        otpExpiry
      ]
    );

    if (email) {
      const verificationLink = `${process.env.BASE_URL}/auth/verify-email?token=${verificationToken}`;
      await transporter.sendMail({
        to: email,
        subject: 'Verify Your Email Address',
        html: `
          <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 40px; background-color: #f7f9f9; border-radius: 8px; box-shadow: 0 4px 12px rgba(0,0,0,0.05);">
            <div style="text-align: center; margin-bottom: 24px;">
              <h2 style="color: #004F2D; margin: 0;">Transport Share</h2>
              <p style="color: #7F6A93; font-size: 16px;">Secure Your Account</p>
            </div>
            
            <p style="font-size: 16px; color: #333; margin-bottom: 24px;">
              Hi there,<br /><br />
              Thank you for signing up! To complete your registration and start using Transport Share, please verify your email address by clicking the button below:
            </p>
    
            <div style="text-align: center; margin: 30px 0;">
              <a href="${verificationLink}" style="background-color: #004F2D; color: #ffffff; text-decoration: none; padding: 14px 28px; border-radius: 6px; font-weight: bold; display: inline-block;">
                Verify My Email
              </a>
            </div>
    
            <p style="font-size: 14px; color: #555;">
              Or copy and paste this URL into your browser:<br />
              <a href="${verificationLink}" style="color: #004F2D;">${verificationLink}</a>
            </p>
    
            <hr style="margin: 40px 0; border: none; border-top: 1px solid #eee;" />
    
            <p style="font-size: 12px; color: #888888;">
              If you didn’t create an account, no further action is required.
            </p>
          </div>
        `,
      });
    }    

    res.status(201).json({
      message: 'Registration successful. Check your email/phone for verification.',
      user: result.rows[0]
    });

  } catch (error) {
    console.error('Registration Error:', error);
    res.status(500).json({ error: 'Registration failed' });
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

    await query('UPDATE users SET phone_verified = true WHERE phone_number = $1', [phone_number]);

    res.json({ message: 'Phone verified successfully!' });
  } catch (error) {
    console.error('Verify Phone Error:', error);
    res.status(500).json({ error: 'Verification failed' });
  }
});

// Add this email verification endpoint
router.get('/verify-email', async (req, res) => {
  try {
    const { token } = req.query;
    const user = await query(
      'UPDATE users SET email_verified = true, verification_token = NULL ' +
      'WHERE verification_token = $1 RETURNING id, email',
      [token]
    );

    if (!user.rows[0]) {
      return res.status(400).json({ error: 'Invalid or expired verification token' });
    }

    res.json({ message: 'Email verified successfully! You can now login.' });
  } catch (error) {
    console.error('Verify Email Error:', error);
    res.status(500).json({ error: 'Verification failed' });
  }
});

// Email/phone + password login
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
      expiresIn: '1d'
    });

    res.json({ user: user.rows[0], token });
  } catch (error) {
    console.error('Login Error:', error);
    res.status(500).json({ error: 'Login failed' });
  }
});

// Request OTP for login
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
    console.error('Request OTP Error:', error);
    res.status(500).json({ error: 'Failed to send OTP' });
  }
});

// Login with OTP
router.post('/login-otp', apiLimiter, async (req, res) => {
  try {
    const { phone_number, otp } = req.body;

    const user = await query('SELECT * FROM users WHERE phone_number = $1', [phone_number]);

    if (
      !user.rows[0] ||
      !(await bcrypt.compare(otp, user.rows[0].otp_hash)) ||
      new Date() > new Date(user.rows[0].otp_expiry)
    ) {
      return res.status(401).json({ error: 'Invalid or expired OTP' });
    }

    const token = jwt.sign({ id: user.rows[0].id }, process.env.JWT_SECRET, {
      expiresIn: '1d'
    });

    res.json({ user: user.rows[0], token });
  } catch (error) {
    console.error('Login OTP Error:', error);
    res.status(500).json({ error: 'Login failed' });
  }
});

// Resend verification email
router.post('/resend-verification', async (req, res) => {
  try {
    const { email } = req.body;
    const user = await query('SELECT * FROM users WHERE email = $1', [email]);
    
    if (!user.rows[0]) {
      return res.status(404).json({ error: 'User not found' });
    }

    const verificationToken = crypto.randomBytes(32).toString('hex');
    await query(
      'UPDATE users SET verification_token = $1 WHERE email = $2',
      [verificationToken, email]
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
