const express = require('express');
const { query } = require('../config/database');
const { authenticate } = require('../middlewares');
const bcrypt = require('bcrypt');

const router = express.Router();

// Security-sensitive fields to exclude
const EXCLUDED_FIELDS = [
  'password_hash',
  'verification_token',
  'otp_hash',
  'otp_expiry',
  'otp_secret',
  'refresh_token'
];

// GET current user's profile (authenticated)
router.get('/', authenticate, async (req, res) => {
  try {
    const user = await query(
      `SELECT id, email, first_name, last_name, phone_number, 
       created_at, email_verified, phone_verified, age, gender, 
       id_image_url, id_verified, profile_image_url
       FROM users 
       WHERE id = $1`,
      [req.user.id]
    );

    if (user.rows.length === 0) {
      return res.status(404).json({ error: 'User not found' });
    }

    res.json({ user: user.rows[0] });
  } catch (error) {
    console.error('Profile fetch error:', error);
    res.status(500).json({ error: 'Failed to fetch profile' });
  }
});

// GET any user's profile by userId param (authenticated)
router.get('/:userId', authenticate, async (req, res) => {
  try {
    const { userId } = req.params;

    const user = await query(
      `SELECT id, email, first_name, last_name, phone_number, 
       created_at, email_verified, phone_verified, age, gender, 
       id_image_url, id_verified, profile_image_url
       FROM users 
       WHERE id = $1`,
      [userId]
    );

    if (user.rows.length === 0) {
      return res.status(404).json({ error: 'User not found' });
    }

    res.json({ user: user.rows[0] });
  } catch (error) {
    console.error('Profile fetch error:', error);
    res.status(500).json({ error: 'Failed to fetch profile' });
  }
});

// PUT to update current user's profile
router.put('/', authenticate, async (req, res) => {
  try {
    const { email, password, first_name, last_name, phone_number, age, gender } = req.body;
    const updates = [];
    const values = [];
    let index = 1;

    // Add updatable fields
    const updatableFields = {
      email: { value: email, type: 'string' },
      password: { value: password, type: 'password' },
      first_name: { value: first_name, type: 'string' },
      last_name: { value: last_name, type: 'string' },
      phone_number: { value: phone_number, type: 'string' },
      age: { value: age, type: 'number' },
      gender: { value: gender, type: 'string' }
    };

    for (const [field, config] of Object.entries(updatableFields)) {
      if (config.value !== undefined) {
        if (field === 'password') {
          const hashedPassword = await bcrypt.hash(config.value, 10);
          updates.push(`password_hash = $${index}`);
          values.push(hashedPassword);
        } else {
          updates.push(`${field} = $${index}`);
          values.push(config.value);
        }
        index++;
      }
    }

    if (updates.length === 0) {
      return res.status(400).json({ error: 'No fields to update' });
    }

    values.push(req.user.id);

    const result = await query(
      `UPDATE users 
       SET ${updates.join(', ')} 
       WHERE id = $${index}
       RETURNING id, email, first_name, last_name, phone_number, 
       created_at, email_verified, phone_verified, age, gender, 
       id_image_url, id_verified, profile_image_url`,
      values
    );

    res.json({ user: result.rows[0] });
  } catch (error) {
    if (error.code === '23505') {
      res.status(400).json({ error: 'Email or phone number already in use' });
    } else {
      console.error('Profile update error:', error);
      res.status(500).json({ error: 'Failed to update profile' });
    }
  }
});

module.exports = router;