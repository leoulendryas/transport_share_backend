const express = require('express');
const { query } = require('../config/database');
const { authenticate } = require('../middlewares');
const bcrypt = require('bcrypt');

const router = express.Router();

// GET user profile with more fields
router.get('/', authenticate, async (req, res) => {
  try {
    const user = await query(
      `SELECT id, email, first_name, last_name, phone_number, created_at, email_verified, phone_verified
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

// PUT to update user profile
router.put('/', authenticate, async (req, res) => {
  try {
    const { email, password, first_name, last_name, phone_number } = req.body;
    const updates = [];
    const values = [];
    let index = 1;

    if (email !== undefined) {
      updates.push(`email = $${index}`);
      values.push(email);
      index++;
    }

    if (password !== undefined) {
      const hashedPassword = await bcrypt.hash(password, 10);
      updates.push(`password_hash = $${index}`);
      values.push(hashedPassword);
      index++;
    }

    if (first_name !== undefined) {
      updates.push(`first_name = $${index}`);
      values.push(first_name);
      index++;
    }

    if (last_name !== undefined) {
      updates.push(`last_name = $${index}`);
      values.push(last_name);
      index++;
    }

    if (phone_number !== undefined) {
      updates.push(`phone_number = $${index}`);
      values.push(phone_number);
      index++;
    }

    if (updates.length === 0) {
      return res.status(400).json({ error: 'No fields to update' });
    }

    values.push(req.user.id); // Add user ID at the end

    const result = await query(
      `UPDATE users SET ${updates.join(', ')} WHERE id = $${index} RETURNING id, email, first_name, last_name, phone_number, created_at`,
      values
    );

    res.json({ user: result.rows[0] });
  } catch (error) {
    if (error.code === '23505') {
      res.status(400).json({ error: 'Email already in use' });
    } else {
      console.error('Profile update error:', error);
      res.status(500).json({ error: 'Failed to update profile' });
    }
  }
});

module.exports = router;
