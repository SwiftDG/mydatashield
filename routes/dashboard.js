import express from 'express';
import jwt from 'jsonwebtoken';
import pool from '../config/db.js';
import dotenv from 'dotenv';
import multer from 'multer';
import path from 'path';

dotenv.config();
const router = express.Router();

// Simple auth middleware
function authMiddleware(req, res, next) {
  const token = req.cookies.token;
  if (!token) return res.redirect('/login');

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.user = decoded;
    next();
  } catch {
    res.redirect('/login');
  }
}

// -------- DASHBOARDS ---------
router.get('/user-dashboard', authMiddleware, async (req, res) => {
  if (req.user.role !== 'citizen') return res.send('Access denied');

  const consents = await pool.query(
    'SELECT c.id, u.name as org_name, c.consent_given FROM consents c JOIN users u ON u.id=c.organization_id WHERE c.user_id=$1',
    [req.user.id]
  );

  res.render('user-dashboard', { consents: consents.rows });
});

router.get('/org-dashboard', authMiddleware, async (req, res) => {
  if (req.user.role !== 'organization') return res.send('Access denied');

  const users = await pool.query(
    'SELECT u.id, u.name, u.email, c.consent_given FROM users u LEFT JOIN consents c ON u.id=c.user_id AND c.organization_id=$1',
    [req.user.id]
  );

  res.render('org-dashboard', { users: users.rows });
});

// --------- CONSENT TOGGLE ---------
router.post('/toggle-consent', authMiddleware, async (req, res) => {
  const { userId, consent } = req.body;

  try {
    await pool.query(
      `INSERT INTO consents (user_id, organization_id, consent_given)
       VALUES ($1,$2,$3)
       ON CONFLICT (user_id, organization_id) DO UPDATE SET consent_given=$3`,
      [userId, req.user.id, consent]
    );
    res.redirect('/user-dashboard');
  } catch (err) {
    console.error(err);
    res.send('Error updating consent');
  }
});

// --------- SCAN UPLOAD (ORG) ---------
const storage = multer.diskStorage({
  destination: function (req, file, cb) {
    cb(null, 'public/uploads/');
  },
  filename: function (req, file, cb) {
    cb(null, Date.now() + '-' + file.originalname);
  }
});
const upload = multer({ storage });

router.post('/upload-scan', authMiddleware, upload.single('scanFile'), async (req, res) => {
  if (req.user.role !== 'organization') return res.send('Access denied');

  const fileName = req.file.filename;

  // Simple NDPR keyword check (example)
  const keywords = ['consent', 'data', 'privacy', 'personal'];
  const text = '...'; // parse uploaded file text here
  let score = keywords.reduce((acc, word) => acc + (text.includes(word) ? 1 : 0), 0);

  await pool.query(
    'INSERT INTO scans (organization_id, file_name, compliance_score) VALUES ($1,$2,$3)',
    [req.user.id, fileName, score]
  );

  res.redirect('/org-dashboard');
});

export default router;
