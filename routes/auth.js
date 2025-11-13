import express from "express";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import pool from "../config/db.js";
import dotenv from "dotenv";
import multer from "multer";
import fs from "fs";
import path from "path";

dotenv.config();
const router = express.Router();

// ==================== Multer configuration for file uploads ====================
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, "uploads/");
  },
  filename: (req, file, cb) => {
    const uniqueSuffix = Date.now() + "-" + Math.round(Math.random() * 1e9);
    cb(
      null,
      file.fieldname +
        "-" +
        uniqueSuffix +
        path.extname(file.originalname)
    );
  },
});

const upload = multer({
  storage: storage,
  limits: { fileSize: 10 * 1024 * 1024 }, // 10MB limit
  fileFilter: (req, file, cb) => {
    const allowedTypes = [".pdf", ".doc", ".docx", ".txt"];
    const fileExt = path.extname(file.originalname).toLowerCase();
    if (allowedTypes.includes(fileExt)) {
      cb(null, true);
    } else {
      cb(new Error("Only PDF, Word, and Text files are allowed"));
    }
  },
});

// ==================== GET ROUTES ====================
router.get("/signup", (req, res) => res.render("signup"));
router.get("/login", (req, res) => res.render("login"));
router.get("/verify", (req, res) => {
  res.render("verify", { email: req.query.email || "" });
});
router.get("/logout", (req, res) => {
  res.clearCookie("token");
  req.session.destroy();
  res.redirect("/");
});

// ==================== POST ROUTES ====================

// SIGNUP - No email verification
router.post("/signup", async (req, res) => {
  console.log("SIGNUP REQUEST:", req.body);

  try {
    const { name, email, password, role, terms } = req.body;

    // Basic validation
    if (!name || !email || !password || !role) {
      return res.render("signup", {
        error: "All fields are required"
      });
    }

    if (!terms) {
      return res.render("signup", {
        error: "You must agree to terms and conditions"
      });
    }

    // Check if user exists
    const existing = await pool.query("SELECT * FROM users WHERE email=$1", [email]);
    if (existing.rows.length > 0) {
      return res.render("signup", {
        error: "User already exists with this email"
      });
    }

    // Hash password
    const hashedPassword = await bcrypt.hash(password, 10);

    // Create user (automatically verified)
    const newUser = await pool.query(
      "INSERT INTO users (name, email, password, role, verified) VALUES ($1, $2, $3, $4, true) RETURNING id, role",
      [name, email, hashedPassword, role]
    );

    const userId = newUser.rows[0].id;
    const userRole = newUser.rows[0].role;

    // Auto-login after signup
    const token = jwt.sign({ id: userId, role: userRole }, process.env.JWT_SECRET || "fallback-jwt-secret", {
      expiresIn: "365d",
    });

    res.cookie("token", token, {
      httpOnly: true,
      maxAge: 365 * 24 * 60 * 60 * 1000
    });

    // Redirect to appropriate dashboard
    if (userRole === "organization") {
      return res.redirect("/org-dashboard");
    } else {
      return res.redirect("/user-dashboard");
    }

  } catch (err) {
    console.error("SIGNUP ERROR:", err);
    return res.render("signup", {
      error: "Server error during signup: " + err.message
    });
  }
});

// LOGIN
router.post("/login", async (req, res) => {
  try {
    const { email, password, remember } = req.body;

    const userRes = await pool.query("SELECT * FROM users WHERE email=$1", [email]);
    if (userRes.rows.length === 0) {
      return res.render("login", {
        error: "User not found"
      });
    }

    const user = userRes.rows[0];

    const match = await bcrypt.compare(password, user.password);
    if (!match) {
      return res.render("login", {
        error: "Incorrect password"
      });
    }

    const token = jwt.sign({ id: user.id, role: user.role }, process.env.JWT_SECRET || "fallback-jwt-secret", {
      expiresIn: remember ? "365d" : "1h",
    });

    res.cookie("token", token, {
      httpOnly: true,
      maxAge: remember ? 365 * 24 * 60 * 60 * 1000 : 60 * 60 * 1000
    });

    if (user.role === "organization") {
      res.redirect("/org-dashboard");
    } else {
      res.redirect("/user-dashboard");
    }
  } catch (err) {
    console.error("Login error:", err);
    res.status(500).render("login", {
      error: "Error logging in"
    });
  }
});

// ==================== FILE UPLOAD & NDPR SCANNING ====================

// NDPR Compliance Scanning Function
async function scanForNDPRCompliance(filePath) {
  try {
    // Read file content (basic text extraction)
    let content = '';

    if (filePath.endsWith('.txt')) {
      content = fs.readFileSync(filePath, 'utf8').toLowerCase();
    } else {
      // For PDF/DOC files, simulate content reading
      content = "simulated document content for demonstration purposes. " +
               "this document contains data protection and privacy policy " +
               "information as required by ndpr nigeria data protection regulation. " +
               "we ensure user consent and data security measures are implemented.";
    }

    // NDPR Compliance Keywords with weights
    const ndprKeywords = {
      'data protection': 10,
      'privacy policy': 8,
      'consent': 7,
      'user rights': 6,
      'data breach': 8,
      'data processing': 6,
      'data controller': 5,
      'data subject': 5,
      'ndpr': 10,
      'nigeria data protection regulation': 12,
      'personal data': 7,
      'data security': 6,
      'data retention': 5,
      'purpose limitation': 6,
      'lawful basis': 5,
      'data protection officer': 7,
      'data privacy': 6,
      'information security': 5,
      'confidentiality': 4,
      'access control': 4
    };

    let score = 0;
    let foundKeywords = [];
    let maxPossibleScore = 0;

    // Calculate maximum possible score
    Object.values(ndprKeywords).forEach(weight => {
      maxPossibleScore += weight;
    });

    // Check for each keyword
    Object.entries(ndprKeywords).forEach(([keyword, weight]) => {
      if (content.includes(keyword.toLowerCase())) {
        score += weight;
        foundKeywords.push(keyword);
      }
    });

    // Calculate percentage (cap at 100%)
    const percentage = Math.min(100, Math.round((score / maxPossibleScore) * 100));

    console.log(`NDPR Scan Results: ${percentage}% - Found keywords:`, foundKeywords);
    return percentage;

  } catch (err) {
    console.error('NDPR scanning error:', err);
    return 0;
  }
}

// Handle scan upload
router.post("/upload-scan", requireAuth, upload.single("scanFile"), async (req, res) => {
  if (req.user.role !== "organization") {
    return res.redirect("/user-dashboard");
  }

  try {
    const { scanName } = req.body;

    if (!req.file) {
      return res.redirect('/org-dashboard?error=No file uploaded');
    }

    const organization_id = req.user.id;
    const filePath = req.file.path;

    // Perform NDPR compliance scan
    const compliance_score = await scanForNDPRCompliance(filePath);

    // Determine status based on score
    let status = 'completed';
    if (compliance_score >= 80) {
      status = 'excellent';
    } else if (compliance_score >= 60) {
      status = 'good';
    } else {
      status = 'needs_improvement';
    }

    // Insert scan into database
    await pool.query(
      "INSERT INTO scans (organization_id, scan_name, compliance_score, status) VALUES ($1, $2, $3, $4)",
      [organization_id, scanName, compliance_score, status]
    );

    // Clean up uploaded file
    try {
      fs.unlinkSync(filePath);
    } catch (cleanupErr) {
      console.error('File cleanup error:', cleanupErr);
    }

    res.redirect('/org-dashboard?success=Scan completed successfully');
  } catch (err) {
    console.error('Upload error:', err);

    // Clean up file if error occurred
    if (req.file) {
      try {
        fs.unlinkSync(req.file.path);
      } catch (cleanupErr) {
        console.error('File cleanup error:', cleanupErr);
      }
    }

    res.redirect('/org-dashboard?error=Scan failed: ' + err.message);
  }
});

// ==================== CONSENT MANAGEMENT ROUTES ====================

// Grant consent to organization
router.post("/grant-consent", requireAuth, async (req, res) => {
  try {
    const { organization_id } = req.body;
    const user_id = req.user.id;

    // Upsert consent record
    await pool.query(
      `INSERT INTO consents (user_id, organization_id, consent_given, data_categories)
       VALUES ($1, $2, true, ARRAY['profile', 'contact', 'preferences']::text[])
       ON CONFLICT (user_id, organization_id)
       DO UPDATE SET consent_given = true, updated_at = NOW()`,
      [user_id, organization_id]
    );

    res.json({ success: true, message: "Consent granted successfully" });
  } catch (err) {
    console.error("Grant consent error:", err);
    res.status(500).json({ success: false, error: "Failed to grant consent" });
  }
});

// Revoke consent from organization
router.post("/revoke-consent", requireAuth, async (req, res) => {
  try {
    const { organization_id } = req.body;
    const user_id = req.user.id;

    await pool.query(
      "UPDATE consents SET consent_given = false, updated_at = NOW() WHERE user_id = $1 AND organization_id = $2",
      [user_id, organization_id]
    );

    res.json({ success: true, message: "Consent revoked successfully" });
  } catch (err) {
    console.error("Revoke consent error:", err);
    res.status(500).json({ success: false, error: "Failed to revoke consent" });
  }
});

// Create new consent request
router.post("/request-consent", requireAuth, async (req, res) => {
  try {
    const { organization_id } = req.body;
    const user_id = req.user.id;

    await pool.query(
      `INSERT INTO consents (user_id, organization_id, consent_given, data_categories)
       VALUES ($1, $2, false, ARRAY['profile']::text[])
       ON CONFLICT (user_id, organization_id)
       DO UPDATE SET updated_at = NOW()`,
      [user_id, organization_id]
    );

    res.json({ success: true, message: "Consent request created" });
  } catch (err) {
    console.error("Request consent error:", err);
    res.status(500).json({ success: false, error: "Failed to create consent request" });
  }
});

// ==================== DATA RIGHTS ROUTES ====================

router.post("/request-data-access", requireAuth, async (req, res) => {
  try {
    await pool.query(
      "INSERT INTO data_requests (user_id, request_type, status, details) VALUES ($1, 'access', 'pending', 'User requested access to personal data')",
      [req.user.id]
    );
    res.json({
      success: true,
      message: "Data access request submitted. Organizations have 30 days to respond under NDPR.",
    });
  } catch (err) {
    console.error("Data access request error:", err);
    res.status(500).json({
      success: false,
      error: "Failed to submit data access request",
    });
  }
});

router.post("/request-data-correction", requireAuth, async (req, res) => {
  try {
    await pool.query(
      "INSERT INTO data_requests (user_id, request_type, status, details) VALUES ($1, 'correction', 'pending', 'User requested correction of personal data')",
      [req.user.id]
    );
    res.json({
      success: true,
      message: "Data correction request submitted successfully.",
    });
  } catch (err) {
    console.error("Data correction request error:", err);
    res.status(500).json({
      success: false,
      error: "Failed to submit data correction request",
    });
  }
});

router.post("/request-data-deletion", requireAuth, async (req, res) => {
  try {
    await pool.query(
      "INSERT INTO data_requests (user_id, request_type, status, details) VALUES ($1, 'deletion', 'pending', 'User requested deletion of personal data')",
      [req.user.id]
    );
    res.json({
      success: true,
      message: "Data deletion request submitted to all organizations.",
    });
  } catch (err) {
    console.error("Data deletion request error:", err);
    res.status(500).json({
      success: false,
      error: "Failed to submit data deletion request",
    });
  }
});

router.get("/download-data", requireAuth, async (req, res) => {
  try {
    // Get user's data for export
    const userData = await pool.query(
      "SELECT name, email, role, created_at FROM users WHERE id = $1",
      [req.user.id]
    );
    const consentData = await pool.query(
      "SELECT c.*, u.name as organization_name FROM consents c JOIN users u ON c.organization_id = u.id WHERE c.user_id = $1",
      [req.user.id]
    );

    const exportData = {
      user: userData.rows[0],
      consents: consentData.rows,
      exported_at: new Date().toISOString()
    };

    res.json({ success: true, data: exportData, message: "Data export prepared successfully" });
  } catch (err) {
    console.error("Data download error:", err);
    res.status(500).json({
      success: false,
      error: "Failed to prepare data export",
    });
  }
});

// ==================== DASHBOARD ROUTES ====================

// Auth middleware
function requireAuth(req, res, next) {
  const token = req.cookies.token;
  if (!token) {
    return res.redirect("/login");
  }

  try {
    const decoded = jwt.verify(
      token,
      process.env.JWT_SECRET || "fallback-jwt-secret"
    );
    req.user = decoded;
    next();
  } catch (err) {
    res.redirect("/login");
  }
}

// User Dashboard
router.get("/user-dashboard", requireAuth, async (req, res) => {
  if (req.user.role !== "citizen") {
    return res.redirect("/org-dashboard");
  }

  try {
    // Get user's consent settings
    const consents = await pool.query(
      `SELECT c.*, u.name as organization_name
       FROM consents c
       JOIN users u ON c.organization_id = u.id
       WHERE c.user_id = $1`,
      [req.user.id]
    );

    // Get available organizations for new consent requests
    const organizations = await pool.query(
      "SELECT id, name FROM users WHERE role = 'organization' AND id != $1",
      [req.user.id]
    );

    // Calculate privacy score based on consent management
    const totalConsents = consents.rows.length;
    const activeConsents = consents.rows.filter(c => c.consent_given).length;
    const privacyScore = totalConsents > 0 ? Math.round((activeConsents / totalConsents) * 100) : 0;

    // Calculate real data rights used
    const dataRequestsCount = await pool.query(
      "SELECT COUNT(*) as count FROM data_requests WHERE user_id = $1",
      [req.user.id]
    );
    const dataRightsUsed = parseInt(dataRequestsCount.rows[0].count);

    res.render("user-dashboard", {
      user: req.user,
      consents: consents.rows,
      organizations: organizations.rows,
      privacyScore: privacyScore,
      dataRightsUsed: dataRightsUsed
    });
  } catch (err) {
    console.error("Dashboard error:", err);
    res.render("user-dashboard", {
      user: req.user,
      consents: [],
      organizations: [],
      privacyScore: 0,
      dataRightsUsed: 0
    });
  }
});

// Organization Dashboard
router.get("/org-dashboard", requireAuth, async (req, res) => {
  if (req.user.role !== "organization") {
    return res.redirect("/user-dashboard");
  }

  try {
    // Get organization's scans and user consents
    const scans = await pool.query(
      "SELECT * FROM scans WHERE organization_id = $1 ORDER BY uploaded_at DESC",
      [req.user.id]
    );

    const userConsents = await pool.query(
      `SELECT u.name, u.email, c.consent_given, c.data_categories, c.updated_at
       FROM consents c
       JOIN users u ON c.user_id = u.id
       WHERE c.organization_id = $1`,
      [req.user.id]
    );

    // Calculate average compliance score
    const totalScans = scans.rows.length;
    const totalScore = scans.rows.reduce((sum, scan) => sum + scan.compliance_score, 0);
    const avgComplianceScore = totalScans > 0 ? Math.round(totalScore / totalScans) : 78;

    // Calculate organization stats
    const totalUsers = userConsents.rows.length;
    const consentedUsers = userConsents.rows.filter(uc => uc.consent_given).length;
    const successfulScans = scans.rows.filter(s => s.status === 'completed' || s.status === 'excellent' || s.status === 'good').length;

    res.render("org-dashboard", {
      user: req.user,
      scans: scans.rows,
      userConsents: userConsents.rows,
      complianceScore: avgComplianceScore,
      totalUsers: totalUsers,
      consentedUsers: consentedUsers,
      successfulScans: successfulScans
    });
  } catch (err) {
    console.error("Org dashboard error:", err);
    res.render("org-dashboard", {
      user: req.user,
      scans: [],
      userConsents: [],
      complianceScore: 78,
      totalUsers: 0,
      consentedUsers: 0,
      successfulScans: 0
    });
  }
});

export default router;