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
      cb(
        new Error("Only PDF, Word, and Text files are allowed")
      );
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

    // TODO: Implement signup logic (hash password, insert user, etc.)

  } catch (err) {
    console.error("SIGNUP ERROR:", err);
    return res.render("signup", {
      error: "Server error during signup: " + err.message,
    });
  }
});

// LOGIN
router.post("/login", async (req, res) => {
  try {
    const { email, password, remember } = req.body;

    // TODO: Implement login logic (verify credentials, set token, etc.)

  } catch (err) {
    console.error("Login error:", err);
    res
      .status(500)
      .render("login", { error: "Error logging in" });
  }
});

// ==================== FILE UPLOAD & NDPR SCANNING ====================

// NDPR Compliance Scanning Function
async function scanForNDPRCompliance(filePath) {
  try {
    // Read file content (basic text extraction)
    let content = "";

    // TODO: Implement file reading and NDPR keyword scanning logic

    return 0; // Placeholder
  } catch (err) {
    console.error("NDPR scanning error:", err);
    return 0; // Return 0 if scanning fails
  }
}

// Handle scan upload
router.post(
  "/upload-scan",
  requireAuth,
  upload.single("scanFile"),
  async (req, res) => {
    if (req.user.role !== "organization") {
      return res.redirect("/user-dashboard");
    }

    try {
      const { scanName } = req.body;

      // TODO: Process uploaded file, run NDPR scan, store result

    } catch (err) {
      console.error("Upload error:", err);
      // TODO: Handle error appropriately
    }
  }
);

// ==================== CONSENT MANAGEMENT ROUTES ====================

// Grant consent to organization
router.post("/grant-consent", requireAuth, async (req, res) => {
  try {
    const { organization_id } = req.body;
    const user_id = req.user.id;

    // TODO: Insert consent record

  } catch (err) {
    console.error("Grant consent error:", err);
    res
      .status(500)
      .json({ success: false, error: "Failed to grant consent" });
  }
});

// Revoke consent from organization
router.post("/revoke-consent", requireAuth, async (req, res) => {
  try {
    const { organization_id } = req.body;
    const user_id = req.user.id;

    // TODO: Delete/revoke consent record

  } catch (err) {
    console.error("Revoke consent error:", err);
    res
      .status(500)
      .json({ success: false, error: "Failed to revoke consent" });
  }
});

// Create new consent request
router.post("/request-consent", requireAuth, async (req, res) => {
  try {
    const { organization_id } = req.body;
    const user_id = req.user.id;

    // TODO: Insert consent request record

  } catch (err) {
    console.error("Request consent error:", err);
    res
      .status(500)
      .json({
        success: false,
        error: "Failed to create consent request",
      });
  }
});

// ==================== DATA RIGHTS ROUTES ====================

router.post(
  "/request-data-access",
  requireAuth,
  async (req, res) => {
    try {
      await pool.query(
        "INSERT INTO data_requests (user_id, request_type, status, details) VALUES ($1, 'access', 'pending', 'User requested access to personal data')",
        [req.user.id]
      );
      res.json({
        success: true,
        message:
          "Data access request submitted. Organizations have 30 days to respond under NDPR.",
      });
    } catch (err) {
      console.error("Data access request error:", err);
      res
        .status(500)
        .json({
          success: false,
          error: "Failed to submit data access request",
        });
    }
  }
);

router.post(
  "/request-data-correction",
  requireAuth,
  async (req, res) => {
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
      res
        .status(500)
        .json({
          success: false,
          error: "Failed to submit data correction request",
        });
    }
  }
);

router.post(
  "/request-data-deletion",
  requireAuth,
  async (req, res) => {
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
      res
        .status(500)
        .json({
          success: false,
          error: "Failed to submit data deletion request",
        });
    }
  }
);

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

    // TODO: Generate downloadable file (JSON/CSV/PDF)

  } catch (err) {
    console.error("Data download error:", err);
    res
      .status(500)
      .json({
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

    // TODO: Fetch organizations, privacyScore, dataRightsUsed

    res.render("user-dashboard", {
      user: req.user,
      consents: consents.rows,
      organizations: [],
      privacyScore: 0,
      dataRightsUsed: 0,
    });
  } catch (err) {
    console.error("Dashboard error:", err);
    res.render("user-dashboard", {
      user: req.user,
      consents: [],
      organizations: [],
      privacyScore: 0,
      dataRightsUsed: 0,
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

    // TODO: Fetch userConsents, complianceScore

    res.render("org-dashboard", {
      user: req.user,
      scans: scans.rows,
      userConsents: [],
      complianceScore: 78,
    });
  } catch (err) {
    console.error("Org dashboard error:", err);
    res.render("org-dashboard", {
      user: req.user,
      scans: [],
      userConsents: [],
      complianceScore: 78,
    });
  }
});

export default router;