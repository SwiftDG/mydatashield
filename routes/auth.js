import express from "express";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import pool from "../config/db.js";
import dotenv from "dotenv";

dotenv.config();
const router = express.Router();

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
      expiresIn: "7d",
    });

    res.cookie("token", token, { 
      httpOnly: true, 
      maxAge: 7 * 24 * 60 * 60 * 1000 
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
    const { email, password } = req.body;

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
      expiresIn: "7d",
    });

    res.cookie("token", token, { 
      httpOnly: true, 
      maxAge: 7 * 24 * 60 * 60 * 1000 
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

// ==================== DASHBOARD ROUTES ====================

// Auth middleware
function requireAuth(req, res, next) {
  const token = req.cookies.token;
  if (!token) {
    return res.redirect('/login');
  }

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET || "fallback-jwt-secret");
    req.user = decoded;
    next();
  } catch (err) {
    res.redirect('/login');
  }
}

// User Dashboard
router.get("/user-dashboard", requireAuth, async (req, res) => {
  if (req.user.role !== 'citizen') {
    return res.redirect('/org-dashboard');
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

    res.render("user-dashboard", { 
      user: req.user,
      consents: consents.rows 
    });
  } catch (err) {
    console.error("Dashboard error:", err);
    res.render("user-dashboard", { 
      user: req.user,
      consents: [] 
    });
  }
});

// Organization Dashboard
router.get("/org-dashboard", requireAuth, async (req, res) => {
  if (req.user.role !== 'organization') {
    return res.redirect('/user-dashboard');
  }

  try {
    // Get organization's scans and user consents
    const scans = await pool.query(
      "SELECT * FROM scans WHERE organization_id = $1 ORDER BY uploaded_at DESC",
      [req.user.id]
    );

    const userConsents = await pool.query(
      `SELECT u.name, u.email, c.consent_given, c.data_categories 
       FROM consents c 
       JOIN users u ON c.user_id = u.id 
       WHERE c.organization_id = $1`,
      [req.user.id]
    );

    res.render("org-dashboard", { 
      user: req.user,
      scans: scans.rows,
      userConsents: userConsents.rows
    });
  } catch (err) {
    console.error("Org dashboard error:", err);
    res.render("org-dashboard", { 
      user: req.user,
      scans: [],
      userConsents: []
    });
  }
});

export default router;
