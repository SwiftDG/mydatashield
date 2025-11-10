import express from "express";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import pool from "../config/db.js";
import dotenv from "dotenv";
import { MailerSend, EmailParams, Sender, Recipient } from "mailersend";

dotenv.config();
const router = express.Router();

// ==================== MAILERSEND CONFIGURATION ====================
const mailersend = new MailerSend({
  apiKey: process.env.MAILERSEND_API_KEY,
});

// ==================== EMAIL FUNCTION ====================
async function sendVerificationEmail(email, code) {
  try {
    console.log(`Attempting to send email to: ${email}`);

    const sentFrom = new Sender(process.env.MAILERSEND_SENDER_EMAIL, "MyDataShield");
    const recipients = [new Recipient(email, email)];
    
    const emailParams = new EmailParams()
      .setFrom(sentFrom)
      .setTo(recipients)
      .setSubject("MyDataShield Verification Code")
      .setHtml(`
        <div style="font-family: Arial, sans-serif; padding: 20px; text-align:center;">
          <img src="https://raw.githubusercontent.com/SwiftDG/mydatashield/e19bbd45d2dab8f04d835244c0c0269637ca923c/AQPdVsCAiziCkGNrvMqvYBgAzQuvOTqSWcYtM2bMlILVipKnlI4GQiEydyoPioVv0HKt2M5-Tr5Ir8s-VvTbgQsVdbe_Q1Dn1zDcRGjhEEG8YcEtVRv_6fjxeI7oDUOgRorwZ_ofVY4g2Aet7vqwr-YECaSJ.jpeg" alt="MyDataShield Logo" style="width:100px; height:auto; margin-bottom:20px;" />
          <h2>Verify Your Email</h2>
          <p>Your verification code is:</p>
          <h1 style="color:#2e86de;">${code}</h1>
          <p>This code will expire in 10 minutes.</p>
        </div>
      `)
      .setText(`Your MyDataShield verification code is: ${code}. This code will expire in 10 minutes.`);

    const response = await mailersend.email.send(emailParams);
    console.log("Email sent successfully via MailerSend API");
    return true;
    
  } catch (error) {
    console.error("MailerSend API error:", error);
    throw error;
  }
}

// ==================== GET ROUTES ====================
router.get("/signup", (req, res) => res.render("signup"));
router.get("/login", (req, res) => res.render("login"));
router.get("/verify", (req, res) => {
  const email = req.query.email || "";
  const debug = req.query.debug === 'true';
  res.render("verify", { email, debug });
});
router.get("/logout", (req, res) => {
  res.clearCookie("token");
  req.session.destroy();
  res.redirect("/");
});

// ==================== POST ROUTES ====================

// SIGNUP - Fixed with proper error handling
router.post("/signup", async (req, res) => {
  console.log("=== SIGNUP REQUEST STARTED ===");
  console.log("Request body:", req.body);
  
  try {
    const { name, email, password, role, terms } = req.body;
    
    // Basic validation
    if (!name || !email || !password || !role) {
      console.log("Missing required fields");
      return res.render("signup", { 
        error: "All fields are required" 
      });
    }
    
    if (!terms) {
      console.log("Terms not accepted");
      return res.render("signup", { 
        error: "You must agree to terms and conditions" 
      });
    }

    // Check if user exists
    console.log("Checking if user exists...");
    const existing = await pool.query("SELECT * FROM users WHERE email=$1", [email]);
    if (existing.rows.length > 0) {
      console.log("User already exists");
      return res.render("signup", { 
        error: "User already exists with this email" 
      });
    }

    // Hash password
    console.log("Hashing password...");
    const hashedPassword = await bcrypt.hash(password, 10);

    // Create user
    console.log("Creating user in database...");
    const newUser = await pool.query(
      "INSERT INTO users (name, email, password, role, verified) VALUES ($1, $2, $3, $4, false) RETURNING id",
      [name, email, hashedPassword, role]
    );
    
    const userId = newUser.rows[0].id;
    console.log("User created with ID:", userId);

    // Generate verification code
    const code = Math.floor(100000 + Math.random() * 900000).toString();
    const expires = new Date(Date.now() + 10 * 60 * 1000);

    // Store verification code
    console.log("Storing verification code...");
    await pool.query(
      "INSERT INTO email_verifications (user_id, code, expires_at) VALUES ($1, $2, $3)",
      [userId, code, expires]
    );

    console.log(`VERIFICATION CODE for ${email}: ${code}`);

    // Try to send email (but continue even if it fails)
    try {
      await sendVerificationEmail(email, code);
      console.log("Email sent successfully via MailerSend");
    } catch (emailError) {
      console.error("EMAIL FAILED:", emailError);
      // Don't block the flow - user can still verify with code from logs
    }

    // Store in session for verification
    req.session.pendingEmail = email;
    req.session.pendingUserId = userId;
    
    // Redirect to verify page
    return res.redirect(`/verify?email=${encodeURIComponent(email)}`);
    
  } catch (err) {
    console.error("SIGNUP ERROR:", err);
    return res.render("signup", { 
      error: "Server error during signup" 
    });
  }
});

// VERIFY EMAIL
router.post("/verify", async (req, res) => {
  try {
    const { email, code } = req.body;

    // Find user
    const userRes = await pool.query("SELECT id, role FROM users WHERE email=$1", [email]);
    if (userRes.rows.length === 0) {
      return res.status(404).render("verify", { 
        email, 
        error: "User not found" 
      });
    }

    const userId = userRes.rows[0].id;
    const userRole = userRes.rows[0].role;

    // Check verification code
    const codeRes = await pool.query(
      "SELECT * FROM email_verifications WHERE user_id=$1 AND code=$2 AND expires_at > NOW()",
      [userId, code]
    );

    if (codeRes.rows.length === 0) {
      return res.status(400).render("verify", { 
        email, 
        error: "Invalid or expired verification code" 
      });
    }

    // Mark user as verified and clean up
    await pool.query("UPDATE users SET verified=true WHERE id=$1", [userId]);
    await pool.query("DELETE FROM email_verifications WHERE user_id=$1", [userId]);

    // Clear session
    req.session.pendingEmail = null;
    req.session.pendingUserId = null;

    // Auto-login after verification
    const token = jwt.sign({ id: userId, role: userRole }, process.env.JWT_SECRET, {
      expiresIn: "1h",
    });

    res.cookie("token", token, { httpOnly: true, maxAge: 60 * 60 * 1000 });

    // Redirect to appropriate dashboard
    if (userRole === "organization") {
      res.redirect("/org-dashboard");
    } else {
      res.redirect("/user-dashboard");
    }
  } catch (err) {
    console.error("Verify error:", err);
    res.status(500).render("verify", { 
      email: req.body.email, 
      error: "Error verifying email" 
    });
  }
});

// LOGIN
router.post("/login", async (req, res) => {
  try {
    const { email, password, remember } = req.body;

    const userRes = await pool.query("SELECT * FROM users WHERE email=$1", [email]);
    if (userRes.rows.length === 0) {
      return res.status(404).render("login", { 
        error: "User not found" 
      });
    }

    const user = userRes.rows[0];
    
    // Check if email is verified
    if (!user.verified) {
      // Redirect to verification page
      req.session.pendingEmail = email;
      req.session.pendingUserId = user.id;
      return res.redirect(`/verify?email=${encodeURIComponent(email)}`);
    }

    const match = await bcrypt.compare(password, user.password);
    if (!match) {
      return res.status(401).render("login", { 
        error: "Incorrect password" 
      });
    }

    const token = jwt.sign({ id: user.id, role: user.role }, process.env.JWT_SECRET, {
      expiresIn: remember ? "7d" : "1h",
    });

    res.cookie("token", token, { 
      httpOnly: true, 
      maxAge: remember ? 7 * 24 * 60 * 60 * 1000 : 60 * 60 * 1000 
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

export default router;