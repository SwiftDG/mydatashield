import express from "express";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import pool from "../config/db.js";                        
import dotenv from "dotenv";
import { MailerSend, EmailParams, Recipient } from "mailersend";

dotenv.config();
const router = express.Router();

// MailerSend setup
const ms = new MailerSend({ api_key: process.env.MAILERSEND_API_KEY });

// Helper: Send verification email
async function sendVerificationEmail(email, code) {
  const recipients = [new Recipient(email)];
  const emailParams = new EmailParams()
    .setFrom(process.env.MAILERSEND_FROM_EMAIL, process.env.MAILERSEND_FROM_NAME)
    .setRecipients(recipients)
    .setSubject("MyDataShield Verification Code")
    .setHtml(`<p>Your verification code is: <strong>${code}</strong></p>`);

  await ms.send(emailParams);
}

/* =========================
   GET ROUTES
========================= */

// Landing pages
router.get("/signup", (req, res) => {
  res.render("signup");
});

router.get("/login", (req, res) => {
  res.render("login");
});

router.get("/verify", (req, res) => {
  res.render("verify", { email: "" }); // will populate email via query or session
});

router.get("/logout", (req, res) => {
  res.clearCookie("token");
  res.redirect("/");
});

/* =========================
   POST ROUTES
========================= */

// SIGNUP
router.post("/signup", async (req, res) => {
  try {
    const { name, email, password, role, terms } = req.body;

    if (!terms) return res.status(400).send("You must agree to terms and conditions");

    // Check if user already exists
    const existing = await pool.query("SELECT * FROM users WHERE email=$1", [email]);
    if (existing.rows.length > 0) return res.status(400).send("User already exists");

    // Hash password
    const hashedPassword = await bcrypt.hash(password, 10);

    // Insert user
    const newUser = await pool.query(
      "INSERT INTO users (name, email, password, role, verified) VALUES ($1, $2, $3, $4, false) RETURNING id",
      [name, email, hashedPassword, role]
    );

    const userId = newUser.rows[0].id;

    // Generate verification code
    const code = Math.floor(100000 + Math.random() * 900000).toString();
    const expires = new Date(Date.now() + 10 * 60 * 1000); // 10 min

    // Save verification code
    await pool.query(
      "INSERT INTO email_verifications (user_id, code, expires_at) VALUES ($1, $2, $3)",
      [userId, code, expires]
    );

    try {
      // Send verification email
      await sendVerificationEmail(email, code);
    } catch (mailErr) {
      console.error("MailerSend error:", mailErr);
      return res.status(500).send("User created but failed to send verification email. Check logs.");
    }

    res.status(201).send("Signup successful! Check your email for verification code.");
  } catch (err) {
    console.error("Signup error:", err);
    res.status(500).send("Error creating user: " + (err.message || err));
  }
});

// VERIFY EMAIL
router.post("/verify", async (req, res) => {
  try {
    const { email, code } = req.body;

    const userRes = await pool.query("SELECT id FROM users WHERE email=$1", [email]);
    if (userRes.rows.length === 0) return res.status(404).send("User not found");

    const userId = userRes.rows[0].id;

    const codeRes = await pool.query(
      "SELECT * FROM email_verifications WHERE user_id=$1 AND code=$2 AND expires_at > NOW()",
      [userId, code]
    );

    if (codeRes.rows.length === 0) return res.status(400).send("Invalid or expired code");

    // Mark user as verified
    await pool.query("UPDATE users SET verified=true WHERE id=$1", [userId]);

    // Optionally delete the verification code
    await pool.query("DELETE FROM email_verifications WHERE user_id=$1", [userId]);

    res.send("Email verified! You can now log in.");
  } catch (err) {
    console.error("Verify error:", err);
    res.status(500).send("Error verifying email: " + (err.message || err));
  }
});

// LOGIN
router.post("/login", async (req, res) => {
  try {
    const { email, password, remember } = req.body;

    const userRes = await pool.query("SELECT * FROM users WHERE email=$1", [email]);
    if (userRes.rows.length === 0) return res.status(404).send("User not found");

    const user = userRes.rows[0];

    if (!user.verified) return res.status(403).send("Please verify your email first");

    const match = await bcrypt.compare(password, user.password);
    if (!match) return res.status(401).send("Incorrect password");

    const token = jwt.sign({ id: user.id, role: user.role }, process.env.JWT_SECRET, {
      expiresIn: remember ? "7d" : "1h",
    });

    // Set cookie
    res.cookie("token", token, { httpOnly: true, maxAge: remember ? 7 * 24 * 60 * 60 * 1000 : 60 * 60 * 1000 });

    // Redirect based on role
    if (user.role === "organization") res.redirect("/org-dashboard");
    else res.redirect("/user-dashboard");
  } catch (err) {
    console.error("Login error:", err);
    res.status(500).send("Error logging in: " + (err.message || err));
  }
});

export default router;