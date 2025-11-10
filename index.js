import express from 'express';
import bodyParser from 'body-parser';
import session from 'express-session';
import cookieParser from 'cookie-parser';
import dotenv from 'dotenv';
import path from 'path';

// Import Routes
import authRoutes from './routes/auth.js';
import dashboardRoutes from './routes/dashboard.js';

dotenv.config();

const app = express();
const PORT = process.env.PORT || 3000;

// Middleware
app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());
app.use(cookieParser());
app.use(
  session({
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: false
  })
);
app.use(express.static('public'));

// Simple middleware to attach user info to all views
app.use((req, res, next) => {
  res.locals.user = req.user || null;
  next();
});

// View engine
app.set('view engine', 'ejs');
app.set('views', path.join('views')); // relative path

// Routes
app.use('/', authRoutes);
app.use('/', dashboardRoutes);

// Landing page
app.get('/', (req, res) => {
  res.render('index');
});

// 404 page
app.use((req, res) => {
  res.status(404).send('Page not found');
});

// Start server
app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
});