import pg from 'pg';
import dotenv from 'dotenv';

dotenv.config();

const { Pool } = pg;

// Create a new pool connection
const pool = new Pool({
  user: process.env.DB_USER,
  host: process.env.DB_HOST,
  database: process.env.DB_NAME,
  password: process.env.DB_PASSWORD,
  port: process.env.DB_PORT || 5432,
  // Add SSL for production (Render requires this)
  ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false
});

// Test connection
(async () => {
  try {
    const res = await pool.query('SELECT NOW()');
    console.log('Database connected successfully');
  } catch (err) {
    console.error('Database connection failed:', err.message);
  }
})();

export default pool;
