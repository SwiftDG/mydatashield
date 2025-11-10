import pg from "pg";
import dotenv from "dotenv";
dotenv.config();

const { Pool } = pg;

// Create a new pool connection
const pool = new Pool ({
  user: process.env.DB_USER,
  host: process.env.DB_HOST,
  database: process.env.DB_NAME,
  password: process.env.DB_PASSWORD,
  port: process.env.DB_PORT || 5432,
});


(async() => {
try {
  const res = await pool.query("SELECT NOW()");
  console.log("DB CONNECTED:", res.rows[0]);
} catch (err) {
  console.error("DB CONNECTION FAILED:", err);
}
})();


export default pool;
