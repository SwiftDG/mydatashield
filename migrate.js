const { Client } = require('pg');

const client = new Client({
  connectionString: 'postgresql://mydatashield_db_user:0PH88WOB2gsVtZ7BFUT9R02QFgSmmqdG@dpg-d7pr6ke7r5hc73ahb1sg-a.oregon-postgres.render.com/mydatashield_db',
  ssl: { rejectUnauthorized: false }
});

const schema = `
CREATE TABLE IF NOT EXISTS users (
    id SERIAL PRIMARY KEY,
    name VARCHAR(100) NOT NULL,
    email VARCHAR(150) UNIQUE NOT NULL,
    password VARCHAR(255) NOT NULL,
    role VARCHAR(20) NOT NULL CHECK (role IN ('citizen', 'organization')),
    verified BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS consents (
    id SERIAL PRIMARY KEY,
    user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
    organization_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
    consent_given BOOLEAN DEFAULT FALSE,
    data_categories TEXT[],
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS scans (
    id SERIAL PRIMARY KEY,
    organization_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
    scan_name VARCHAR(255) NOT NULL,
    compliance_score INTEGER DEFAULT 0,
    status VARCHAR(50) DEFAULT 'pending',
    uploaded_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);
CREATE INDEX IF NOT EXISTS idx_consents_user_id ON consents(user_id);
CREATE INDEX IF NOT EXISTS idx_consents_org_id ON consents(organization_id);
CREATE INDEX IF NOT EXISTS idx_scans_org_id ON scans(organization_id);
`;

async function migrate() {
  await client.connect();
  console.log('Connected to database');
  await client.query(schema);
  console.log('Schema created successfully');
  await client.end();
}

migrate().catch(console.error);
