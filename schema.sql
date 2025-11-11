-- Users table
CREATE TABLE IF NOT EXISTS users (
    id SERIAL PRIMARY KEY,
    name VARCHAR(100) NOT NULL,
    email VARCHAR(150) UNIQUE NOT NULL,
    password VARCHAR(255) NOT NULL,
    role VARCHAR(20) NOT NULL CHECK (role IN ('citizen', 'organization')),
    verified BOOLEAN DEFAULT TRUE, -- No email verification for prototype
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Consents table
CREATE TABLE IF NOT EXISTS consents (
    id SERIAL PRIMARY KEY,
    user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
    organization_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
    consent_given BOOLEAN DEFAULT FALSE,
    data_categories TEXT[], -- Array of data types user consents to share
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Scans table (for organizations to track compliance scans)
CREATE TABLE IF NOT EXISTS scans (
    id SERIAL PRIMARY KEY,
    organization_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
    scan_name VARCHAR(255) NOT NULL,
    compliance_score INTEGER DEFAULT 0,
    status VARCHAR(50) DEFAULT 'pending',
    uploaded_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Create indexes for better performance
CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);
CREATE INDEX IF NOT EXISTS idx_consents_user_id ON consents(user_id);
CREATE INDEX IF NOT EXISTS idx_consents_org_id ON consents(organization_id);
CREATE INDEX IF NOT EXISTS idx_scans_org_id ON scans(organization_id);
