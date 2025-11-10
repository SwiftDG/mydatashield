-- Users table
CREATE TABLE users (
    id SERIAL PRIMARY KEY,
    name VARCHAR(100) NOT NULL,
    email VARCHAR(150) UNIQUE NOT NULL,
    password VARCHAR(255) NOT NULL,
    role VARCHAR(20) NOT NULL, -- citizen or organization
    verified BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Consents table
CREATE TABLE consents (
    id SERIAL PRIMARY KEY,
    user_id INT REFERENCES users(id) ON DELETE CASCADE,
    organization_id INT REFERENCES users(id) ON DELETE CASCADE,
    consent_given BOOLEAN DEFAULT FALSE,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Scans table
CREATE TABLE scans (
    id SERIAL PRIMARY KEY,
    organization_id INT REFERENCES users(id) ON DELETE CASCADE,
    file_name VARCHAR(255) NOT NULL,
    compliance_score INT,
    uploaded_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Email verification codes
CREATE TABLE email_verifications (
    id SERIAL PRIMARY KEY,
    user_id INT REFERENCES users(id) ON DELETE CASCADE,
    code VARCHAR(10) NOT NULL,
    expires_at TIMESTAMP NOT NULL
);
