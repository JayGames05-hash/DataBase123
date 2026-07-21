const { Pool } = require('pg');
require('dotenv').config();

const pool = new Pool({
  connectionString: process.env.DATABASE_URL || 'postgres://postgres:postgres@localhost:5432/storageapp',
  ssl: process.env.DATABASE_URL ? { rejectUnauthorized: false } : false
});

async function initializeDatabase() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id SERIAL PRIMARY KEY,
      username VARCHAR(100) UNIQUE NOT NULL,
      email VARCHAR(255) UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      role VARCHAR(20) DEFAULT 'member',
      created_at TIMESTAMP DEFAULT NOW()
    )
  `);

  await pool.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS email VARCHAR(255)`);
  await pool.query(`ALTER TABLE users ADD CONSTRAINT users_email_key UNIQUE (email) DEFERRABLE INITIALLY DEFERRED`);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS folders (
      id SERIAL PRIMARY KEY,
      owner_id INT REFERENCES users(id) ON DELETE CASCADE,
      name VARCHAR(255) NOT NULL,
      parent_id INT REFERENCES folders(id) ON DELETE CASCADE,
      created_at TIMESTAMP DEFAULT NOW()
    )
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS files (
      id SERIAL PRIMARY KEY,
      owner_id INT REFERENCES users(id) ON DELETE CASCADE,
      folder_id INT REFERENCES folders(id) ON DELETE SET NULL,
      title VARCHAR(255) NOT NULL,
      original_name VARCHAR(255) NOT NULL,
      stored_name VARCHAR(255) NOT NULL,
      mime_type VARCHAR(255),
      size BIGINT,
      visibility VARCHAR(20) DEFAULT 'private',
      file_data BYTEA NOT NULL,
      created_at TIMESTAMP DEFAULT NOW()
    )
  `);

  await pool.query(`ALTER TABLE files ADD COLUMN IF NOT EXISTS folder_id INT REFERENCES folders(id) ON DELETE SET NULL`);

  const adminEmail = process.env.ADMIN_EMAIL || 'admin@cloudvault.local';
  const adminPassword = process.env.ADMIN_PASSWORD || 'Admin123!';
  const adminCheck = await pool.query('SELECT id FROM users WHERE role = $1', ['admin']);

  if (adminCheck.rowCount === 0) {
    const hashed = require('bcryptjs').hashSync(adminPassword, 10);
    await pool.query(
      'INSERT INTO users (username, email, password_hash, role) VALUES ($1, $2, $3, $4)',
      ['admin', adminEmail, hashed, 'admin']
    );
  }
}

module.exports = { pool, initializeDatabase };
