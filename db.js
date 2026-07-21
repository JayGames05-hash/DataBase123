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
      password_hash TEXT NOT NULL,
      role VARCHAR(20) DEFAULT 'member',
      created_at TIMESTAMP DEFAULT NOW()
    )
  `);

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
}

module.exports = { pool, initializeDatabase };
