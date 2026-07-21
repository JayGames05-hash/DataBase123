const express = require('express');
const session = require('express-session');
const multer = require('multer');
const path = require('path');
const bcrypt = require('bcryptjs');
require('dotenv').config();

const { pool, initializeDatabase } = require('./db');

const app = express();
const port = process.env.PORT || 3000;

app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'public')));
app.use(
  session({
    secret: process.env.SESSION_SECRET || 'change-this-secret',
    resave: false,
    saveUninitialized: false,
    cookie: { secure: false }
  })
);

const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 50 * 1024 * 1024 }
});

app.locals.siteName = 'Railway Storage';

let dbReady = false;
let dbError = null;

async function bootstrapDatabase() {
  try {
    await initializeDatabase();
    dbReady = true;
  } catch (error) {
    dbReady = false;
    dbError = error.message;
    console.error('Database initialization failed:', error.message);
  }
}

bootstrapDatabase();

function requireAuth(req, res, next) {
  if (!req.session.user) {
    return res.redirect('/login');
  }
  next();
}

function canAccessFile(file, user) {
  if (!user) {
    return file.visibility === 'public';
  }
  return file.visibility === 'public' || file.owner_id === user.id || user.role === 'admin';
}

app.use((req, res, next) => {
  res.locals.user = req.session.user || null;
  next();
});

app.get('/', async (req, res) => {
  try {
    if (!dbReady) {
      return res.render('index', {
        files: [],
        error: `Database is not ready yet. ${dbError || 'Set DATABASE_URL to a PostgreSQL instance and restart.'}`
      });
    }

    const user = req.session.user || null;
    let query = 'SELECT f.*, u.username AS owner_name FROM files f JOIN users u ON u.id = f.owner_id ORDER BY f.created_at DESC';

    if (user && user.role !== 'admin') {
      query = 'SELECT f.*, u.username AS owner_name FROM files f JOIN users u ON u.id = f.owner_id WHERE f.visibility = $1 OR f.owner_id = $2 ORDER BY f.created_at DESC';
    }

    const values = user && user.role !== 'admin' ? ['public', user.id] : [];
    const result = await pool.query(query, values);
    const files = result.rows.filter((file) => canAccessFile(file, user));

    res.render('index', { files, error: null });
  } catch (error) {
    console.error(error);
    res.render('index', { files: [], error: error.message });
  }
});

app.get('/health', (req, res) => {
  res.json({ ok: true, dbReady, error: dbError || null });
});

app.get('/register', (req, res) => {
  res.render('register', { error: null });
});

app.post('/register', async (req, res) => {
  const username = (req.body.username || '').trim().toLowerCase();
  const password = req.body.password || '';

  if (!username || !password) {
    return res.render('register', { error: 'Please provide a username and password.' });
  }

  try {
    const existing = await pool.query('SELECT id FROM users WHERE username = $1', [username]);
    if (existing.rowCount > 0) {
      return res.render('register', { error: 'That username already exists.' });
    }

    const passwordHash = await bcrypt.hash(password, 10);
    await pool.query('INSERT INTO users (username, password_hash, role) VALUES ($1, $2, $3)', [username, passwordHash, 'member']);
    res.redirect('/login');
  } catch (error) {
    console.error(error);
    res.render('register', { error: error.message });
  }
});

app.get('/login', (req, res) => {
  res.render('login', { error: null });
});

app.post('/login', async (req, res) => {
  const username = (req.body.username || '').trim().toLowerCase();
  const password = req.body.password || '';

  try {
    const result = await pool.query('SELECT * FROM users WHERE username = $1', [username]);
    const user = result.rows[0];

    if (!user) {
      return res.render('login', { error: 'Invalid credentials.' });
    }

    const passwordOk = await bcrypt.compare(password, user.password_hash);
    if (!passwordOk) {
      return res.render('login', { error: 'Invalid credentials.' });
    }

    req.session.user = { id: user.id, username: user.username, role: user.role };
    res.redirect('/');
  } catch (error) {
    console.error(error);
    res.render('login', { error: error.message });
  }
});

app.post('/logout', (req, res) => {
  req.session.destroy(() => {
    res.redirect('/');
  });
});

app.get('/upload', requireAuth, (req, res) => {
  res.render('upload', { error: null });
});

app.post('/upload', requireAuth, upload.single('file'), async (req, res) => {
  try {
    if (!req.file) {
      return res.render('upload', { error: 'Please choose a file to upload.' });
    }

    const title = (req.body.title || req.file.originalname || 'Untitled').trim();
    const visibility = req.body.visibility || 'private';

    await pool.query(
      `INSERT INTO files (owner_id, title, original_name, stored_name, mime_type, size, visibility, file_data)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
      [req.session.user.id, title, req.file.originalname, req.file.originalname, req.file.mimetype, req.file.size, visibility, req.file.buffer]
    );

    res.redirect('/');
  } catch (error) {
    console.error(error);
    res.render('upload', { error: error.message });
  }
});

app.get('/files/:id', async (req, res) => {
  try {
    const result = await pool.query('SELECT f.*, u.username AS owner_name FROM files f JOIN users u ON u.id = f.owner_id WHERE f.id = $1', [req.params.id]);
    const file = result.rows[0];

    if (!file) {
      return res.status(404).send('File not found.');
    }

    if (!canAccessFile(file, req.session.user)) {
      return res.status(403).send('You do not have permission to access this file.');
    }

    res.render('file', { file });
  } catch (error) {
    console.error(error);
    res.status(500).send(error.message);
  }
});

app.get('/download/:id', async (req, res) => {
  try {
    const result = await pool.query('SELECT * FROM files WHERE id = $1', [req.params.id]);
    const file = result.rows[0];

    if (!file) {
      return res.status(404).send('File not found.');
    }

    if (!canAccessFile(file, req.session.user)) {
      return res.status(403).send('You do not have permission to download this file.');
    }

    res.set('Content-Type', file.mime_type || 'application/octet-stream');
    res.set('Content-Disposition', `attachment; filename="${file.original_name}"`);
    res.send(file.file_data);
  } catch (error) {
    console.error(error);
    res.status(500).send(error.message);
  }
});

app.listen(port, () => {
  console.log(`App listening on port ${port}`);
});
