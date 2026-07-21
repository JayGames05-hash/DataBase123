const express = require('express');
const session = require('express-session');
const multer = require('multer');
const path = require('path');
const bcrypt = require('bcryptjs');
require('dotenv').config();

const { pool, initializeDatabase } = require('./db');
const { canAccessFile } = require('./permissions');

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

app.locals.siteName = 'Cloud Vault';

let dbReady = false;
let dbError = null;
let dbInitializing = false;
let dbInitPromise = null;

async function bootstrapDatabase() {
  if (dbReady) return true;
  if (dbInitializing) return dbInitPromise;

  dbInitializing = true;
  dbInitPromise = (async () => {
    try {
      await initializeDatabase();
      dbReady = true;
      dbError = null;
      return true;
    } catch (error) {
      dbReady = false;
      dbError = error.message;
      console.error('Database initialization failed:', error.message);
      return false;
    } finally {
      dbInitializing = false;
    }
  })();

  return dbInitPromise;
}

function requireAuth(req, res, next) {
  if (!req.session.user) {
    return res.redirect('/login');
  }
  next();
}

app.use((req, res, next) => {
  res.locals.user = req.session.user || null;
  next();
});

app.get('/', async (req, res) => {
  try {
    await bootstrapDatabase();

    if (!dbReady) {
      return res.render('index', {
        files: [],
        folders: [],
        currentFolder: null,
        error: `Database connection is not ready. ${dbError || 'Set DATABASE_URL to a valid PostgreSQL connection string and restart the app.'}`
      });
    }

    const user = req.session.user || null;
    const folderId = req.query.folder ? Number(req.query.folder) : null;

    let currentFolder = null;
    let folders = [];
    let parentFolder = null;

    if (user) {
      if (folderId) {
        const folderResult = await pool.query('SELECT * FROM folders WHERE id = $1 AND owner_id = $2', [folderId, user.id]);
        currentFolder = folderResult.rows[0] || null;
      }

      const folderQuery = folderId ? 'SELECT * FROM folders WHERE owner_id = $1 AND parent_id = $2 ORDER BY name' : 'SELECT * FROM folders WHERE owner_id = $1 AND parent_id IS NULL ORDER BY name';
      const folderValues = folderId ? [user.id, folderId] : [user.id];
      const folderResult = await pool.query(folderQuery, folderValues);
      folders = folderResult.rows;

      if (currentFolder && currentFolder.parent_id) {
        const parentResult = await pool.query('SELECT * FROM folders WHERE id = $1 AND owner_id = $2', [currentFolder.parent_id, user.id]);
        parentFolder = parentResult.rows[0] || null;
      }
    }

    const filesResult = await pool.query(
      'SELECT f.*, u.username AS owner_name FROM files f JOIN users u ON u.id = f.owner_id ORDER BY f.created_at DESC'
    );

    const files = filesResult.rows
      .filter((file) => canAccessFile(file, user))
      .filter((file) => (folderId ? file.folder_id === folderId : file.folder_id === null));

    let storageStats = { usedBytes: 0, fileCount: 0 };
    if (user) {
      const storageResult = await pool.query(
        'SELECT COALESCE(SUM(size), 0)::bigint AS used_bytes, COUNT(*)::int AS file_count FROM files WHERE owner_id = $1',
        [user.id]
      );
      storageStats = storageResult.rows[0];
    }

    res.render('index', { files, folders, currentFolder, parentFolder, storageStats, error: null });
  } catch (error) {
    console.error(error);
    res.render('index', { files: [], folders: [], currentFolder: null, parentFolder: null, storageStats: { usedBytes: 0, fileCount: 0 }, error: error.message });
  }
});

app.get('/health', (req, res) => {
  res.json({ ok: dbReady, databaseConfigured: Boolean(process.env.DATABASE_URL), dbReady, error: dbError || null });
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
    await bootstrapDatabase();
    const existing = await pool.query('SELECT id FROM users WHERE username = $1', [username]);
    if (existing.rowCount > 0) {
      return res.render('register', { error: 'That username already exists.' });
    }

    const usersCount = await pool.query('SELECT COUNT(*) AS count FROM users');
    const role = Number(usersCount.rows[0].count) === 0 ? 'admin' : 'member';
    const passwordHash = await bcrypt.hash(password, 10);

    await pool.query('INSERT INTO users (username, password_hash, role) VALUES ($1, $2, $3)', [username, passwordHash, role]);
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
    await bootstrapDatabase();
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

app.post('/folders', requireAuth, async (req, res) => {
  try {
    await bootstrapDatabase();
    const name = (req.body.name || '').trim();
    const parentId = req.body.parent_id ? Number(req.body.parent_id) : null;

    if (!name) {
      return res.redirect('/');
    }

    await pool.query('INSERT INTO folders (owner_id, name, parent_id) VALUES ($1, $2, $3)', [req.session.user.id, name, parentId]);
    res.redirect(parentId ? `/?folder=${parentId}` : '/');
  } catch (error) {
    console.error(error);
    res.redirect('/');
  }
});

app.get('/upload', requireAuth, async (req, res) => {
  try {
    await bootstrapDatabase();
    const result = await pool.query('SELECT * FROM folders WHERE owner_id = $1 ORDER BY name', [req.session.user.id]);
    res.render('upload', { error: null, folders: result.rows, selectedFolder: req.query.folder || null });
  } catch (error) {
    console.error(error);
    res.render('upload', { error: error.message, folders: [], selectedFolder: null });
  }
});

app.post('/upload', requireAuth, upload.single('file'), async (req, res) => {
  try {
    await bootstrapDatabase();

    if (!req.file) {
      return res.render('upload', { error: 'Please choose a file to upload.', folders: [], selectedFolder: null });
    }

    const title = (req.body.title || req.file.originalname || 'Untitled').trim();
    const visibility = req.body.visibility || 'private';
    const folderId = req.body.folder_id ? Number(req.body.folder_id) : null;

    if (folderId) {
      const folderResult = await pool.query('SELECT id FROM folders WHERE id = $1 AND owner_id = $2', [folderId, req.session.user.id]);
      if (!folderResult.rows[0]) {
        return res.render('upload', { error: 'That folder does not exist.', folders: [], selectedFolder: null });
      }
    }

    await pool.query(
      `INSERT INTO files (owner_id, folder_id, title, original_name, stored_name, mime_type, size, visibility, file_data)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`,
      [req.session.user.id, folderId, title, req.file.originalname, req.file.originalname, req.file.mimetype, req.file.size, visibility, req.file.buffer]
    );

    res.redirect(folderId ? `/?folder=${folderId}` : '/');
  } catch (error) {
    console.error(error);
    res.render('upload', { error: error.message, folders: [], selectedFolder: null });
  }
});

app.get('/users', requireAuth, async (req, res) => {
  try {
    if (req.session.user.role !== 'admin') {
      return res.status(403).send('Only admins can view the user list.');
    }

    const result = await pool.query('SELECT id, username, email, role, created_at FROM users ORDER BY created_at DESC');
    res.render('users', { users: result.rows, error: null });
  } catch (error) {
    console.error(error);
    res.render('users', { users: [], error: error.message });
  }
});

app.get('/admin', requireAuth, async (req, res) => {
  try {
    if (req.session.user.role !== 'admin') {
      return res.status(403).send('Only admins can access the admin dashboard.');
    }

    const result = await pool.query('SELECT id, username, email, role, created_at FROM users ORDER BY created_at DESC');
    res.render('admin', { users: result.rows, error: null });
  } catch (error) {
    console.error(error);
    res.render('admin', { users: [], error: error.message });
  }
});

app.post('/admin/users', requireAuth, async (req, res) => {
  try {
    if (req.session.user.role !== 'admin') {
      return res.status(403).send('Only admins can create users.');
    }

    const username = (req.body.username || '').trim().toLowerCase();
    const email = (req.body.email || '').trim().toLowerCase();
    const password = req.body.password || '';
    const role = (req.body.role || 'member').trim();

    if (!username || !email || !password) {
      return res.redirect('/admin');
    }

    const existing = await pool.query('SELECT id FROM users WHERE username = $1 OR email = $2', [username, email]);
    if (existing.rowCount > 0) {
      return res.render('admin', { users: [], error: 'A user with that username or email already exists.' });
    }

    const passwordHash = await bcrypt.hash(password, 10);
    await pool.query('INSERT INTO users (username, email, password_hash, role) VALUES ($1, $2, $3, $4)', [username, email, passwordHash, role]);
    res.redirect('/admin');
  } catch (error) {
    console.error(error);
    res.redirect('/admin');
  }
});

app.get('/files/:id', async (req, res) => {
  try {
    await bootstrapDatabase();
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
    await bootstrapDatabase();
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
