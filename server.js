const express = require('express');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');
const cookieParser = require('cookie-parser');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const multer = require('multer');
const { Pool } = require('pg');

const PORT = process.env.PORT || 3000;
const SESSION_SECRET = process.env.SESSION_SECRET;
const ADMIN_USERNAME = process.env.ADMIN_USERNAME;
const ADMIN_PASSWORD_HASH = process.env.ADMIN_PASSWORD_HASH;
const UPLOAD_DIR = process.env.UPLOAD_DIR || path.join(__dirname, 'data-uploads');

if (!SESSION_SECRET || !ADMIN_USERNAME || !ADMIN_PASSWORD_HASH) {
  console.error('Missing required env vars: SESSION_SECRET, ADMIN_USERNAME, ADMIN_PASSWORD_HASH');
  process.exit(1);
}

fs.mkdirSync(UPLOAD_DIR, { recursive: true });

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: false,
});

async function initDb() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS properties (
      id TEXT PRIMARY KEY,
      titulo TEXT NOT NULL,
      direccion TEXT,
      barrio TEXT,
      ciudad TEXT,
      categoria TEXT NOT NULL,
      precio NUMERIC,
      m2 NUMERIC,
      hab INTEGER,
      banos INTEGER,
      tag TEXT,
      descripcion TEXT,
      fotos JSONB NOT NULL DEFAULT '[]',
      created_at TIMESTAMPTZ NOT NULL DEFAULT now()
    );
  `);

  const { rows } = await pool.query('SELECT count(*)::int AS n FROM properties');
  if (rows[0].n === 0) {
    const seedPath = path.join(__dirname, 'seed-data.json');
    if (fs.existsSync(seedPath)) {
      const seed = JSON.parse(fs.readFileSync(seedPath, 'utf8'));
      for (const p of seed) {
        await pool.query(
          `INSERT INTO properties (id, titulo, direccion, barrio, ciudad, categoria, precio, m2, hab, banos, tag, descripcion, fotos)
           VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)
           ON CONFLICT (id) DO NOTHING`,
          [p.id, p.titulo, p.direccion, p.barrio, p.ciudad, p.categoria, p.precio, p.m2, p.hab, p.banos, p.tag, p.descripcion, JSON.stringify(p.fotos || [])]
        );
      }
      console.log(`Seeded ${seed.length} properties`);
    }
  }
}

const app = express();
app.use(express.json({ limit: '2mb' }));
app.use(cookieParser());

// ---- static site + uploaded photos ----
app.use('/uploads', express.static(UPLOAD_DIR, { maxAge: '30d' }));
app.use(express.static(__dirname, { extensions: ['html'] }));

// ---- auth ----
function requireAuth(req, res, next) {
  const token = req.cookies.session;
  if (!token) return res.status(401).json({ error: 'No autenticado' });
  try {
    req.user = jwt.verify(token, SESSION_SECRET);
    next();
  } catch {
    res.status(401).json({ error: 'Sesión inválida' });
  }
}

app.post('/api/login', async (req, res) => {
  const { username, password } = req.body || {};
  if (username !== ADMIN_USERNAME || !(await bcrypt.compare(password || '', ADMIN_PASSWORD_HASH))) {
    return res.status(401).json({ error: 'Usuario o contraseña incorrectos' });
  }
  const token = jwt.sign({ sub: username }, SESSION_SECRET, { expiresIn: '30d' });
  res.cookie('session', token, {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'lax',
    maxAge: 30 * 24 * 60 * 60 * 1000,
  });
  res.json({ ok: true });
});

app.post('/api/logout', (req, res) => {
  res.clearCookie('session');
  res.json({ ok: true });
});

app.get('/api/me', (req, res) => {
  const token = req.cookies.session;
  if (!token) return res.json({ authenticated: false });
  try {
    const user = jwt.verify(token, SESSION_SECRET);
    res.json({ authenticated: true, username: user.sub });
  } catch {
    res.json({ authenticated: false });
  }
});

// ---- photo upload ----
const storage = multer.diskStorage({
  destination: UPLOAD_DIR,
  filename: (req, file, cb) => {
    const ext = (path.extname(file.originalname) || '.jpg').toLowerCase().replace(/[^a-z0-9.]/g, '') || '.jpg';
    cb(null, crypto.randomBytes(10).toString('hex') + ext);
  },
});
const upload = multer({
  storage,
  limits: { fileSize: 10 * 1024 * 1024 },
  fileFilter: (req, file, cb) => {
    cb(null, /^image\/(jpeg|png|webp)$/.test(file.mimetype));
  },
});

app.post('/api/upload', requireAuth, upload.single('photo'), (req, res) => {
  if (!req.file) return res.status(400).json({ error: 'Archivo inválido (solo jpg/png/webp, máx 10MB)' });
  res.json({ path: `/uploads/${req.file.filename}` });
});

// ---- properties CRUD ----
const toRow = (p) => ({
  id: p.id,
  titulo: p.titulo,
  direccion: p.direccion,
  barrio: p.barrio,
  ciudad: p.ciudad,
  categoria: p.categoria,
  precio: p.precio === '' || p.precio == null ? null : Number(p.precio),
  m2: p.m2 === '' || p.m2 == null ? null : Number(p.m2),
  hab: p.hab === '' || p.hab == null ? null : Number(p.hab),
  banos: p.banos === '' || p.banos == null ? null : Number(p.banos),
  tag: p.tag || null,
  descripcion: p.descripcion || '',
  fotos: Array.isArray(p.fotos) ? p.fotos : [],
});

app.get('/api/properties', async (req, res) => {
  const { rows } = await pool.query('SELECT * FROM properties ORDER BY created_at DESC');
  res.json(rows);
});

app.post('/api/properties', requireAuth, async (req, res) => {
  const p = toRow(req.body);
  if (!p.titulo || !p.categoria) return res.status(400).json({ error: 'Título y categoría son obligatorios' });
  const id = crypto.randomBytes(6).toString('hex');
  const { rows } = await pool.query(
    `INSERT INTO properties (id, titulo, direccion, barrio, ciudad, categoria, precio, m2, hab, banos, tag, descripcion, fotos)
     VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13) RETURNING *`,
    [id, p.titulo, p.direccion, p.barrio, p.ciudad, p.categoria, p.precio, p.m2, p.hab, p.banos, p.tag, p.descripcion, JSON.stringify(p.fotos)]
  );
  res.status(201).json(rows[0]);
});

app.put('/api/properties/:id', requireAuth, async (req, res) => {
  const p = toRow(req.body);
  const { rows } = await pool.query(
    `UPDATE properties SET titulo=$1, direccion=$2, barrio=$3, ciudad=$4, categoria=$5, precio=$6, m2=$7, hab=$8, banos=$9, tag=$10, descripcion=$11, fotos=$12
     WHERE id=$13 RETURNING *`,
    [p.titulo, p.direccion, p.barrio, p.ciudad, p.categoria, p.precio, p.m2, p.hab, p.banos, p.tag, p.descripcion, JSON.stringify(p.fotos), req.params.id]
  );
  if (!rows.length) return res.status(404).json({ error: 'No encontrada' });
  res.json(rows[0]);
});

app.delete('/api/properties/:id', requireAuth, async (req, res) => {
  await pool.query('DELETE FROM properties WHERE id=$1', [req.params.id]);
  res.json({ ok: true });
});

initDb()
  .then(() => {
    app.listen(PORT, () => console.log(`VANAR server listening on ${PORT}`));
  })
  .catch((err) => {
    console.error('Failed to initialize database', err);
    process.exit(1);
  });
