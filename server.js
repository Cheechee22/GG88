require('dotenv').config();
const express = require('express');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const rateLimit = require('express-rate-limit');
const db = require('./db');
const { createClient } = require('@supabase/supabase-js');
const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET;
const UPLOAD_DIR = path.join(__dirname, 'uploads');
const MAX_MB = parseInt(process.env.MAX_UPLOAD_MB || '2048', 10);
const supabase = createClient(process.env.SUPABASE_URL, process.env.SUPABASE_KEY);
const R2_BUCKET_NAME = 'gg88-images'; // We are using this name for the Supabase bucket
if (!fs.existsSync(UPLOAD_DIR)) fs.mkdirSync(UPLOAD_DIR);

const CATEGORIES = ['Arcade', 'Racing', 'Sports', 'Indie', 'Horror', 'Simulation', 'RPG'];

app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

const ALLOWED_EXT = new Set(['.zip', '.rar', '.7z', '.exe', '.msi', '.dmg', '.tar', '.gz', '.apk', '.torrent']);
storage: multer.memoryStorage(),

  limits: { fileSize: MAX_MB * 1024 * 1024 },
    fileFilter: (req, file, cb) => {
    const ext = path.extname(file.originalname).toLowerCase();
    if (file.fieldname === 'image' || file.fieldname.startsWith('screenshot')) {
      if (!ALLOWED_IMG.has(ext)) return cb(new Error('Image type not allowed'));
    } else {
      if (!ALLOWED_EXT.has(ext)) return cb(new Error('File type not allowed'));
    }
    cb(null, true);
  }
});

function requireAdmin(req, res, next) {
  const auth = req.headers.authorization || '';
  const token = auth.startsWith('Bearer ') ? auth.slice(7) : null;
  if (!token) return res.status(401).json({ error: 'No token' });
  try { jwt.verify(token, JWT_SECRET); next(); }
  catch { return res.status(401).json({ error: 'Invalid token' }); }
}

app.use('/api/', rateLimit({ windowMs: 60_000, max: 180 }));
const loginLimiter = rateLimit({ windowMs: 15 * 60_000, max: 10 });

app.post('/api/login', loginLimiter, (req, res) => {
  const { username, password } = req.body || {};
  if (username !== process.env.ADMIN_USERNAME)
    return res.status(401).json({ error: 'Invalid credentials' });
  if (!bcrypt.compareSync(password || '', process.env.ADMIN_PASSWORD_HASH))
    return res.status(401).json({ error: 'Invalid credentials' });
  const token = jwt.sign({ role: 'admin' }, JWT_SECRET, { expiresIn: '8h' });
  res.json({ token });
});

app.get('/api/categories', (req, res) => {
  const rows = db.prepare(`
    SELECT category, subcategory, COUNT(*) as count
    FROM games WHERE category IS NOT NULL
    GROUP BY category, subcategory
  `).all();

  const map = {};
  CATEGORIES.forEach(c => map[c] = { name: c, total: 0, subcategories: {} });
  rows.forEach(r => {
    if (!map[r.category]) map[r.category] = { name: r.category, total: 0, subcategories: {} };
    map[r.category].total += r.count;
    const sub = r.subcategory || 'General';
    map[r.category].subcategories[sub] = (map[r.category].subcategories[sub] || 0) + r.count;
  });
  res.json(Object.values(map));
});

app.get('/api/search', (req, res) => {
  const q = (req.query.q || '').trim();
  if (!q) return res.json([]);
  const like = `%${q}%`;
  const rows = db.prepare(`
    SELECT id,title,description,category,subcategory,platform,version,size_bytes,downloads,created_at
    FROM games
    WHERE title LIKE ? OR description LIKE ? OR category LIKE ?
       OR subcategory LIKE ? OR platform LIKE ?
    ORDER BY (title LIKE ?) DESC, downloads DESC, id DESC
    LIMIT 200
  `).all(like, like, like, like, like, `${q}%`);
  res.json(rows);
});

app.get('/api/games', (req, res) => {
  const { category, subcategory, q } = req.query;
  const where = [];
  const params = [];
  if (category) { where.push('category = ?'); params.push(category); }
  if (subcategory) { where.push('subcategory = ?'); params.push(subcategory); }
  if (q) {
    where.push('(title LIKE ? OR description LIKE ? OR platform LIKE ?)');
    params.push(`%${q}%`, `%${q}%`, `%${q}%`);
  }
  const sql = `SELECT id,title,description,category,subcategory,platform,version,size_bytes,downloads,created_at
               FROM games ${where.length ? 'WHERE ' + where.join(' AND ') : ''}
               ORDER BY id DESC`;
  res.json(db.prepare(sql).all(...params));
});

app.get('/api/games/:id', (req, res) => {
  const row = db.prepare('SELECT * FROM games WHERE id = ?').get(req.params.id);
  if (!row) return res.status(404).json({ error: 'Not found' });
  delete row.filename; delete row.original_name;
  res.json(row);
});
app.get('/api/games/:id/download', (req, res) => {
  const game = db.prepare('SELECT * FROM games WHERE id = ?').get(req.params.id);
  if (!game) return res.status(404).json({ error: 'Not found' });
  
  db.prepare('UPDATE games SET downloads = downloads + 1 WHERE id = ?').run(game.id);

  // If it's a link, redirect them to the external site
  if (game.download_url) {
    return res.redirect(game.download_url);
  }

  // If it's an uploaded file, download it normally
  const filePath = path.join(UPLOAD_DIR, game.filename);
  if (!fs.existsSync(filePath)) return res.status(404).json({ error: 'File missing' });
  res.download(filePath, game.original_name);
});
app.post('/api/admin/games', requireAdmin, upload.fields([
  { name: 'file', maxCount: 1 }, 
  { name: 'image', maxCount: 1 },
  { name: 'screenshot1', maxCount: 1 },
  { name: 'screenshot2', maxCount: 1 },
  { name: 'screenshot3', maxCount: 1 }
]), async (req, res) => {
  try {
    const { title, description, category, subcategory = '', platform = '', version = '', download_url = '', installation = '' } = req.body;
    
    const gameFile = req.files && req.files['file'] ? req.files['file'][0] : null;
    const imgFile = req.files && req.files['image'] ? req.files['image'][0] : null;
    const ss1 = req.files && req.files['screenshot1'] ? req.files['screenshot1'][0] : null;
    const ss2 = req.files && req.files['screenshot2'] ? req.files['screenshot2'][0] : null;
    const ss3 = req.files && req.files['screenshot3'] ? req.files['screenshot3'][0] : null;

    if (!title || !description || !category || (!gameFile && !download_url)) {
      return res.status(400).json({ error: 'title, description, category, and either a file or link are required' });
    }
    
    const cols = db.prepare("PRAGMA table_info(games)").all().map(c => c.name);
    if (!cols.includes('image_url')) db.exec("ALTER TABLE games ADD COLUMN image_url TEXT");
    if (!cols.includes('download_url')) db.exec("ALTER TABLE games ADD COLUMN download_url TEXT");
    if (!cols.includes('installation')) db.exec("ALTER TABLE games ADD COLUMN installation TEXT");
    if (!cols.includes('screenshots')) db.exec("ALTER TABLE games ADD COLUMN screenshots TEXT");

    // Helper to upload a single file to Supabase
    const uploadToSupabase = async (file) => {
      if (!file) return null;
      const fileName = `${Date.now()}-${crypto.randomBytes(4).toString('hex')}${path.extname(file.originalname)}`;
      
      const { data, error } = await supabase.storage
        .from(R2_BUCKET_NAME) // Your bucket name
        .upload(fileName, file.buffer, {
          contentType: file.mimetype,
          upsert: false
        });

      if (error) throw error;

      // Get public URL
      const { data: publicUrlData } = supabase.storage
        .from(R2_BUCKET_NAME)
        .getPublicUrl(fileName);

      return publicUrlData.publicUrl;
    };

    // Upload all files to Supabase
    const imageUrl = await uploadToSupabase(imgFile);
    const fileUrl = await uploadToSupabase(gameFile); 
    
    const ssArray = [];
    const s1 = await uploadToSupabase(ss1); if (s1) ssArray.push(s1);
    const s2 = await uploadToSupabase(ss2); if (s2) ssArray.push(s2);
    const s3 = await uploadToSupabase(ss3); if (s3) ssArray.push(s3);
    
    const screenshotsJson = JSON.stringify(ssArray);

    // Save to Database
    const info = db.prepare(`
      INSERT INTO games (title, description, category, subcategory, platform, version, size_bytes, filename, original_name, image_url, download_url, installation, screenshots)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).run(title, description, category, subcategory, platform, version,
           gameFile ? gameFile.size : 0, 
           fileUrl || 'link', 
           gameFile ? gameFile.originalname : title, 
           imageUrl, download_url, installation, screenshotsJson);
           
    res.json({ id: info.lastInsertRowid, message: 'Game uploaded' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: err.message });
  }
});
app.delete('/api/admin/games/:id', requireAdmin, (req, res) => {
  const game = db.prepare('SELECT * FROM games WHERE id = ?').get(req.params.id);
  if (!game) return res.status(404).json({ error: 'Not found' });
  const filePath = path.join(UPLOAD_DIR, game.filename);
  if (fs.existsSync(filePath)) fs.unlinkSync(filePath);
  db.prepare('DELETE FROM games WHERE id = ?').run(game.id);
  res.json({ message: 'Deleted' });
});

app.use((err, req, res, next) => {
  if (err instanceof multer.MulterError) return res.status(400).json({ error: `Upload error: ${err.message}` });
  if (err) return res.status(400).json({ error: err.message });
  next();
});

app.listen(PORT, () => {
  console.log(`🎮 GG88 running at http://localhost:${PORT}`);
});
