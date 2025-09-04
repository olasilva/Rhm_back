// index.js - Complete Node.js Backend for Radiant Hope Media (SQLite, Full)
import dotenv from 'dotenv';
dotenv.config();
import express from 'express';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import cors from 'cors';
import multer from 'multer';
import path from 'path';
import fs from 'fs';
import Database from 'better-sqlite3';
import { fileURLToPath } from 'url';
import { dirname } from 'path';

// ------------------- DIRNAME POLYFILL FOR ES MODULES -------------------
const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

// ------------------- APP & MIDDLEWARE -------------------
const app = express();
app.use(cors());
app.use(express.json());

const UPLOAD_DIR = path.join(__dirname, 'uploads');
if (!fs.existsSync(UPLOAD_DIR)) fs.mkdirSync(UPLOAD_DIR, { recursive: true });
app.use('/uploads', express.static(UPLOAD_DIR));

// ------------------- DATABASE -------------------
const db = new Database(process.env.DB_FILE || 'database.sqlite');

db.exec(`
CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL,
  email TEXT UNIQUE NOT NULL,
  password TEXT NOT NULL,
  role TEXT NOT NULL DEFAULT 'editor',
  createdAt DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS blog_posts (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  title TEXT NOT NULL,
  content TEXT NOT NULL,
  authorId INTEGER,
  category TEXT NOT NULL,
  imageUrl TEXT,
  publishedAt DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (authorId) REFERENCES users(id)
);

CREATE TABLE IF NOT EXISTS events (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  title TEXT NOT NULL,
  description TEXT NOT NULL,
  date TEXT NOT NULL,
  location TEXT NOT NULL,
  imageUrl TEXT,
  registrationUrl TEXT,
  createdAt DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS workshops (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  title TEXT NOT NULL,
  description TEXT NOT NULL,
  date TEXT NOT NULL,
  facilitator TEXT NOT NULL,
  imageUrl TEXT,
  registrationUrl TEXT,
  createdAt DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS webinars (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  title TEXT NOT NULL,
  description TEXT NOT NULL,
  date TEXT NOT NULL,
  speaker TEXT NOT NULL,
  imageUrl TEXT,
  registrationUrl TEXT,
  createdAt DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS careers (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  title TEXT NOT NULL,
  description TEXT NOT NULL,
  requirements TEXT, -- JSON array of strings
  location TEXT NOT NULL,
  deadline TEXT NOT NULL,
  createdAt DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS contact_forms (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL,
  email TEXT NOT NULL,
  subject TEXT NOT NULL,
  message TEXT NOT NULL,
  createdAt DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS newsletter_subscribers (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  email TEXT UNIQUE NOT NULL,
  subscribedAt DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS donations (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL,
  email TEXT NOT NULL,
  amount REAL NOT NULL,
  message TEXT,
  paymentMethod TEXT NOT NULL,
  createdAt DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);
`);

// After database initialization, add:
const adminCheck = db.prepare('SELECT * FROM users WHERE email = ?').get('admin@radianthope.com');
if (!adminCheck) {
  const hashedPassword = bcrypt.hashSync('admin123', 10);
  db.prepare('INSERT INTO users (name, email, password, role) VALUES (?, ?, ?, ?)')
    .run('Admin User', 'admin@radianthope.com', hashedPassword, 'admin');
  console.log('Default admin user created: admin@radianthope.com / admin123');
}

// ------------------- UPLOADS (multer) -------------------
const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, UPLOAD_DIR),
  filename: (req, file, cb) => cb(null, `${Date.now()}-${file.originalname}`)
});
const upload = multer({ storage });

// ------------------- AUTH HELPERS -------------------
const getUserById = (id) => db.prepare('SELECT id, name, email, role, password, createdAt FROM users WHERE id = ?').get(id);

const authMiddleware = (req, res, next) => {
  try {
    const token = req.header('Authorization')?.replace('Bearer ', '');
    if (!token) return res.status(401).send({ error: 'Please authenticate' });
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    const user = getUserById(decoded.id);
    if (!user) return res.status(401).send({ error: 'Please authenticate' });
    req.user = user; // attach full user
    next();
  } catch (e) {
    res.status(401).send({ error: 'Please authenticate' });
  }
};

const adminMiddleware = (req, res, next) => {
  if (req.user?.role !== 'admin') return res.status(403).send({ error: 'Admin access required' });
  next();
};

// ------------------- AUTH ROUTES -------------------
app.post('/api/auth/register', async (req, res) => {
  try {
    const { name, email, password, role } = req.body;
    const hashed = await bcrypt.hash(password, 10);
    const stmt = db.prepare('INSERT INTO users (name, email, password, role) VALUES (?, ?, ?, ?)');
    const info = stmt.run(name, email, hashed, role || 'editor');
    const user = { id: info.lastInsertRowid, name, email, role: role || 'editor' };
    const token = jwt.sign({ id: user.id }, process.env.JWT_SECRET);
    res.status(201).send({ user, token });
  } catch (err) {
    res.status(400).send({ error: err.message });
  }
});

app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    const user = db.prepare('SELECT * FROM users WHERE email = ?').get(email);
    if (!user) return res.status(400).send({ error: 'Invalid login credentials' });
    const ok = await bcrypt.compare(password, user.password);
    if (!ok) return res.status(400).send({ error: 'Invalid login credentials' });
    const token = jwt.sign({ id: user.id }, process.env.JWT_SECRET);
    const safe = { id: user.id, name: user.name, email: user.email, role: user.role, createdAt: user.createdAt };
    res.send({ user: safe, token });
  } catch (err) {
    res.status(500).send({ error: err.message });
  }
});

app.get('/api/auth/me', authMiddleware, (req, res) => {
  const { password, ...safe } = req.user;
  res.send(safe);
});

// ------------------- BLOG ROUTES -------------------
app.get('/api/blog', (req, res) => {
  try {
    const rows = db.prepare(`
      SELECT b.*, u.name AS authorName
      FROM blog_posts b LEFT JOIN users u ON u.id = b.authorId
      ORDER BY b.publishedAt DESC
    `).all();
    res.send(rows);
  } catch (e) { res.status(500).send({ error: 'Error fetching blog posts' }); }
});

app.get('/api/blog/:id', (req, res) => {
  const post = db.prepare(`
    SELECT b.*, u.name AS authorName
    FROM blog_posts b LEFT JOIN users u ON u.id = b.authorId
    WHERE b.id = ?
  `).get(req.params.id);
  if (!post) return res.status(404).send({ error: 'Post not found' });
  res.send(post);
});

app.post('/api/blog', authMiddleware, upload.single('image'), (req, res) => {
  try {
    const { title, content, category } = req.body;
    const imageUrl = req.file ? `/uploads/${req.file.filename}` : null;
    const info = db.prepare(`
      INSERT INTO blog_posts (title, content, authorId, category, imageUrl)
      VALUES (?, ?, ?, ?, ?)
    `).run(title, content, req.user.id, category, imageUrl);
    const created = db.prepare('SELECT * FROM blog_posts WHERE id = ?').get(info.lastInsertRowid);
    res.status(201).send(created);
  } catch (e) { res.status(400).send({ error: e.message }); }
});

app.put('/api/blog/:id', authMiddleware, upload.single('image'), (req, res) => {
  const post = db.prepare('SELECT * FROM blog_posts WHERE id = ?').get(req.params.id);
  if (!post) return res.status(404).send({ error: 'Post not found' });
  if (post.authorId !== req.user.id && req.user.role !== 'admin') {
    return res.status(403).send({ error: 'Not authorized to update this post' });
  }
  const imageUrl = req.file ? `/uploads/${req.file.filename}` : post.imageUrl;
  const { title, content, category } = req.body;
  db.prepare('UPDATE blog_posts SET title=?, content=?, category=?, imageUrl=? WHERE id=?')
    .run(title || post.title, content || post.content, category || post.category, imageUrl, req.params.id);
  const updated = db.prepare('SELECT * FROM blog_posts WHERE id = ?').get(req.params.id);
  res.send(updated);
});

app.delete('/api/blog/:id', authMiddleware, (req, res) => {
  const post = db.prepare('SELECT * FROM blog_posts WHERE id = ?').get(req.params.id);
  if (!post) return res.status(404).send({ error: 'Post not found' });
  if (post.authorId !== req.user.id && req.user.role !== 'admin') {
    return res.status(403).send({ error: 'Not authorized to delete this post' });
  }
  db.prepare('DELETE FROM blog_posts WHERE id = ?').run(req.params.id);
  res.send({ message: 'Post deleted successfully' });
});

// ------------------- EVENT ROUTES -------------------
app.get('/api/events', (req, res) => {
  try {
    const rows = db.prepare('SELECT * FROM events ORDER BY date DESC').all();
    res.send(rows);
  } catch { res.status(500).send({ error: 'Error fetching events' }); }
});

app.get('/api/events/:id', (req, res) => {
  const row = db.prepare('SELECT * FROM events WHERE id = ?').get(req.params.id);
  if (!row) return res.status(404).send({ error: 'Event not found' });
  res.send(row);
});

app.post('/api/events', authMiddleware, upload.single('image'), (req, res) => {
  try {
    const { title, description, date, location, registrationUrl } = req.body;
    const imageUrl = req.file ? `/uploads/${req.file.filename}` : null;
    const info = db.prepare(`
      INSERT INTO events (title, description, date, location, imageUrl, registrationUrl)
      VALUES (?, ?, ?, ?, ?, ?)
    `).run(title, description, date, location, imageUrl, registrationUrl || null);
    const created = db.prepare('SELECT * FROM events WHERE id = ?').get(info.lastInsertRowid);
    res.status(201).send(created);
  } catch (e) { res.status(400).send({ error: e.message }); }
});

app.put('/api/events/:id', authMiddleware, upload.single('image'), (req, res) => {
  const row = db.prepare('SELECT * FROM events WHERE id = ?').get(req.params.id);
  if (!row) return res.status(404).send({ error: 'Event not found' });
  const { title, description, date, location, registrationUrl } = req.body;
  const imageUrl = req.file ? `/uploads/${req.file.filename}` : row.imageUrl;
  db.prepare('UPDATE events SET title=?, description=?, date=?, location=?, imageUrl=?, registrationUrl=? WHERE id=?')
    .run(title || row.title, description || row.description, date || row.date, location || row.location, imageUrl, registrationUrl || row.registrationUrl, req.params.id);
  const updated = db.prepare('SELECT * FROM events WHERE id = ?').get(req.params.id);
  res.send(updated);
});

app.delete('/api/events/:id', authMiddleware, (req, res) => {
  const row = db.prepare('SELECT * FROM events WHERE id = ?').get(req.params.id);
  if (!row) return res.status(404).send({ error: 'Event not found' });
  db.prepare('DELETE FROM events WHERE id = ?').run(req.params.id);
  res.send({ message: 'Event deleted successfully' });
});

// ------------------- WORKSHOP ROUTES -------------------
app.get('/api/workshops', (req, res) => {
  try { res.send(db.prepare('SELECT * FROM workshops ORDER BY date DESC').all()); }
  catch { res.status(500).send({ error: 'Error fetching workshops' }); }
});

app.get('/api/workshops/:id', (req, res) => {
  const row = db.prepare('SELECT * FROM workshops WHERE id = ?').get(req.params.id);
  if (!row) return res.status(404).send({ error: 'Workshop not found' });
  res.send(row);
});

app.post('/api/workshops', authMiddleware, upload.single('image'), (req, res) => {
  try {
    const { title, description, date, facilitator, registrationUrl } = req.body;
    const imageUrl = req.file ? `/uploads/${req.file.filename}` : null;
    const info = db.prepare(`
      INSERT INTO workshops (title, description, date, facilitator, imageUrl, registrationUrl)
      VALUES (?, ?, ?, ?, ?, ?)
    `).run(title, description, date, facilitator, imageUrl, registrationUrl || null);
    const created = db.prepare('SELECT * FROM workshops WHERE id = ?').get(info.lastInsertRowid);
    res.status(201).send(created);
  } catch (e) { res.status(400).send({ error: e.message }); }
});

app.put('/api/workshops/:id', authMiddleware, upload.single('image'), (req, res) => {
  const row = db.prepare('SELECT * FROM workshops WHERE id = ?').get(req.params.id);
  if (!row) return res.status(404).send({ error: 'Workshop not found' });
  const { title, description, date, facilitator, registrationUrl } = req.body;
  const imageUrl = req.file ? `/uploads/${req.file.filename}` : row.imageUrl;
  db.prepare('UPDATE workshops SET title=?, description=?, date=?, facilitator=?, imageUrl=?, registrationUrl=? WHERE id=?')
    .run(title || row.title, description || row.description, date || row.date, facilitator || row.facilitator, imageUrl, registrationUrl || row.registrationUrl, req.params.id);
  const updated = db.prepare('SELECT * FROM workshops WHERE id = ?').get(req.params.id);
  res.send(updated);
});

app.delete('/api/workshops/:id', authMiddleware, (req, res) => {
  const row = db.prepare('SELECT * FROM workshops WHERE id = ?').get(req.params.id);
  if (!row) return res.status(404).send({ error: 'Workshop not found' });
  db.prepare('DELETE FROM workshops WHERE id = ?').run(req.params.id);
  res.send({ message: 'Workshop deleted successfully' });
});

// ------------------- WEBINAR ROUTES -------------------
app.get('/api/webinars', (req, res) => {
  try { res.send(db.prepare('SELECT * FROM webinars ORDER BY date DESC').all()); }
  catch { res.status(500).send({ error: 'Error fetching webinars' }); }
});

app.get('/api/webinars/:id', (req, res) => {
  const row = db.prepare('SELECT * FROM webinars WHERE id = ?').get(req.params.id);
  if (!row) return res.status(404).send({ error: 'Webinar not found' });
  res.send(row);
});

app.post('/api/webinars', authMiddleware, upload.single('image'), (req, res) => {
  try {
    const { title, description, date, speaker, registrationUrl } = req.body;
    const imageUrl = req.file ? `/uploads/${req.file.filename}` : null;
    const info = db.prepare(`
      INSERT INTO webinars (title, description, date, speaker, imageUrl, registrationUrl)
      VALUES (?, ?, ?, ?, ?, ?)
    `).run(title, description, date, speaker, imageUrl, registrationUrl || null);
    const created = db.prepare('SELECT * FROM webinars WHERE id = ?').get(info.lastInsertRowid);
    res.status(201).send(created);
  } catch (e) { res.status(400).send({ error: e.message }); }
});

app.put('/api/webinars/:id', authMiddleware, upload.single('image'), (req, res) => {
  const row = db.prepare('SELECT * FROM webinars WHERE id = ?').get(req.params.id);
  if (!row) return res.status(404).send({ error: 'Webinar not found' });
  const { title, description, date, speaker, registrationUrl } = req.body;
  const imageUrl = req.file ? `/uploads/${req.file.filename}` : row.imageUrl;
  db.prepare('UPDATE webinars SET title=?, description=?, date=?, speaker=?, imageUrl=?, registrationUrl=? WHERE id=?')
    .run(title || row.title, description || row.description, date || row.date, speaker || row.speaker, imageUrl, registrationUrl || row.registrationUrl, req.params.id);
  const updated = db.prepare('SELECT * FROM webinars WHERE id = ?').get(req.params.id);
  res.send(updated);
});

app.delete('/api/webinars/:id', authMiddleware, (req, res) => {
  const row = db.prepare('SELECT * FROM webinars WHERE id = ?').get(req.params.id);
  if (!row) return res.status(404).send({ error: 'Webinar not found' });
  db.prepare('DELETE FROM webinars WHERE id = ?').run(req.params.id);
  res.send({ message: 'Webinar deleted successfully' });
});

// ------------------- CAREER ROUTES -------------------
app.get('/api/careers', (req, res) => {
  try { res.send(db.prepare('SELECT * FROM careers ORDER BY deadline DESC').all().map(c => ({ ...c, requirements: c.requirements ? JSON.parse(c.requirements) : [] }))); }
  catch { res.status(500).send({ error: 'Error fetching careers' }); }
});

app.get('/api/careers/:id', (req, res) => {
  const row = db.prepare('SELECT * FROM careers WHERE id = ?').get(req.params.id);
  if (!row) return res.status(404).send({ error: 'Career not found' });
  row.requirements = row.requirements ? JSON.parse(row.requirements) : [];
  res.send(row);
});

app.post('/api/careers', authMiddleware, (req, res) => {
  try {
    const { title, description, requirements, location, deadline } = req.body;
    const reqJson = JSON.stringify(Array.isArray(requirements) ? requirements : (requirements ? [requirements] : []));
    const info = db.prepare(`
      INSERT INTO careers (title, description, requirements, location, deadline)
      VALUES (?, ?, ?, ?, ?)
    `).run(title, description, reqJson, location, deadline);
    const created = db.prepare('SELECT * FROM careers WHERE id = ?').get(info.lastInsertRowid);
    created.requirements = created.requirements ? JSON.parse(created.requirements) : [];
    res.status(201).send(created);
  } catch (e) { res.status(400).send({ error: e.message }); }
});

app.put('/api/careers/:id', authMiddleware, (req, res) => {
  const row = db.prepare('SELECT * FROM careers WHERE id = ?').get(req.params.id);
  if (!row) return res.status(404).send({ error: 'Career not found' });
  const { title, description, requirements, location, deadline } = req.body;
  const reqJson = requirements ? JSON.stringify(Array.isArray(requirements) ? requirements : [requirements]) : row.requirements;
  db.prepare('UPDATE careers SET title=?, description=?, requirements=?, location=?, deadline=? WHERE id=?')
    .run(title || row.title, description || row.description, reqJson, location || row.location, deadline || row.deadline, req.params.id);
  const updated = db.prepare('SELECT * FROM careers WHERE id = ?').get(req.params.id);
  updated.requirements = updated.requirements ? JSON.parse(updated.requirements) : [];
  res.send(updated);
});

app.delete('/api/careers/:id', authMiddleware, (req, res) => {
  const row = db.prepare('SELECT * FROM careers WHERE id = ?').get(req.params.id);
  if (!row) return res.status(404).send({ error: 'Career not found' });
  db.prepare('DELETE FROM careers WHERE id = ?').run(req.params.id);
  res.send({ message: 'Career deleted successfully' });
});

// ------------------- CONTACT ROUTES -------------------
app.post('/api/contact', (req, res) => {
  try {
    const { name, email, subject, message } = req.body;
    db.prepare('INSERT INTO contact_forms (name, email, subject, message) VALUES (?, ?, ?, ?)')
      .run(name, email, subject, message);
    res.status(201).send({ message: 'Contact form submitted successfully' });
  } catch (e) { res.status(400).send({ error: e.message }); }
});

app.get('/api/admin/contact-forms', authMiddleware, adminMiddleware, (req, res) => {
  try { res.send(db.prepare('SELECT * FROM contact_forms ORDER BY createdAt DESC').all()); }
  catch { res.status(500).send({ error: 'Error fetching contact forms' }); }
});

app.delete('/api/admin/contact-forms/:id', authMiddleware, adminMiddleware, (req, res) => {
  const row = db.prepare('SELECT * FROM contact_forms WHERE id = ?').get(req.params.id);
  if (!row) return res.status(404).send({ error: 'Contact form not found' });
  db.prepare('DELETE FROM contact_forms WHERE id = ?').run(req.params.id);
  res.send({ message: 'Contact form deleted successfully' });
});

// ------------------- NEWSLETTER ROUTES -------------------
app.post('/api/newsletter/subscribe', (req, res) => {
  try {
    const { email } = req.body;
    const existing = db.prepare('SELECT * FROM newsletter_subscribers WHERE email = ?').get(email);
    if (existing) return res.status(400).send({ error: 'Email already subscribed' });
    db.prepare('INSERT INTO newsletter_subscribers (email) VALUES (?)').run(email);
    res.status(201).send({ message: 'Subscribed successfully' });
  } catch (e) { res.status(400).send({ error: e.message }); }
});

app.get('/api/admin/newsletter', authMiddleware, adminMiddleware, (req, res) => {
  try { res.send(db.prepare('SELECT * FROM newsletter_subscribers ORDER BY subscribedAt DESC').all()); }
  catch { res.status(500).send({ error: 'Error fetching subscribers' }); }
});

app.delete('/api/admin/newsletter/:id', authMiddleware, adminMiddleware, (req, res) => {
  const row = db.prepare('SELECT * FROM newsletter_subscribers WHERE id = ?').get(req.params.id);
  if (!row) return res.status(404).send({ error: 'Subscriber not found' });
  db.prepare('DELETE FROM newsletter_subscribers WHERE id = ?').run(req.params.id);
  res.send({ message: 'Subscriber removed successfully' });
});

// ------------------- DONATION ROUTES -------------------
app.post('/api/donate', (req, res) => {
  try {
    const { name, email, amount, message, paymentMethod } = req.body;
    db.prepare('INSERT INTO donations (name, email, amount, message, paymentMethod) VALUES (?, ?, ?, ?, ?)')
      .run(name, email, amount, message || null, paymentMethod);
    res.status(201).send({ message: 'Donation recorded successfully' });
  } catch (e) { res.status(400).send({ error: e.message }); }
});

app.get('/api/admin/donations', authMiddleware, adminMiddleware, (req, res) => {
  try { res.send(db.prepare('SELECT * FROM donations ORDER BY createdAt DESC').all()); }
  catch { res.status(500).send({ error: 'Error fetching donations' }); }
});

// ------------------- ADMIN DASHBOARD -------------------
app.get('/api/admin/stats', authMiddleware, adminMiddleware, (req, res) => {
  try {
    const q = (sql) => db.prepare(sql).get();
    const stats = {
      blogPostsCount: q('SELECT COUNT(*) AS c FROM blog_posts').c,
      eventsCount: q('SELECT COUNT(*) AS c FROM events').c,
      workshopsCount: q('SELECT COUNT(*) AS c FROM workshops').c,
      webinarsCount: q('SELECT COUNT(*) AS c FROM webinars').c,
      careerCount: q('SELECT COUNT(*) AS c FROM careers').c,
      contactFormsCount: q('SELECT COUNT(*) AS c FROM contact_forms').c,
      subscribersCount: q('SELECT COUNT(*) AS c FROM newsletter_subscribers').c,
      donationsCount: q('SELECT COUNT(*) AS c FROM donations').c,
      totalDonations: q('SELECT COALESCE(SUM(amount), 0) AS total FROM donations').total
    };
    res.send(stats);
  } catch (e) { res.status(500).send({ error: 'Error fetching stats' }); }
});

// ------------------- SERVER -------------------
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`✅ Server running on port ${PORT}`));
app.use(cors({
  origin: 'http://localhost:8080', // Your Vue.js dev server
  credentials: true
}))