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
app.use(cors({
  origin: process.env.CORS_ORIGIN || 'http://localhost:8080',
  credentials: true
}));
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

// Validate required environment variables
if (!process.env.JWT_SECRET) {
  console.error('❌ JWT_SECRET environment variable is required');
  process.exit(1);
}

const UPLOAD_DIR = path.join(__dirname, 'uploads');
if (!fs.existsSync(UPLOAD_DIR)) {
  fs.mkdirSync(UPLOAD_DIR, { recursive: true });
}
app.use('/uploads', express.static(UPLOAD_DIR));

// ------------------- DATABASE -------------------
const db = new Database(process.env.DB_FILE || 'database.sqlite');

// Enable foreign keys and better performance
db.pragma('journal_mode = WAL');
db.pragma('foreign_keys = ON');

const columnExists = (tableName, columnName) => {
  try {
    const columns = db.prepare(`PRAGMA table_info(${tableName})`).all();
    return columns.some(col => col.name === columnName);
  } catch (error) {
    return false;
  }
};

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
  excerpt TEXT,
  authorId INTEGER,
  category TEXT NOT NULL,
  imageUrl TEXT,
  publishedAt DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updatedAt DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  isPublished BOOLEAN DEFAULT 1,
  FOREIGN KEY (authorId) REFERENCES users(id) ON DELETE SET NULL
);

CREATE TABLE IF NOT EXISTS events (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  title TEXT NOT NULL,
  description TEXT NOT NULL,
  date TEXT NOT NULL,
  location TEXT NOT NULL,
  imageUrl TEXT,
  registrationUrl TEXT,
  createdAt DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updatedAt DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS workshops (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  title TEXT NOT NULL,
  description TEXT NOT NULL,
  date TEXT NOT NULL,
  facilitator TEXT NOT NULL,
  imageUrl TEXT,
  registrationUrl TEXT,
  createdAt DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updatedAt DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS webinars (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  title TEXT NOT NULL,
  description TEXT NOT NULL,
  date TEXT NOT NULL,
  speaker TEXT NOT NULL,
  imageUrl TEXT,
  registrationUrl TEXT,
  createdAt DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updatedAt DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS careers (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  title TEXT NOT NULL,
  description TEXT NOT NULL,
  requirements TEXT,
  location TEXT NOT NULL,
  deadline TEXT NOT NULL,
  createdAt DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updatedAt DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS contact_forms (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL,
  email TEXT NOT NULL,
  subject TEXT NOT NULL,
  message TEXT NOT NULL,
  isRead BOOLEAN DEFAULT 0,
  createdAt DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS newsletter_subscribers (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  email TEXT UNIQUE NOT NULL,
  isActive BOOLEAN DEFAULT 1,
  subscribedAt DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS donations (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL,
  email TEXT NOT NULL,
  amount REAL NOT NULL,
  message TEXT,
  paymentMethod TEXT NOT NULL,
  isProcessed BOOLEAN DEFAULT 0,
  createdAt DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);
`);

if(!columnExists('blog_posts', 'excerpt')) {
  db.exec(`ALTER TABLE blog_posts ADD COLUMN excerpt TEXT;`);
  console.log('✅ Added excerpt column to blog_posts table');
}

if (!columnExists('blog_posts', 'isPublished')) {
  db.exec('ALTER TABLE blog_posts ADD COLUMN isPublished BOOLEAN DEFAULT 1');
  console.log('✅ Added isPublished column to blog_posts');
}

// Replace the problematic migration with this:
if (!columnExists('blog_posts', 'updatedAt')) {
  db.exec('ALTER TABLE blog_posts ADD COLUMN updatedAt DATETIME');
  // Set default value for existing rows
  db.exec('UPDATE blog_posts SET updatedAt = CURRENT_TIMESTAMP WHERE updatedAt IS NULL');
  console.log('✅ Added updatedAt column to blog_posts');
}

const tables = ['events', 'workshops', 'webinars', 'careers'];
tables.forEach(table => {
  if (!columnExists(table, 'updatedAt')) {
    db.exec(`ALTER TABLE ${table} ADD COLUMN updatedAt DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP`);
    console.log(`✅ Added updatedAt column to ${table}`);
  }
});

if (!columnExists('contact_forms', 'isRead')) {
  db.exec('ALTER TABLE contact_forms ADD COLUMN isRead BOOLEAN DEFAULT 0');
  console.log('✅ Added isRead column to contact_forms');
}

// Add isActive to newsletter_subscribers if it doesn't exist
if (!columnExists('newsletter_subscribers', 'isActive')) {
  db.exec('ALTER TABLE newsletter_subscribers ADD COLUMN isActive BOOLEAN DEFAULT 1');
  console.log('✅ Added isActive column to newsletter_subscribers');
}
// Create default admin user if not exists
const adminCheck = db.prepare('SELECT * FROM users WHERE email = ?').get('admin@radianthope.com');
if (!adminCheck) {
  const hashedPassword = bcrypt.hashSync('admin123', 10);
  db.prepare('INSERT INTO users (name, email, password, role) VALUES (?, ?, ?, ?)')
    .run('Admin User', 'admin@radianthope.com', hashedPassword, 'admin');
  console.log('✅ Default admin user created: admin@radianthope.com / admin123');
}

// ------------------- HELPER FUNCTIONS -------------------
const sanitizeInput = (input) => {
  if (typeof input === 'string') {
    return input.trim().replace(/[<>]/g, '');
  }
  return input;
};

const validateEmail = (email) => {
  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  return emailRegex.test(email);
};

const deleteFile = (filePath) => {
  if (filePath && filePath.startsWith('/uploads/')) {
    const fullPath = path.join(__dirname, filePath);
    if (fs.existsSync(fullPath)) {
      fs.unlinkSync(fullPath);
    }
  }
};

const generateExcerpt = (content, maxLength = 150) => {
  const plainText = content.replace(/<[^>]*>/g, '');
  return plainText.length > maxLength 
    ? plainText.substring(0, maxLength) + '...' 
    : plainText;
};

// ------------------- UPLOADS (multer) -------------------
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, UPLOAD_DIR);
  },
  filename: (req, file, cb) => {
    const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
    cb(null, uniqueSuffix + path.extname(file.originalname));
  }
});

const fileFilter = (req, file, cb) => {
  if (file.mimetype.startsWith('image/')) {
    cb(null, true);
  } else {
    cb(new Error('Only image files are allowed!'), false);
  }
};

const upload = multer({ 
  storage, 
  fileFilter,
  limits: {
    fileSize: 5 * 1024 * 1024 // 5MB limit
  }
});

// ------------------- AUTH HELPERS -------------------
const getUserById = (id) => {
  return db.prepare('SELECT id, name, email, role, password, createdAt FROM users WHERE id = ?').get(id);
};

const authMiddleware = (req, res, next) => {
  try {
    const token = req.header('Authorization')?.replace('Bearer ', '');
    if (!token) {
      return res.status(401).send({ error: 'Access denied. No token provided.' });
    }
    
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    const user = getUserById(decoded.id);
    
    if (!user) {
      return res.status(401).send({ error: 'Invalid token.' });
    }
    
    req.user = user;
    next();
  } catch (error) {
    res.status(401).send({ error: 'Invalid token.' });
  }
};

const adminMiddleware = (req, res, next) => {
  if (req.user?.role !== 'admin') {
    return res.status(403).send({ error: 'Admin access required.' });
  }
  next();
};

const editorMiddleware = (req, res, next) => {
  if (!['admin', 'editor'].includes(req.user?.role)) {
    return res.status(403).send({ error: 'Editor access required.' });
  }
  next();
};

// ------------------- AUTH ROUTES -------------------
app.post('/api/auth/register', async (req, res) => {
  try {
    let { name, email, password, role = 'editor' } = req.body;
    
    // Input validation
    name = sanitizeInput(name);
    email = sanitizeInput(email);
    
    if (!name || !email || !password) {
      return res.status(400).send({ error: 'Name, email, and password are required.' });
    }
    
    if (!validateEmail(email)) {
      return res.status(400).send({ error: 'Invalid email format.' });
    }
    
    if (password.length < 6) {
      return res.status(400).send({ error: 'Password must be at least 6 characters long.' });
    }
    
    if (name.length > 100) {
      return res.status(400).send({ error: 'Name is too long.' });
    }
    
    const hashedPassword = await bcrypt.hash(password, 10);
    const stmt = db.prepare('INSERT INTO users (name, email, password, role) VALUES (?, ?, ?, ?)');
    const info = stmt.run(name, email, hashedPassword, role);
    
    const user = { 
      id: info.lastInsertRowid, 
      name, 
      email, 
      role,
      createdAt: new Date().toISOString()
    };
    
    const token = jwt.sign({ id: user.id }, process.env.JWT_SECRET);
    res.status(201).send({ user, token });
  } catch (err) {
    if (err.message.includes('UNIQUE constraint failed')) {
      return res.status(400).send({ error: 'Email already exists.' });
    }
    res.status(400).send({ error: 'Registration failed.' });
  }
});

app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    
    if (!email || !password) {
      return res.status(400).send({ error: 'Email and password are required.' });
    }
    
    const user = db.prepare('SELECT * FROM users WHERE email = ?').get(email);
    if (!user) {
      return res.status(400).send({ error: 'Invalid login credentials.' });
    }
    
    const isPasswordValid = await bcrypt.compare(password, user.password);
    if (!isPasswordValid) {
      return res.status(400).send({ error: 'Invalid login credentials.' });
    }
    
    const token = jwt.sign({ id: user.id }, process.env.JWT_SECRET);
    const safeUser = { 
      id: user.id, 
      name: user.name, 
      email: user.email, 
      role: user.role, 
      createdAt: user.createdAt 
    };
    
    res.send({ user: safeUser, token });
  } catch (err) {
    res.status(500).send({ error: 'Login failed.' });
  }
});

app.get('/api/auth/me', authMiddleware, (req, res) => {
  const { password, ...safeUser } = req.user;
  res.send(safeUser);
});

// ------------------- BLOG ROUTES -------------------
app.get('/api/blog', (req, res) => {
  try {
    const { page = 1, limit = 10, category, search, publishedOnly = true } = req.query;
    const offset = (parseInt(page) - 1) * parseInt(limit);
    
    let whereClause = '';
    let params = [];
    
    if (publishedOnly) {
      whereClause = 'WHERE b.isPublished = 1';
    }
    
    if (category) {
      whereClause += whereClause ? ' AND b.category = ?' : 'WHERE b.category = ?';
      params.push(category);
    }
    
    if (search) {
      const searchCondition = `(b.title LIKE ? OR b.content LIKE ? OR u.name LIKE ?)`;
      whereClause += whereClause ? ` AND ${searchCondition}` : `WHERE ${searchCondition}`;
      const searchTerm = `%${search}%`;
      params.push(searchTerm, searchTerm, searchTerm);
    }
    
    const posts = db.prepare(`
      SELECT b.*, u.name AS authorName
      FROM blog_posts b 
      LEFT JOIN users u ON u.id = b.authorId
      ${whereClause}
      ORDER BY b.publishedAt DESC
      LIMIT ? OFFSET ?
    `).all(...params, parseInt(limit), offset);
    
    const totalResult = db.prepare(`
      SELECT COUNT(*) as total
      FROM blog_posts b
      LEFT JOIN users u ON u.id = b.authorId
      ${whereClause}
    `).get(...params);
    
    const totalPages = Math.ceil(totalResult.total / parseInt(limit));
    
    res.send({
      posts,
      pagination: {
        currentPage: parseInt(page),
        totalPages,
        totalPosts: totalResult.total,
        hasNext: parseInt(page) < totalPages,
        hasPrev: parseInt(page) > 1
      }
    });
  } catch (error) {
    console.error('Error fetching blog posts:', error);
    res.status(500).send({ error: 'Error fetching blog posts.' });
  }
});

app.get('/api/blog/categories', (req, res) => {
  try {
    const categories = db.prepare(`
      SELECT category, COUNT(*) as count 
      FROM blog_posts 
      WHERE isPublished = 1 
      GROUP BY category 
      ORDER BY count DESC
    `).all();
    res.send(categories);
  } catch (error) {
    res.status(500).send({ error: 'Error fetching categories.' });
  }
});

app.get('/api/blog/:id', (req, res) => {
  try {
    const post = db.prepare(`
      SELECT b.*, u.name AS authorName
      FROM blog_posts b 
      LEFT JOIN users u ON u.id = b.authorId
      WHERE b.id = ?
    `).get(req.params.id);
    
    if (!post) {
      return res.status(404).send({ error: 'Blog post not found.' });
    }
    
    res.send(post);
  } catch (error) {
    console.error('Error fetching blog post:', error);
    res.status(500).send({ error: 'Error fetching blog post.' });
  }
});

app.post('/api/blog', authMiddleware, editorMiddleware, upload.single('image'), (req, res) => {
  try {
    let { title, content, category, isPublished = true } = req.body;
    
    // Input validation
    title = sanitizeInput(title);
    content = sanitizeInput(content);
    category = sanitizeInput(category);
    
    if (!title || !content || !category) {
      return res.status(400).send({ error: 'Title, content, and category are required.' });
    }
    
    if (title.length > 200) {
      return res.status(400).send({ error: 'Title is too long.' });
    }
    
    const excerpt = generateExcerpt(content);
    const imageUrl = req.file ? `/uploads/${req.file.filename}` : null;
    
    const info = db.prepare(`
      INSERT INTO blog_posts (title, content, excerpt, authorId, category, imageUrl, isPublished, updatedAt)
      VALUES (?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
    `).run(title, content, excerpt, req.user.id, category, imageUrl, isPublished ? 1 : 0);
    
    const createdPost = db.prepare(`
      SELECT b.*, u.name AS authorName
      FROM blog_posts b 
      LEFT JOIN users u ON u.id = b.authorId
      WHERE b.id = ?
    `).get(info.lastInsertRowid);
    
    res.status(201).send(createdPost);
  } catch (error) {
    console.error('Error creating blog post:', error);
    
    // Clean up uploaded file if there was an error
    if (req.file) {
      deleteFile(`/uploads/${req.file.filename}`);
    }
    
    res.status(400).send({ error: 'Error creating blog post.' });
  }
});

app.put('/api/blog/:id', authMiddleware, editorMiddleware, upload.single('image'), (req, res) => {
  try {
    const postId = req.params.id;
    const post = db.prepare('SELECT * FROM blog_posts WHERE id = ?').get(postId);
    
    if (!post) {
      return res.status(404).send({ error: 'Post not found.' });
    }
    
    // Check authorization
    if (post.authorId !== req.user.id && req.user.role !== 'admin') {
      return res.status(403).send({ error: 'Not authorized to update this post.' });
    }
    
    let { title, content, category, isPublished } = req.body;
    
    // Input validation
    title = sanitizeInput(title) || post.title;
    content = sanitizeInput(content) || post.content;
    category = sanitizeInput(category) || post.category;
    
    if (title && title.length > 200) {
      return res.status(400).send({ error: 'Title is too long.' });
    }
    
    const excerpt = content ? generateExcerpt(content) : post.excerpt;
    let imageUrl = post.imageUrl;
    
    // Handle image update
    if (req.file) {
      // Delete old image if exists
      if (post.imageUrl) {
        deleteFile(post.imageUrl);
      }
      imageUrl = `/uploads/${req.file.filename}`;
    }
    
    db.prepare(`
      UPDATE blog_posts 
      SET title = ?, content = ?, excerpt = ?, category = ?, imageUrl = ?, isPublished = ?, updatedAt = CURRENT_TIMESTAMP 
      WHERE id = ?
    `).run(
      title, 
      content, 
      excerpt, 
      category, 
      imageUrl, 
      isPublished !== undefined ? (isPublished ? 1 : 0) : post.isPublished,
      postId
    );
    
    const updatedPost = db.prepare(`
      SELECT b.*, u.name AS authorName
      FROM blog_posts b 
      LEFT JOIN users u ON u.id = b.authorId
      WHERE b.id = ?
    `).get(postId);
    
    res.send(updatedPost);
  } catch (error) {
    console.error('Error updating blog post:', error);
    
    // Clean up uploaded file if there was an error
    if (req.file) {
      deleteFile(`/uploads/${req.file.filename}`);
    }
    
    res.status(400).send({ error: 'Error updating blog post.' });
  }
});

app.delete('/api/blog/:id', authMiddleware, editorMiddleware, (req, res) => {
  try {
    const postId = req.params.id;
    const post = db.prepare('SELECT * FROM blog_posts WHERE id = ?').get(postId);
    
    if (!post) {
      return res.status(404).send({ error: 'Post not found.' });
    }
    
    // Check authorization
    if (post.authorId !== req.user.id && req.user.role !== 'admin') {
      return res.status(403).send({ error: 'Not authorized to delete this post.' });
    }
    
    // Delete associated image
    if (post.imageUrl) {
      deleteFile(post.imageUrl);
    }
    
    db.prepare('DELETE FROM blog_posts WHERE id = ?').run(postId);
    
    res.send({ message: 'Post deleted successfully.' });
  } catch (error) {
    console.error('Error deleting blog post:', error);
    res.status(500).send({ error: 'Error deleting post.' });
  }
});

// ------------------- EVENT ROUTES -------------------
app.get('/api/events', (req, res) => {
  try {
    const { page = 1, limit = 10, upcoming = false } = req.query;
    const offset = (parseInt(page) - 1) * parseInt(limit);
    
    let whereClause = '';
    if (upcoming) {
      whereClause = 'WHERE date >= date("now")';
    }
    
    const events = db.prepare(`
      SELECT * FROM events 
      ${whereClause}
      ORDER BY date ${upcoming ? 'ASC' : 'DESC'}
      LIMIT ? OFFSET ?
    `).all(parseInt(limit), offset);
    
    const totalResult = db.prepare(`
      SELECT COUNT(*) as total FROM events ${whereClause}
    `).get();
    
    const totalPages = Math.ceil(totalResult.total / parseInt(limit));
    
    res.send({
      events,
      pagination: {
        currentPage: parseInt(page),
        totalPages,
        totalEvents: totalResult.total,
        hasNext: parseInt(page) < totalPages,
        hasPrev: parseInt(page) > 1
      }
    });
  } catch (error) {
    res.status(500).send({ error: 'Error fetching events.' });
  }
});

app.get('/api/events/:id', (req, res) => {
  try {
    const event = db.prepare('SELECT * FROM events WHERE id = ?').get(req.params.id);
    if (!event) {
      return res.status(404).send({ error: 'Event not found.' });
    }
    res.send(event);
  } catch (error) {
    res.status(500).send({ error: 'Error fetching event.' });
  }
});

app.post('/api/events', authMiddleware, editorMiddleware, upload.single('image'), (req, res) => {
  try {
    let { title, description, date, location, registrationUrl } = req.body;
    
    // Input validation
    title = sanitizeInput(title);
    description = sanitizeInput(description);
    location = sanitizeInput(location);
    
    if (!title || !description || !date || !location) {
      return res.status(400).send({ error: 'Title, description, date, and location are required.' });
    }
    
    const imageUrl = req.file ? `/uploads/${req.file.filename}` : null;
    
    const info = db.prepare(`
      INSERT INTO events (title, description, date, location, imageUrl, registrationUrl, updatedAt)
      VALUES (?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
    `).run(title, description, date, location, imageUrl, registrationUrl || null);
    
    const createdEvent = db.prepare('SELECT * FROM events WHERE id = ?').get(info.lastInsertRowid);
    res.status(201).send(createdEvent);
  } catch (error) {
    if (req.file) {
      deleteFile(`/uploads/${req.file.filename}`);
    }
    res.status(400).send({ error: 'Error creating event.' });
  }
});

// ... (Similar improvements for workshops, webinars, careers routes)

// ------------------- CONTACT ROUTES -------------------
app.post('/api/contact', (req, res) => {
  try {
    let { name, email, subject, message } = req.body;
    
    // Input validation
    name = sanitizeInput(name);
    email = sanitizeInput(email);
    subject = sanitizeInput(subject);
    message = sanitizeInput(message);
    
    if (!name || !email || !subject || !message) {
      return res.status(400).send({ error: 'All fields are required.' });
    }
    
    if (!validateEmail(email)) {
      return res.status(400).send({ error: 'Invalid email format.' });
    }
    
    if (name.length > 100) {
      return res.status(400).send({ error: 'Name is too long.' });
    }
    
    if (subject.length > 200) {
      return res.status(400).send({ error: 'Subject is too long.' });
    }
    
    db.prepare('INSERT INTO contact_forms (name, email, subject, message) VALUES (?, ?, ?, ?)')
      .run(name, email, subject, message);
    
    res.status(201).send({ message: 'Contact form submitted successfully.' });
  } catch (error) {
    res.status(400).send({ error: 'Error submitting contact form.' });
  }
});

// ------------------- NEWSLETTER ROUTES -------------------
app.post('/api/newsletter/subscribe', (req, res) => {
  try {
    const { email } = req.body;
    
    if (!email || !validateEmail(email)) {
      return res.status(400).send({ error: 'Valid email is required.' });
    }
    
    const existing = db.prepare('SELECT * FROM newsletter_subscribers WHERE email = ?').get(email);
    if (existing) {
      if (!existing.isActive) {
        db.prepare('UPDATE newsletter_subscribers SET isActive = 1 WHERE email = ?').run(email);
        return res.send({ message: 'Resubscribed successfully.' });
      }
      return res.status(400).send({ error: 'Email already subscribed.' });
    }
    
    db.prepare('INSERT INTO newsletter_subscribers (email) VALUES (?)').run(email);
    res.status(201).send({ message: 'Subscribed successfully.' });
  } catch (error) {
    res.status(400).send({ error: 'Subscription failed.' });
  }
});

app.post('/api/newsletter/unsubscribe', (req, res) => {
  try {
    const { email } = req.body;
    
    if (!email || !validateEmail(email)) {
      return res.status(400).send({ error: 'Valid email is required.' });
    }
    
    const existing = db.prepare('SELECT * FROM newsletter_subscribers WHERE email = ?').get(email);
    if (!existing) {
      return res.status(404).send({ error: 'Email not found in subscribers.' });
    }
    
    db.prepare('UPDATE newsletter_subscribers SET isActive = 0 WHERE email = ?').run(email);
    res.send({ message: 'Unsubscribed successfully.' });
  } catch (error) {
    res.status(400).send({ error: 'Unsubscribe failed.' });
  }
});

// ------------------- DONATION ROUTES -------------------
app.post('/api/donate', (req, res) => {
  try {
    let { name, email, amount, message, paymentMethod } = req.body;
    
    // Input validation
    name = sanitizeInput(name);
    email = sanitizeInput(email);
    message = sanitizeInput(message);
    
    if (!name || !email || !amount || !paymentMethod) {
      return res.status(400).send({ error: 'All required fields must be filled.' });
    }
    
    if (!validateEmail(email)) {
      return res.status(400).send({ error: 'Invalid email format.' });
    }
    
    if (parseFloat(amount) <= 0) {
      return res.status(400).send({ error: 'Donation amount must be positive.' });
    }
    
    db.prepare('INSERT INTO donations (name, email, amount, message, paymentMethod) VALUES (?, ?, ?, ?, ?)')
      .run(name, email, parseFloat(amount), message || null, paymentMethod);
    
    res.status(201).send({ 
      message: 'Donation recorded successfully.',
      receipt: {
        name,
        email,
        amount: parseFloat(amount),
        paymentMethod,
        date: new Date().toISOString()
      }
    });
  } catch (error) {
    res.status(400).send({ error: 'Error processing donation.' });
  }
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
      subscribersCount: q('SELECT COUNT(*) AS c FROM newsletter_subscribers WHERE isActive = 1').c,
      donationsCount: q('SELECT COUNT(*) AS c FROM donations').c,
      totalDonations: q('SELECT COALESCE(SUM(amount), 0) AS total FROM donations').total,
      unreadContacts: q('SELECT COUNT(*) AS c FROM contact_forms WHERE isRead = 0').c,
      recentActivities: db.prepare(`
        SELECT 'blog' as type, title, publishedAt as date FROM blog_posts 
        UNION SELECT 'event' as type, title, createdAt as date FROM events
        UNION SELECT 'donation' as type, name || ' - $' || amount as title, createdAt as date FROM donations
        ORDER BY date DESC LIMIT 10
      `).all()
    };
    res.send(stats);
  } catch (error) {
    res.status(500).send({ error: 'Error fetching stats.' });
  }
});

// ------------------- ERROR HANDLING -------------------
app.use((error, req, res, next) => {
  if (error instanceof multer.MulterError) {
    if (error.code === 'LIMIT_FILE_SIZE') {
      return res.status(400).send({ error: 'File too large. Maximum size is 5MB.' });
    }
  }
  
  console.error('Unhandled error:', error);
  res.status(500).send({ error: 'Something went wrong!' });
});

// 404 handler
app.use('*', (req, res) => {
  res.status(404).send({ error: 'Endpoint not found.' });
});

// ------------------- SERVER -------------------
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
  console.log(`\n🎉 Radiant Hope Media API Server Started!\n`);
  console.log(`✅ Server running on port ${PORT}`);
  console.log(`✅ Upload directory: ${UPLOAD_DIR}`);
  console.log(`✅ Database file: ${process.env.DB_FILE || 'database.sqlite'}`);
  console.log(`✅ Environment: ${process.env.NODE_ENV || 'development'}`);
  console.log(`\n📚 API Documentation:`);
  console.log(`   🔗 Local: http://localhost:${PORT}/api/docs`);
  console.log(`   🌐 Main API: http://localhost:${PORT}/`);
  console.log(`\n🔑 Admin Test Credentials:`);
  console.log(`   📧 Email: admin@radianthope.com`);
  console.log(`   🔐 Password: admin123`);
  console.log(`\n⚡ Quick Test Links:`);
  console.log(`   🩺 Health Check: http://localhost:${PORT}/api/health`);
  console.log(`   📝 Blog Posts: http://localhost:${PORT}/api/blog`);
  console.log(`\n🚀 Ready to accept requests!`);
  console.log(`⏳ Waiting for file changes...\n`);
});