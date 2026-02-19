// ============================================================
//  FarmLink - Agricultural Marketplace Backend Server
//  Built with: Node.js + Express + SQLite + JWT Auth
// ============================================================

const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const bcrypt  = require('bcryptjs');
const jwt     = require('jsonwebtoken');
const path    = require('path');
const cors    = require('cors');
const fs      = require('fs');

const app  = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'farmlink_secure_jwt_secret_2024_pcl6';

// ── Create database directory if it doesn't exist ──────────
if (!fs.existsSync('./database')) {
  fs.mkdirSync('./database');
}

// ── Middleware ──────────────────────────────────────────────
app.use(express.json());
app.use(cors());
app.use(express.static(path.join(__dirname, 'public')));

// ── SQLite Database ─────────────────────────────────────────
const db = new sqlite3.Database('./database/farmlink.db', (err) => {
  if (err) {
    console.error('❌ Database connection failed:', err.message);
    process.exit(1);
  }
  console.log('✅ Connected to SQLite database');
  initDatabase();
});

function initDatabase() {
  db.serialize(() => {
    // Enable foreign keys
    db.run('PRAGMA foreign_keys = ON');

    // Users table
    db.run(`
      CREATE TABLE IF NOT EXISTS users (
        id         INTEGER PRIMARY KEY AUTOINCREMENT,
        full_name  TEXT    NOT NULL,
        phone      TEXT    UNIQUE NOT NULL,
        location   TEXT    NOT NULL,
        user_type  TEXT    NOT NULL CHECK(user_type IN ('farmer','vendor')),
        password   TEXT    NOT NULL,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
      )
    `, logTableReady('users'));

    // Crops table (posted by farmers)
    db.run(`
      CREATE TABLE IF NOT EXISTS crops (
        id           INTEGER PRIMARY KEY AUTOINCREMENT,
        farmer_id    INTEGER NOT NULL,
        farmer_name  TEXT    NOT NULL,
        crop_name    TEXT    NOT NULL,
        quantity     TEXT    NOT NULL,
        price_per_kg REAL    NOT NULL,
        location     TEXT    NOT NULL,
        phone        TEXT    NOT NULL,
        created_at   DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (farmer_id) REFERENCES users(id) ON DELETE CASCADE
      )
    `, logTableReady('crops'));

    // Products table (posted by vendors)
    db.run(`
      CREATE TABLE IF NOT EXISTS products (
        id           INTEGER PRIMARY KEY AUTOINCREMENT,
        vendor_id    INTEGER NOT NULL,
        vendor_name  TEXT    NOT NULL,
        product_name TEXT    NOT NULL,
        price        REAL    NOT NULL,
        description  TEXT    DEFAULT '',
        location     TEXT    NOT NULL,
        phone        TEXT    NOT NULL,
        created_at   DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (vendor_id) REFERENCES users(id) ON DELETE CASCADE
      )
    `, logTableReady('products'));
  });
}

function logTableReady(name) {
  return (err) => {
    if (err) console.error(`❌ Error creating ${name} table:`, err.message);
    else     console.log(`✅ ${name} table ready`);
  };
}

// ── Auth Middleware ─────────────────────────────────────────
function authenticate(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  if (!token) {
    return res.status(401).json({ success: false, error: 'Access denied. Please login.' });
  }
  jwt.verify(token, JWT_SECRET, (err, decoded) => {
    if (err) {
      return res.status(403).json({ success: false, error: 'Session expired. Please login again.' });
    }
    req.user = decoded;
    next();
  });
}

// ============================================================
//  AUTH ROUTES
// ============================================================

// POST /api/register
app.post('/api/register', async (req, res) => {
  const { full_name, phone, location, user_type, password } = req.body;

  if (!full_name || !phone || !location || !user_type || !password) {
    return res.status(400).json({ success: false, error: 'All fields are required.' });
  }
  if (!['farmer', 'vendor'].includes(user_type)) {
    return res.status(400).json({ success: false, error: 'User type must be farmer or vendor.' });
  }
  if (password.length < 6) {
    return res.status(400).json({ success: false, error: 'Password must be at least 6 characters.' });
  }
  if (!/^\d{10,15}$/.test(phone.trim())) {
    return res.status(400).json({ success: false, error: 'Enter a valid phone number (10-15 digits).' });
  }

  try {
    const hashed = await bcrypt.hash(password, 12);
    db.run(
      'INSERT INTO users (full_name, phone, location, user_type, password) VALUES (?, ?, ?, ?, ?)',
      [full_name.trim(), phone.trim(), location.trim(), user_type, hashed],
      function (err) {
        if (err) {
          if (err.message.includes('UNIQUE constraint failed')) {
            return res.status(409).json({ success: false, error: 'Phone number already registered.' });
          }
          console.error('Register error:', err);
          return res.status(500).json({ success: false, error: 'Registration failed. Try again.' });
        }
        res.status(201).json({ success: true, message: 'Registration successful! Please login.' });
      }
    );
  } catch (err) {
    console.error('Hash error:', err);
    res.status(500).json({ success: false, error: 'Server error.' });
  }
});

// POST /api/login
app.post('/api/login', (req, res) => {
  const { phone, password } = req.body;
  if (!phone || !password) {
    return res.status(400).json({ success: false, error: 'Phone number and password are required.' });
  }

  db.get('SELECT * FROM users WHERE phone = ?', [phone.trim()], async (err, user) => {
    if (err) {
      console.error('Login DB error:', err);
      return res.status(500).json({ success: false, error: 'Server error.' });
    }
    if (!user) {
      return res.status(401).json({ success: false, error: 'Invalid phone number or password.' });
    }
    try {
      const valid = await bcrypt.compare(password, user.password);
      if (!valid) {
        return res.status(401).json({ success: false, error: 'Invalid phone number or password.' });
      }
      const token = jwt.sign(
        { id: user.id, phone: user.phone, user_type: user.user_type, full_name: user.full_name, location: user.location },
        JWT_SECRET,
        { expiresIn: '24h' }
      );
      res.json({
        success: true,
        token,
        user: { id: user.id, full_name: user.full_name, phone: user.phone, location: user.location, user_type: user.user_type }
      });
    } catch (err) {
      console.error('Compare error:', err);
      res.status(500).json({ success: false, error: 'Server error.' });
    }
  });
});

// GET /api/profile
app.get('/api/profile', authenticate, (req, res) => {
  db.get(
    'SELECT id, full_name, phone, location, user_type, created_at FROM users WHERE id = ?',
    [req.user.id],
    (err, user) => {
      if (err)   return res.status(500).json({ success: false, error: 'Server error.' });
      if (!user) return res.status(404).json({ success: false, error: 'User not found.' });
      res.json({ success: true, user });
    }
  );
});

// ============================================================
//  CROPS ROUTES
// ============================================================

// GET /api/crops – all crops (for vendors to browse)
app.get('/api/crops', authenticate, (req, res) => {
  db.all('SELECT * FROM crops ORDER BY created_at DESC', [], (err, rows) => {
    if (err) return res.status(500).json({ success: false, error: 'Server error.' });
    res.json({ success: true, crops: rows });
  });
});

// GET /api/my-crops – logged-in farmer's own crops
app.get('/api/my-crops', authenticate, (req, res) => {
  if (req.user.user_type !== 'farmer') {
    return res.status(403).json({ success: false, error: 'Access denied.' });
  }
  db.all('SELECT * FROM crops WHERE farmer_id = ? ORDER BY created_at DESC', [req.user.id], (err, rows) => {
    if (err) return res.status(500).json({ success: false, error: 'Server error.' });
    res.json({ success: true, crops: rows });
  });
});

// POST /api/crops – farmer posts a new crop
app.post('/api/crops', authenticate, (req, res) => {
  if (req.user.user_type !== 'farmer') {
    return res.status(403).json({ success: false, error: 'Only farmers can post crops.' });
  }
  const { crop_name, quantity, price_per_kg, location, phone } = req.body;
  if (!crop_name || !quantity || !price_per_kg || !location || !phone) {
    return res.status(400).json({ success: false, error: 'All fields are required.' });
  }
  const price = parseFloat(price_per_kg);
  if (isNaN(price) || price <= 0) {
    return res.status(400).json({ success: false, error: 'Enter a valid price.' });
  }
  db.run(
    'INSERT INTO crops (farmer_id, farmer_name, crop_name, quantity, price_per_kg, location, phone) VALUES (?,?,?,?,?,?,?)',
    [req.user.id, req.user.full_name, crop_name.trim(), quantity.trim(), price, location.trim(), phone.trim()],
    function (err) {
      if (err) {
        console.error('Post crop error:', err);
        return res.status(500).json({ success: false, error: 'Failed to post crop.' });
      }
      res.status(201).json({ success: true, message: 'Crop posted successfully!', id: this.lastID });
    }
  );
});

// DELETE /api/crops/:id
app.delete('/api/crops/:id', authenticate, (req, res) => {
  if (req.user.user_type !== 'farmer') {
    return res.status(403).json({ success: false, error: 'Access denied.' });
  }
  db.run(
    'DELETE FROM crops WHERE id = ? AND farmer_id = ?',
    [req.params.id, req.user.id],
    function (err) {
      if (err)             return res.status(500).json({ success: false, error: 'Failed to delete.' });
      if (this.changes === 0) return res.status(404).json({ success: false, error: 'Crop not found or unauthorized.' });
      res.json({ success: true, message: 'Crop deleted.' });
    }
  );
});

// ============================================================
//  PRODUCTS ROUTES
// ============================================================

// GET /api/products – all products (for farmers to browse)
app.get('/api/products', authenticate, (req, res) => {
  db.all('SELECT * FROM products ORDER BY created_at DESC', [], (err, rows) => {
    if (err) return res.status(500).json({ success: false, error: 'Server error.' });
    res.json({ success: true, products: rows });
  });
});

// GET /api/my-products – logged-in vendor's own products
app.get('/api/my-products', authenticate, (req, res) => {
  if (req.user.user_type !== 'vendor') {
    return res.status(403).json({ success: false, error: 'Access denied.' });
  }
  db.all('SELECT * FROM products WHERE vendor_id = ? ORDER BY created_at DESC', [req.user.id], (err, rows) => {
    if (err) return res.status(500).json({ success: false, error: 'Server error.' });
    res.json({ success: true, products: rows });
  });
});

// POST /api/products – vendor posts a new product
app.post('/api/products', authenticate, (req, res) => {
  if (req.user.user_type !== 'vendor') {
    return res.status(403).json({ success: false, error: 'Only vendors can post products.' });
  }
  const { product_name, price, description, location, phone } = req.body;
  if (!product_name || !price || !location || !phone) {
    return res.status(400).json({ success: false, error: 'Product name, price, location, and phone are required.' });
  }
  const priceNum = parseFloat(price);
  if (isNaN(priceNum) || priceNum <= 0) {
    return res.status(400).json({ success: false, error: 'Enter a valid price.' });
  }
  db.run(
    'INSERT INTO products (vendor_id, vendor_name, product_name, price, description, location, phone) VALUES (?,?,?,?,?,?,?)',
    [req.user.id, req.user.full_name, product_name.trim(), priceNum, (description || '').trim(), location.trim(), phone.trim()],
    function (err) {
      if (err) {
        console.error('Post product error:', err);
        return res.status(500).json({ success: false, error: 'Failed to post product.' });
      }
      res.status(201).json({ success: true, message: 'Product posted successfully!', id: this.lastID });
    }
  );
});

// DELETE /api/products/:id
app.delete('/api/products/:id', authenticate, (req, res) => {
  if (req.user.user_type !== 'vendor') {
    return res.status(403).json({ success: false, error: 'Access denied.' });
  }
  db.run(
    'DELETE FROM products WHERE id = ? AND vendor_id = ?',
    [req.params.id, req.user.id],
    function (err) {
      if (err)             return res.status(500).json({ success: false, error: 'Failed to delete.' });
      if (this.changes === 0) return res.status(404).json({ success: false, error: 'Product not found or unauthorized.' });
      res.json({ success: true, message: 'Product deleted.' });
    }
  );
});

// ── Fallback ────────────────────────────────────────────────
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// ── Start Server ────────────────────────────────────────────
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
  console.log('📁  Database: ./database/farmlink.db');
});
