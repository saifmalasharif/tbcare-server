const express = require('express');
const { Pool } = require('pg');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'tbcare_secret_2024';

// Database connection
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false }
});

// Middleware
app.use(cors());
app.use(express.json({ limit: '50mb' }));
app.use(express.static('public'));

// ── DATABASE SETUP ──────────────────────────────────────────
async function initDB() {
  const client = await pool.connect();
  try {
    await client.query(`
      CREATE TABLE IF NOT EXISTS users (
        id SERIAL PRIMARY KEY,
        username VARCHAR(50) UNIQUE NOT NULL,
        password VARCHAR(255) NOT NULL,
        role VARCHAR(20) DEFAULT 'admin',
        governorate VARCHAR(50),
        label VARCHAR(50),
        created_at TIMESTAMP DEFAULT NOW(),
        active BOOLEAN DEFAULT true
      );

      CREATE TABLE IF NOT EXISTS patients (
        id VARCHAR(50) PRIMARY KEY,
        name VARCHAR(100) NOT NULL,
        code VARCHAR(30) UNIQUE NOT NULL,
        age VARCHAR(10),
        gender VARCHAR(10),
        phone VARCHAR(20),
        gov VARCHAR(50),
        sector VARCHAR(50),
        tbtype VARCHAR(30),
        site VARCHAR(30),
        category VARCHAR(30),
        smear VARCHAR(20),
        center VARCHAR(100),
        start_date VARCHAR(20),
        drug1 VARCHAR(30),
        drug2 VARCHAR(30),
        daily INTEGER DEFAULT 4,
        total INTEGER DEFAULT 56,
        remaining INTEGER DEFAULT 56,
        last_refill VARCHAR(20),
        selfcollect BOOLEAN DEFAULT false,
        notes TEXT DEFAULT '',
        created_by VARCHAR(50),
        created_at TIMESTAMP DEFAULT NOW(),
        updated_at TIMESTAMP DEFAULT NOW()
      );

      CREATE TABLE IF NOT EXISTS audit_log (
        id SERIAL PRIMARY KEY,
        user_id INTEGER,
        username VARCHAR(50),
        action VARCHAR(50),
        patient_id VARCHAR(50),
        patient_name VARCHAR(100),
        details TEXT,
        created_at TIMESTAMP DEFAULT NOW()
      );

      CREATE TABLE IF NOT EXISTS photos (
        id SERIAL PRIMARY KEY,
        patient_id VARCHAR(50),
        data TEXT,
        filename VARCHAR(200),
        created_at TIMESTAMP DEFAULT NOW()
      );
    `);

    // Create default superadmin if not exists
    const existing = await client.query("SELECT id FROM users WHERE username = 'saif'");
    if (existing.rows.length === 0) {
      const hash = await bcrypt.hash('tb2024!secure', 10);
      await client.query(
        "INSERT INTO users (username, password, role, governorate, label) VALUES ($1, $2, $3, $4, $5)",
        ['saif', hash, 'superadmin', null, 'SAIF']
      );

      // Create default governorate admins
      const govAdmins = [
        ['ninawa',  'nnw2024!tb',  'admin', 'Ninawa',  'NINAWA'],
        ['baghdad', 'bgd2024!tb',  'admin', 'Baghdad', 'BAGHDAD'],
        ['dohuk',   'dhk2024!tb',  'admin', 'Dohuk',   'DOHUK'],
      ];
      for (const [u, p, r, g, l] of govAdmins) {
        const h = await bcrypt.hash(p, 10);
        await client.query(
          "INSERT INTO users (username, password, role, governorate, label) VALUES ($1, $2, $3, $4, $5)",
          [u, h, r, g, l]
        );
      }
      console.log('✅ Default users created');
    }

    console.log('✅ Database initialized');
  } finally {
    client.release();
  }
}

// ── AUTH MIDDLEWARE ──────────────────────────────────────────
function auth(req, res, next) {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'No token' });
  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch {
    res.status(401).json({ error: 'Invalid token' });
  }
}

function superadmin(req, res, next) {
  if (req.user.role !== 'superadmin') return res.status(403).json({ error: 'Superadmin only' });
  next();
}

// Log action helper
async function log(username, action, patientId, patientName, details) {
  try {
    await pool.query(
      'INSERT INTO audit_log (username, action, patient_id, patient_name, details) VALUES ($1, $2, $3, $4, $5)',
      [username, action, patientId || null, patientName || null, details || null]
    );
  } catch (e) { console.error('Log error:', e.message); }
}

// ── AUTH ROUTES ──────────────────────────────────────────────
app.post('/api/login', async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) return res.status(400).json({ error: 'Missing credentials' });

  try {
    const result = await pool.query(
      'SELECT * FROM users WHERE username = $1 AND active = true',
      [username.toLowerCase().trim()]
    );
    if (result.rows.length === 0) return res.status(401).json({ error: 'Invalid credentials' });

    const user = result.rows[0];
    const valid = await bcrypt.compare(password, user.password);
    if (!valid) return res.status(401).json({ error: 'Invalid credentials' });

    const token = jwt.sign(
      { id: user.id, username: user.username, role: user.role, governorate: user.governorate, label: user.label },
      JWT_SECRET,
      { expiresIn: '7d' }
    );

    await log(user.username, 'LOGIN', null, null, 'Logged in');
    res.json({ token, user: { username: user.username, role: user.role, governorate: user.governorate, label: user.label } });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'Server error' });
  }
});

// ── PATIENT ROUTES ───────────────────────────────────────────
// Get all patients (filtered by governorate for non-superadmins)
app.get('/api/patients', auth, async (req, res) => {
  try {
    let query = 'SELECT * FROM patients ORDER BY created_at DESC';
    let params = [];

    if (req.user.role !== 'superadmin' && req.user.governorate) {
      query = 'SELECT * FROM patients WHERE gov = $1 ORDER BY created_at DESC';
      params = [req.user.governorate];
    }

    const result = await pool.query(query, params);
    // Convert snake_case to camelCase for frontend
    const patients = result.rows.map(p => ({
      id: p.id, name: p.name, code: p.code, age: p.age, gender: p.gender,
      phone: p.phone, gov: p.gov, sector: p.sector, tbtype: p.tbtype,
      site: p.site, category: p.category, smear: p.smear, center: p.center,
      startDate: p.start_date, drug1: p.drug1, drug2: p.drug2,
      daily: p.daily, total: p.total, remaining: p.remaining,
      lastRefill: p.last_refill, selfcollect: p.selfcollect, notes: p.notes
    }));

    res.json(patients);
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'Server error' });
  }
});

// Add patient
app.post('/api/patients', auth, async (req, res) => {
  const p = req.body;
  try {
    await pool.query(
      `INSERT INTO patients (id, name, code, age, gender, phone, gov, sector, tbtype, site, category,
       smear, center, start_date, drug1, drug2, daily, total, remaining, last_refill, selfcollect, notes, created_by)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21,$22,$23)`,
      [p.id, p.name, p.code, p.age, p.gender, p.phone, p.gov, p.sector, p.tbtype,
       p.site, p.category, p.smear, p.center, p.startDate, p.drug1, p.drug2,
       p.daily, p.total, p.remaining, p.lastRefill, p.selfcollect || false, p.notes || '', req.user.username]
    );
    await log(req.user.username, 'ADD_PATIENT', p.id, p.name, `Added patient ${p.code}`);
    res.json({ success: true });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: e.message });
  }
});

// Update patient
app.put('/api/patients/:id', auth, async (req, res) => {
  const p = req.body;
  try {
    await pool.query(
      `UPDATE patients SET name=$1, code=$2, age=$3, gender=$4, phone=$5, gov=$6, sector=$7,
       tbtype=$8, site=$9, category=$10, smear=$11, center=$12, start_date=$13, drug1=$14,
       drug2=$15, daily=$16, total=$17, remaining=$18, last_refill=$19, selfcollect=$20,
       notes=$21, updated_at=NOW() WHERE id=$22`,
      [p.name, p.code, p.age, p.gender, p.phone, p.gov, p.sector, p.tbtype,
       p.site, p.category, p.smear, p.center, p.startDate, p.drug1, p.drug2,
       p.daily, p.total, p.remaining, p.lastRefill, p.selfcollect || false, p.notes || '', req.params.id]
    );
    await log(req.user.username, 'EDIT_PATIENT', req.params.id, p.name, `Edited patient ${p.code}`);
    res.json({ success: true });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: e.message });
  }
});

// Delete patient
app.delete('/api/patients/:id', auth, async (req, res) => {
  try {
    const pt = await pool.query('SELECT name, code FROM patients WHERE id = $1', [req.params.id]);
    await pool.query('DELETE FROM patients WHERE id = $1', [req.params.id]);
    await pool.query('DELETE FROM photos WHERE patient_id = $1', [req.params.id]);
    const p = pt.rows[0];
    await log(req.user.username, 'DELETE_PATIENT', req.params.id, p?.name, `Deleted ${p?.code}`);
    res.json({ success: true });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: e.message });
  }
});

// Refill patient
app.post('/api/patients/:id/refill', auth, async (req, res) => {
  try {
    const pt = await pool.query('SELECT * FROM patients WHERE id = $1', [req.params.id]);
    if (!pt.rows.length) return res.status(404).json({ error: 'Patient not found' });
    const p = pt.rows[0];
    const today = new Date().toISOString().split('T')[0];
    await pool.query(
      'UPDATE patients SET remaining = total, last_refill = $1, updated_at = NOW() WHERE id = $2',
      [today, req.params.id]
    );
    await log(req.user.username, 'REFILL', req.params.id, p.name, `Refilled ${p.code} — reset to ${p.total} tablets`);
    res.json({ success: true, remaining: p.total, lastRefill: today });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: e.message });
  }
});

// Toggle self-collect
app.post('/api/patients/:id/selfcollect', auth, async (req, res) => {
  try {
    const pt = await pool.query('SELECT selfcollect, name, code FROM patients WHERE id = $1', [req.params.id]);
    if (!pt.rows.length) return res.status(404).json({ error: 'Not found' });
    const newVal = !pt.rows[0].selfcollect;
    await pool.query('UPDATE patients SET selfcollect = $1, updated_at = NOW() WHERE id = $2', [newVal, req.params.id]);
    await log(req.user.username, 'SELFCOLLECT', req.params.id, pt.rows[0].name, `Self-collect set to ${newVal}`);
    res.json({ success: true, selfcollect: newVal });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// ── PHOTO ROUTES ─────────────────────────────────────────────
app.get('/api/patients/:id/photos', auth, async (req, res) => {
  try {
    const result = await pool.query(
      'SELECT id, data, filename, created_at FROM photos WHERE patient_id = $1 ORDER BY created_at DESC',
      [req.params.id]
    );
    res.json(result.rows.map(r => ({ id: r.id, data: r.data, name: r.filename, date: r.created_at })));
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.post('/api/patients/:id/photos', auth, async (req, res) => {
  try {
    const { photos } = req.body;
    for (const photo of photos) {
      await pool.query(
        'INSERT INTO photos (patient_id, data, filename) VALUES ($1, $2, $3)',
        [req.params.id, photo.data, photo.name || 'photo']
      );
    }
    res.json({ success: true });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.delete('/api/photos/:id', auth, async (req, res) => {
  try {
    await pool.query('DELETE FROM photos WHERE id = $1', [req.params.id]);
    res.json({ success: true });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// ── USER MANAGEMENT (superadmin only) ───────────────────────
app.get('/api/users', auth, superadmin, async (req, res) => {
  try {
    const result = await pool.query('SELECT id, username, role, governorate, label, created_at, active FROM users ORDER BY id');
    res.json(result.rows);
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.post('/api/users', auth, superadmin, async (req, res) => {
  const { username, password, role, governorate, label } = req.body;
  try {
    const hash = await bcrypt.hash(password, 10);
    await pool.query(
      'INSERT INTO users (username, password, role, governorate, label) VALUES ($1, $2, $3, $4, $5)',
      [username.toLowerCase(), hash, role || 'admin', governorate || null, label || username.toUpperCase()]
    );
    await log(req.user.username, 'ADD_USER', null, null, `Created user: ${username}`);
    res.json({ success: true });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.put('/api/users/:id', auth, superadmin, async (req, res) => {
  const { password, role, governorate, label, active } = req.body;
  try {
    if (password) {
      const hash = await bcrypt.hash(password, 10);
      await pool.query('UPDATE users SET password=$1, role=$2, governorate=$3, label=$4, active=$5 WHERE id=$6',
        [hash, role, governorate, label, active, req.params.id]);
    } else {
      await pool.query('UPDATE users SET role=$1, governorate=$2, label=$3, active=$4 WHERE id=$5',
        [role, governorate, label, active, req.params.id]);
    }
    res.json({ success: true });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.delete('/api/users/:id', auth, superadmin, async (req, res) => {
  try {
    await pool.query('DELETE FROM users WHERE id = $1', [req.params.id]);
    res.json({ success: true });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// ── AUDIT LOG ────────────────────────────────────────────────
app.get('/api/audit', auth, superadmin, async (req, res) => {
  try {
    const result = await pool.query('SELECT * FROM audit_log ORDER BY created_at DESC LIMIT 500');
    res.json(result.rows);
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// ── PATIENT LOOKUP (for patient login) ──────────────────────
app.get('/api/patient-lookup/:code', async (req, res) => {
  try {
    const result = await pool.query(
      'SELECT * FROM patients WHERE UPPER(code) = $1',
      [req.params.code.toUpperCase()]
    );
    if (!result.rows.length) return res.status(404).json({ error: 'Not found' });
    const p = result.rows[0];
    res.json({
      id: p.id, name: p.name, code: p.code, gov: p.gov, sector: p.sector,
      tbtype: p.tbtype, site: p.site, startDate: p.start_date,
      drug1: p.drug1, drug2: p.drug2, daily: p.daily, total: p.total,
      remaining: p.remaining, lastRefill: p.last_refill
    });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// Health check
app.get('/api/health', (req, res) => res.json({ status: 'ok', time: new Date().toISOString() }));

// ── START ────────────────────────────────────────────────────
initDB().then(() => {
  app.listen(PORT, () => console.log(`✅ TB-Care server running on port ${PORT}`));
}).catch(e => {
  console.error('Failed to init DB:', e);
  process.exit(1);
});
