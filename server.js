const express = require('express');
const { Pool } = require('pg');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 3000;

// ── SECURITY: no fallback secret. Refuse to start without it. ──
const JWT_SECRET = process.env.JWT_SECRET;
if (!JWT_SECRET) {
  console.error('FATAL: JWT_SECRET environment variable is not set. Set it in Railway before deploying.');
  process.exit(1);
}

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false }
});

app.set('trust proxy', 1); // required for correct client IPs behind Railway
app.use(helmet({ contentSecurityPolicy: false })); // CSP off so existing inline scripts keep working
app.use(cors());
app.use(express.json({ limit: '50mb' }));
app.use(express.static('public'));

// ── RATE LIMIT: login brute-force protection ──────────────────
const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 10,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Too many login attempts. Try again in 15 minutes.' }
});

// ── DATABASE INIT ─────────────────────────────────────────────
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
        extensions INTEGER DEFAULT 0,
        extension_log JSONB DEFAULT '[]',
        completed_months INTEGER DEFAULT 6,
        treatment_status VARCHAR(30) DEFAULT NULL,
        treatment_end_date VARCHAR(20) DEFAULT NULL,
        treatment_outcome VARCHAR(50) DEFAULT NULL,
        created_by VARCHAR(50),
        created_at TIMESTAMP DEFAULT NOW(),
        updated_at TIMESTAMP DEFAULT NOW()
      );

      ALTER TABLE patients ADD COLUMN IF NOT EXISTS extensions INTEGER DEFAULT 0;
      ALTER TABLE patients ADD COLUMN IF NOT EXISTS extension_log JSONB DEFAULT '[]';
      ALTER TABLE patients ADD COLUMN IF NOT EXISTS completed_months INTEGER DEFAULT 6;
      ALTER TABLE patients ADD COLUMN IF NOT EXISTS treatment_status VARCHAR(30) DEFAULT NULL;
      ALTER TABLE patients ADD COLUMN IF NOT EXISTS treatment_end_date VARCHAR(20) DEFAULT NULL;
      ALTER TABLE patients ADD COLUMN IF NOT EXISTS treatment_outcome VARCHAR(50) DEFAULT NULL;

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

    // ── BOOTSTRAP ONLY: create a superadmin only if NO users exist.
    // Never seeds or overwrites passwords on redeploy. Existing DB users
    // keep whatever password is set through the users panel.
    const existing = await client.query('SELECT COUNT(*)::int AS n FROM users');
    if (existing.rows[0].n === 0) {
      const bootPass = process.env.SEED_ADMIN_PASSWORD;
      if (!bootPass) {
        console.error('Users table is empty and SEED_ADMIN_PASSWORD is not set — no way to log in. Set it, deploy once, then remove it.');
      } else {
        const h = await bcrypt.hash(bootPass, 10);
        await client.query(
          `INSERT INTO users (username,password,role,governorate,label) VALUES ($1,$2,'superadmin',NULL,'SAIF')`,
          ['saif', h]
        );
        console.log('Bootstrap superadmin created. Remove SEED_ADMIN_PASSWORD from env and change the password after first login.');
      }
    }

    console.log('Database initialized');
  } finally {
    client.release();
  }
}

// ── AUTH ──────────────────────────────────────────────────────
function auth(req, res, next) {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'No token' });
  try { req.user = jwt.verify(token, JWT_SECRET); next(); }
  catch { res.status(401).json({ error: 'Invalid token' }); }
}

function superadmin(req, res, next) {
  if (req.user.role !== 'superadmin') return res.status(403).json({ error: 'Superadmin only' });
  next();
}

// ── GOVERNORATE ENFORCEMENT ───────────────────────────────────
// Non-superadmin users can only touch patients inside their own governorate.
// Returns the patient row if allowed, otherwise responds and returns null.
async function getPatientIfAllowed(req, res) {
  const result = await pool.query('SELECT * FROM patients WHERE id=$1', [req.params.id]);
  if (!result.rows.length) { res.status(404).json({ error: 'Not found' }); return null; }
  const patient = result.rows[0];
  if (req.user.role !== 'superadmin' && req.user.governorate && patient.gov !== req.user.governorate) {
    res.status(403).json({ error: 'Access denied: patient outside your governorate' });
    return null;
  }
  return patient;
}

async function log(username, action, patientId, patientName, details) {
  try {
    await pool.query(
      'INSERT INTO audit_log (username,action,patient_id,patient_name,details) VALUES ($1,$2,$3,$4,$5)',
      [username, action, patientId||null, patientName||null, details||null]
    );
  } catch(e) { console.error('Log error:', e.message); }
}

// Generic client-facing error. Full details go to server logs only.
function fail(res, e, context) {
  console.error(`[${context}]`, e);
  res.status(500).json({ error: 'Server error' });
}

function mapPatient(p) {
  return {
    id: p.id, name: p.name, code: p.code, age: p.age, gender: p.gender,
    phone: p.phone, gov: p.gov, sector: p.sector, tbtype: p.tbtype,
    site: p.site, category: p.category, smear: p.smear, center: p.center,
    startDate: p.start_date, drug1: p.drug1, drug2: p.drug2,
    daily: p.daily, total: p.total, remaining: p.remaining,
    lastRefill: p.last_refill, selfcollect: p.selfcollect, notes: p.notes,
    extensions: p.extensions || 0,
    extensionLog: p.extension_log || [],
    completedMonths: p.completed_months || 6,
    treatmentStatus: p.treatment_status || null,
    treatmentEndDate: p.treatment_end_date || null,
    treatmentOutcome: p.treatment_outcome || null
  };
}

// ── ROUTES ────────────────────────────────────────────────────
app.post('/api/login', loginLimiter, async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) return res.status(400).json({ error: 'Missing credentials' });
  try {
    const result = await pool.query(
      'SELECT * FROM users WHERE username=$1 AND active=true',
      [username.toLowerCase().trim()]
    );
    if (!result.rows.length) {
      await log(username.toLowerCase().trim(), 'FAILED_LOGIN', null, null, 'Unknown or inactive user');
      return res.status(401).json({ error: 'Invalid credentials' });
    }
    const user = result.rows[0];
    if (!await bcrypt.compare(password, user.password)) {
      await log(user.username, 'FAILED_LOGIN', null, null, 'Wrong password');
      return res.status(401).json({ error: 'Invalid credentials' });
    }
    const token = jwt.sign(
      { id: user.id, username: user.username, role: user.role, governorate: user.governorate, label: user.label },
      JWT_SECRET, { expiresIn: '24h' }
    );
    await log(user.username, 'LOGIN', null, null, 'Logged in');
    res.json({ token, user: { username: user.username, role: user.role, governorate: user.governorate, label: user.label } });
  } catch(e) { fail(res, e, 'login'); }
});

app.get('/api/patients', auth, async (req, res) => {
  try {
    let query = 'SELECT * FROM patients ORDER BY created_at DESC';
    let params = [];
    if (req.user.role !== 'superadmin' && req.user.governorate) {
      query = 'SELECT * FROM patients WHERE gov=$1 ORDER BY created_at DESC';
      params = [req.user.governorate];
    }
    const result = await pool.query(query, params);
    res.json(result.rows.map(mapPatient));
  } catch(e) { fail(res, e, 'list-patients'); }
});

app.post('/api/patients', auth, async (req, res) => {
  const p = req.body;
  try {
    // Non-superadmin users can only register patients inside their own governorate.
    if (req.user.role !== 'superadmin' && req.user.governorate) {
      p.gov = req.user.governorate;
    }
    const newId = p.id || ('pt_' + Date.now() + '_' + Math.random().toString(36).substr(2,6));
    await pool.query(
      `INSERT INTO patients
       (id,name,code,age,gender,phone,gov,sector,tbtype,site,category,smear,center,
        start_date,drug1,drug2,daily,total,remaining,last_refill,selfcollect,notes,
        extensions,extension_log,completed_months,treatment_status,treatment_end_date,
        treatment_outcome,created_by)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,
               $17,$18,$19,$20,$21,$22,$23,$24,$25,$26,$27,$28,$29)`,
      [newId,p.name,p.code,p.age||null,p.gender||null,p.phone||null,
       p.gov||null,p.sector||null,p.tbtype||null,p.site||null,p.category||null,
       p.smear||null,p.center||null,p.startDate||null,p.drug1||null,p.drug2||null,
       p.daily||0,p.total||0,p.remaining||0,p.lastRefill||null,
       p.selfcollect||false,p.notes||'',
       p.extensions||0,JSON.stringify(p.extensionLog||[]),
       p.completedMonths||6,p.treatmentStatus||null,
       p.treatmentEndDate||null,p.treatmentOutcome||null,
       req.user.username]
    );
    await log(req.user.username, 'ADD_PATIENT', newId, p.name, `Registered ${p.code}`);
    res.json({ success: true, id: newId });
  } catch(e) { fail(res, e, 'add-patient'); }
});

app.put('/api/patients/:id', auth, async (req, res) => {
  const p = req.body;
  try {
    const existing = await getPatientIfAllowed(req, res);
    if (!existing) return;
    // Non-superadmin users cannot move a patient to another governorate.
    if (req.user.role !== 'superadmin' && req.user.governorate) {
      p.gov = req.user.governorate;
    }
    await pool.query(
      `UPDATE patients SET
       name=$1,code=$2,age=$3,gender=$4,phone=$5,gov=$6,sector=$7,
       tbtype=$8,site=$9,category=$10,smear=$11,center=$12,start_date=$13,
       drug1=$14,drug2=$15,daily=$16,total=$17,remaining=$18,last_refill=$19,
       selfcollect=$20,notes=$21,extensions=$22,extension_log=$23,
       completed_months=$24,treatment_status=$25,treatment_end_date=$26,
       treatment_outcome=$27,updated_at=NOW()
       WHERE id=$28`,
      [p.name,p.code,p.age||null,p.gender||null,p.phone||null,
       p.gov||null,p.sector||null,p.tbtype||null,p.site||null,
       p.category||null,p.smear||null,p.center||null,p.startDate||null,
       p.drug1||null,p.drug2||null,p.daily||0,p.total||0,p.remaining||0,
       p.lastRefill||null,p.selfcollect||false,p.notes||'',
       p.extensions||0,JSON.stringify(p.extensionLog||[]),
       p.completedMonths||6,p.treatmentStatus||null,
       p.treatmentEndDate||null,p.treatmentOutcome||null,
       req.params.id]
    );
    await log(req.user.username, 'EDIT_PATIENT', req.params.id, p.name, `Edited ${p.code}`);
    res.json({ success: true });
  } catch(e) { fail(res, e, 'edit-patient'); }
});

app.delete('/api/patients/:id', auth, async (req, res) => {
  try {
    const patient = await getPatientIfAllowed(req, res);
    if (!patient) return;
    await pool.query('DELETE FROM patients WHERE id=$1', [req.params.id]);
    await pool.query('DELETE FROM photos WHERE patient_id=$1', [req.params.id]);
    await log(req.user.username, 'DELETE_PATIENT', req.params.id, patient.name, `Deleted ${patient.code}`);
    res.json({ success: true });
  } catch(e) { fail(res, e, 'delete-patient'); }
});

app.post('/api/patients/:id/refill', auth, async (req, res) => {
  try {
    const p = await getPatientIfAllowed(req, res);
    if (!p) return;
    const today = new Date().toISOString().split('T')[0];
    await pool.query(
      'UPDATE patients SET remaining=total,last_refill=$1,updated_at=NOW() WHERE id=$2',
      [today, req.params.id]
    );
    await log(req.user.username, 'REFILL', req.params.id, p.name, `Refilled ${p.code}`);
    res.json({ success: true, remaining: p.total, lastRefill: today });
  } catch(e) { fail(res, e, 'refill'); }
});

app.post('/api/patients/:id/selfcollect', auth, async (req, res) => {
  try {
    const p = await getPatientIfAllowed(req, res);
    if (!p) return;
    const newVal = !p.selfcollect;
    await pool.query('UPDATE patients SET selfcollect=$1,updated_at=NOW() WHERE id=$2', [newVal, req.params.id]);
    await log(req.user.username, 'SELFCOLLECT', req.params.id, p.name, `Self-collect: ${newVal}`);
    res.json({ success: true, selfcollect: newVal });
  } catch(e) { fail(res, e, 'selfcollect'); }
});

app.get('/api/patients/:id/photos', auth, async (req, res) => {
  try {
    const p = await getPatientIfAllowed(req, res);
    if (!p) return;
    const result = await pool.query(
      'SELECT id,data,filename,created_at FROM photos WHERE patient_id=$1 ORDER BY created_at DESC',
      [req.params.id]
    );
    res.json(result.rows.map(r => ({ id: r.id, data: r.data, name: r.filename, date: r.created_at })));
  } catch(e) { fail(res, e, 'get-photos'); }
});

app.post('/api/patients/:id/photos', auth, async (req, res) => {
  try {
    const p = await getPatientIfAllowed(req, res);
    if (!p) return;
    for (const photo of req.body.photos) {
      await pool.query(
        'INSERT INTO photos (patient_id,data,filename) VALUES ($1,$2,$3)',
        [req.params.id, photo.data, photo.name||'photo']
      );
    }
    await log(req.user.username, 'ADD_PHOTOS', req.params.id, p.name, `${req.body.photos.length} photo(s)`);
    res.json({ success: true });
  } catch(e) { fail(res, e, 'add-photos'); }
});

app.delete('/api/photos/:id', auth, async (req, res) => {
  try {
    // Enforce governorate through the photo's patient.
    const ph = await pool.query('SELECT patient_id FROM photos WHERE id=$1', [req.params.id]);
    if (!ph.rows.length) return res.status(404).json({ error: 'Not found' });
    const pt = await pool.query('SELECT gov,name FROM patients WHERE id=$1', [ph.rows[0].patient_id]);
    if (pt.rows.length && req.user.role !== 'superadmin' && req.user.governorate && pt.rows[0].gov !== req.user.governorate) {
      return res.status(403).json({ error: 'Access denied: patient outside your governorate' });
    }
    await pool.query('DELETE FROM photos WHERE id=$1', [req.params.id]);
    await log(req.user.username, 'DELETE_PHOTO', ph.rows[0].patient_id, pt.rows[0]?.name, `Photo ${req.params.id}`);
    res.json({ success: true });
  } catch(e) { fail(res, e, 'delete-photo'); }
});

// ── USER MANAGEMENT (superadmin) ──────────────────────────────
app.get('/api/users', auth, superadmin, async (req, res) => {
  try {
    const result = await pool.query(
      'SELECT id,username,role,governorate,label,created_at,active FROM users ORDER BY id'
    );
    res.json(result.rows);
  } catch(e) { fail(res, e, 'list-users'); }
});

app.post('/api/users', auth, superadmin, async (req, res) => {
  const { username, password, role, governorate, label } = req.body;
  try {
    if (!username || !password) return res.status(400).json({ error: 'Username and password required' });
    if (password.length < 10) return res.status(400).json({ error: 'Password must be at least 10 characters' });
    const hash = await bcrypt.hash(password, 10);
    await pool.query(
      'INSERT INTO users (username,password,role,governorate,label) VALUES ($1,$2,$3,$4,$5)',
      [username.toLowerCase(), hash, role||'admin', governorate||null, label||username.toUpperCase()]
    );
    await log(req.user.username, 'ADD_USER', null, null, `Created user: ${username}`);
    res.json({ success: true });
  } catch(e) { fail(res, e, 'add-user'); }
});

app.put('/api/users/:id', auth, superadmin, async (req, res) => {
  const { password, role, governorate, label, active } = req.body;
  try {
    if (password) {
      if (password.length < 10) return res.status(400).json({ error: 'Password must be at least 10 characters' });
      const hash = await bcrypt.hash(password, 10);
      await pool.query(
        'UPDATE users SET password=$1,role=$2,governorate=$3,label=$4,active=$5 WHERE id=$6',
        [hash, role, governorate, label, active, req.params.id]
      );
      await log(req.user.username, 'EDIT_USER', null, null, `Updated user ${req.params.id} (password changed)`);
    } else {
      await pool.query(
        'UPDATE users SET role=$1,governorate=$2,label=$3,active=$4 WHERE id=$5',
        [role, governorate, label, active, req.params.id]
      );
      await log(req.user.username, 'EDIT_USER', null, null, `Updated user ${req.params.id}`);
    }
    res.json({ success: true });
  } catch(e) { fail(res, e, 'edit-user'); }
});

app.delete('/api/users/:id', auth, superadmin, async (req, res) => {
  try {
    // Prevent deleting your own account by accident.
    if (parseInt(req.params.id, 10) === req.user.id) {
      return res.status(400).json({ error: 'You cannot delete your own account' });
    }
    await pool.query('DELETE FROM users WHERE id=$1', [req.params.id]);
    await log(req.user.username, 'DELETE_USER', null, null, `Deleted user ${req.params.id}`);
    res.json({ success: true });
  } catch(e) { fail(res, e, 'delete-user'); }
});

app.get('/api/audit', auth, superadmin, async (req, res) => {
  try {
    const result = await pool.query('SELECT * FROM audit_log ORDER BY created_at DESC LIMIT 500');
    res.json(result.rows);
  } catch(e) { fail(res, e, 'audit'); }
});

// ── PATIENT LOOKUP ────────────────────────────────────────────
// SECURITY FIX: this endpoint previously exposed full patient records with
// no authentication. It now requires a valid token. If a public patient
// self-check page depends on this, it needs a separate minimal endpoint —
// do NOT remove `auth` from this one.
app.get('/api/patient-lookup/:code', auth, async (req, res) => {
  try {
    const result = await pool.query(
      'SELECT * FROM patients WHERE UPPER(code)=$1',
      [req.params.code.toUpperCase()]
    );
    if (!result.rows.length) return res.status(404).json({ error: 'Not found' });
    const patient = result.rows[0];
    if (req.user.role !== 'superadmin' && req.user.governorate && patient.gov !== req.user.governorate) {
      return res.status(403).json({ error: 'Access denied: patient outside your governorate' });
    }
    res.json(mapPatient(patient));
  } catch(e) { fail(res, e, 'lookup'); }
});

// ── BACKUP (roadmap priority #1) ──────────────────────────────
// Superadmin downloads a full JSON snapshot: patients, users (no password
// hashes), and the audit log. Photos are excluded from the payload (they can
// be very large) — only counts are included. Download this weekly and store
// it off Railway (Google Drive, external disk).
app.get('/api/backup', auth, superadmin, async (req, res) => {
  try {
    const [patients, users, audit, photoCount] = await Promise.all([
      pool.query('SELECT * FROM patients ORDER BY created_at'),
      pool.query('SELECT id,username,role,governorate,label,created_at,active FROM users ORDER BY id'),
      pool.query('SELECT * FROM audit_log ORDER BY created_at DESC LIMIT 5000'),
      pool.query('SELECT COUNT(*)::int AS n FROM photos')
    ]);
    await log(req.user.username, 'BACKUP', null, null, `Exported ${patients.rows.length} patients`);
    const stamp = new Date().toISOString().split('T')[0];
    res.setHeader('Content-Disposition', `attachment; filename="tbcare-backup-${stamp}.json"`);
    res.json({
      exported_at: new Date().toISOString(),
      exported_by: req.user.username,
      counts: {
        patients: patients.rows.length,
        users: users.rows.length,
        audit_entries: audit.rows.length,
        photos_not_included: photoCount.rows[0].n
      },
      patients: patients.rows,
      users: users.rows,
      audit_log: audit.rows
    });
  } catch(e) { fail(res, e, 'backup'); }
});

app.get('/api/health', (req, res) => res.json({ status: 'ok', time: new Date().toISOString() }));

initDB().then(() => {
  app.listen(PORT, () => console.log(`TB-Care running on port ${PORT}`));
}).catch(e => {
  console.error('Failed to init DB:', e);
  process.exit(1);
});
