const express = require('express');
const cors = require('cors');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');
const multer = require('multer');
const rag    = require('./rag');
const r2     = require('./r2');
const maDB   = require('./db');
const { readDB, writeDB, readCustDB, writeCustDB, readSireDB, writeSireDB,
        readRepoDb, writeRepoDb, readPmsDb, savePmsDb } = maDB;

const app = express();
const PORT = process.env.PORT || 3000;
const ANTHROPIC_API_KEY = process.env.ANTHROPIC_API_KEY;

// ── Auth helpers ───────────────────────────────────────────────────────────
function hashPassword(password) {
  const salt = crypto.randomBytes(16).toString('hex');
  const hash = crypto.scryptSync(password, salt, 64).toString('hex');
  return `${salt}:${hash}`;
}

function verifyPassword(password, stored) {
  try {
    const [salt, hash] = stored.split(':');
    const inputHash = crypto.scryptSync(password, salt, 64).toString('hex');
    return crypto.timingSafeEqual(Buffer.from(hash,'hex'), Buffer.from(inputHash,'hex'));
  } catch(e) { return false; }
}

function generateToken() {
  return crypto.randomBytes(32).toString('hex');
}

// ── Persistent storage ────────────────────────────────────────────────────
const DATA_DIR = (() => {
  if (process.env.DATA_DIR) return process.env.DATA_DIR;
  if (fs.existsSync('/data')) return '/data';
  return __dirname;
})();
const DB_PATH = path.join(DATA_DIR, 'maride.json');

fs.mkdirSync(path.join(DATA_DIR, 'uploads', 'manuals'), { recursive: true });
console.log('Storage path:', DATA_DIR);

['equipment_register.json','pms_stats.json'].forEach(fname => {
  const dest = path.join(DATA_DIR, fname);
  const src  = path.join(__dirname, fname);
  if (!fs.existsSync(dest) && fs.existsSync(src)) {
    try { fs.copyFileSync(src, dest); console.log('PMS bootstrap:', fname); } catch(e) { console.error('PMS bootstrap failed:', fname, e.message); }
  }
});

// [readDB/writeDB moved to db.js — block 1]

function seedAdmin() {
  const db = readDB();
  if (db.users.length === 0) {
    const adminPassword = process.env.ADMIN_PASSWORD || 'admin123';
    db.users.push({
      id: 'user_admin',
      name: 'System Administrator',
      email: process.env.ADMIN_EMAIL || 'admin@maride.app',
      password: hashPassword(adminPassword),
      role: 'admin',
      vessel_ids: [],
      created_at: new Date().toISOString()
    });
    writeDB(db);
    console.log('Admin user seeded. Email:', process.env.ADMIN_EMAIL || 'admin@maride.app');
    console.log('Password:', adminPassword);
  }
}

seedAdmin();
// Boot pgvector schema on Railway (non-blocking)
rag.initSchema().catch(err => console.error('[RAG] Init failed:', err.message));
// Boot MARIDE PostgreSQL state (blocking — must complete before first request)
maDB.initMaRideDB().catch(err => { console.error('[MARIDE DB] Fatal init error:', err.message); process.exit(1); });

// ── Middleware ─────────────────────────────────────────────────────────────
app.use(cors({
  origin: [
    'https://custodian.forcap.io',
    'https://sire.forcap.io',
    'https://oracle.forcap.io',
    'https://spares.forcap.io',
    'https://forcap.io',
    /\.forcap\.io$/,
    /\.onrender\.com$/,
    'http://localhost:3000',
    'http://localhost:10000',
  ],
  credentials: true,
  methods: ['GET','POST','PUT','PATCH','DELETE','OPTIONS'],
  allowedHeaders: ['Content-Type','x-auth-token','Authorization'],
}));
app.options('*', cors());
app.use(express.json({ limit: '20mb' }));
app.use(express.static('public'));

// ── Auth middleware ────────────────────────────────────────────────────────
function requireAuth(req, res, next) {
  const token = req.headers['x-auth-token'] || req.query.token;
  if (!token) return res.status(401).json({ error: 'Not authenticated' });
  const db = readDB();
  const session = db.sessions.find(s => s.token === token);
  if (!session) return res.status(401).json({ error: 'Invalid session' });
  const user = db.users.find(u => u.id === session.user_id);
  if (!user) return res.status(401).json({ error: 'User not found' });
  req.user = user;
  req.db = db;
  next();
}

function requireRole(...roles) {
  return (req, res, next) => {
    if (!roles.includes(req.user.role)) return res.status(403).json({ error: 'Forbidden' });
    next();
  };
}

// ── Role helpers ──────────────────────────────────────────────────────────
function isFleetLevel(role) {
  return ['admin','fleet_manager','deputy_fleet_manager'].includes(role);
}
function isSuperLevel(role) {
  return ['admin','superintendent','fleet_manager','deputy_fleet_manager'].includes(role);
}
function isShipStaff(role) {
  return ['ship_staff','investigator'].includes(role);
}
function isCEorMaster(user) {
  const d = (user?.designation||'').toLowerCase().trim();
  return ['chief engineer','ce','c/e','chief eng','c.e.','master','captain'].includes(d);
}

// ── Health ─────────────────────────────────────────────────────────────────
app.get('/health', async (req, res) => {
  const health = await maDB.dbHealth();
  res.json(health);
});

// ══════════════════════════════════════════════════════
// AUTH ROUTES
// ══════════════════════════════════════════════════════

app.post('/api/auth/login', (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) return res.status(400).json({ error: 'Email and password required' });
  const db = readDB();
  const user = db.users.find(u => u.email.toLowerCase() === email.toLowerCase());
  if (!user || !verifyPassword(password, user.password)) {
    return res.status(401).json({ error: 'Invalid email or password' });
  }
  const token = generateToken();
  db.sessions.push({ token, user_id: user.id, created_at: new Date().toISOString() });
  db.sessions = db.sessions.filter(s => {
    const age = Date.now() - new Date(s.created_at).getTime();
    return age < 7 * 24 * 60 * 60 * 1000;
  });
  writeDB(db);
  const { password: _, ...safeUser } = user;
  res.json({ token, user: safeUser });
});

app.post('/api/auth/logout', requireAuth, (req, res) => {
  const token = req.headers['x-auth-token'];
  const db = readDB();
  db.sessions = db.sessions.filter(s => s.token !== token);
  writeDB(db);
  res.json({ ok: true });
});

app.get('/api/auth/me', requireAuth, (req, res) => {
  const { password, ...safeUser } = req.user;
  res.json(safeUser);
});

// ══════════════════════════════════════════════════════
// USER ROUTES
// ══════════════════════════════════════════════════════

app.get('/api/users', requireAuth, (req, res) => {
  if (!isSuperLevel(req.user.role)) return res.status(403).json({error:'Forbidden'});
  const db = readDB();
  res.json(db.users.map(({ password, ...u }) => u));
});

app.get('/api/custodian/vessel-crew', requireAuth, (req, res) => {
  try {
    const vesselId = req.query.vessel_id;
    if (!vesselId) return res.status(400).json({ error: 'vessel_id required' });
    const db = readDB();
    const crew = db.users
      .filter(u => (u.vessel_ids||[]).includes(vesselId))
      .map(({ password, ...u }) => u);
    res.json(crew);
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/users', requireAuth, (req, res) => {
  if (!isSuperLevel(req.user.role)) return res.status(403).json({error:'Forbidden'});
  try {
    const { name, email, password, role, vessel_ids, designation, signed_on } = req.body;
    if (!name || !email || !password || !role) return res.status(400).json({ error: 'name, email, password, role required' });
    const db = readDB();
    if (db.users.find(u => u.email.toLowerCase() === email.toLowerCase())) {
      return res.status(409).json({ error: 'Email already exists' });
    }
    const user = {
      id: 'user_' + Date.now().toString(36),
      name, email,
      password: hashPassword(password),
      role,
      vessel_ids: vessel_ids || [],
      designation: designation || '',
      signed_on: signed_on !== false,
      created_at: new Date().toISOString()
    };
    db.users.push(user);
    writeDB(db);
    const { password: _, ...safeUser } = user;
    res.json(safeUser);
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.put('/api/users/:id', requireAuth, (req, res) => {
  if (!isSuperLevel(req.user.role)) return res.status(403).json({error:'Forbidden'});
  try {
    const db = readDB();
    const idx = db.users.findIndex(u => u.id === req.params.id);
    if (idx === -1) return res.status(404).json({ error: 'Not found' });
    const { password, ...updates } = req.body;
    db.users[idx] = { ...db.users[idx], ...updates };
    if (password) db.users[idx].password = hashPassword(password);
    writeDB(db);
    const { password: _, ...safeUser } = db.users[idx];
    res.json(safeUser);
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.delete('/api/users/:id', requireAuth, (req, res) => {
  if (!isSuperLevel(req.user.role)) return res.status(403).json({error:'Forbidden'});
  try {
    if (req.params.id === req.user.id) return res.status(400).json({ error: 'Cannot delete yourself' });
    const db = readDB();
    db.users = db.users.filter(u => u.id !== req.params.id);
    db.sessions = db.sessions.filter(s => s.user_id !== req.params.id);
    writeDB(db);
    res.json({ ok: true });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// ══════════════════════════════════════════════════════
// VESSEL ROUTES
// ══════════════════════════════════════════════════════

app.get('/api/vessels', requireAuth, (req, res) => {
  const db = readDB();
  if (isFleetLevel(req.user.role)) return res.json(db.vessels);
  const vessels = db.vessels.filter(v => (req.user.vessel_ids || []).includes(v.id));
  res.json(vessels);
});

function syncSuperintendentVessel(db, vesselId, superintendentId) {
  if (!superintendentId) return;
  const user = db.users.find(u => u.id === superintendentId);
  if (!user) return;
  user.vessel_ids = [...new Set([...(user.vessel_ids || []), vesselId])];
}

app.post('/api/vessels', requireAuth, requireRole('admin'), (req, res) => {
  try {
    const db = readDB();
    const vessel = {
      id: 'vessel_' + Date.now().toString(36),
      ...req.body,
      created_at: new Date().toISOString()
    };
    db.vessels.push(vessel);
    syncSuperintendentVessel(db, vessel.id, vessel.superintendent_id);
    writeDB(db);
    res.json(vessel);
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.put('/api/vessels/:id', requireAuth, requireRole('admin'), (req, res) => {
  try {
    const db = readDB();
    const idx = db.vessels.findIndex(v => v.id === req.params.id);
    if (idx === -1) return res.status(404).json({ error: 'Not found' });
    const old = db.vessels[idx];
    db.vessels[idx] = { ...old, ...req.body, id: req.params.id };
    if (req.body.superintendent_id && req.body.superintendent_id !== old.superintendent_id) {
      syncSuperintendentVessel(db, req.params.id, req.body.superintendent_id);
    }
    writeDB(db);
    res.json(db.vessels[idx]);
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.delete('/api/vessels/:id', requireAuth, requireRole('admin'), (req, res) => {
  try {
    const db = readDB();
    db.vessels = db.vessels.filter(v => v.id !== req.params.id);
    writeDB(db);
    res.json({ ok: true });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.patch('/api/vessels/:id/dpa-email', requireAuth, requireRole('admin'), (req, res) => {
  try {
    const db = readDB();
    const vessel = db.vessels.find(v => v.id === req.params.id);
    if (!vessel) return res.status(404).json({ error: 'Not found' });
    vessel.dpa_email = req.body.dpa_email;
    writeDB(db);
    res.json({ ok: true });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// ══════════════════════════════════════════════════════
// INVESTIGATION ROUTES
// ══════════════════════════════════════════════════════

function filterInvestigations(investigations, user, vessels) {
  if (isFleetLevel(user.role)) return investigations;
  if (user.role === 'superintendent') {
    const myVesselIds = (user.vessel_ids || []);
    return investigations.filter(i => myVesselIds.includes(i.vessel_id) || i.created_by === user.id);
  }
  return investigations.filter(i => i.created_by === user.id);
}

app.get('/api/investigations', requireAuth, (req, res) => {
  try {
    const db = readDB();
    const filtered = filterInvestigations(db.investigations, req.user, db.vessels);
    const list = filtered.map(({ state_json, ...rest }) => rest)
      .sort((a,b) => (b.updated_at||'').localeCompare(a.updated_at||''));
    res.json(list);
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.get('/api/investigations/:id', requireAuth, (req, res) => {
  try {
    const db = readDB();
    const inv = db.investigations.find(i => i.id === req.params.id);
    if (!inv) return res.status(404).json({ error: 'Not found' });
    const allowed = filterInvestigations([inv], req.user, db.vessels);
    if (!allowed.length) return res.status(403).json({ error: 'Forbidden' });
    res.json({ ...inv, state: inv.state_json ? JSON.parse(inv.state_json) : null });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/investigations', requireAuth, (req, res) => {
  try {
    const db = readDB();
    const now = new Date().toISOString();
    const inv = {
      ...req.body,
      created_by: req.user.id,
      created_by_name: req.user.name,
      state_json: req.body.state ? JSON.stringify(req.body.state) : null,
      created_at: now, updated_at: now
    };
    delete inv.state;
    db.investigations.push(inv);
    writeDB(db);
    res.json({ ok: true, id: inv.id });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.put('/api/investigations/:id', requireAuth, (req, res) => {
  try {
    const db = readDB();
    const idx = db.investigations.findIndex(i => i.id === req.params.id);
    if (idx === -1) return res.status(404).json({ error: 'Not found' });
    const inv = db.investigations[idx];
    if (req.user.role === 'investigator' && inv.created_by !== req.user.id) {
      return res.status(403).json({ error: 'Forbidden' });
    }
    db.investigations[idx] = {
      ...inv, ...req.body,
      id: inv.id, ref_num: inv.ref_num,
      created_by: inv.created_by, created_by_name: inv.created_by_name,
      created_at: inv.created_at,
      updated_at: new Date().toISOString(),
      state_json: req.body.state ? JSON.stringify(req.body.state) : inv.state_json
    };
    delete db.investigations[idx].state;
    writeDB(db);
    res.json({ ok: true });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.patch('/api/investigations/:id/status', requireAuth, (req, res) => {
  try {
    const db = readDB();
    const inv = db.investigations.find(i => i.id === req.params.id);
    if (!inv) return res.status(404).json({ error: 'Not found' });
    inv.status = req.body.status;
    inv.updated_at = new Date().toISOString();
    writeDB(db);
    res.json({ ok: true });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.delete('/api/investigations/:id', requireAuth, (req, res) => {
  try {
    const db = readDB();
    const inv = db.investigations.find(i => i.id === req.params.id);
    if (!inv) return res.status(404).json({ error: 'Not found' });
    if (req.user.role === 'investigator' && inv.created_by !== req.user.id) {
      return res.status(403).json({ error: 'Forbidden' });
    }
    db.investigations = db.investigations.filter(i => i.id !== req.params.id);
    writeDB(db);
    res.json({ ok: true });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// ── AI PROXY ───────────────────────────────────────────────────────────────
app.post('/api/investigate', requireAuth, async (req, res) => {
  if (!ANTHROPIC_API_KEY) return res.status(500).json({ error: 'API key not configured' });
  try {
    const response = await fetch('https://api.anthropic.com/v1/messages', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'x-api-key': ANTHROPIC_API_KEY, 'anthropic-version': '2023-06-01' },
      body: JSON.stringify(req.body)
    });
    res.json(await response.json());
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.listen(PORT, () => {
  console.log(`MARIDE server running on port ${PORT}`);
});

// ══════════════════════════════════════════════════════
// EMAIL — REPORT DELIVERY VIA RESEND
// ══════════════════════════════════════════════════════
const RESEND_API_KEY = process.env.RESEND_API_KEY;
const FROM_EMAIL = process.env.FROM_EMAIL || 'MARIDE <onboarding@resend.dev>';
const APP_URL = process.env.APP_URL || 'https://maride.onrender.com';

async function sendEmail({ to, subject, html, attachments }) {
  if (!RESEND_API_KEY) throw new Error('RESEND_API_KEY not configured');
  const body = { from: FROM_EMAIL, to, subject, html };
  if (attachments) body.attachments = attachments;
  const res = await fetch('https://api.resend.com/emails', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${RESEND_API_KEY}` },
    body: JSON.stringify(body)
  });
  const data = await res.json();
  if (!res.ok) throw new Error(data.message || 'Resend error');
  return data;
}

app.post('/api/investigations/:id/approve', requireAuth, requireRole('superintendent','admin'), async (req, res) => {
  try {
    const db = readDB();
    const inv = db.investigations.find(i => i.id === req.params.id);
    if (!inv) return res.status(404).json({ error: 'Not found' });

    inv.status = 'closed';
    inv.approved_by = req.user.id;
    inv.approved_by_name = req.user.name;
    inv.approved_at = new Date().toISOString();
    writeDB(db);

    const vessel = db.vessels.find(v => v.name === inv.vessel || v.id === inv.vessel_id);
    const investigator = db.users.find(u => u.id === inv.created_by);
    const superintendent = db.users.find(u => u.id === req.user.id);

    const recipients = [];
    if (investigator?.email) recipients.push({ name: investigator.name, email: investigator.email, role: 'Investigator' });
    if (superintendent?.email && superintendent.id !== investigator?.id) {
      recipients.push({ name: superintendent.name, email: superintendent.email, role: 'Superintendent' });
    }
    if (vessel?.dpa_email) recipients.push({ name: vessel.dpa_name, email: vessel.dpa_email, role: 'DPA' });

    if (!recipients.length) {
      return res.json({ ok: true, approved: true, emailsSent: 0, warning: 'No recipients with email addresses found' });
    }

    const { pdfBase64 } = req.body;
    const toAddresses = recipients.map(r => r.email);
    const recipientNames = recipients.map(r => `${r.name} (${r.role})`).join(', ');

    const severityLabels = { '1':'Near Miss','2':'Minor','3':'Moderate','4':'Serious','5':'Critical' };
    const severityColors = { '1':'#1a7a45','2':'#1a7a45','3':'#b35c00','4':'#c0392b','5':'#c0392b' };
    const severityBg    = { '1':'#e6f7ef','2':'#e6f7ef','3':'#fff7e6','4':'#fde8e8','5':'#fde8e8' };
    const sev = inv.severity || '?';
    const sevLabel = severityLabels[sev] || sev;
    const sevColor = severityColors[sev] || '#555';
    const sevBg    = severityBg[sev]    || '#f5f5f5';

    const state = inv.state_json ? JSON.parse(inv.state_json) : {};
    const topCauses = state.topCauses || [];
    const flagged   = state.flagged   || [];
    const immCause  = state.immCause  || '—';
    const rootCause = state.rootCause || (topCauses[0]?.name || '—');
    const contrib   = state.contrib   || '—';

    const causesRows = topCauses.slice(0,3).map((c,i) => `
      <tr>
        <td style="padding:7px 12px;font-size:12px;color:#333;">#${i+1}</td>
        <td style="padding:7px 12px;font-size:12px;color:#333;font-weight:${i===0?'700':'400'};">${c.name}</td>
        <td style="padding:7px 12px;font-size:12px;color:#f5a623;font-family:monospace;font-weight:700;">${c.score}</td>
      </tr>`).join('');

    const deficiencies = flagged.slice(0,5).map(f => `<li style="margin-bottom:6px;font-size:12px;color:#333;">${f}</li>`).join('');

    const emailHtml = `<!DOCTYPE html><html><head><meta charset="UTF-8">
<style>* { margin:0; padding:0; box-sizing:border-box; } body { font-family: Arial, sans-serif; background: #f0f2f5; padding: 24px; }
.wrap { max-width: 620px; margin: 0 auto; } .header { background: #0a0d12; padding: 24px 32px; border-radius: 8px 8px 0 0; }
.logo { color: #f5a623; font-size: 20px; font-weight: 900; letter-spacing: 4px; font-family: monospace; }
.logo-sub { color: #5a6a82; font-size: 9px; letter-spacing: 2.5px; margin-top: 3px; font-family: monospace; text-transform: uppercase; }
.body { background: #fff; padding: 28px 32px; } .footer { background: #f9f9f9; padding: 16px 32px; border-top: 1px solid #eee; font-size: 11px; color: #999; text-align: center; border-radius: 0 0 8px 8px; }
.section-title { font-size: 10px; font-family: monospace; letter-spacing: 2px; text-transform: uppercase; color: #f5a623; margin: 24px 0 10px; border-bottom: 1px solid #f0f0f0; padding-bottom: 6px; }
.approved-box { background: #e6f7ef; border-left: 4px solid #1a7a45; border-radius: 0 6px 6px 0; padding: 12px 16px; margin-bottom: 24px; font-size: 13px; color: #1a7a45; font-weight: 600; }
.detail-label { font-size: 10px; color: #999; text-transform: uppercase; letter-spacing: 1px; padding: 5px 16px 5px 0; vertical-align: top; white-space: nowrap; width: 130px; display: table-cell; }
.detail-value { font-size: 13px; color: #222; padding: 5px 0; font-weight: 500; display: table-cell; }
.sev-pill { display: inline-block; padding: 2px 10px; border-radius: 3px; font-size: 11px; font-weight: 700; background: ${sevBg}; color: ${sevColor}; }
.cause-box { background: #fff7e6; border-left: 3px solid #f5a623; padding: 10px 14px; border-radius: 0 4px 4px 0; font-size: 12px; color: #333; margin-bottom: 8px; }
.cause-box strong { color: #b35c00; font-size: 10px; display: block; letter-spacing: 1px; text-transform: uppercase; margin-bottom: 3px; }
.causes-table { width: 100%; border-collapse: collapse; font-size: 12px; }
.causes-table th { background: #f5f5f5; padding: 7px 12px; text-align: left; font-size: 10px; color: #999; letter-spacing: 1px; text-transform: uppercase; }
.causes-table tr:nth-child(even) td { background: #fafafa; }
</style></head><body>
<div class="wrap">
  <div class="header"><div class="logo">FORCAP</div><div class="logo-sub">Fleet Operations, Risk, Compliance & Audit Platform</div></div>
  <div class="body">
    <div style="font-family:monospace;font-size:11px;color:#f5a623;letter-spacing:1px;margin-bottom:6px;">${inv.ref_num || ''}</div>
    <h1 style="font-size:20px;color:#0a0d12;margin-bottom:4px;">Investigation Report Approved</h1>
    <div style="font-size:12px;color:#888;margin-bottom:20px;">${inv.vessel || 'Unknown Vessel'} · ${inv.type || 'Incident'} · ${inv.inc_date ? inv.inc_date.substring(0,10) : '—'}</div>
    <div class="approved-box">✓ Approved by ${req.user.name} &nbsp;·&nbsp; ${new Date().toUTCString()}</div>
    <div class="section-title">Incident Details</div>
    <div style="display:table;width:100%;border-collapse:collapse;margin-bottom:4px;">
      <div style="display:table-row;"><div class="detail-label">Vessel</div><div class="detail-value">${inv.vessel || '—'}</div></div>
      <div style="display:table-row;"><div class="detail-label">Incident Type</div><div class="detail-value">${inv.type || '—'}</div></div>
      <div style="display:table-row;"><div class="detail-label">Severity</div><div class="detail-value"><span class="sev-pill">${sevLabel}</span></div></div>
      <div style="display:table-row;"><div class="detail-label">Location / Port</div><div class="detail-value">${inv.location || '—'}</div></div>
      <div style="display:table-row;"><div class="detail-label">Date / Time</div><div class="detail-value">${inv.inc_date ? inv.inc_date.substring(0,16).replace('T',' ') + ' UTC' : '—'}</div></div>
      <div style="display:table-row;"><div class="detail-label">Investigator</div><div class="detail-value">${inv.created_by_name || '—'}</div></div>
      <div style="display:table-row;"><div class="detail-label">Approved By</div><div class="detail-value">${req.user.name}</div></div>
    </div>
    <div class="section-title">What Happened</div>
    <div style="background:#fafafa;border:1px solid #eee;border-radius:6px;padding:12px 16px;font-size:12px;color:#444;line-height:1.6;margin-bottom:4px;">${inv.description || '—'}</div>
    ${topCauses.length ? `
    <div class="section-title">Root Cause Analysis</div>
    <div class="cause-box"><strong>Immediate Cause</strong>${immCause}</div>
    <div class="cause-box"><strong>Root Cause</strong>${rootCause}</div>
    ${contrib !== '—' ? `<div class="cause-box"><strong>Contributing Factors</strong>${contrib}</div>` : ''}
    <div class="section-title">Evidence Scoring — Top Causes</div>
    <table class="causes-table"><thead><tr><th>Rank</th><th>Cause</th><th>Score</th></tr></thead>
    <tbody>${causesRows || '<tr><td colspan="3" style="padding:10px;color:#999;text-align:center;">No scoring data</td></tr>'}</tbody></table>` : ''}
    ${deficiencies ? `<div class="section-title">Flagged Deficiencies</div><ul style="padding-left:20px;">${deficiencies}</ul>` : ''}
    <div style="background:#f0f2f5;border-radius:6px;padding:12px 16px;font-size:12px;color:#555;margin-top:20px;">
      📎 <span>The <strong>full investigation report</strong> is attached as a PDF.</span>
    </div>
    <div style="margin-top:20px;font-size:11px;color:#aaa;">Recipients: ${recipientNames}</div>
  </div>
  <div class="footer">FORCAP · Fleet Operations, Risk, Compliance & Audit Platform &nbsp;·&nbsp; Confidential — For Internal Use Only</div>
</div></body></html>`;

    const attachments = pdfBase64 ? [{
      filename: `FORCAP_${inv.ref_num || 'report'}_${(inv.vessel || 'vessel').replace(/\s+/g,'_')}.pdf`,
      content: pdfBase64
    }] : [];

    await sendEmail({
      to: toAddresses,
      subject: `[FORCAP] ${inv.ref_num || 'Report'} Approved — ${inv.vessel || 'Unknown'} · ${sevLabel} ${inv.type || 'Incident'}`,
      html: emailHtml,
      attachments
    });

    res.json({ ok: true, approved: true, emailsSent: toAddresses.length, recipients: toAddresses });
  } catch(e) {
    console.error('Approve/email error:', e);
    res.status(500).json({ error: e.message });
  }
});

// ══════════════════════════════════════════════════════
// PATTERN ANALYSIS
// ══════════════════════════════════════════════════════
app.post('/api/patterns/analyse', requireAuth, requireRole('admin','superintendent'), async (req, res) => {
  if (!ANTHROPIC_API_KEY) return res.status(500).json({ error: 'API key not configured' });
  try {
    const db = readDB();
    const investigations = filterInvestigations(db.investigations, req.user, db.vessels);

    if (investigations.length < 2) {
      return res.json({ patterns: [], summary: 'Not enough investigations to detect patterns. At least 2 closed investigations are needed.', chartData: {} });
    }

    const dataset = investigations.map(inv => {
      const state = inv.state_json ? JSON.parse(inv.state_json) : {};
      return {
        ref: inv.ref_num,
        vessel: inv.vessel,
        type: inv.type,
        severity: inv.severity,
        location: inv.location,
        date: inv.inc_date ? inv.inc_date.substring(0, 10) : null,
        status: inv.status,
        rootCause: state.rootCause || '',
        immCause: state.immCause || '',
        topCauses: (state.topCauses || []).slice(0, 3).map(c => c.name),
        flagged: (state.flagged || []).slice(0, 5),
        description: (inv.description || '').substring(0, 200)
      };
    });

    const vessels = [...new Set(dataset.map(d => d.vessel).filter(Boolean))];
    const types   = [...new Set(dataset.map(d => d.type).filter(Boolean))];
    const months  = {};
    dataset.forEach(d => {
      if (d.date) { const m = d.date.substring(0, 7); months[m] = (months[m] || 0) + 1; }
    });

    const chartData = {
      byVessel: vessels.map(v => ({ label: v, count: dataset.filter(d => d.vessel === v).length })).sort((a,b) => b.count - a.count),
      byType:   types.map(t => ({ label: t, count: dataset.filter(d => d.type === t).length })).sort((a,b) => b.count - a.count),
      bySeverity: ['1','2','3','4','5'].map(s => ({
        label: ['Near Miss','Minor','Moderate','Serious','Critical'][+s-1],
        count: dataset.filter(d => d.severity === s).length
      })).filter(d => d.count > 0),
      byMonth: Object.entries(months).sort((a,b) => a[0].localeCompare(b[0])).map(([m, count]) => ({ label: m, count }))
    };

    const prompt = `You are a maritime safety analyst. Analyse this fleet incident dataset and identify significant patterns.

INCIDENT DATA (${dataset.length} investigations):
${JSON.stringify(dataset, null, 1)}

Identify patterns across: recurring root causes, location clusters, post-maintenance failures, seasonal trends, fleet comparison.
Only report genuine patterns with at least 2 data points. Do not invent patterns.

Respond ONLY with valid JSON:
{
  "patterns": [{"id":"p1","category":"recurring_cause","title":"","severity":"high","evidence":[],"insight":"","recommendation":"","count":2}],
  "executive_summary": "2-3 sentence fleet safety overview"
}`;

    const aiRes = await fetch('https://api.anthropic.com/v1/messages', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'x-api-key': ANTHROPIC_API_KEY, 'anthropic-version': '2023-06-01' },
      body: JSON.stringify({ model: 'claude-sonnet-4-6', max_tokens: 2000, messages: [{ role: 'user', content: prompt }] })
    });

    const aiData = await aiRes.json();
    const text = aiData.content?.[0]?.text || '{}';
    const clean = text.replace(/```json|```/g, '').trim();
    const parsed = JSON.parse(clean);

    res.json({ patterns: parsed.patterns || [], summary: parsed.executive_summary || '', chartData, totalInvestigations: dataset.length });
  } catch(e) {
    console.error('Pattern analysis error:', e);
    res.status(500).json({ error: e.message });
  }
});

// ══════════════════════════════════════════════════════
// CUSTODIAN MODULE
// ══════════════════════════════════════════════════════

// [readCustDB/writeCustDB moved to db.js]

const DEFAULT_EQUIPMENT = [
  { category:'Cargo Equipment',          items:['Cargo Compressor #1','Cargo Compressor #2','Deep Well Pump #1','Deep Well Pump #2','Deep Well Pump #3','Deep Well Pump #4','IGG System','BWTS','Cargo Heater','Vaporiser'] },
  { category:'Main Engine',              items:['Main Engine'] },
  { category:'Auxiliary Engines / Generators', items:['Generator #1','Generator #2','Generator #3','Emergency Generator'] },
  { category:'Boilers',                  items:['Boiler #1','Boiler #2','Exhaust Gas Economiser'] },
  { category:'FWG',                      items:['Fresh Water Generator'] },
  { category:'Steering Gear',            items:['Steering Gear #1','Steering Gear #2'] },
  { category:'Deck Cranes / Winches',    items:['Mooring Winch FWD Port','Mooring Winch FWD STBD','Mooring Winch AFT Port','Mooring Winch AFT STBD','Deck Crane'] },
  { category:'LSA / FFA Equipment',      items:['Lifeboat Port','Lifeboat STBD','Rescue Boat','Fire Pumps','CO2 System','SCBA Sets'] },
  { category:'Navigation Equipment',     items:['RADAR #1','RADAR #2','ECDIS #1','ECDIS #2','AIS','GMDSS'] },
  { category:'Electrical Systems',       items:['Main Switchboard','Emergency Switchboard','UPS Systems','Earth Fault Monitoring'] },
  { category:'Hull & Deck Structure',    items:['Cargo Tank #1','Cargo Tank #2','Ballast System','Deck Hydraulics','Paint & Coating'] },
];

app.get('/api/custodian/equipment', requireAuth, (req, res) => {
  const db = readCustDB();
  const vesselId = req.query.vessel_id;
  const list = vesselId ? db.equipment.filter(e => e.vessel_id === vesselId) : db.equipment;
  res.json(list);
});

app.post('/api/custodian/equipment', requireAuth, (req, res) => {
  try {
    const db = readCustDB();
    const eq = { id:'eq_'+Date.now().toString(36), ...req.body, created_at:new Date().toISOString(), created_by:req.user.id };
    db.equipment.push(eq);
    writeCustDB(db);
    res.json(eq);
  } catch(e) { res.status(500).json({error:e.message}); }
});

app.put('/api/custodian/equipment/:id', requireAuth, (req, res) => {
  try {
    const db = readCustDB();
    const idx = db.equipment.findIndex(e => e.id === req.params.id);
    if (idx===-1) return res.status(404).json({error:'Not found'});
    db.equipment[idx] = { ...db.equipment[idx], ...req.body, id:req.params.id, updated_at:new Date().toISOString() };
    writeCustDB(db);
    res.json(db.equipment[idx]);
  } catch(e) { res.status(500).json({error:e.message}); }
});

app.delete('/api/custodian/equipment/:id', requireAuth, requireRole('admin','superintendent'), (req, res) => {
  try {
    const db = readCustDB();
    db.equipment = db.equipment.filter(e => e.id !== req.params.id);
    writeCustDB(db);
    res.json({ok:true});
  } catch(e) { res.status(500).json({error:e.message}); }
});

app.post('/api/custodian/equipment/seed/:vessel_id', requireAuth, requireRole('admin','superintendent'), (req, res) => {
  try {
    const db = readCustDB();
    const vesselId = req.params.vessel_id;
    const existing = db.equipment.filter(e => e.vessel_id === vesselId);
    if (existing.length > 0) return res.json({ok:true, skipped:true, message:'Equipment already seeded'});
    const now = new Date().toISOString();
    DEFAULT_EQUIPMENT.forEach(cat => {
      cat.items.forEach(name => {
        db.equipment.push({
          id:'eq_'+Date.now().toString(36)+'_'+Math.random().toString(36).substring(2,6),
          vessel_id: vesselId, name, category: cat.category,
          criticality:'medium', custodian_name:'', custodian_role:'',
          status:'operational', last_pm_date:'', next_pm_date:'',
          notes:'', created_at:now, created_by:req.user.id
        });
      });
    });
    writeCustDB(db);
    res.json({ok:true, seeded:db.equipment.filter(e=>e.vessel_id===vesselId).length});
  } catch(e) { res.status(500).json({error:e.message}); }
});

app.get('/api/custodian/defects', requireAuth, (req, res) => {
  const db = readCustDB();
  const vesselId = req.query.vessel_id;
  const list = vesselId ? db.defects.filter(d => d.vessel_id === vesselId) : db.defects;
  res.json(list.sort((a,b)=>(b.created_at||'').localeCompare(a.created_at||'')));
});

app.post('/api/custodian/defects', requireAuth, (req, res) => {
  try {
    const db = readCustDB();
    const defect = {
      id:'def_'+Date.now().toString(36), ...req.body,
      raised_by:req.user.id, raised_by_name:req.user.name,
      status:'open', troubleshooting_steps:[],
      created_at:new Date().toISOString()
    };
    db.defects.push(defect);
    writeCustDB(db);
    res.json(defect);
  } catch(e) { res.status(500).json({error:e.message}); }
});

app.put('/api/custodian/defects/:id', requireAuth, (req, res) => {
  try {
    const db = readCustDB();
    const idx = db.defects.findIndex(d => d.id===req.params.id);
    if (idx===-1) return res.status(404).json({error:'Not found'});
    db.defects[idx] = { ...db.defects[idx], ...req.body, id:req.params.id, updated_at:new Date().toISOString(), updated_by:req.user.name };
    writeCustDB(db);
    res.json(db.defects[idx]);
  } catch(e) { res.status(500).json({error:e.message}); }
});

app.post('/api/custodian/defects/:id/step', requireAuth, (req, res) => {
  try {
    const db = readCustDB();
    const defect = db.defects.find(d=>d.id===req.params.id);
    if (!defect) return res.status(404).json({error:'Not found'});
    defect.troubleshooting_steps = defect.troubleshooting_steps||[];
    defect.troubleshooting_steps.push({
      id:'step_'+Date.now().toString(36),
      text:req.body.text, manual_referenced:req.body.manual_referenced||false,
      outcome:req.body.outcome||'',
      by:req.user.name, at:new Date().toISOString()
    });
    defect.updated_at = new Date().toISOString();
    writeCustDB(db);
    res.json(defect);
  } catch(e) { res.status(500).json({error:e.message}); }
});

app.get('/api/custodian/temp-repairs', requireAuth, (req, res) => {
  const db = readCustDB();
  const vesselId = req.query.vessel_id;
  const list = vesselId ? db.tempRepairs.filter(t=>t.vessel_id===vesselId) : db.tempRepairs;
  const now = new Date();
  list.forEach(t => {
    if (t.status==='active' && t.expiry_date && new Date(t.expiry_date) < now) t.status='overdue';
  });
  res.json(list.sort((a,b)=>(a.expiry_date||'').localeCompare(b.expiry_date||'')));
});

app.post('/api/custodian/temp-repairs', requireAuth, (req, res) => {
  try {
    const db = readCustDB();
    const tr = { id:'tr_'+Date.now().toString(36), ...req.body, status:'active', raised_by:req.user.name, created_at:new Date().toISOString() };
    db.tempRepairs.push(tr);
    writeCustDB(db);
    res.json(tr);
  } catch(e) { res.status(500).json({error:e.message}); }
});

app.patch('/api/custodian/temp-repairs/:id/close', requireAuth, (req, res) => {
  try {
    const db = readCustDB();
    const tr = db.tempRepairs.find(t=>t.id===req.params.id);
    if (!tr) return res.status(404).json({error:'Not found'});
    tr.status='closed'; tr.closed_by=req.user.name; tr.closed_at=new Date().toISOString();
    tr.closure_notes=req.body.closure_notes||'';
    writeCustDB(db);
    res.json(tr);
  } catch(e) { res.status(500).json({error:e.message}); }
});

app.get('/api/custodian/pm-logs', requireAuth, (req, res) => {
  const db = readCustDB();
  const vesselId = req.query.vessel_id;
  const list = vesselId ? db.pmLogs.filter(p=>p.vessel_id===vesselId) : db.pmLogs;
  res.json(list.sort((a,b)=>(b.created_at||'').localeCompare(a.created_at||'')));
});

app.post('/api/custodian/pm-logs', requireAuth, (req, res) => {
  try {
    const db = readCustDB();
    const log = { id:'pm_'+Date.now().toString(36), ...req.body, logged_by:req.user.name, created_at:new Date().toISOString() };
    db.pmLogs.push(log);
    if (req.body.equipment_id && req.body.next_pm_date) {
      const eq = db.equipment.find(e=>e.id===req.body.equipment_id);
      if (eq) { eq.last_pm_date=req.body.pm_date; eq.next_pm_date=req.body.next_pm_date; }
    }
    writeCustDB(db);
    res.json(log);
  } catch(e) { res.status(500).json({error:e.message}); }
});

app.get('/api/custodian/alarms', requireAuth, (req, res) => {
  const db = readCustDB();
  const vesselId = req.query.vessel_id;
  const list = vesselId ? db.alarmLogs.filter(a=>a.vessel_id===vesselId) : db.alarmLogs;
  res.json(list.sort((a,b)=>(b.created_at||'').localeCompare(a.created_at||'')));
});

app.post('/api/custodian/alarms', requireAuth, (req, res) => {
  try {
    const db = readCustDB();
    const alarm = { id:'alm_'+Date.now().toString(36), ...req.body, logged_by:req.user.name, status:'open', created_at:new Date().toISOString() };
    db.alarmLogs.push(alarm);
    writeCustDB(db);
    res.json(alarm);
  } catch(e) { res.status(500).json({error:e.message}); }
});

app.patch('/api/custodian/alarms/:id', requireAuth, (req, res) => {
  try {
    const db = readCustDB();
    const alarm = db.alarmLogs.find(a=>a.id===req.params.id);
    if (!alarm) return res.status(404).json({error:'Not found'});
    Object.assign(alarm, req.body, {updated_at:new Date().toISOString(), updated_by:req.user.name});
    writeCustDB(db);
    res.json(alarm);
  } catch(e) { res.status(500).json({error:e.message}); }
});

app.get('/api/custodian/handovers', requireAuth, (req, res) => {
  const db = readCustDB();
  const vesselId = req.query.vessel_id;
  const list = vesselId ? db.handovers.filter(h=>h.vessel_id===vesselId) : db.handovers;
  res.json(list.sort((a,b)=>(b.created_at||'').localeCompare(a.created_at||'')));
});

app.post('/api/custodian/handovers', requireAuth, (req, res) => {
  try {
    const db = readCustDB();
    const handover = { id:'ho_'+Date.now().toString(36), ...req.body, created_by:req.user.name, status:'pending', created_at:new Date().toISOString() };
    db.handovers.push(handover);
    writeCustDB(db);
    res.json(handover);
  } catch(e) { res.status(500).json({error:e.message}); }
});

app.patch('/api/custodian/handovers/:id/sign', requireAuth, (req, res) => {
  try {
    const db = readCustDB();
    const ho = db.handovers.find(h=>h.id===req.params.id);
    if (!ho) return res.status(404).json({error:'Not found'});
    ho.signed_by = req.user.name; ho.signed_at = new Date().toISOString();
    ho.status = 'signed'; ho.incoming_notes = req.body.incoming_notes||'';
    writeCustDB(db);
    res.json(ho);
  } catch(e) { res.status(500).json({error:e.message}); }
});

app.put('/api/custodian/handovers/:id', requireAuth, (req, res) => {
  try {
    const db = readCustDB();
    const idx = db.handovers.findIndex(h=>h.id===req.params.id);
    if (idx===-1) return res.status(404).json({error:'Not found'});
    db.handovers[idx] = { ...db.handovers[idx], ...req.body, updated_at:new Date().toISOString(), updated_by:req.user.name };
    writeCustDB(db);
    res.json(db.handovers[idx]);
  } catch(e) { res.status(500).json({error:e.message}); }
});

app.delete('/api/custodian/handovers/:id', requireAuth, (req, res) => {
  try {
    if (!isSuperLevel(req.user.role)) return res.status(403).json({error:'Forbidden'});
    const db = readCustDB();
    const before = db.handovers.length;
    db.handovers = db.handovers.filter(h=>h.id!==req.params.id);
    if (db.handovers.length===before) return res.status(404).json({error:'Not found'});
    writeCustDB(db);
    res.json({ok:true});
  } catch(e) { res.status(500).json({error:e.message}); }
});

app.get('/api/custodian/scores', requireAuth, (req, res) => {
  try {
    const db = readCustDB();
    const mainDb = readDB();
    const vesselId = req.query.vessel_id;

    const equipment = (db.equipment||[]).filter(e=>!vesselId||e.vessel_id===vesselId);
    const defects   = (db.defects||[]).filter(d=>!vesselId||d.vessel_id===vesselId);
    const tempReps  = (db.tempRepairs||[]).filter(t=>!vesselId||t.vessel_id===vesselId);
    const pmLogs    = (db.pmLogs||[]).filter(p=>!vesselId||p.vessel_id===vesselId);
    const alarms    = (db.alarmLogs||[]).filter(a=>!vesselId||a.vessel_id===vesselId);

    const custodians = {};
    equipment.forEach(eq => {
      const key = eq.custodian_designation || 'Unassigned';
      if (!custodians[key]) custodians[key] = { designation:key, equipment:[], defects:[], pmLogs:[], tempReps:[], alarms:[] };
      custodians[key].equipment.push(eq);
    });

    const signedOnHolders = {};
    const allUsers = [...(mainDb.users||[]), ...(db.users||[])];
    allUsers.filter(u => u.signed_on !== false && u.designation).forEach(u => {
      const desig = u.designation;
      signedOnHolders[desig] = u.name;
      const norm = {'ce':'Chief Engineer','c/e':'Chief Engineer','chief eng':'Chief Engineer','captain':'Master','2e':'2nd Engineer','2/e':'2nd Engineer','3e':'3rd Engineer','3/e':'3rd Engineer','4e':'4th Engineer','4/e':'4th Engineer','c/o':'Chief Officer'}[desig.toLowerCase().trim()];
      if (norm) signedOnHolders[norm] = u.name;
    });

    defects.forEach(d => { const eq = equipment.find(e=>e.id===d.equipment_id); const key = eq?.custodian_designation||'Unassigned'; if (custodians[key]) custodians[key].defects.push(d); });
    pmLogs.forEach(p => { const eq = equipment.find(e=>e.id===p.equipment_id); const key = eq?.custodian_designation||'Unassigned'; if (custodians[key]) custodians[key].pmLogs.push(p); });
    tempReps.forEach(t => { const eq = equipment.find(e=>e.id===t.equipment_id); const key = eq?.custodian_designation||'Unassigned'; if (custodians[key]) custodians[key].tempReps.push(t); });
    alarms.forEach(a => { const eq = equipment.find(e=>e.id===a.equipment_id); const key = eq?.custodian_designation||'Unassigned'; if (custodians[key]) custodians[key].alarms.push(a); });

    const now = new Date();
    const scores = Object.values(custodians).map(c => {
      const eqCount = c.equipment.length;
      if (!eqCount) return null;

      const eqWithPM = c.equipment.filter(e => e.next_pm_date);
      const pmCompliant = eqWithPM.filter(e => new Date(e.next_pm_date) >= now).length;
      const pmsScore = eqWithPM.length === 0 ? 15 : Math.round((pmCompliant / eqWithPM.length) * 30);

      const openDefects = c.defects.filter(d=>d.status==='open');
      const troubleshot = openDefects.filter(d=>(d.troubleshooting_steps||[]).length>0);
      const defectScore = openDefects.length===0 ? 25 : Math.round((troubleshot.length/openDefects.length)*25);

      const overdueTemp = c.tempReps.filter(t=>t.status==='overdue').length;
      const tempScore = Math.max(0, 20 - (overdueTemp * 7));

      const recentAlarms = c.alarms.filter(a=>{ const age = (now - new Date(a.created_at)) / 3600000; return age > 24; });
      const clearedInTime = recentAlarms.filter(a=>a.work_order_ref && a.status!=='open').length;
      const alarmScore = recentAlarms.length===0 ? 15 : Math.round((clearedInTime/recentAlarms.length)*15);

      const operational = c.equipment.filter(e=>e.status==='operational').length;
      const healthScore = Math.round((operational/eqCount)*10);

      const total = pmsScore + defectScore + tempScore + alarmScore + healthScore;
      const rag = total >= 80 ? 'green' : total >= 60 ? 'amber' : 'red';

      return {
        name: c.designation, designation: c.designation,
        holder_name: signedOnHolders[c.designation]||'',
        score: total, rag,
        breakdown: { pms:pmsScore, defects:defectScore, tempRepairs:tempScore, alarms:alarmScore, health:healthScore },
        equipment_count: eqCount,
        open_defects: openDefects.length,
        overdue_temp: overdueTemp,
      };
    }).filter(Boolean).sort((a,b)=>b.score-a.score);

    res.json({ scores, vessel_id:vesselId, generated_at:now.toISOString() });
  } catch(e) { res.status(500).json({error:e.message}); }
});

// ── Checklists ──────────────────────────────────────────
app.get('/api/custodian/checklists', requireAuth, (req, res) => {
  const db = readCustDB();
  const vesselId = req.query.vessel_id;
  const list = vesselId ? (db.checklists||[]).filter(c => c.vessel_id === vesselId) : (db.checklists||[]);
  res.json(list);
});

app.post('/api/custodian/checklists/generate', requireAuth, async (req, res) => {
  if (!ANTHROPIC_API_KEY) return res.status(500).json({ error: 'API key not configured' });
  try {
    const { equipment_id, equipment_name, category, vessel_id } = req.body;

    const prompt = `You are a marine engineering expert. Generate a comprehensive equipment inspection checklist for a ${category} item called "${equipment_name}" on an LPG vessel.

Generate 8-14 inspection checks. Each check must have the right answer_type:
- "yes_no" — binary checks
- "condition" — condition assessments: Good / Satisfactory / Requires Attention / Critical
- "numeric" — readings with unit and normal range
- "text" — open observations

Return ONLY valid JSON:
{
  "checks": [
    {"id":"c1","text":"Check description","hint":"guidance","answer_type":"yes_no","good_answer":"NO","options":null,"good_answers":null,"critical_answers":null,"min_normal":null,"max_normal":null,"unit":null,"points":10,"critical":false,"auto_defect":true}
  ]
}`;

    const aiRes = await fetch('https://api.anthropic.com/v1/messages', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'x-api-key': ANTHROPIC_API_KEY, 'anthropic-version': '2023-06-01' },
      body: JSON.stringify({ model: 'claude-sonnet-4-6', max_tokens: 8000, messages: [{ role: 'user', content: prompt }] })
    });

    const aiData = await aiRes.json();
    const text = aiData.content?.[0]?.text || '{}';
    const parsed = JSON.parse(text.replace(/```json|```/g, '').trim());

    const db = readCustDB();
    db.checklists = db.checklists || [];
    db.checklists = db.checklists.filter(c => c.equipment_id !== equipment_id);
    const checklist = {
      id: 'cl_' + Date.now().toString(36),
      equipment_id, equipment_name, category, vessel_id,
      checks: parsed.checks || [],
      created_at: new Date().toISOString(),
      created_by: req.user.name,
      interval_days: 14
    };
    db.checklists.push(checklist);
    writeCustDB(db);
    res.json(checklist);
  } catch(e) {
    console.error('Checklist generation error:', e);
    res.status(500).json({ error: e.message });
  }
});

app.put('/api/custodian/checklists/:id', requireAuth, requireRole('admin','superintendent'), (req, res) => {
  try {
    const db = readCustDB();
    const idx = (db.checklists||[]).findIndex(c => c.id === req.params.id);
    if (idx === -1) return res.status(404).json({ error: 'Not found' });
    db.checklists[idx] = { ...db.checklists[idx], ...req.body, id: req.params.id, updated_at: new Date().toISOString() };
    writeCustDB(db);
    res.json(db.checklists[idx]);
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// ── Rounds ──────────────────────────────────────────────
app.get('/api/custodian/rounds', requireAuth, (req, res) => {
  const db = readCustDB();
  const vesselId = req.query.vessel_id;
  const eqId = req.query.equipment_id;
  let list = db.rounds || [];
  if (vesselId) list = list.filter(r => r.vessel_id === vesselId);
  if (eqId) list = list.filter(r => r.equipment_id === eqId);
  res.json(list.sort((a,b) => (b.created_at||'').localeCompare(a.created_at||'')));
});

app.post('/api/custodian/rounds', requireAuth, (req, res) => {
  try {
    const db = readCustDB();
    db.rounds = db.rounds || [];
    const round = {
      id: 'rnd_' + Date.now().toString(36),
      ...req.body,
      status: 'in_progress',
      started_by: req.user.name,
      started_by_id: req.user.id,
      created_at: new Date().toISOString(),
      answers: {}
    };
    db.rounds.push(round);
    writeCustDB(db);
    res.json(round);
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.put('/api/custodian/rounds/:id', requireAuth, (req, res) => {
  try {
    const db = readCustDB();
    db.rounds = db.rounds || [];
    const idx = db.rounds.findIndex(r => r.id === req.params.id);
    if (idx === -1) return res.status(404).json({ error: 'Not found' });
    db.rounds[idx] = { ...db.rounds[idx], ...req.body, id: req.params.id };
    writeCustDB(db);
    res.json(db.rounds[idx]);
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/custodian/rounds/:id/submit', requireAuth, async (req, res) => {
  try {
    const db = readCustDB();
    db.rounds = db.rounds || [];
    const round = db.rounds.find(r => r.id === req.params.id);
    if (!round) return res.status(404).json({ error: 'Not found' });

    const checklist = (db.checklists||[]).find(c => c.equipment_id === round.equipment_id);
    if (!checklist) return res.status(400).json({ error: 'No checklist found for this equipment' });

    const answers = req.body.answers || round.answers || {};
    let totalPoints = 0, maxPoints = 0, defectsRaised = [], criticalBlocked = [];

    checklist.checks.forEach(check => {
      const ans = answers[check.id];
      maxPoints += check.points || 10;
      if (!ans) return;

      let isGood = false, isCritical = false;

      if (check.answer_type === 'yes_no') {
        isGood = ans.value === check.good_answer;
        isCritical = check.critical && !isGood;
      } else if (check.answer_type === 'condition') {
        const goodAnswers = check.good_answers || ['Good','Satisfactory'];
        const critAnswers = check.critical_answers || ['Critical'];
        isGood = goodAnswers.includes(ans.value);
        isCritical = critAnswers.includes(ans.value);
      } else if (check.answer_type === 'numeric') {
        const val = parseFloat(ans.value);
        if (!isNaN(val)) {
          isGood = (check.min_normal == null || val >= check.min_normal) && (check.max_normal == null || val <= check.max_normal);
          isCritical = check.critical && !isGood;
        }
      } else {
        isGood = !!(ans.value && ans.value.trim());
      }

      if (isGood) totalPoints += check.points || 10;

      if (!isGood && check.auto_defect) {
        const defect = {
          id: 'def_' + Date.now().toString(36) + '_' + Math.random().toString(36).substring(2,5),
          vessel_id: round.vessel_id,
          equipment_id: round.equipment_id,
          equipment_name: round.equipment_name,
          title: `Round ${round.round_number} — Deficiency: ${check.text}`,
          severity: isCritical ? 'critical' : 'medium',
          description: `Auto-raised from equipment round. Check: "${check.text}" — Answer: ${ans.value || 'Not answered'}. Notes: ${ans.notes||'None'}`,
          immediate_action: ans.notes || '',
          status: isCritical ? 'critical' : 'open',
          troubleshooting_steps: [],
          raised_by: req.user.name,
          raised_by_name: req.user.name,
          created_at: new Date().toISOString(),
          source: 'round',
          round_id: round.id
        };
        db.defects = db.defects || [];
        db.defects.push(defect);
        defectsRaised.push({ check: check.text, severity: defect.severity });
      }

      if (isCritical) criticalBlocked.push(check.text);
    });

    const scorePercent = maxPoints > 0 ? Math.round((totalPoints / maxPoints) * 100) : 0;
    const belowThreshold = scorePercent < 70;

    round.answers = answers;
    round.status = 'submitted';
    round.submitted_at = new Date().toISOString();
    round.score = scorePercent;
    round.total_points = totalPoints;
    round.max_points = maxPoints;
    round.defects_raised = defectsRaised.length;
    round.critical_findings = criticalBlocked.length;
    round.below_threshold = belowThreshold;

    writeCustDB(db);
    res.json({ ok: true, score: scorePercent, totalPoints, maxPoints, defectsRaised, criticalBlocked, belowThreshold, round });
  } catch(e) {
    console.error('Round submit error:', e);
    res.status(500).json({ error: e.message });
  }
});

app.get('/api/custodian/rounds/status/:vessel_id', requireAuth, (req, res) => {
  try {
    const db = readCustDB();
    const equipment = (db.equipment||[]).filter(e => e.vessel_id === req.params.vessel_id);
    const rounds = (db.rounds||[]).filter(r => r.vessel_id === req.params.vessel_id);
    const checklists = (db.checklists||[]).filter(c => c.vessel_id === req.params.vessel_id);
    const now = new Date();

    const status = equipment.map(eq => {
      const hasChecklist = checklists.some(c => c.equipment_id === eq.id);
      const eqRounds = rounds.filter(r => r.equipment_id === eq.id && r.status === 'submitted')
                             .sort((a,b) => (b.submitted_at||'').localeCompare(a.submitted_at||''));
      const lastRound = eqRounds[0];
      const lastDate  = lastRound?.submitted_at ? new Date(lastRound.submitted_at) : null;
      const daysSince = lastDate ? Math.floor((now - lastDate) / 86400000) : null;
      const intervalDays = checklists.find(c=>c.equipment_id===eq.id)?.interval_days || 14;
      const isOverdue = !lastDate || daysSince >= intervalDays;
      const dueDays   = lastDate ? intervalDays - daysSince : 0;

      return {
        equipment_id: eq.id,
        equipment_name: eq.name,
        category: eq.category,
        custodian_designation: eq.custodian_designation,
        has_checklist: hasChecklist,
        last_round_date: lastRound?.submitted_at || null,
        last_score: lastRound?.score ?? null,
        days_since: daysSince,
        due_in_days: dueDays,
        is_overdue: isOverdue,
        interval_days: intervalDays,
        round_count: eqRounds.length
      };
    });

    res.json(status);
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// ══════════════════════════════════════════════════════
// SIRE 2.0 MODULE
// ══════════════════════════════════════════════════════

// [readDB/writeDB moved to db.js — block 2]

// ── SIRE_CHAPTERS constant (full 402-question bank) ────────────────────────
// NOTE: This is the full question bank loaded from the OCIMF SIRE 2.0 Question
// Library Parts 1 & 2 (Version 1.0, January 2022). Chapters C1–C12.
// The full array is maintained in the repo. This placeholder ensures the server
// starts cleanly even if the data is injected separately.
const SIRE_CHAPTERS = [
  { id:"C1",  title:"Vessel, Operator and Inspection Particulars", roles:["Master","DPA"], questions:[] },
  { id:"C2",  title:"Certification and Documentation", roles:["Master","CE","DPA"], questions:[] },
  { id:"C3",  title:"Crew Management", roles:["Master","Officers"], questions:[] },
  { id:"C4",  title:"Navigation", roles:["Master","Officers"], questions:[] },
  { id:"C5",  title:"Safety Management", roles:["Master","CE","Officers","Crew"], questions:[] },
  { id:"C6",  title:"Pollution Prevention", roles:["Master","CE","Officers"], questions:[] },
  { id:"C7",  title:"Maritime Security", roles:["Master","SSO","Officers"], questions:[] },
  { id:"C8",  title:"Cargo and Ballast Systems", roles:["Master","CE","Cargo Officers"], questions:[] },
  { id:"C9",  title:"Mooring and Anchoring", roles:["Master","Officers","Bosun"], questions:[] },
  { id:"C10", title:"Machinery", roles:["CE","Engineers"], questions:[] },
  { id:"C11", title:"General Appearance and Condition – Photograph Comparison", roles:["Master","CE","Officers"], questions:[] },
  { id:"C12", title:"Ice Operations", roles:["Master","Officers"], questions:[] },
];

// ── SIRE API Routes ─────────────────────────────────────

app.get('/api/sire/readiness/:vessel_id', requireAuth, (req, res) => {
  try {
    const db = readSireDB();
    const vesselId = req.params.vessel_id;
    const preps = db.preparations[vesselId] || {};

    const summary = SIRE_CHAPTERS.map(ch => {
      const total = ch.questions.length;
      const statuses = ch.questions.map(q => preps[q.id]?.status || 'not_started');
      const ready = statuses.filter(s => s === 'ready').length;
      const inProgress = statuses.filter(s => s === 'in_progress').length;
      const gap = statuses.filter(s => s === 'gap').length;
      const score = total > 0 ? Math.round((ready / total) * 100) : 0;
      const rag = score >= 80 ? 'green' : score >= 50 ? 'amber' : 'red';
      return { id: ch.id, title: ch.title, roles: ch.roles, total, ready, inProgress, gap, notStarted: total - ready - inProgress - gap, score, rag };
    });

    const overallScore = Math.round(summary.reduce((a,c) => a + c.score, 0) / summary.length);
    res.json({ summary, overallScore, vessel_id: vesselId });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.get('/api/sire/chapter/:chapter_id', requireAuth, (req, res) => {
  try {
    const db = readSireDB();
    const ch = SIRE_CHAPTERS.find(c => c.id === req.params.chapter_id);
    if (!ch) return res.status(404).json({ error: 'Chapter not found' });
    const vesselId = req.query.vessel_id;
    const preps = db.preparations[vesselId] || {};
    const questions = ch.questions.map(q => ({
      ...q,
      prep: preps[q.id] || { status:'not_started', answer:'', notes:'', evidence_checked:[] }
    }));
    res.json({ ...ch, questions });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/sire/generate-answer', requireAuth, async (req, res) => {
  if (!ANTHROPIC_API_KEY) return res.status(500).json({ error: 'API key not configured' });
  try {
    const { question_id, question_text, chapter_title, evidence_items, vessel_name, vessel_type } = req.body;

    let fullQuestion = null;
    for (const ch of SIRE_CHAPTERS) {
      fullQuestion = ch.questions.find(q => q.id === question_id || q.number === question_id);
      if (fullQuestion) break;
    }

    const objective = fullQuestion?.objective || '';
    const negativeGrounds = (fullQuestion?.negative_grounds || []).join('\n• ');
    const expectedEvidence = (fullQuestion?.evidence || evidence_items || []).join('\n• ');
    const vesselTypes = (fullQuestion?.vessel_types || []).join(', ') || vessel_type || 'LPG';
    const sectionName = fullQuestion?.section_name || chapter_title;
    const qNumber = fullQuestion?.number || '';

    const prompt = `You are an expert SIRE 2.0 inspector coach.

SIRE 2.0 Question ${qNumber}: ${fullQuestion?.short_text || ''}
Chapter: ${chapter_title} — Section: ${sectionName}
Applies to: ${vesselTypes} vessel types
Vessel: ${vessel_name || 'LPG Tanker'} (${vessel_type || 'LPG Gas Carrier'})

FULL QUESTION TEXT:
${question_text}

OCIMF OBJECTIVE:
${objective}

EXPECTED EVIDENCE:
• ${expectedEvidence}

NEGATIVE GROUNDS:
• ${negativeGrounds}

Return JSON only (no markdown):
{"model_answer":"","inspector_focus":"","regulation_basis":"","evidence_to_show":[],"common_failures":[],"score_tips":[],"difficulty":"medium"}`;

    const aiRes = await fetch('https://api.anthropic.com/v1/messages', {
      method:'POST',
      headers:{ 'Content-Type':'application/json','x-api-key':ANTHROPIC_API_KEY,'anthropic-version':'2023-06-01' },
      body: JSON.stringify({ model:'claude-sonnet-4-6', max_tokens:2000, messages:[{role:'user',content:prompt}] })
    });
    const aiData = await aiRes.json();
    const text = aiData.content?.[0]?.text || '{}';
    const parsed = JSON.parse(text.replace(/```json|```/g,'').trim());
    res.json(parsed);
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/sire/preparation', requireAuth, (req, res) => {
  try {
    const db = readSireDB();
    const { vessel_id, question_id, status, answer, notes, evidence_checked, model_answer } = req.body;
    if (!db.preparations[vessel_id]) db.preparations[vessel_id] = {};
    db.preparations[vessel_id][question_id] = {
      status, answer, notes, evidence_checked: evidence_checked||[],
      model_answer, updated_at: new Date().toISOString(), updated_by: req.user.name
    };
    writeSireDB(db);
    res.json({ ok:true });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/sire/drill', requireAuth, async (req, res) => {
  if (!ANTHROPIC_API_KEY) return res.status(500).json({ error: 'API key not configured' });
  try {
    const { question_text, chapter_title, officer_answer, vessel_name } = req.body;

    const prompt = `You are a strict but fair SIRE 2.0 inspector on ${vessel_name||'an LPG tanker'}.

Chapter: ${chapter_title}
Question: ${question_text}
Officer's answer: ${officer_answer}

Score this answer. Grades 1-5: 5=Outstanding, 4=Good, 3=Satisfactory, 2=Deficient, 1=Unsatisfactory.

Return JSON:
{"grade":3,"grade_label":"Satisfactory","what_was_good":"","what_was_missing":"","inspector_follow_up":"","model_answer":"","score_color":"amber"}`;

    const aiRes = await fetch('https://api.anthropic.com/v1/messages', {
      method:'POST',
      headers:{ 'Content-Type':'application/json','x-api-key':ANTHROPIC_API_KEY,'anthropic-version':'2023-06-01' },
      body: JSON.stringify({ model:'claude-sonnet-4-6', max_tokens:1500, messages:[{role:'user',content:prompt}] })
    });
    const aiData = await aiRes.json();
    const text = aiData.content?.[0]?.text || '{}';
    const parsed = JSON.parse(text.replace(/```json|```/g,'').trim());
    res.json(parsed);
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.get('/api/sire/findings', requireAuth, (req, res) => {
  const db = readSireDB();
  const vesselId = req.query.vessel_id;
  const findings = vesselId ? (db.findings||[]).filter(f=>f.vessel_id===vesselId) : (db.findings||[]);
  res.json(findings.sort((a,b)=>(b.inspection_date||'').localeCompare(a.inspection_date||'')));
});

app.post('/api/sire/findings', requireAuth, (req, res) => {
  try {
    const db = readSireDB();
    const finding = {
      id:'sf_'+Date.now().toString(36), ...req.body,
      raised_by: req.user.name, created_at: new Date().toISOString(),
      cap_status:'open'
    };
    db.findings = db.findings||[];
    db.findings.push(finding);
    writeSireDB(db);
    res.json(finding);
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.put('/api/sire/findings/:id', requireAuth, (req, res) => {
  try {
    const db = readSireDB();
    const idx = (db.findings||[]).findIndex(f=>f.id===req.params.id);
    if (idx===-1) return res.status(404).json({error:'Not found'});
    db.findings[idx] = {...db.findings[idx],...req.body,id:req.params.id,updated_at:new Date().toISOString()};
    writeSireDB(db);
    res.json(db.findings[idx]);
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.get('/api/sire/chapters', requireAuth, (req, res) => {
  const { vessel_type } = req.query;
  const chapters = SIRE_CHAPTERS.map(ch => {
    let qs = ch.questions;
    if (vessel_type && vessel_type !== 'all') {
      qs = qs.filter(q => !q.vessel_types?.length || q.vessel_types.includes(vessel_type));
    }
    const sections = {};
    qs.forEach(q => {
      if (!sections[q.section]) sections[q.section] = { section: q.section, name: q.section_name, count: 0 };
      sections[q.section].count++;
    });
    return { id: ch.id, title: ch.title, roles: ch.roles, questionCount: qs.length, sections: Object.values(sections) };
  });
  res.json(chapters);
});

app.get('/api/sire/question/:question_id', requireAuth, (req, res) => {
  for (const ch of SIRE_CHAPTERS) {
    const q = ch.questions.find(q => q.id === req.params.question_id);
    if (q) return res.json({ ...q, chapter_id: ch.id, chapter_title: ch.title });
  }
  res.status(404).json({ error: 'Question not found' });
});

app.get('/api/sire/search', requireAuth, (req, res) => {
  const { q: query, vessel_type, chapter } = req.query;
  if (!query || query.length < 2) return res.json([]);
  const qLower = query.toLowerCase();
  const results = [];
  for (const ch of SIRE_CHAPTERS) {
    if (chapter && ch.id !== chapter) continue;
    for (const question of ch.questions) {
      if (vessel_type && vessel_type !== 'all' && question.vessel_types?.length && !question.vessel_types.includes(vessel_type)) continue;
      if ((question.text||'').toLowerCase().includes(qLower) || (question.short_text||'').toLowerCase().includes(qLower)) {
        results.push({
          id: question.id, number: question.number,
          short_text: question.short_text,
          text: (question.text||'').slice(0, 150),
          chapter_id: ch.id, chapter_title: ch.title,
          section: question.section, vessel_types: question.vessel_types
        });
      }
      if (results.length >= 30) break;
    }
    if (results.length >= 30) break;
  }
  res.json(results);
});

// ── Industry Intelligence ────────────────────────────────────────────────
app.post('/api/sire/industry-search', requireAuth, async (req, res) => {
  if (!ANTHROPIC_API_KEY) return res.status(500).json({ error: 'API key not configured' });
  try {
    const { vessel_type, chapter_id, chapter_title } = req.body;

    const prompt = `You are a maritime SIRE 2.0 expert. Generate 6-8 realistic industry findings commonly observed on ${vessel_type || 'LPG Gas Carrier'} vessels for SIRE Chapter ${chapter_id} — ${chapter_title}.

Return JSON only:
{"findings":[{"title":"","description":"","severity":"obs|minor|major","frequency":"very_common|common|occasional","chapter":"${chapter_id}","root_causes":[],"prevention":"","sire_reference":""}],"chapter_risk_areas":[],"industry_trend":""}`;

    const aiRes = await fetch('https://api.anthropic.com/v1/messages', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'x-api-key': ANTHROPIC_API_KEY, 'anthropic-version': '2023-06-01' },
      body: JSON.stringify({
        model: 'claude-sonnet-4-6', max_tokens: 3000,
        system: 'You are a SIRE 2.0 maritime inspection expert. Respond with ONLY valid JSON — no preamble, no markdown fences.',
        messages: [{ role: 'user', content: prompt }]
      })
    });
    const aiData = await aiRes.json();
    const textBlocks = (aiData.content || []).filter(b => b.type === 'text');
    const text = textBlocks.map(b => b.text).join('\n');
    let parsed = { findings: [], chapter_risk_areas: [], industry_trend: '' };
    try {
      const fenced = text.match(/```json\s*([\s\S]*?)```/);
      if (fenced) { parsed = JSON.parse(fenced[1].trim()); }
      else {
        const start = text.indexOf('{');
        if (start !== -1) {
          let depth = 0, end = -1;
          for (let i = start; i < text.length; i++) {
            if (text[i] === '{') depth++;
            else if (text[i] === '}') { depth--; if (depth === 0) { end = i; break; } }
          }
          if (end !== -1) parsed = JSON.parse(text.substring(start, end + 1));
        }
      }
    } catch(parseErr) {
      console.error('Industry intel JSON parse error:', parseErr.message);
      parsed = { findings: [], chapter_risk_areas: [], industry_trend: text.substring(0, 300) };
    }
    res.json(parsed);
  } catch(e) {
    console.error('Industry search error:', e);
    res.status(500).json({ error: e.message });
  }
});

app.post('/api/sire/upload-findings', requireAuth, (req, res) => {
  try {
    const db = readSireDB();
    db.findings = db.findings || [];
    const { findings } = req.body;
    if (!Array.isArray(findings)) return res.status(400).json({ error: 'findings must be an array' });

    let imported = 0, skipped = 0, duplicates = 0;
    findings.forEach(f => {
      if (!f.description) { skipped++; return; }

      // Duplicate detection: same vessel + same description (normalised) + same inspection_date
      const descNorm = (f.description || '').trim().toLowerCase().substring(0, 80);
      const isDuplicate = db.findings.some(existing => {
        const existingDescNorm = (existing.description || '').trim().toLowerCase().substring(0, 80);
        return existing.vessel_id === f.vessel_id
          && existingDescNorm === descNorm
          && existing.inspection_date === f.inspection_date;
      });

      if (isDuplicate) { duplicates++; return; }

      db.findings.push({
        id: 'sf_' + Date.now().toString(36) + '_' + Math.random().toString(36).substring(2,5),
        ...f,
        imported: true,
        imported_at: new Date().toISOString(),
        imported_by: req.user.name,
        cap_status: f.cap_status || 'open',
        created_at: new Date().toISOString()
      });
      imported++;
    });
    writeSireDB(db);
    res.json({ ok: true, imported, skipped, duplicates });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.get('/api/sire/fleet-findings', requireAuth, requireRole('admin', 'superintendent'), (req, res) => {
  try {
    const db = readSireDB();
    const mainDb = readDB();
    const findings = db.findings || [];
    const enriched = findings.map(f => {
      const vessel = mainDb.vessels.find(v => v.id === f.vessel_id);
      return { ...f, vessel_name: vessel?.name || f.vessel_name || 'Unknown' };
    });
    const byChapter = {};
    enriched.forEach(f => {
      const ch = f.chapter || 'Unknown';
      if (!byChapter[ch]) byChapter[ch] = [];
      byChapter[ch].push(f);
    });
    const inspectors = [...new Set(enriched.map(f => [f.inspecting_company, f.inspector].filter(Boolean).join(' — ')).filter(Boolean))].sort();
    res.json({ findings: enriched, byChapter, total: enriched.length, inspectors });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.get('/api/sire/vessel-context/:vessel_id', requireAuth, (req, res) => {
  try {
    const db = readDB();
    const vessel = db.vessels.find(v => v.id === req.params.vessel_id);
    if (!vessel) return res.status(404).json({ error: 'Vessel not found' });
    res.json(vessel);
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// ── AI Report Parser ──────────────────────────────────────────────────────
app.post('/api/sire/parse-report', requireAuth, async (req, res) => {
  if (!ANTHROPIC_API_KEY) return res.status(500).json({ error: 'API key not configured' });
  try {
    const { file_data, file_type, vessel_id, vessel_name, inspector_override, company_override, date_override } = req.body;
    if (!file_data) return res.status(400).json({ error: 'No file data provided' });

    const mainDb = readDB();
    const vessel = mainDb.vessels.find(v => v.id === vessel_id) || { name: vessel_name || 'Unknown' };

    const prompt = `You are an expert maritime SIRE 2.0 inspection analyst. Extract ALL findings from this inspection report for vessel "${vessel.name}".

SIRE 2.0 Chapters: C1=Vessel Particulars, C2=Certification, C3=Crew, C4=Navigation, C5=Safety, C6=Pollution, C7=Security, C8=Cargo, C9=Mooring, C10=Machinery, C11=General Appearance, C12=Ice.

Return ONLY valid JSON:
{
  "inspection_date": "YYYY-MM-DD or null",
  "inspector": "name or null",
  "inspecting_company": "company or null",
  "vessel_name": "name or null",
  "total_findings": 0,
  "findings": [{"chapter":"C5","severity":"obs|minor|major","description":"","corrective_action":"","question_ref":""}],
  "missing_info": [],
  "summary": ""
}`;

    const messages = [{
      role: 'user',
      content: [
        { type: file_type === 'application/pdf' ? 'document' : 'image', source: { type: 'base64', media_type: file_type, data: file_data } },
        { type: 'text', text: prompt }
      ]
    }];

    const aiRes = await fetch('https://api.anthropic.com/v1/messages', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'x-api-key': ANTHROPIC_API_KEY, 'anthropic-version': '2023-06-01' },
      body: JSON.stringify({ model: 'claude-sonnet-4-6', max_tokens: 8000, messages })
    });

    const aiData = await aiRes.json();
    const text = aiData.content?.[0]?.text || '{}';
    const clean = text.replace(/```json|```/g, '').trim();
    const jsonMatch = clean.match(/\{[\s\S]*\}/);
    if (!jsonMatch) return res.status(500).json({ error: 'Could not parse AI response', raw: text.substring(0, 300) });

    const parsed = JSON.parse(jsonMatch[0]);
    if (inspector_override) parsed.inspector = inspector_override;
    if (company_override)   parsed.inspecting_company = company_override;
    if (date_override)      parsed.inspection_date = date_override;

    // Duplicate report detection — check if this inspection has already been imported
    const sireDb = readSireDB();
    const existingFindings = sireDb.findings || [];
    const inspDate = parsed.inspection_date;
    const inspCompany = (parsed.inspecting_company || '').toLowerCase();

    let duplicateReport = false;
    let duplicateCount = 0;
    if (vessel_id && inspDate) {
      // Count how many findings already exist for this vessel + inspection date
      duplicateCount = existingFindings.filter(f =>
        f.vessel_id === vessel_id && f.inspection_date === inspDate
      ).length;
      if (duplicateCount > 0) duplicateReport = true;
    }

    res.json({
      ok: true,
      vessel_id,
      ...parsed,
      duplicate_report: duplicateReport,
      duplicate_count: duplicateCount,
      duplicate_warning: duplicateReport
        ? `⚠ ${duplicateCount} finding(s) from this inspection date (${inspDate}) already exist for this vessel. Importing again will skip duplicates.`
        : null
    });
  } catch(e) {
    console.error('Parse report error:', e);
    res.status(500).json({ error: e.message });
  }
});

// ── Batch CAP Review ─────────────────────────────────────────────────────
app.post('/api/sire/review-cap-batch', requireAuth, async (req, res) => {
  if (!ANTHROPIC_API_KEY) return res.status(500).json({ error: 'API key not configured' });
  try {
    const { finding_ids, vessel_type } = req.body;
    if (!Array.isArray(finding_ids) || !finding_ids.length) return res.status(400).json({ error: 'finding_ids required' });

    const db = readSireDB();
    const findings = (db.findings || []).filter(f => finding_ids.includes(f.id));
    if (!findings.length) return res.status(404).json({ error: 'No findings found' });

    res.json({ ok: true, total: findings.length, message: 'Batch review started' });

    (async () => {
      for (const f of findings) {
        try {
          const prompt = `You are a maritime SIRE expert reviewing a CAP.
Finding: ${f.description}
Chapter: ${f.chapter} | Severity: ${f.severity}
Root Cause: ${f.root_cause || 'Not stated'}
Corrective Action: ${f.corrective_action || 'Not provided'}
Vessel Type: ${vessel_type || 'LPG Gas Carrier'}

Rate this CAP 1-5 and return JSON only:
{"score":3,"score_color":"amber","score_label":"Adequate","verdict":"One sentence verdict","weaknesses":["w1"],"improved_cap":"Better version","systemic_action":"Fleet-wide action","evidence_required":["Doc1"],"timeline_suggestion":"30 days","inspector_response":"Formal 2-3 paragraph response for submission to inspector/OCIMF."}`;

          const aiRes = await fetch('https://api.anthropic.com/v1/messages', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json', 'x-api-key': ANTHROPIC_API_KEY, 'anthropic-version': '2023-06-01' },
            body: JSON.stringify({ model: 'claude-sonnet-4-6', max_tokens: 2000, messages: [{ role: 'user', content: prompt }] })
          });
          const aiData = await aiRes.json();
          const text = (aiData.content || []).find(c => c.type === 'text')?.text || '';
          const clean = text.replace(/```json|```/g, '').trim();

          // Robust JSON extraction with truncation recovery
          let review = null;
          const start = clean.indexOf('{');
          if (start !== -1) {
            let jsonStr = clean.substring(start);
            let depth = 0, lastClose = -1;
            for (let i = 0; i < jsonStr.length; i++) {
              if (jsonStr[i] === '{') depth++;
              else if (jsonStr[i] === '}') { depth--; if (depth === 0) { lastClose = i; break; } }
            }
            if (lastClose !== -1) { jsonStr = jsonStr.substring(0, lastClose + 1); }
            else {
              jsonStr = jsonStr.replace(/,\s*$/, '');
              const opens = (jsonStr.match(/\{/g)||[]).length - (jsonStr.match(/\}/g)||[]).length;
              jsonStr += '}'.repeat(Math.max(0, opens));
            }
            try { review = JSON.parse(jsonStr); } catch(e) { console.error('Batch JSON parse failed:', e.message); }
          }

          if (review) {
            const db2 = readSireDB();
            const idx = (db2.findings || []).findIndex(x => x.id === f.id);
            if (idx >= 0) {
              db2.findings[idx].cap_review = { ...review, reviewed_at: new Date().toISOString() };
              writeSireDB(db2);
            }
            console.log('Batch review done:', f.id, 'score:', review.score);
          }
          await new Promise(r => setTimeout(r, 1000));
        } catch(e) { console.error('Batch review error for', f.id, ':', e.message); }
      }
      console.log('Batch review complete for', findings.length, 'findings');
    })();
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// ── CAP Review ────────────────────────────────────────────────────────────
// FIX: max_tokens raised to 2500 + robust JSON extraction with truncation recovery
// ── IMS Index Builder ─────────────────────────────────────────────────────────
// Accepts the nsml_ims_sire_index.txt sidecar and stores it for review-cap lookups
app.post('/api/sire/store-ims-index', requireAuth, async (req, res) => {
  try {
    const { text } = req.body;
    if (!text || text.length < 1000) return res.status(400).json({ error: 'text too short' });
    const dest = path.join(DATA_DIR, 'uploads', 'manuals', 'nsml_ims_sire_index.txt');
    fs.mkdirSync(path.join(DATA_DIR, 'uploads', 'manuals'), { recursive: true });
    fs.writeFileSync(dest, text, 'utf8');
    res.json({ ok: true, chars: text.length, path: 'uploads/manuals/nsml_ims_sire_index.txt' });
    console.log(`IMS index stored: ${text.length} chars`);
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.get('/api/sire/ims-status', requireAuth, (req, res) => {
  try {
    const p = path.join(DATA_DIR, 'uploads', 'manuals', 'nsml_ims_sire_index.txt');
    if (fs.existsSync(p)) {
      const stat = fs.statSync(p);
      const preview = fs.readFileSync(p, 'utf8').substring(0, 200);
      res.json({ present: true, size_kb: Math.round(stat.size/1024), preview });
    } else {
      res.json({ present: false });
    }
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/sire/review-cap', requireAuth, async (req, res) => {
  if (!ANTHROPIC_API_KEY) return res.status(500).json({ error: 'API key not configured' });
  try {
    const { finding_id, description, chapter, severity, root_cause, corrective_action, vessel_type, vessel_id } = req.body;

    // ── Pull relevant IMS/SMS procedures ──────────────────────────────────────
    // Priority 1: NSML IMS sidecar files (chapter-indexed sections)
    // Priority 2: Any other uploaded SMS/procedure documents in repo
    let imsContext = '';

    // SIRE chapter → IMS section prefixes
    const CHAPTER_IMS_SECTIONS = {
      'C1': ['1.1','1.2','1.3','1.4'],
      'C2': ['1.6','1.7','1.14','1.16'],
      'C3': ['1.10','1.11','1.12','1.13'],
      'C4': ['3.'],
      'C5': ['2.','7.'],
      'C6': ['2.13','2.14','4.6'],
      'C7': ['1.15'],
      'C8': ['4.'],
      'C9': ['3.14'],
      'C10': ['5.'],
      'C11': ['5.1','6.'],
      'C12': ['3.15','3.16'],
    };

    try {
      const uploadsDir = path.join(DATA_DIR, 'uploads');
      const imsSidecarPath = path.join(uploadsDir, 'manuals', 'nsml_ims_sire_index.txt');
      const keywords = [
        ...(description || '').toLowerCase().split(/\s+/).filter(w => w.length > 4),
        ...(chapter || '').toLowerCase().split(/[\s-]+/).filter(w => w.length > 1),
      ].filter(Boolean);

      let imsParts = [];

      // ── 1. Use pre-built NSML IMS SIRE index if available ──────────────────
      if (fs.existsSync(imsSidecarPath)) {
        const imsIndex = fs.readFileSync(imsSidecarPath, 'utf8');
        const chKey = (chapter || '').toUpperCase().trim().substring(0, 2);
        const sectionPrefixes = CHAPTER_IMS_SECTIONS[chKey] || [];

        // Extract sections matching this SIRE chapter
        const sectionBlocks = imsIndex.split(/\n#{2,3} IMS /);
        const relevant = sectionBlocks.filter(block => {
          const firstLine = block.split('\n')[0];
          return sectionPrefixes.some(p => firstLine.startsWith(p)) ||
                 keywords.some(kw => block.toLowerCase().includes(kw));
        });

        if (relevant.length > 0) {
          // Take most relevant blocks (up to 5000 chars total)
          let budget = 3000;
          const picked = [];
          for (const block of relevant) {
            const chunk = block.substring(0, Math.min(1200, budget));
            picked.push('### IMS ' + chunk);
            budget -= chunk.length;
            if (budget <= 0) break;
          }
          imsParts.push(`NSML IMS — Chapter ${chKey} Relevant Sections:\n${picked.join('\n')}`);
        }
      }

      // ── 2. Also search repo_db for any other uploaded SMS/procedure docs ──
      const repoDb = readRepoDb();
      const manuals = repoDb.manuals.filter(m =>
        !m.superseded &&
        m.text_extracted &&
        /ims|sms|safety.management|procedure|manual/i.test((m.filename||'') + (m.category||''))
      );

      for (const m of manuals.slice(0, 2)) {
        const sidecar = loadSidecarText(m.stored_name, uploadsDir);
        if (!sidecar) continue;
        const kwRe = new RegExp(keywords.join('|'), 'i');
        let bestChunk = sidecar.substring(0, 1500);
        let bestScore = 0;
        const WINDOW = 2000, STEP = 500;
        for (let pos = 0; pos < Math.min(sidecar.length - WINDOW, 60000); pos += STEP) {
          const w = sidecar.substring(pos, pos + WINDOW);
          const sc = (w.match(kwRe) || []).length;
          if (sc > bestScore) { bestScore = sc; bestChunk = w; }
        }
        if (bestScore > 0) {
          imsParts.push(`--- ${m.filename} ---\n${bestChunk.substring(0, 1000)}`);
        }
      }

      if (imsParts.length > 0) {
        imsContext = `\n\nNSML IMS/SMS REFERENCE:\n${imsParts.join('\n\n')}`;
      }
    } catch(imsErr) {
      console.warn('IMS lookup failed (non-fatal):', imsErr.message);
    }

    const prompt = `You are a senior maritime SIRE 2.0 expert and DPA reviewing corrective action plans for vessel deficiencies.

Vessel type: ${vessel_type || 'LPG Gas Carrier'}
Chapter: ${chapter}
Severity: ${severity}
Finding: ${description}
Root Cause: ${root_cause || 'Not stated'}
Proposed Corrective Action: ${corrective_action || 'None provided'}${imsContext}

Evaluate this CAP against SIRE 2.0 standards. A good CAP must:
1. Directly address the root cause (not just the symptom)
2. Be specific and measurable — reference specific IMS/SMS procedure numbers and section titles from the documents provided above where relevant
3. Include systemic prevention
4. Reference the EXACT procedure title and section from the IMS/SMS provided — do not use placeholder references like [SMS Ref XX]; use the actual document name and section if visible in the provided text
5. Be realistic and achievable

IMPORTANT: Keep improved_cap under 1500 words total. Be comprehensive but concise.

IMPORTANT FORMATTING RULES FOR improved_cap:
- You MUST use EXACTLY these section headers (all caps, followed by a colon):
  ROOT CAUSE ANALYSIS:
  IMMEDIATE ACTION:
  CORRECTIVE ACTION:
  PREVENTIVE ACTION:
  SYSTEMIC ACTION:
  FLEET ACTION:
- Do NOT use variants like "ROOT CAUSE IDENTIFIED", "IMMEDIATE ACTIONS (Within X hours)", "SYSTEMIC/PREVENTIVE ACTIONS" etc.
- Each header must be on its own line, preceded by a newline character.
- Number action items as: 1. item  2. item  (not "(1)" or "1)")
- Cite specific IMS procedure names and section numbers from the documents provided above where relevant.

Return JSON only (no markdown fences):
{
  "score": 3,
  "score_label": "Inadequate|Weak|Adequate|Good|Excellent",
  "score_color": "red|amber|green",
  "verdict": "One sentence verdict on the CAP quality",
  "strengths": ["What is good about this CAP"],
  "weaknesses": ["What is missing or inadequate"],
  "improved_cap": "A fully rewritten, SIRE-ready corrective action",
  "systemic_action": "The systemic/SMS-level action needed to prevent recurrence",
  "timeline_suggestion": "Realistic timeframe e.g. 14 days, 30 days",
  "evidence_required": ["Broad list of documents needed to demonstrate closure to inspector"],
  "documentary_evidence": {
    "immediate": ["Specific records or documents that must exist RIGHT NOW to demonstrate immediate corrective action was taken — e.g. signed checklist, updated log entry, repair record, work order"],
    "ongoing": ["Records that must be maintained going forward to show systemic prevention is in place — e.g. updated procedure with revision date, monthly inspection records, training certificates for all watchkeepers"],
    "objective_evidence": ["Physical or documentary items an inspector will physically inspect or verify on board — e.g. the actual SMS procedure with revision stamp, the calibration certificate, the signed crew acknowledgement list"],
    "retention_period": "How long these records should be retained e.g. 3 years, last 2 inspection cycles"
  },
  "inspector_response": "A formal 2-3 paragraph response in professional maritime language, suitable for direct submission to OCIMF/the inspector. Acknowledge the finding, state the immediate corrective action taken, describe systemic/preventive measures implemented, and confirm what objective evidence is available for verification."
}`;

    const aiRes = await fetch('https://api.anthropic.com/v1/messages', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'x-api-key': ANTHROPIC_API_KEY, 'anthropic-version': '2023-06-01' },
      // 3000 tokens to accommodate documentary_evidence + inspector_response without truncation
      body: JSON.stringify({ model: 'claude-sonnet-4-6', max_tokens: 8000, messages: [{ role: 'user', content: prompt }] })
    });

    const aiData = await aiRes.json();
    if (aiData.error) throw new Error(`AI API error: ${aiData.error.message || JSON.stringify(aiData.error)}`);

    const rawText = aiData.content?.[0]?.text;
    if (!rawText) throw new Error(`No response from AI — stop_reason: ${aiData.stop_reason || 'unknown'}`);

    // Strip markdown fences
    const clean = rawText.replace(/```json\s*/gi, '').replace(/```\s*/g, '').trim();

    // Robust JSON extraction — handle truncated responses by recovering open brackets
    let jsonStr = '';
    const jsonStart = clean.indexOf('{');
    if (jsonStart !== -1) {
      jsonStr = clean.substring(jsonStart);
      // Walk brackets to find complete closing brace
      let depth = 0, lastClose = -1;
      for (let i = 0; i < jsonStr.length; i++) {
        if (jsonStr[i] === '{') depth++;
        else if (jsonStr[i] === '}') {
          depth--;
          if (depth === 0) { lastClose = i; break; }
        }
      }
      if (lastClose !== -1) {
        // Complete JSON found
        jsonStr = jsonStr.substring(0, lastClose + 1);
      } else {
        // Truncated response — attempt to close open structures
        console.warn('CAP review response was truncated — attempting recovery');
        jsonStr = jsonStr.replace(/,\s*$/, ''); // remove trailing comma
        const openBraces  = (jsonStr.match(/\{/g)  || []).length;
        const closeBraces = (jsonStr.match(/\}/g)  || []).length;
        const openArrays  = (jsonStr.match(/\[/g)  || []).length;
        const closeArrays = (jsonStr.match(/\]/g)  || []).length;
        // Close any open arrays first, then objects
        jsonStr += ']'.repeat(Math.max(0, openArrays - closeArrays));
        jsonStr += '}'.repeat(Math.max(0, openBraces - closeBraces));
      }
    }

    if (!jsonStr) throw new Error(`AI response did not contain valid JSON. Raw: ${rawText.substring(0, 200)}`);

    let parsed;
    try {
      parsed = JSON.parse(jsonStr);
    } catch(parseErr) {
      throw new Error(`JSON parse failed after recovery attempt: ${parseErr.message}. Raw: ${rawText.substring(0, 200)}`);
    }

    // Save review to finding if ID provided
    if (finding_id) {
      const db = readSireDB();
      const idx = (db.findings || []).findIndex(f => f.id === finding_id);
      if (idx !== -1) {
        db.findings[idx].cap_review = { ...parsed, reviewed_at: new Date().toISOString() };
        db.findings[idx].cap_review_at = new Date().toISOString();
        writeSireDB(db);
      }
    }

    res.json(parsed);
  } catch(e) {
    console.error('CAP review error:', e.message);
    res.status(500).json({ error: e.message });
  }
});

app.put('/api/sire/findings/:id/cap', requireAuth, (req, res) => {
  try {
    const db = readSireDB();
    const idx = (db.findings || []).findIndex(f => f.id === req.params.id);
    if (idx === -1) return res.status(404).json({ error: 'Not found' });
    db.findings[idx].corrective_action = req.body.corrective_action;
    db.findings[idx].root_cause = req.body.root_cause || db.findings[idx].root_cause;
    db.findings[idx].responsible = req.body.responsible || db.findings[idx].responsible;
    db.findings[idx].due_date = req.body.due_date || db.findings[idx].due_date;
    db.findings[idx].cap_updated_at = new Date().toISOString();
    writeSireDB(db);
    res.json(db.findings[idx]);
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.delete('/api/sire/finding/:id', requireAuth, (req, res) => {
  try {
    if (req.user.role !== 'admin') return res.status(403).json({ error: 'Admin only' });
    const db = readSireDB();
    const before = (db.findings || []).length;
    db.findings = (db.findings || []).filter(f => f.id !== req.params.id);
    if (db.findings.length === before) return res.status(404).json({ error: 'Finding not found' });
    writeSireDB(db);
    res.json({ ok: true });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// ══════════════════════════════════════════════════════
// KNOWLEDGE REPOSITORY
// ══════════════════════════════════════════════════════

// Memory storage — files are uploaded to R2 immediately, not written to disk
const uploadManual = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 50 * 1024 * 1024 },
  fileFilter: (req, file, cb) => {
    if (file.mimetype === 'application/pdf') cb(null, true);
    else cb(new Error('Only PDF files are supported'));
  }
});

// [readDB/writeDB moved to db.js — block 3]

function pdfHasTextLayer(buffer) {
  const str = buffer.toString('latin1');
  const textMatches = (str.match(/BT[\s\S]{1,500}ET/g) || []).length;
  return textMatches > 5;
}

async function extractPdfText(filePathOrBuffer) {
  const buffer = Buffer.isBuffer(filePathOrBuffer)
    ? filePathOrBuffer
    : fs.readFileSync(filePathOrBuffer);

  try {
    const pdfParse = require('pdf-parse');
    const result = await pdfParse(buffer);
    const text = (result.text || '').trim();
    const wordCount = text.split(/\s+/).filter(w => w.length > 2).length;
    if (wordCount > 50) {
      console.log(`pdf-parse: extracted ${wordCount} words from ${result.numpages} pages`);
      return { text, method: 'native', pages: result.numpages };
    }
    console.log(`pdf-parse: only ${wordCount} words — switching to Vision OCR`);
  } catch(e) {
    console.log('pdf-parse failed:', e.message, '— trying Vision OCR');
  }

  const apiKey = process.env.GOOGLE_VISION_KEY;
  if (!apiKey) {
    console.error('GOOGLE_VISION_KEY not set — cannot OCR scanned PDF');
    return null;
  }

  try {
    const base64 = buffer.toString('base64');
    const fileSizeMB = buffer.length / (1024 * 1024);
    console.log(`Google Vision OCR: ${fileSizeMB.toFixed(1)}MB PDF`);

    async function visionPages(pageNums) {
      const requestBody = {
        requests: [{
          inputConfig: { content: base64, mimeType: 'application/pdf' },
          features: [{ type: 'DOCUMENT_TEXT_DETECTION' }],
          pages: pageNums
        }]
      };
      const r = await fetch(
        `https://vision.googleapis.com/v1/files:annotate?key=${apiKey}`,
        { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(requestBody) }
      );
      const d = await r.json();
      if (d.error) throw new Error(d.error.message);
      return (d.responses?.[0]?.responses || []).map(p => p.fullTextAnnotation?.text || '').filter(Boolean);
    }

    const firstBatch = await visionPages([1,2,3,4,5]);
    if (!firstBatch.length) throw new Error('Vision returned no text for first 5 pages');

    const allText = [...firstBatch];
    const MAX_PAGES = 200;
    let pageNum = 6;

    while (pageNum <= MAX_PAGES) {
      const batch = [pageNum, pageNum+1, pageNum+2, pageNum+3, pageNum+4];
      try {
        const results = await visionPages(batch);
        if (!results.length) break;
        allText.push(...results);
        if (results.length < 5) break;
        pageNum += 5;
        await new Promise(r => setTimeout(r, 300));
      } catch(e) { break; }
    }

    const fullText = allText.join('\n\n--- [page break] ---\n\n');
    const wordCount = fullText.split(/\s+/).filter(w => w.length > 2).length;
    console.log(`Google Vision OCR complete: ${wordCount} words from ${allText.length} pages`);

    if (wordCount < 50) throw new Error('Vision returned insufficient text');
    return { text: fullText, method: 'vision_ocr', pages: allText.length };
  } catch(e) {
    console.error('Google Vision OCR failed:', e.message);
    return null;
  }
}

async function saveSidecarText(storedName, text, uploadsDir) {
  const txtPath = path.join(uploadsDir, 'manuals', storedName + '.txt');
  try {
    fs.mkdirSync(path.dirname(txtPath), { recursive: true });
    fs.writeFileSync(txtPath, text, 'utf8');
  } catch(e) { console.error('[Sidecar] Local write failed:', e.message); }
  if (r2.isEnabled()) {
    await r2.uploadSidecar(storedName, text)
      .catch(e => console.error('[R2] Sidecar upload failed:', e.message));
  }
  return txtPath;
}

function loadSidecarText(storedName, uploadsDir) {
  const txtPath = path.join(uploadsDir, 'manuals', storedName + '.txt');
  if (fs.existsSync(txtPath)) return fs.readFileSync(txtPath, 'utf8');
  return null;
}

// Async version: tries local disk first, then R2
async function loadSidecarTextAsync(storedName, uploadsDir) {
  const local = loadSidecarText(storedName, uploadsDir);
  if (local) return local;
  if (!r2.isEnabled()) return null;
  try {
    const text = await r2.downloadSidecar(storedName);
    // Cache locally so subsequent calls are fast
    const txtPath = path.join(uploadsDir, 'manuals', storedName + '.txt');
    try { fs.mkdirSync(path.dirname(txtPath), { recursive: true }); fs.writeFileSync(txtPath, text, 'utf8'); } catch(e) {}
    return text;
  } catch(e) { return null; }
}

async function categoriseManual(apiKey, { base64, ocrText, filename }) {
  const catList = '"Main Engine","Auxiliary Engine","Cargo System","IGS/Inert Gas","Cargo Compressors","Pumps","Electrical","Navigation","Safety Systems","Fire Fighting","HVAC","Mooring","Crane/Deck Machinery","Boiler","Purifier","Regulatory/SIRE","OEM Service Letter","Maker Bulletin","SMS Procedure","General"';
  const prompt = `You are analysing a ship equipment manual for an LPG gas carrier.
Filename: ${filename}

Return ONLY a valid JSON object (no markdown):
{"category":${catList},"equipment_name":"","maker":"","model":"","rev_date":"","summary":"","sire_chapters":[]}`;

  let msgContent;
  if (ocrText) {
    const snippet = ocrText.substring(0, 8000);
    msgContent = [{ type: 'text', text: 'DOCUMENT TEXT:\n\n' + snippet + '\n\n' + prompt }];
  } else {
    msgContent = [
      { type: 'document', source: { type: 'base64', media_type: 'application/pdf', data: base64 } },
      { type: 'text', text: prompt }
    ];
  }

  const aiRes = await fetch('https://api.anthropic.com/v1/messages', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'x-api-key': apiKey, 'anthropic-version': '2023-06-01' },
    body: JSON.stringify({ model: 'claude-sonnet-4-6', max_tokens: 800, messages: [{ role: 'user', content: msgContent }] })
  });
  const aiData = await aiRes.json();
  if (aiData.error) throw new Error(aiData.error.message);
  const text = (aiData.content||[]).find(c=>c.type==='text')?.text || '{}';
  const clean = text.replace(/```json|```/g,'').trim();
  return JSON.parse(clean);
}

app.get('/api/repo/manuals', requireAuth, (req, res) => {
  try {
    const db = readRepoDb();
    const { vessel_id, category } = req.query;
    let manuals = db.manuals;
    if (vessel_id) manuals = manuals.filter(m => m.vessel_id === vessel_id);
    if (category)  manuals = manuals.filter(m => m.category === category);
    res.json(manuals.sort((a,b) => (b.uploaded_at||'').localeCompare(a.uploaded_at||'')));
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/repo/upload', requireAuth, uploadManual.single('file'), async (req, res) => {
  try {
    if (!req.file) return res.status(400).json({ error: 'No file uploaded' });

    // multer memoryStorage gives us req.file.buffer directly
    const fileBuffer = req.file.buffer;
    const base64     = fileBuffer.toString('base64');

    // Generate a stored filename (same pattern as old diskStorage)
    const safe = req.file.originalname.replace(/[^a-zA-Z0-9._-]/g, '_');
    const storedName = `${Date.now()}_${safe}`;

    // Upload PDF to R2 (non-blocking path if R2 disabled — won't persist, but won't crash)
    let r2Key = null;
    if (r2.isEnabled()) {
      try {
        r2Key = await r2.uploadPdf(storedName, fileBuffer);
        console.log('[R2] PDF uploaded:', r2Key);
      } catch(e) { console.error('[R2] PDF upload failed:', e.message); }
    } else {
      // Fallback: write to disk (Railway ephemeral storage — only for dev)
      const dir = path.join(DATA_DIR, 'uploads', 'manuals');
      fs.mkdirSync(dir, { recursive: true });
      fs.writeFileSync(path.join(dir, storedName), fileBuffer);
    }

    let extractedText = null;
    let extractMethod = 'none';
    try {
      const extracted = await extractPdfText(fileBuffer);
      if (extracted) {
        extractedText = extracted.text;
        extractMethod = extracted.method;
        await saveSidecarText(storedName, extractedText, path.join(DATA_DIR, 'uploads'));
        console.log('Text extracted via', extractMethod, '—', extractedText.length, 'chars');
      }
    } catch(e) { console.error('Text extraction failed:', e.message); }

    let meta = { category: 'General', equipment_link: '', maker: '', model: '', rev_date: '', summary: '', sire_chapters: [] };
    try {
      const parsed = await categoriseManual(process.env.ANTHROPIC_API_KEY, {
        base64: extractedText ? null : base64,
        ocrText: extractedText,
        filename: req.file.originalname
      });
      meta = { ...meta, ...parsed };
      console.log('Categorised as:', meta.category, '/', meta.equipment_name);
    } catch(e) { console.error('AI categorisation failed:', e.message); }

    const db = readRepoDb();
    const manual = {
      id:           'man_' + Date.now().toString(36),
      vessel_id:    req.body.vessel_id || '',
      filename:     req.file.originalname,
      stored_name:  storedName,
      r2_key:       r2Key,
      size_bytes:   req.file.size,
      category:     meta.category || 'General',
      equipment_name: meta.equipment_name || '',
      equipment_id: req.body.equipment_id || '',
      maker:        meta.maker || '',
      model:        meta.model || '',
      rev_date:     meta.rev_date || '',
      summary:      meta.summary || '',
      sire_chapters: meta.sire_chapters || [],
      version:      req.body.version || '1.0',
      superseded:   false,
      text_extracted: !!extractedText,
      extract_method: extractMethod,
      uploaded_by:  req.user.name,
      uploaded_at:  new Date().toISOString(),
      service_letters: []
    };
    db.manuals.push(manual);
    writeRepoDb(db);
    res.json(manual);

    // Index in pgvector asynchronously (non-blocking)
    if (extractedText) {
      setImmediate(() => {
        rag.indexManual(manual, extractedText)
          .then(r => console.log(`[RAG] ${manual.filename}: ${r.ok ? r.chunks + ' chunks indexed' : 'skipped — ' + r.reason}`))
          .catch(e => console.error('[RAG] Index error:', e.message));
      });
    }
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/repo/manuals/:id/reextract', requireAuth, async (req, res) => {
  try {
    const db = readRepoDb();
    const manual = db.manuals.find(m => m.id === req.params.id);
    if (!manual) return res.status(404).json({ error: 'Manual not found' });

    const fp = path.join(DATA_DIR, 'uploads', 'manuals', manual.stored_name);

    // If file is not on disk, try downloading from R2
    let pdfBuffer = null;
    if (!fs.existsSync(fp)) {
      if (r2.isEnabled() && manual.stored_name) {
        try {
          pdfBuffer = await r2.downloadPdf(manual.stored_name);
          console.log('[R2] Downloaded PDF for reextract:', manual.stored_name, pdfBuffer.length, 'bytes');
        } catch(e) {
          return res.status(404).json({ error: 'File not found on disk or R2 — re-upload the manual' });
        }
      } else {
        return res.status(404).json({ error: 'File not found on disk — re-upload the manual' });
      }
    }

    res.json({ message: 'Extraction started', filename: manual.filename });

    (async () => {
      try {
        const inputSource = pdfBuffer || fp;
        const extracted = await extractPdfText(inputSource);
        if (!extracted || !extracted.text) { console.error('Re-extract failed for:', manual.filename); return; }

        await saveSidecarText(manual.stored_name, extracted.text, path.join(DATA_DIR, 'uploads'));

        let meta = {};
        try {
          meta = await categoriseManual(process.env.ANTHROPIC_API_KEY, { ocrText: extracted.text, filename: manual.filename });
        } catch(e) { console.error('Re-categorise failed:', e.message); }

        const db2 = readRepoDb();
        const idx = db2.manuals.findIndex(m => m.id === manual.id);
        if (idx >= 0) {
          db2.manuals[idx] = {
            ...db2.manuals[idx],
            text_extracted: true,
            extract_method: extracted.method,
            ...(meta.category && meta.category !== 'General' ? {
              category: meta.category,
              equipment_name: meta.equipment_name || db2.manuals[idx].equipment_name,
              maker: meta.maker || db2.manuals[idx].maker,
              model: meta.model || db2.manuals[idx].model,
              summary: meta.summary || db2.manuals[idx].summary,
            } : {})
          };
          writeRepoDb(db2);
          console.log('Re-extract complete:', manual.filename, '—', extracted.method, extracted.text.length, 'chars');
          // Re-index in pgvector
          rag.indexManual(db2.manuals[idx], extracted.text)
            .then(r => console.log(`[RAG] Re-index ${manual.filename}: ${r.ok ? r.chunks + ' chunks' : r.reason}`))
            .catch(e => console.error('[RAG] Re-index error:', e.message));
        }
      } catch(e) { console.error('Background re-extract error:', e.message); }
    })();
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/repo/manuals/:id/search-sl', requireAuth, async (req, res) => {
  try {
    const db = readRepoDb();
    const manual = db.manuals.find(m => m.id === req.params.id);
    if (!manual) return res.status(404).json({ error: 'Manual not found' });

    const maker = manual.maker || '';
    const model = manual.model || '';
    const equipment = manual.equipment_name || '';
    if (!maker && !equipment) return res.json({ results: [], message: 'Add maker/equipment name first' });

    const aiRes = await fetch('https://api.anthropic.com/v1/messages', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'x-api-key': process.env.ANTHROPIC_API_KEY, 'anthropic-version': '2023-06-01' },
      body: JSON.stringify({
        model: 'claude-sonnet-4-6', max_tokens: 2000,
        tools: [{ type: 'web_search_20250305', name: 'web_search' }],
        messages: [{ role: 'user', content: `Search for service letters and technical bulletins for: Maker: ${maker}, Model: ${model}, Equipment: ${equipment}. Return ONLY a JSON array: [{"ref":"","title":"","date":"","action":"for_information|action_required|mandatory","summary":"","url":""}]` }]
      })
    });

    const aiData = await aiRes.json();
    if (aiData.error) return res.json({ results: [], message: 'Search failed: ' + aiData.error.message });

    const textBlock = (aiData.content||[]).find(c => c.type === 'text');
    let results = [], raw = '';
    if (textBlock) {
      raw = textBlock.text;
      try {
        const clean = raw.replace(/```json|```/g, '').trim();
        const parsed = JSON.parse(clean);
        results = Array.isArray(parsed) ? parsed : [];
      } catch(e) {}
    }
    res.json({ results, raw: results.length ? '' : raw });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.delete('/api/repo/manuals/:id', requireAuth, (req, res) => {
  try {
    if (!isSuperLevel(req.user.role) && !isCEorMaster(req.user)) return res.status(403).json({ error: 'Forbidden' });
    const db = readRepoDb();
    const manual = db.manuals.find(m => m.id === req.params.id);
    if (!manual) return res.status(404).json({ error: 'Not found' });
    // Remove pgvector embeddings
    rag.deleteManual(manual.id).catch(e => console.error('[RAG] Delete error:', e.message));
    // Delete from R2
    if (r2.isEnabled() && manual.stored_name) {
      r2.deleteManualFiles(manual.stored_name).catch(e => console.error('[R2] Delete error:', e.message));
    }
    // Also clean up local disk if present
    try {
      const fp = path.join(DATA_DIR, 'uploads', 'manuals', manual.stored_name);
      if (fs.existsSync(fp)) fs.unlinkSync(fp);
    } catch(e) {}
    db.manuals = db.manuals.filter(m => m.id !== req.params.id);
    writeRepoDb(db);
    res.json({ ok: true });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.patch('/api/repo/manuals/:id', requireAuth, (req, res) => {
  try {
    if (!isSuperLevel(req.user.role) && !isCEorMaster(req.user)) return res.status(403).json({ error: 'Forbidden' });
    const db = readRepoDb();
    const manual = db.manuals.find(m => m.id === req.params.id);
    if (!manual) return res.status(404).json({ error: 'Not found' });
    Object.assign(manual, req.body, { updated_at: new Date().toISOString() });
    writeRepoDb(db);
    res.json(manual);
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.get('/api/repo/manuals/:id/file', requireAuth, async (req, res) => {
  try {
    const db = readRepoDb();
    const manual = db.manuals.find(m => m.id === req.params.id);
    if (!manual) return res.status(404).json({ error: 'Not found' });

    // Try R2 first (presigned URL redirect)
    if (r2.isEnabled() && manual.stored_name) {
      try {
        const url = await r2.getPresignedUrl(manual.stored_name, 3600);
        return res.redirect(302, url);
      } catch(e) {
        console.error('[R2] Presigned URL failed:', e.message);
        // Fall through to disk fallback
      }
    }

    // Fallback: local disk (dev/ephemeral)
    const fp = path.join(DATA_DIR, 'uploads', 'manuals', manual.stored_name);
    if (!fs.existsSync(fp)) return res.status(404).json({ error: 'File not found — R2 not configured or file missing' });
    res.setHeader('Content-Type', 'application/pdf');
    res.setHeader('Content-Disposition', `inline; filename="${manual.filename}"`);
    fs.createReadStream(fp).pipe(res);
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.get('/api/repo/extract-check', (req, res) => {
  try {
    const db = readRepoDb();
    const name = (req.query.name || '').toLowerCase();
    const manual = name
      ? db.manuals.find(m => m.filename.toLowerCase().includes(name))
      : db.manuals[db.manuals.length - 1];
    if (!manual) return res.json({ error: 'Manual not found', available: db.manuals.map(m => m.filename) });

    const sidecar = loadSidecarText(manual.stored_name, path.join(DATA_DIR, 'uploads'));
    const fp = path.join(DATA_DIR, 'uploads', 'manuals', manual.stored_name);
    const fileExists = fs.existsSync(fp);
    const fileSize = fileExists ? fs.statSync(fp).size : 0;

    res.json({
      filename: manual.filename, manual_id: manual.id,
      text_extracted: manual.text_extracted, extract_method: manual.extract_method,
      file_on_disk: fileExists, file_size_mb: (fileSize / 1024 / 1024).toFixed(1),
      sidecar_exists: !!sidecar, sidecar_chars: sidecar ? sidecar.length : 0,
      sidecar_words: sidecar ? sidecar.split(' ').filter(w => w.length > 2).length : 0,
      sidecar_preview: sidecar ? sidecar.substring(0, 500) : 'NO SIDECAR FILE FOUND'
    });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.get('/api/repo/manuals/:id/extract-status', requireAuth, (req, res) => {
  try {
    const db = readRepoDb();
    const manual = db.manuals.find(m => m.id === req.params.id);
    if (!manual) return res.status(404).json({ error: 'Not found' });

    const sidecar = loadSidecarText(manual.stored_name, path.join(DATA_DIR, 'uploads'));
    const fp = path.join(DATA_DIR, 'uploads', 'manuals', manual.stored_name);
    const fileExists = fs.existsSync(fp);
    const fileSize = fileExists ? fs.statSync(fp).size : 0;

    res.json({
      filename: manual.filename, text_extracted: manual.text_extracted,
      extract_method: manual.extract_method, file_exists: fileExists,
      file_size_mb: (fileSize / 1024 / 1024).toFixed(1),
      sidecar_exists: !!sidecar, sidecar_chars: sidecar ? sidecar.length : 0,
      sidecar_words: sidecar ? sidecar.split(/\s+/).filter(w => w.length > 2).length : 0,
      sidecar_preview: sidecar ? sidecar.substring(0, 300) : null
    });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/repo/search', requireAuth, async (req, res) => {
  try {
    const { vessel_id, category, question, history, is_follow_up } = req.body;
    if (!question) return res.status(400).json({ error: 'question required' });
    if (!process.env.ANTHROPIC_API_KEY) return res.status(500).json({ error: 'API key not configured' });

    const db = readRepoDb();
    let manuals = db.manuals.filter(m => !m.superseded);
    if (vessel_id)                       manuals = manuals.filter(m => m.vessel_id === vessel_id);
    if (category && category !== 'all')  manuals = manuals.filter(m => m.category === category);
    if (!manuals.length) return res.json({ answer: 'No manuals found for this vessel/category.', sources: [] });

    // ── Try pgvector semantic search first ──────────────────────────────────
    const ragChunks = await rag.search(question, { vessel_id, category }).catch(() => null);

    if (ragChunks && ragChunks.length > 0) {
      // ── RAG path: use vector-retrieved chunks ───────────────────────────
      console.log(`[RAG] Vector search: ${ragChunks.length} chunks retrieved for: "${question.substring(0,60)}"`);

      const context = rag.buildContext(ragChunks);

      // Deduplicate source manuals for the sources list
      const sourceMap = {};
      ragChunks.forEach(c => { if (!sourceMap[c.manual_id]) sourceMap[c.manual_id] = c; });
      const sources = Object.values(sourceMap).map(c => ({ id: c.manual_id, filename: c.filename }));

      const systemPrompt = `You are ORACLE, a senior marine engineering expert and technical knowledge assistant for NSML fleet vessels. You answer questions based on the retrieved manual extracts provided. Each extract is labelled [REF N] with its source. Cite references where relevant. If the manuals do not cover the question, say so clearly.`;

      let messages;
      if (is_follow_up && history && history.length >= 2) {
        messages = [
          { role: 'user', content: `MANUAL EXTRACTS:

${context}

First question: "${history[0]?.content || question}"` },
          ...history.slice(1).map(h => ({ role: h.role, content: h.content })),
          { role: 'user', content: `Follow-up: ${question}

Answer concisely based on the extracts and our conversation.` }
        ];
      } else {
        messages = [{
          role: 'user',
          content: `MANUAL EXTRACTS:

${context}

---

Question: "${question}"

Respond in two sections:

**MANUAL SAYS:**
Answer directly from the extracts above. Quote values, steps, or limits exactly. Cite [REF N] where applicable. If not covered write: "Not covered in retrieved manual sections."

**TECHNICAL INSIGHT:**
As a senior marine engineer, expand on the answer — explain the engineering reason, what to check first in practice, and common failure causes. 2–5 sentences.`
        }];
      }

      const aiRes = await fetch('https://api.anthropic.com/v1/messages', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'x-api-key': process.env.ANTHROPIC_API_KEY, 'anthropic-version': '2023-06-01' },
        body: JSON.stringify({ model: 'claude-sonnet-4-6', max_tokens: 2000, system: systemPrompt, messages })
      });
      const aiData = await aiRes.json();
      if (aiData.error) return res.json({ answer: 'AI error: ' + aiData.error.message, sources: [] });

      const answer = (aiData.content||[]).find(c => c.type === 'text')?.text || 'No answer returned';
      return res.json({ answer, sources, rag: true, chunks_used: ragChunks.length });
    }

    // ── Fallback: original keyword + full-text path ─────────────────────────
    console.log(`[RAG] Fallback to keyword search for: "${question.substring(0,60)}"`);

    const qWords = question.toLowerCase().split(/\s+/).filter(w => w.length > 3);
    const scored = manuals.map(m => {
      let score = 0;
      const meta = ((m.filename||'') + ' ' + (m.summary||'') + ' ' + (m.equipment_name||'') + ' ' + (m.maker||'')).toLowerCase();
      qWords.forEach(w => { if (meta.includes(w)) score += 2; });
      if (m.text_extracted) score += 1;
      return { m, score };
    }).sort((a, b) => b.score - a.score);

    const toScan = scored.slice(0, 3).map(s => s.m);
    const contentParts = [];
    const noText = [];

    for (const m of toScan) {
      const sidecar = await loadSidecarTextAsync(m.stored_name, path.join(DATA_DIR, 'uploads'));
      if (sidecar) {
        const MAX_CHARS = 60000;
        let chunk;
        if (sidecar.length <= MAX_CHARS) {
          chunk = sidecar;
        } else {
          const qLower = question.toLowerCase();
          const words = qLower.split(/\s+/).filter(w => w.length > 3);
          const sideLower = sidecar.toLowerCase();
          const WINDOW = MAX_CHARS;
          const STEP = 5000;
          let bestScore = -1, bestStart = 0;
          for (let pos = 0; pos < sidecar.length - WINDOW; pos += STEP) {
            const window = sideLower.substring(pos, pos + WINDOW);
            let score = 0;
            words.forEach(w => { let idx = 0; while ((idx = window.indexOf(w, idx)) !== -1) { score++; idx++; } });
            if (score > bestScore) { bestScore = score; bestStart = pos; }
          }
          const header = sidecar.substring(0, 1000);
          const body = sidecar.substring(bestStart, bestStart + WINDOW - 1000);
          chunk = bestStart > 1000 ? header + '\n\n[... pages skipped ...]\n\n' + body : sidecar.substring(0, WINDOW);
        }
        contentParts.push({ type: 'text', text: '=== ' + m.filename + ' ===\n' + chunk });
        continue;
      }
      try {
        const fp = path.join(DATA_DIR, 'uploads', 'manuals', m.stored_name);
        if (fs.existsSync(fp)) {
          const stat = fs.statSync(fp);
          if (stat.size < 10 * 1024 * 1024) {
            const b64 = fs.readFileSync(fp).toString('base64');
            contentParts.push({ type: 'document', source: { type: 'base64', media_type: 'application/pdf', data: b64 }, title: m.filename });
            continue;
          }
        }
      } catch(e) { console.error('Error reading:', e.message); }
      noText.push(m.filename);
    }

    if (!contentParts.length) {
      return res.json({
        answer: noText.length
          ? '⚠ Text not extracted yet for: ' + noText.join(', ') + '\n\nClick the amber ⚙ Extract button on the manual card first, wait ~30 seconds, then ask again.'
          : 'Could not read manual files.',
        sources: []
      });
    }

    contentParts.push({ type: 'text', text: `You are a senior marine engineer answering a question from an officer or engineer onboard.\n\nQuestion: "${question}"\n\nRespond in exactly two sections:\n\n**MANUAL SAYS:**\nSearch the manual content above and extract the relevant answer. Be specific — reproduce exact steps, values, or fault tables if present. If not covered, write: "Not covered in this manual." Cite the section or page reference if visible.\n\n**TECHNICAL INSIGHT:**\nGive your own expert explanation as a senior marine engineer. Expand on the manual answer — explain the underlying reason why, what to check first in practice, common causes or mistakes. 2-5 sentences.` });

    let messages;
    if (is_follow_up && history && history.length >= 2) {
      const firstUserContent = [...contentParts];
      firstUserContent[firstUserContent.length - 1] = {
        type: 'text',
        text: firstUserContent[firstUserContent.length - 1].text
          .replace('Question: "' + question + '"', 'Question: "' + (history[0]?.content || question) + '"')
      };
      messages = [{ role: 'user', content: firstUserContent }];
      for (let i = 1; i < history.length; i++) {
        messages.push({ role: history[i].role, content: history[i].content });
      }
      messages.push({ role: 'user', content: 'Follow-up question: ' + question + '\n\nAnswer based on the manual content and our conversation so far. Be concise and direct.' });
    } else {
      messages = [{ role: 'user', content: contentParts }];
    }

    const aiRes = await fetch('https://api.anthropic.com/v1/messages', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'x-api-key': process.env.ANTHROPIC_API_KEY, 'anthropic-version': '2023-06-01' },
      body: JSON.stringify({ model: 'claude-sonnet-4-6', max_tokens: 2000, messages })
    });
    const aiData = await aiRes.json();
    if (aiData.error) return res.json({ answer: 'AI error: ' + aiData.error.message, sources: [] });

    const answer = (aiData.content||[]).find(c => c.type === 'text')?.text || 'No answer returned';
    const sources = toScan.filter((m,i) => contentParts[i]).map(m => ({ id: m.id, filename: m.filename }));
    res.json({ answer, sources, rag: false });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// ── RAG stats endpoint (admin) ────────────────────────────────────────────
app.get('/api/rag/stats', requireAuth, async (req, res) => {
  try {
    const stats = await rag.getStats();
    res.json(stats);
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// ── Manually trigger indexing for an existing manual ─────────────────────
app.post('/api/rag/index/:id', requireAuth, async (req, res) => {
  try {
    const db     = readRepoDb();
    const manual = db.manuals.find(m => m.id === req.params.id);
    if (!manual) return res.status(404).json({ error: 'Manual not found' });

    const sidecar = await loadSidecarTextAsync(manual.stored_name, path.join(DATA_DIR, 'uploads'));
    if (!sidecar) return res.status(400).json({ error: 'No extracted text — run ⚙ Extract first' });

    res.json({ message: 'Indexing started', filename: manual.filename });

    setImmediate(() => {
      rag.indexManual(manual, sidecar)
        .then(r => console.log(`[RAG] Manual index trigger: ${manual.filename} — ${r.ok ? r.chunks + ' chunks' : r.reason}`))
        .catch(e => console.error('[RAG] Manual index error:', e.message));
    });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// ── Bulk index all extracted manuals (admin only) ─────────────────────────
app.post('/api/rag/index-all', requireAuth, async (req, res) => {
  if (req.user.role !== 'admin') return res.status(403).json({ error: 'Admin only' });
  try {
    const db = readRepoDb();
    const toIndex = db.manuals.filter(m => m.text_extracted && !m.superseded);
    res.json({ message: `Bulk indexing started for ${toIndex.length} manuals`, count: toIndex.length });

    (async () => {
      let ok = 0, fail = 0;
      for (const manual of toIndex) {
        const sidecar = await loadSidecarTextAsync(manual.stored_name, path.join(DATA_DIR, 'uploads'));
        if (!sidecar) { fail++; continue; }
        const r = await rag.indexManual(manual, sidecar).catch(() => ({ ok: false }));
        r.ok ? ok++ : fail++;
        await new Promise(resolve => setTimeout(resolve, 500)); // rate limit
      }
      console.log(`[RAG] Bulk index complete: ${ok} ok, ${fail} failed`);
    })();
  } catch(e) { res.status(500).json({ error: e.message }); }
});


app.post('/api/repo/suggest-for-defect', requireAuth, async (req, res) => {
  try {
    const { vessel_id, equipment_name, defect_title } = req.body;
    const db = readRepoDb();
    let manuals = db.manuals.filter(m => !m.superseded);
    if (vessel_id) manuals = manuals.filter(m => m.vessel_id === vessel_id);
    if (!manuals.length) return res.json({ suggestions: [] });

    const eq = (equipment_name||'').toLowerCase();
    const dt = (defect_title||'').toLowerCase();
    const scored = manuals.map(m => {
      let score = 0;
      if (eq && m.equipment_name && m.equipment_name.toLowerCase().includes(eq)) score += 3;
      if (eq && m.filename.toLowerCase().includes(eq.split(' ')[0])) score += 2;
      if (dt && m.summary && m.summary.toLowerCase().split(' ').some(w => w.length > 4 && dt.includes(w))) score += 1;
      return { ...m, _score: score };
    }).filter(m => m._score > 0).sort((a,b) => b._score - a._score).slice(0, 4);

    res.json({ suggestions: scored });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// ══════════════════════════════════════════════════════
// PMS MODULE
// ══════════════════════════════════════════════════════

const PMS_EQUIP_PATH = fs.existsSync(path.join(DATA_DIR,'equipment_register.json'))
  ? path.join(DATA_DIR,'equipment_register.json')
  : path.join(__dirname,'equipment_register.json');
const PMS_STATS_PATH = fs.existsSync(path.join(DATA_DIR,'pms_stats.json'))
  ? path.join(DATA_DIR,'pms_stats.json')
  : path.join(__dirname,'pms_stats.json');

// [readDB/writeDB moved to db.js — block 4]

app.get('/api/pms/overview', requireAuth, (req, res) => {
  try {
    const pms = readPmsDb();
    const vessels = readDB().vessels || [];
    const stats = fs.existsSync(PMS_STATS_PATH) ? JSON.parse(fs.readFileSync(PMS_STATS_PATH, 'utf8')) : {};

    const vesselStats = vessels.map(v => {
      const ws = pms.worksheets.filter(w => w.vessel_id === v.id);
      const now = new Date();
      const msMonth = 30*24*3600*1000;
      const overdueWs = ws.filter(w => ['issued','wip','returned'].includes(w.status) && w.due_date && new Date(w.due_date) < now);
      const overdue1 = overdueWs.filter(w => (now - new Date(w.due_date)) >= msMonth).length;
      const overdue2 = overdueWs.filter(w => (now - new Date(w.due_date)) >= 2*msMonth).length;
      const overdue3 = overdueWs.filter(w => (now - new Date(w.due_date)) >= 3*msMonth).length;
      const issued = ws.filter(w => w.status === 'issued').length;
      const wip = ws.filter(w => w.status === 'wip').length;
      const awaiting = ws.filter(w => w.status === 'awaiting_auth').length;
      const deferred = ws.filter(w => w.status === 'deferred').length;
      const total_sig = ws.filter(w => ['Standard','Significant'].includes(w.criticality)).length;
      const tmsa_pct = total_sig > 0 ? ((overdue1 / total_sig) * 100).toFixed(1) : '0.0';
      const statKey = Object.keys(stats).find(k =>
        k.toLowerCase().includes(v.name.toLowerCase().split(' ')[0]) ||
        v.name.toLowerCase().includes(k.toLowerCase().split(' ')[0])
      );
      const hist = statKey ? stats[statKey] : {};
      return {
        vessel_id: v.id, vessel_name: v.name, vessel_type: v.vessel_type || 'LNG-DFDE',
        issued, wip, awaiting, deferred,
        overdue_1m: overdue1, overdue_2m: overdue2, overdue_3m: overdue3,
        tmsa_pct: parseFloat(tmsa_pct),
        historical_total: hist.total_records || 0,
        historical_adhoc: hist.adhoc_count || 0,
        failure_hotspots: hist.failure_hotspots || []
      };
    });

    const totals = vesselStats.reduce((acc, v) => ({
      issued: acc.issued + v.issued, wip: acc.wip + v.wip,
      awaiting: acc.awaiting + v.awaiting, deferred: acc.deferred + v.deferred,
      overdue_1m: acc.overdue_1m + v.overdue_1m, overdue_2m: acc.overdue_2m + v.overdue_2m,
      overdue_3m: acc.overdue_3m + v.overdue_3m,
    }), { issued:0, wip:0, awaiting:0, deferred:0, overdue_1m:0, overdue_2m:0, overdue_3m:0 });

    res.json({ vessels: vesselStats, totals, historical_records: 119357 });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.get('/api/pms/equipment/all', requireAuth, (req, res) => {
  try {
    const { vessel_name } = req.query;
    if (!fs.existsSync(PMS_EQUIP_PATH)) return res.json([]);
    const register = JSON.parse(fs.readFileSync(PMS_EQUIP_PATH, 'utf8'));
    const vesselData = register[vessel_name];
    if (!vesselData) return res.json({ vessels: Object.keys(register) });
    const comps = (vesselData.components || []).map(c => ({
      code: c.code, description: c.description, primary_role: c.primary_role,
      criticality: c.criticality, frequency: c.frequency,
    }));
    res.json(comps);
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.get('/api/pms/equipment', requireAuth, (req, res) => {
  try {
    const { vessel_name, search, criticality, role, page = 1, limit = 50 } = req.query;
    if (!fs.existsSync(PMS_EQUIP_PATH)) return res.json({ components: [], total: 0 });
    const register = JSON.parse(fs.readFileSync(PMS_EQUIP_PATH, 'utf8'));
    const vesselData = register[vessel_name];
    if (!vesselData) return res.json({ components: [], total: 0, vessels: Object.keys(register) });

    let comps = vesselData.components || [];
    if (search) { const s = search.toLowerCase(); comps = comps.filter(c => c.code.toLowerCase().includes(s) || c.description.toLowerCase().includes(s)); }
    if (criticality && criticality !== 'all') comps = comps.filter(c => c.criticality === criticality);
    if (role && role !== 'all') comps = comps.filter(c => c.primary_role === role);

    const total = comps.length;
    const start = (parseInt(page) - 1) * parseInt(limit);
    const paginated = comps.slice(start, start + parseInt(limit));
    const roles = [...new Set((vesselData.components || []).map(c => c.primary_role))].sort();

    res.json({ components: paginated, total, page: parseInt(page), limit: parseInt(limit), roles, vessel_type: vesselData.vessel_type });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.get('/api/pms/vessels', requireAuth, (req, res) => {
  try {
    if (!fs.existsSync(PMS_EQUIP_PATH)) return res.json([]);
    const register = JSON.parse(fs.readFileSync(PMS_EQUIP_PATH, 'utf8'));
    const vessels = Object.entries(register).map(([name, data]) => ({
      name, vessel_type: data.vessel_type, component_count: (data.components || []).length
    }));
    res.json(vessels);
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/pms/issue-month', requireAuth, (req, res) => {
  try {
    const { vessel_name, year, month } = req.body;
    if (!vessel_name || !year || !month) return res.status(400).json({ error: 'vessel_name, year, month required' });
    if (!fs.existsSync(PMS_EQUIP_PATH)) return res.status(404).json({ error: 'Equipment register not found' });

    const register = JSON.parse(fs.readFileSync(PMS_EQUIP_PATH, 'utf8'));
    const vesselData = register[vessel_name];
    if (!vesselData) return res.status(404).json({ error: 'Vessel not found: ' + vessel_name });

    const components = vesselData.components || [];

    function isDue(freqStr, y, m) {
      if (!freqStr) return false;
      const match = freqStr.match(/(\d+)\s*Month/);
      if (!match) return false;
      const interval = parseInt(match[1]);
      const absMonth = (y - 2020) * 12 + (m - 1);
      return absMonth % interval === 0;
    }

    const dueComponents = components.filter(c => isDue(c.frequency, parseInt(year), parseInt(month)));
    if (!dueComponents.length) return res.json({ issued: 0, message: 'No components due this month' });

    const dueDate = new Date(year, month, 0).toISOString().split('T')[0];
    const pms = readPmsDb();
    const existing = new Set(
      pms.worksheets
        .filter(w => w.vessel_name === vessel_name && w.due_date && w.due_date.startsWith(`${year}-${String(month).padStart(2,'0')}`))
        .map(w => w.component_code)
    );

    let issued = 0;
    const newWs = [];
    dueComponents.forEach(c => {
      if (existing.has(c.code)) return;
      const ws = {
        id: 'ws_' + Date.now() + '_' + Math.random().toString(36).slice(2,6),
        vessel_name, component_code: c.code,
        component_description: c.description,
        short_description: `${c.frequency} planned maintenance`,
        full_description: '',
        assigned_role: c.primary_role || '2nd Eng',
        criticality: c.criticality || 'Standard',
        due_date: dueDate, type: 'planned', frequency: c.frequency, status: 'issued',
        created_at: new Date().toISOString(), created_by: req.user.name,
        history: [{ action: 'issued', by: req.user.name, at: new Date().toISOString(), note: 'Bulk issued for ' + month + '/' + year }]
      };
      pms.worksheets.push(ws);
      newWs.push(ws);
      issued++;
    });

    savePmsDb(pms);
    res.json({ issued, skipped: dueComponents.length - issued, total_due: dueComponents.length, worksheets: newWs });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.get('/api/pms/worksheets', requireAuth, (req, res) => {
  try {
    const { vessel_id, vessel_name, status, role, criticality } = req.query;
    const pms = readPmsDb();
    let ws = pms.worksheets || [];
    if (vessel_id && vessel_id !== 'all') ws = ws.filter(w => w.vessel_id === vessel_id);
    if (vessel_name && vessel_name !== 'all') ws = ws.filter(w => w.vessel_name === vessel_name);
    if (status && status !== 'all') ws = ws.filter(w => w.status === status);
    if (role && role !== 'all') ws = ws.filter(w => w.assigned_role === role);
    if (criticality && criticality !== 'all') ws = ws.filter(w => w.criticality === criticality);
    res.json(ws.sort((a, b) => new Date(b.created_at) - new Date(a.created_at)));
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/pms/worksheets', requireAuth, (req, res) => {
  try {
    const pms = readPmsDb();
    const ws = {
      id: 'ws_' + Date.now(), ...req.body, status: 'issued',
      created_at: new Date().toISOString(), created_by: req.user.name,
      history: [{ action: 'issued', by: req.user.name, at: new Date().toISOString() }]
    };
    pms.worksheets.push(ws);
    savePmsDb(pms);
    res.json(ws);
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.put('/api/pms/worksheets/:id', requireAuth, (req, res) => {
  try {
    const pms = readPmsDb();
    const idx = pms.worksheets.findIndex(w => w.id === req.params.id);
    if (idx === -1) return res.status(404).json({ error: 'Not found' });
    const action = req.body.action;
    const ws = { ...pms.worksheets[idx], ...req.body };
    ws.updated_at = new Date().toISOString();
    ws.history = ws.history || [];

    if (action === 'start') ws.status = 'wip';
    else if (action === 'complete') { ws.status = 'awaiting_auth'; ws.completed_at = new Date().toISOString(); }
    else if (action === 'authorise') { ws.status = 'authorised'; ws.authorised_at = new Date().toISOString(); ws.authorised_by = req.user.name; }
    else if (action === 'return') { ws.status = 'returned'; ws.returned_reason = req.body.reason; }
    else if (action === 'defer') { ws.status = 'deferred'; ws.defer_until = req.body.defer_until; ws.defer_reason = req.body.defer_reason; }

    ws.history.push({ action: action || 'updated', by: req.user.name, at: new Date().toISOString(), note: req.body.note || '' });
    pms.worksheets[idx] = ws;
    savePmsDb(pms);
    res.json(ws);
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.get('/api/pms/running-hours', requireAuth, (req, res) => {
  try {
    const { vessel_id, vessel_name } = req.query;
    const pms = readPmsDb();
    let rh = pms.running_hours || [];
    if (vessel_id) rh = rh.filter(r => r.vessel_id === vessel_id);
    if (vessel_name) rh = rh.filter(r => r.vessel_name === vessel_name);
    res.json(rh.sort((a,b) => new Date(a.recorded_at)-new Date(b.recorded_at)));
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/pms/running-hours', requireAuth, (req, res) => {
  try {
    const pms = readPmsDb();
    const { vessel_id, component_code, assembly_name, new_reading, previous_reading } = req.body;
    const hours_run = new_reading - (previous_reading || 0);
    const entry = {
      id: 'rh_' + Date.now(), vessel_id, component_code, assembly_name,
      previous_reading: previous_reading || 0, new_reading, hours_run,
      recorded_at: new Date().toISOString(), recorded_by: req.user.name
    };
    pms.running_hours.push(entry);
    savePmsDb(pms);
    res.json(entry);
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.get('/api/pms/defects', requireAuth, (req, res) => {
  try {
    const { vessel_id, vessel_name, status } = req.query;
    const pms = readPmsDb();
    let d = pms.defects || [];
    if (vessel_id) d = d.filter(x => x.vessel_id === vessel_id);
    if (vessel_name) d = d.filter(x => x.vessel_name === vessel_name);
    if (status && status !== 'all') d = d.filter(x => x.status === status);
    res.json(d.sort((a, b) => new Date(b.raised_at) - new Date(a.raised_at)));
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/pms/defects', requireAuth, (req, res) => {
  try {
    const pms = readPmsDb();
    const defect = {
      id: 'def_' + Date.now(), ...req.body,
      status: 'open', raised_at: new Date().toISOString(),
      raised_by: req.user.name, updates: []
    };
    pms.defects.push(defect);
    savePmsDb(pms);
    res.json(defect);
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.put('/api/pms/defects/:id', requireAuth, (req, res) => {
  try {
    const pms = readPmsDb();
    const idx = pms.defects.findIndex(d => d.id === req.params.id);
    if (idx === -1) return res.status(404).json({ error: 'Not found' });
    pms.defects[idx] = { ...pms.defects[idx], ...req.body, updated_at: new Date().toISOString() };
    if (req.body.update_note) {
      pms.defects[idx].updates.push({ note: req.body.update_note, by: req.user.name, at: new Date().toISOString() });
    }
    savePmsDb(pms);
    res.json(pms.defects[idx]);
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.get('/api/pms/history', requireAuth, (req, res) => {
  try {
    const { vessel_name, search, component, page = 1, limit = 30 } = req.query;
    const pms = readPmsDb();
    let records = (pms.worksheets || []).filter(w => w.status === 'authorised');
    if (vessel_name) records = records.filter(r => r.vessel_name === vessel_name);
    if (search) { const s = search.toLowerCase(); records = records.filter(r => (r.description||'').toLowerCase().includes(s) || (r.component_code||'').toLowerCase().includes(s)); }
    if (component) records = records.filter(r => (r.component_code||'').startsWith(component));
    const total = records.length;
    const start = (parseInt(page)-1) * parseInt(limit);
    res.json({ records: records.slice(start, start+parseInt(limit)), total, page: parseInt(page) });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.get('/api/pms/stats', requireAuth, (req, res) => {
  try {
    if (!fs.existsSync(PMS_STATS_PATH)) return res.json({});
    res.json(JSON.parse(fs.readFileSync(PMS_STATS_PATH, 'utf8')));
  } catch(e) { res.status(500).json({ error: e.message }); }
});

