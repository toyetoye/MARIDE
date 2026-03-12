const express = require('express');
const cors = require('cors');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');
const multer = require('multer');

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
// Uses /data (Render mounted disk) in production, falls back to __dirname locally
const DATA_DIR = (() => {
  if (process.env.DATA_DIR) return process.env.DATA_DIR;
  if (fs.existsSync('/data')) return '/data';
  return __dirname;
})();
const DB_PATH = path.join(DATA_DIR, 'maride.json');

// Ensure upload directory exists
fs.mkdirSync(path.join(DATA_DIR, 'uploads', 'manuals'), { recursive: true });
console.log('Storage path:', DATA_DIR);

// Bootstrap PMS static data files to DATA_DIR (so they survive on Render persistent disk)
['equipment_register.json','pms_stats.json'].forEach(fname => {
  const dest = path.join(DATA_DIR, fname);
  const src  = path.join(__dirname, fname);
  if (!fs.existsSync(dest) && fs.existsSync(src)) {
    try { fs.copyFileSync(src, dest); console.log('PMS bootstrap:', fname); } catch(e) { console.error('PMS bootstrap failed:', fname, e.message); }
  }
});

function readDB() {
  try {
    if (fs.existsSync(DB_PATH)) return JSON.parse(fs.readFileSync(DB_PATH,'utf8'));
  } catch(e) { console.error('DB read error:', e.message); }
  return { users: [], vessels: [], investigations: [], sessions: [] };
}

function writeDB(data) {
  try { fs.writeFileSync(DB_PATH, JSON.stringify(data, null, 2)); }
  catch(e) { console.error('DB write error:', e.message); }
}

// Seed default admin if no users exist
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
// Handle preflight for all routes
app.options('*', cors());
app.use(express.json({ limit: '20mb' }));

// ── Subdomain routing — custodian.forcap.io is now a separate static site ──

app.use(express.static('public'));

// ── Auth middleware ────────────────────────────────────────────────────────
function requireAuth(req, res, next) {
  const token = req.headers['x-auth-token'] || req.query.token;  // allow ?token= for file downloads
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

// ── Health ─────────────────────────────────────────────────────────────────
app.get('/health', (req, res) => {
  const db = readDB();
  res.json({ status: 'ok', users: db.users.length, vessels: db.vessels.length, investigations: db.investigations.length });
});

// ══════════════════════════════════════════════════════
// AUTH ROUTES
// ══════════════════════════════════════════════════════

// Login
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
  // Keep sessions clean — max 10 per user
  db.sessions = db.sessions.filter(s => {
    const age = Date.now() - new Date(s.created_at).getTime();
    return age < 7 * 24 * 60 * 60 * 1000; // 7 days
  });
  writeDB(db);
  const { password: _, ...safeUser } = user;
  res.json({ token, user: safeUser });
});

// Logout
app.post('/api/auth/logout', requireAuth, (req, res) => {
  const token = req.headers['x-auth-token'];
  const db = readDB();
  db.sessions = db.sessions.filter(s => s.token !== token);
  writeDB(db);
  res.json({ ok: true });
});

// Me
app.get('/api/auth/me', requireAuth, (req, res) => {
  const { password, ...safeUser } = req.user;
  res.json(safeUser);
});

// ══════════════════════════════════════════════════════
// USER ROUTES (admin only)
// ══════════════════════════════════════════════════════

app.get('/api/users', requireAuth, (req, res) => {
  if (!isSuperLevel(req.user.role)) return res.status(403).json({error:'Forbidden'});
  const db = readDB();
  res.json(db.users.map(({ password, ...u }) => u));
});

// Vessel-scoped crew list (CE/Master can fetch crew for their vessel without full admin)
app.get('/api/custodian/vessel-crew', requireAuth, (req, res) => {
  try {
    const vesselId = req.query.vessel_id;
    if (!vesselId) return res.status(400).json({ error: 'vessel_id required' });
    const db = readDB();
    // Only return users assigned to this vessel, strip passwords
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
  // Others see only their assigned vessels
  const vessels = db.vessels.filter(v => (req.user.vessel_ids || []).includes(v.id));
  res.json(vessels);
});

function syncSuperintendentVessel(db, vesselId, superintendentId) {
  // Add this vessel to the superintendent's vessel_ids so they can see its investigations
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
    // If superintendent changed, sync vessel access
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

// ══════════════════════════════════════════════════════
// INVESTIGATION ROUTES (auth + role-filtered)
// ══════════════════════════════════════════════════════

// Role helpers
function isFleetLevel(role) {
  return ['admin','fleet_manager','deputy_fleet_manager'].includes(role);
}
function isSuperLevel(role) {
  return ['admin','superintendent','fleet_manager','deputy_fleet_manager'].includes(role);
}
function isShipStaff(role) {
  return ['ship_staff','investigator'].includes(role);
}

function filterInvestigations(investigations, user, vessels) {
  if (isFleetLevel(user.role)) return investigations;  // see all
  if (user.role === 'superintendent') {
    const myVesselIds = (user.vessel_ids || []);
    return investigations.filter(i => myVesselIds.includes(i.vessel_id) || i.created_by === user.id);
  }
  // ship_staff / investigator — own only
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

// Approve investigation + send email
app.post('/api/investigations/:id/approve', requireAuth, requireRole('superintendent','admin'), async (req, res) => {
  try {
    const db = readDB();
    const inv = db.investigations.find(i => i.id === req.params.id);
    if (!inv) return res.status(404).json({ error: 'Not found' });

    // Mark approved + closed
    inv.status = 'closed';
    inv.approved_by = req.user.id;
    inv.approved_by_name = req.user.name;
    inv.approved_at = new Date().toISOString();
    writeDB(db);

    // Build recipient list
    const vessel = db.vessels.find(v => v.name === inv.vessel || v.id === inv.vessel_id);
    const investigator = db.users.find(u => u.id === inv.created_by);
    const superintendent = db.users.find(u => u.id === req.user.id);

    const recipients = [];
    if (investigator?.email) recipients.push({ name: investigator.name, email: investigator.email, role: 'Investigator' });
    if (superintendent?.email && superintendent.id !== investigator?.id) {
      recipients.push({ name: superintendent.name, email: superintendent.email, role: 'Superintendent' });
    }
    if (vessel?.dpa_name) {
      // DPA may not have a login — use DPA email from vessel if set
      if (vessel.dpa_email) recipients.push({ name: vessel.dpa_name, email: vessel.dpa_email, role: 'DPA' });
    }

    if (!recipients.length) {
      return res.json({ ok: true, approved: true, emailsSent: 0, warning: 'No recipients with email addresses found' });
    }

    // PDF is generated client-side and sent as base64 in the request
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

    // Extract key findings from saved state
    const state = inv.state_json ? JSON.parse(inv.state_json) : {};
    const topCauses = state.topCauses || [];
    const flagged   = state.flagged   || [];
    const answers   = state.answers   || {};
    const questions = state.questions || [];

    // Build top causes rows
    const causesRows = topCauses.slice(0,3).map((c,i) => `
      <tr>
        <td style="padding:7px 12px;font-size:12px;color:#333;">#${i+1}</td>
        <td style="padding:7px 12px;font-size:12px;color:#333;font-weight:${i===0?'700':'400'};">${c.name}</td>
        <td style="padding:7px 12px;font-size:12px;color:#f5a623;font-family:monospace;font-weight:700;">${c.score}</td>
      </tr>`).join('');

    // Corrective actions from decision content (pull NO answers as deficiencies)
    const deficiencies = flagged.slice(0,5).map(f => `<li style="margin-bottom:6px;font-size:12px;color:#333;">${f}</li>`).join('');

    // Root cause and immediate cause from state
    const immCause  = state.immCause  || '—';
    const rootCause = state.rootCause || (topCauses[0]?.name || '—');
    const contrib   = state.contrib   || '—';

    const emailHtml = `
<!DOCTYPE html>
<html>
<head><meta charset="UTF-8">
<style>
  * { margin:0; padding:0; box-sizing:border-box; }
  body { font-family: Arial, sans-serif; background: #f0f2f5; padding: 24px; }
  .wrap { max-width: 620px; margin: 0 auto; }
  .header { background: #0a0d12; padding: 24px 32px; border-radius: 8px 8px 0 0; }
  .logo { color: #f5a623; font-size: 20px; font-weight: 900; letter-spacing: 4px; font-family: monospace; }
  .logo-sub { color: #5a6a82; font-size: 9px; letter-spacing: 2.5px; margin-top: 3px; font-family: monospace; text-transform: uppercase; }
  .body { background: #fff; padding: 28px 32px; }
  .footer { background: #f9f9f9; padding: 16px 32px; border-top: 1px solid #eee; font-size: 11px; color: #999; text-align: center; border-radius: 0 0 8px 8px; }
  .ref { font-family: monospace; font-size: 11px; color: #f5a623; letter-spacing: 1px; margin-bottom: 6px; }
  h1 { font-size: 20px; color: #0a0d12; margin-bottom: 4px; }
  .subtitle { font-size: 12px; color: #888; margin-bottom: 20px; }
  .approved-box { background: #e6f7ef; border-left: 4px solid #1a7a45; border-radius: 0 6px 6px 0; padding: 12px 16px; margin-bottom: 24px; font-size: 13px; color: #1a7a45; font-weight: 600; }
  .section-title { font-size: 10px; font-family: monospace; letter-spacing: 2px; text-transform: uppercase; color: #f5a623; margin: 24px 0 10px; border-bottom: 1px solid #f0f0f0; padding-bottom: 6px; }
  .details-grid { display: table; width: 100%; border-collapse: collapse; margin-bottom: 4px; }
  .detail-row { display: table-row; }
  .detail-label { display: table-cell; font-size: 10px; color: #999; text-transform: uppercase; letter-spacing: 1px; padding: 5px 16px 5px 0; vertical-align: top; white-space: nowrap; width: 130px; }
  .detail-value { display: table-cell; font-size: 13px; color: #222; padding: 5px 0; font-weight: 500; }
  .sev-pill { display: inline-block; padding: 2px 10px; border-radius: 3px; font-size: 11px; font-weight: 700; background: ${sevBg}; color: ${sevColor}; }
  .desc-box { background: #fafafa; border: 1px solid #eee; border-radius: 6px; padding: 12px 16px; font-size: 12px; color: #444; line-height: 1.6; margin-bottom: 4px; }
  .causes-table { width: 100%; border-collapse: collapse; font-size: 12px; }
  .causes-table th { background: #f5f5f5; padding: 7px 12px; text-align: left; font-size: 10px; color: #999; letter-spacing: 1px; text-transform: uppercase; }
  .causes-table tr:nth-child(even) td { background: #fafafa; }
  .cause-box { background: #fff7e6; border-left: 3px solid #f5a623; padding: 10px 14px; border-radius: 0 4px 4px 0; font-size: 12px; color: #333; margin-bottom: 8px; }
  .cause-box strong { color: #b35c00; font-size: 10px; display: block; letter-spacing: 1px; text-transform: uppercase; margin-bottom: 3px; }
  ul { padding-left: 20px; }
  .attach-note { background: #f0f2f5; border-radius: 6px; padding: 12px 16px; font-size: 12px; color: #555; display: flex; align-items: center; gap: 10px; margin-top: 20px; }
</style>
</head>
<body>
<div class="wrap">
  <div class="header">
    <div class="logo">M∆ MARIDE</div>
    <div class="logo-sub">Maritime Incident Decision Engine</div>
  </div>
  <div class="body">
    <div class="ref">${inv.ref_num || ''}</div>
    <h1>Investigation Report Approved</h1>
    <div class="subtitle">${inv.vessel || 'Unknown Vessel'} · ${inv.type || 'Incident'} · ${inv.inc_date ? inv.inc_date.substring(0,10) : '—'}</div>

    <div class="approved-box">✓ Approved by ${req.user.name} &nbsp;·&nbsp; ${new Date().toUTCString()}</div>

    <!-- INCIDENT DETAILS -->
    <div class="section-title">Incident Details</div>
    <div class="details-grid">
      <div class="detail-row"><div class="detail-label">Vessel</div><div class="detail-value">${inv.vessel || '—'}</div></div>
      <div class="detail-row"><div class="detail-label">Incident Type</div><div class="detail-value">${inv.type || '—'}</div></div>
      <div class="detail-row"><div class="detail-label">Severity</div><div class="detail-value"><span class="sev-pill">${sevLabel}</span></div></div>
      <div class="detail-row"><div class="detail-label">Location / Port</div><div class="detail-value">${inv.location || '—'}</div></div>
      <div class="detail-row"><div class="detail-label">Date / Time</div><div class="detail-value">${inv.inc_date ? inv.inc_date.substring(0,16).replace('T',' ') + ' UTC' : '—'}</div></div>
      <div class="detail-row"><div class="detail-label">Investigator</div><div class="detail-value">${inv.created_by_name || '—'}</div></div>
      <div class="detail-row"><div class="detail-label">Approved By</div><div class="detail-value">${req.user.name}</div></div>
    </div>

    <!-- DESCRIPTION -->
    <div class="section-title">What Happened</div>
    <div class="desc-box">${inv.description || '—'}</div>

    ${topCauses.length ? `
    <!-- ROOT CAUSE ANALYSIS -->
    <div class="section-title">Root Cause Analysis</div>
    <div class="cause-box"><strong>Immediate Cause</strong>${immCause}</div>
    <div class="cause-box"><strong>Root Cause</strong>${rootCause}</div>
    ${contrib !== '—' ? `<div class="cause-box"><strong>Contributing Factors</strong>${contrib}</div>` : ''}

    <div class="section-title">Evidence Scoring — Top Causes</div>
    <table class="causes-table">
      <thead><tr><th>Rank</th><th>Cause</th><th>Score</th></tr></thead>
      <tbody>${causesRows || '<tr><td colspan="3" style="padding:10px;color:#999;text-align:center;">No scoring data</td></tr>'}</tbody>
    </table>` : ''}

    ${deficiencies ? `
    <!-- FLAGGED DEFICIENCIES -->
    <div class="section-title">Flagged Deficiencies</div>
    <ul>${deficiencies}</ul>` : ''}

    <!-- ATTACHMENT NOTE -->
    <div class="attach-note">
      📎 <span>The <strong>full investigation report</strong> is attached as a PDF, including all investigation questions, answers, evidence notes, and corrective action recommendations.</span>
    </div>

    <div style="margin-top:20px;font-size:11px;color:#aaa;">Recipients: ${recipientNames}</div>
  </div>
  <div class="footer">MARIDE · Maritime Incident Decision Engine &nbsp;·&nbsp; Confidential — For Internal Use Only</div>
</div>
</body>
</html>`;

    const attachments = pdfBase64 ? [{
      filename: `MARIDE_${inv.ref_num || 'report'}_${(inv.vessel || 'vessel').replace(/\s+/g,'_')}.pdf`,
      content: pdfBase64
    }] : [];

    await sendEmail({
      to: toAddresses,
      subject: `[MARIDE] ${inv.ref_num || 'Report'} Approved — ${inv.vessel || 'Unknown'} · ${sevLabel} ${inv.type || 'Incident'}`,
      html: emailHtml,
      attachments
    });

    res.json({ ok: true, approved: true, emailsSent: toAddresses.length, recipients: toAddresses });
  } catch(e) {
    console.error('Approve/email error:', e);
    res.status(500).json({ error: e.message });
  }
});

// Add DPA email field update for vessels
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

    // Build a compact dataset for the AI
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

    // Build chart data server-side (no AI needed for counts)
    const vessels = [...new Set(dataset.map(d => d.vessel).filter(Boolean))];
    const types   = [...new Set(dataset.map(d => d.type).filter(Boolean))];
    const months  = {};
    dataset.forEach(d => {
      if (d.date) {
        const m = d.date.substring(0, 7);
        months[m] = (months[m] || 0) + 1;
      }
    });

    const chartData = {
      byVessel: vessels.map(v => ({ label: v, count: dataset.filter(d => d.vessel === v).length }))
                       .sort((a,b) => b.count - a.count),
      byType:   types.map(t => ({ label: t, count: dataset.filter(d => d.type === t).length }))
                     .sort((a,b) => b.count - a.count),
      bySeverity: ['1','2','3','4','5'].map(s => ({
        label: ['Near Miss','Minor','Moderate','Serious','Critical'][+s-1],
        count: dataset.filter(d => d.severity === s).length
      })).filter(d => d.count > 0),
      byMonth: Object.entries(months).sort((a,b) => a[0].localeCompare(b[0]))
                     .map(([m, count]) => ({ label: m, count }))
    };

    // AI pattern analysis
    const prompt = `You are a maritime safety analyst. Analyse this fleet incident dataset and identify significant patterns.

INCIDENT DATA (${dataset.length} investigations):
${JSON.stringify(dataset, null, 1)}

Identify patterns across these 5 categories:
1. RECURRING ROOT CAUSES — same root cause appearing on same vessel multiple times
2. LOCATION CLUSTERS — same incident type at same port/location  
3. POST-MAINTENANCE FAILURES — equipment failures that may follow maintenance/dry-dock events
4. SEASONAL TRENDS — time-based clustering of incident types
5. FLEET COMPARISON — which vessels have highest frequency/severity

For each pattern found, provide:
- A clear title
- Category (one of: recurring_cause, location_cluster, maintenance_failure, seasonal, fleet_comparison)
- Severity rating: high/medium/low
- Evidence: specific investigation references that support this pattern
- Insight: what this pattern means operationally
- Recommendation: 1-2 specific corrective actions

Only report genuine patterns with at least 2 data points. Do not invent patterns.

Respond ONLY with valid JSON:
{
  "patterns": [
    {
      "id": "p1",
      "category": "recurring_cause",
      "title": "Pattern title",
      "severity": "high",
      "evidence": ["MARIDE-XXX", "MARIDE-YYY"],
      "insight": "What this means",
      "recommendation": "What to do about it",
      "count": 3
    }
  ],
  "executive_summary": "2-3 sentence fleet safety overview"
}`;

    const aiRes = await fetch('https://api.anthropic.com/v1/messages', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'x-api-key': ANTHROPIC_API_KEY, 'anthropic-version': '2023-06-01' },
      body: JSON.stringify({
        model: 'claude-sonnet-4-6',
        max_tokens: 2000,
        messages: [{ role: 'user', content: prompt }]
      })
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
// CUSTODIAN MODULE — EQUIPMENT CUSTODY & ACCOUNTABILITY
// ══════════════════════════════════════════════════════

// ── Custodian DB helpers ───────────────────────────────
function readCustDB() {
  const custPath = require('path').join(DATA_DIR, 'custodian.json');
  try {
    if (fs.existsSync(custPath)) return JSON.parse(fs.readFileSync(custPath,'utf8'));
  } catch(e) {}
  return { equipment:[], defects:[], tempRepairs:[], pmLogs:[], alarmLogs:[], handovers:[] };
}
function writeCustDB(data) {
  const custPath = require('path').join(DATA_DIR, 'custodian.json');
  try { fs.writeFileSync(custPath, JSON.stringify(data,null,2)); } catch(e) { console.error(e); }
}

// Default equipment categories for LPG vessels
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

// ── Equipment Registry ──────────────────────────────────
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

// Seed default equipment for a vessel
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

// ── Defect Log ──────────────────────────────────────────
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

// Add troubleshooting step
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

// ── Temp Repair Register ────────────────────────────────
app.get('/api/custodian/temp-repairs', requireAuth, (req, res) => {
  const db = readCustDB();
  const vesselId = req.query.vessel_id;
  const list = vesselId ? db.tempRepairs.filter(t=>t.vessel_id===vesselId) : db.tempRepairs;
  // Auto-flag overdue
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

// ── PM Logs ─────────────────────────────────────────────
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
    // Update equipment next_pm_date if provided
    if (req.body.equipment_id && req.body.next_pm_date) {
      const eq = db.equipment.find(e=>e.id===req.body.equipment_id);
      if (eq) { eq.last_pm_date=req.body.pm_date; eq.next_pm_date=req.body.next_pm_date; }
    }
    writeCustDB(db);
    res.json(log);
  } catch(e) { res.status(500).json({error:e.message}); }
});

// ── Alarm Logs ──────────────────────────────────────────
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

// ── Handover Log ────────────────────────────────────────
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

// ── Custodian Score ─────────────────────────────────────
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

    // Group by designation (not name)
    const custodians = {};
    equipment.forEach(eq => {
      const key = eq.custodian_designation || 'Unassigned';
      if (!custodians[key]) custodians[key] = { designation:key, equipment:[], defects:[], pmLogs:[], tempReps:[], alarms:[] };
      custodians[key].equipment.push(eq);
    });

    // Find current signed-on holder for each designation (from main users DB)
    const signedOnHolders = {};
    const allUsers = [...(mainDb.users||[]), ...(db.users||[])];
    allUsers.filter(u => u.signed_on !== false && u.designation).forEach(u => {
      // Store under both raw and common abbreviations
      const desig = u.designation;
      signedOnHolders[desig] = u.name;
      // Also store normalised key (CE -> Chief Engineer etc)
      const norm = {
        'ce':'Chief Engineer','c/e':'Chief Engineer','chief eng':'Chief Engineer',
        'captain':'Master','2e':'2nd Engineer','2/e':'2nd Engineer',
        '3e':'3rd Engineer','3/e':'3rd Engineer','4e':'4th Engineer','4/e':'4th Engineer',
        'c/o':'Chief Officer',
      }[desig.toLowerCase().trim()];
      if (norm) signedOnHolders[norm] = u.name;
    });

    // Attach defects/pm/alarms to custodians by designation
    defects.forEach(d => {
      const eq = equipment.find(e=>e.id===d.equipment_id);
      const key = eq?.custodian_designation||'Unassigned';
      if (custodians[key]) custodians[key].defects.push(d);
    });
    pmLogs.forEach(p => {
      const eq = equipment.find(e=>e.id===p.equipment_id);
      const key = eq?.custodian_designation||'Unassigned';
      if (custodians[key]) custodians[key].pmLogs.push(p);
    });
    tempReps.forEach(t => {
      const eq = equipment.find(e=>e.id===t.equipment_id);
      const key = eq?.custodian_designation||'Unassigned';
      if (custodians[key]) custodians[key].tempReps.push(t);
    });
    alarms.forEach(a => {
      const eq = equipment.find(e=>e.id===a.equipment_id);
      const key = eq?.custodian_designation||'Unassigned';
      if (custodians[key]) custodians[key].alarms.push(a);
    });

    const now = new Date();
    const scores = Object.values(custodians).map(c => {
      const eqCount = c.equipment.length;
      if (!eqCount) return null;

      // 1. PMS Compliance (30pts) — % equipment with up-to-date PM
      const eqWithPM = c.equipment.filter(e => e.next_pm_date);
      const pmCompliant = eqWithPM.filter(e => new Date(e.next_pm_date) >= now).length;
      // If no PM dates set at all, give neutral 15pts; otherwise score based on compliance
      const pmsScore = eqWithPM.length === 0 ? 15 : Math.round((pmCompliant / eqWithPM.length) * 30);

      // 2. Defect Resolution (25pts) — % open defects with troubleshooting steps
      const openDefects = c.defects.filter(d=>d.status==='open');
      const troubleshot = openDefects.filter(d=>(d.troubleshooting_steps||[]).length>0);
      const defectScore = openDefects.length===0 ? 25 : Math.round((troubleshot.length/openDefects.length)*25);

      // 3. Temp Repair Discipline (20pts) — penalty for overdue temp repairs
      const overdueTemp = c.tempReps.filter(t=>t.status==='overdue').length;
      const tempScore = Math.max(0, 20 - (overdueTemp * 7));

      // 4. Alarm Clearance (15pts) — alarms with WO within 24h
      const recentAlarms = c.alarms.filter(a=>{
        const age = (now - new Date(a.created_at)) / 3600000;
        return age > 24;
      });
      const clearedInTime = recentAlarms.filter(a=>a.work_order_ref && a.status!=='open').length;
      const alarmScore = recentAlarms.length===0 ? 15 : Math.round((clearedInTime/recentAlarms.length)*15);

      // 5. Equipment Health (10pts) — % equipment operational
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

// ══════════════════════════════════════════════════════
// EQUIPMENT ROUNDS — CHECKLIST & SCORING SYSTEM
// ══════════════════════════════════════════════════════

// ── Checklist Templates ─────────────────────────────────
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

Generate 8-14 inspection checks that a responsible officer should complete every 2 weeks.

Each check must have the RIGHT answer type:
- "yes_no" — for checks that are binary (e.g. "Any leaks observed?", "Running hours logged?")
- "condition" — for condition assessments with options: Good / Satisfactory / Requires Attention / Critical (e.g. "Overall condition of filters", "Condition of shaft seal")
- "numeric" — for readings/measurements with a unit and normal range (e.g. oil level, temperature, pressure)
- "text" — for open observations or serial numbers

Scoring rules (embed in each check):
- "yes_no": good_answer = "YES" or "NO" depending on the question (e.g. "Oil level OK?" → good_answer:"YES", "Leaks observed?" → good_answer:"NO")
- "condition": good_answers = ["Good","Satisfactory"], critical_answers = ["Critical"]
- "numeric": specify min_normal and max_normal range; out of range = deficiency
- points: assign 5-15 points per check based on safety criticality

Also specify:
- "critical": true if this check failing should BLOCK submission (safety-critical only)
- "auto_defect": true if a bad answer should auto-raise a defect
- "hint": brief guidance for the officer

Return ONLY valid JSON:
{
  "checks": [
    {
      "id": "c1",
      "text": "Check description",
      "hint": "What to look for / how to measure",
      "answer_type": "yes_no",
      "good_answer": "NO",
      "options": null,
      "good_answers": null,
      "critical_answers": null,
      "min_normal": null,
      "max_normal": null,
      "unit": null,
      "points": 10,
      "critical": false,
      "auto_defect": true
    }
  ]
}`;

    const aiRes = await fetch('https://api.anthropic.com/v1/messages', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'x-api-key': ANTHROPIC_API_KEY, 'anthropic-version': '2023-06-01' },
      body: JSON.stringify({ model: 'claude-sonnet-4-6', max_tokens: 3000, messages: [{ role: 'user', content: prompt }] })
    });

    const aiData = await aiRes.json();
    const text = aiData.content?.[0]?.text || '{}';
    const parsed = JSON.parse(text.replace(/```json|```/g, '').trim());

    const db = readCustDB();
    db.checklists = db.checklists || [];
    // Remove existing checklist for this equipment
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

// Submit round — score it, auto-raise defects, check thresholds
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

      if (!ans) return; // unanswered

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
          isGood = (check.min_normal == null || val >= check.min_normal) &&
                   (check.max_normal == null || val <= check.max_normal);
          isCritical = check.critical && !isGood;
        }
      } else {
        isGood = !!(ans.value && ans.value.trim());
      }

      if (isGood) totalPoints += check.points || 10;

      // Auto-raise defect for bad answers
      if (!isGood && check.auto_defect) {
        const defect = {
          id: 'def_' + Date.now().toString(36) + '_' + Math.random().toString(36).substring(2,5),
          vessel_id: round.vessel_id,
          equipment_id: round.equipment_id,
          equipment_name: round.equipment_name,
          title: `Round ${round.round_number} — Deficiency: ${check.text}`,
          severity: isCritical ? 'critical' : 'medium',
          description: `Auto-raised from equipment round. Check: "${check.text}" — Answer: ${ans.value || 'Not answered'}. Officer notes: ${ans.notes||'None'}`,
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

    res.json({
      ok: true,
      score: scorePercent,
      totalPoints, maxPoints,
      defectsRaised,
      criticalBlocked,
      belowThreshold,
      round
    });
  } catch(e) {
    console.error('Round submit error:', e);
    res.status(500).json({ error: e.message });
  }
});

// Get round status summary for a vessel — which equipment is overdue
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

function readSireDB() {
  const sirePath = require('path').join(DATA_DIR, 'sire.json');
  try { if (fs.existsSync(sirePath)) return JSON.parse(fs.readFileSync(sirePath,'utf8')); } catch(e) {}
  return { preparations:{}, findings:[], drillSessions:[], fleetFindings:[] };
}
function writeSireDB(data) {
  const sirePath = require('path').join(DATA_DIR, 'sire.json');
  try { fs.writeFileSync(sirePath, JSON.stringify(data,null,2)); } catch(e) { console.error(e); }
}

const SIRE_CHAPTERS = [
  {
    "id": "C2",
    "title": "Certification and Documentation",
    "roles": [
      "Master",
      "Chief Engineer",
      "Chief Officer"
    ],
    "questions": [
      {
        "id": "C2Q2_1_1",
        "number": "2.1.1",
        "text": "Were the Master and senior officers familiar with the company procedure for  maintaining the vessel’s statutory certification up to date, were all certificates and  documents carried onboard up to date and was the vessel free of conditions of class or  significant memoranda?",
        "short_text": "Maintenance of Statutory Certification",
        "vessel_types": [
          "Oil",
          "Chemical",
          "LPG",
          "LNG"
        ],
        "section": "2.1",
        "section_name": "Certification",
        "objective": "To ensure that the vessel had been surveyed in accordance with all statutory requirements and that  certification is onboard to confirm compliance.",
        "risk": "high",
        "evidence": [
          "The company procedure for managing statutory certification and supporting documents.",
          "Folders containing statutory and classification certificates and supporting surveys/test reports.",
          "Certificate index indicating the expiry date all statutory certification, supporting surveys and inspections.",
          "The Class Survey Status Report (CSSR)*.",
          "List of open defects as reported in the defect reporting system.",
          "Details of class attendance during the past twelve months."
        ],
        "negative_grounds": [
          "There was no company procedure which defined the process for managing (indexing and filing) vessel",
          "certificates and documents to ensure compliance with SOLAS, Class and Flag requirements.",
          "Page 9 of 711 – SIRE 2.0 Question Library: Part 1 Version 1.0 (January 2022)",
          "The accompanying officer was unfamiliar with the company procedure for indexing and filing certificates and",
          "documents."
        ]
      },
      {
        "id": "C2Q2_2_1",
        "number": "2.2.1",
        "text": "Had the vessel been attended by a company Superintendent at approximately six- monthly intervals and were reports available to demonstrate that a systematic vessel  inspection had been completed during each attendance declared through the pre- inspection questionnaire?",
        "short_text": "Superintendent vessel inspection and report",
        "vessel_types": [
          "Oil",
          "Chemical",
          "LPG",
          "LNG"
        ],
        "section": "2.2",
        "section_name": "Management Oversight",
        "objective": "To ensure that the vessel had been periodically and systematically inspected by company Marine and  Technical Superintendents to provide shore management with a complete technical and operational  appraisal of their managed vessel.  TMSA KPI 12.1.2 requires that an inspection plan covers all vessels",
        "risk": "high",
        "evidence": [
          "Qualifying vessel inspection reports completed by company Marine or Technical Superintendents during the",
          "previous eighteen months.",
          "Evidence that defects and areas for improvement had been followed up through the company defect",
          "reporting or non-conformity reporting systems.",
          "The company procedure for conducting remote inspections, if applicable."
        ],
        "negative_grounds": [
          "Reports were not available onboard for each declared qualifying vessel inspection conducted by a company",
          "Marine or Technical Superintendent.",
          "Page 12 of 711 – SIRE 2.0 Question Library: Part 1 Version 1.0 (January 2022)",
          "The inspection report format did not cover all operational and accessible areas of the vessel and its",
          "equipment."
        ]
      },
      {
        "id": "C2Q2_2_2",
        "number": "2.2.2",
        "text": "Were recent ISM internal audit reports available on board, had corrective action  been taken on board to close-out any non-conformities and had this corrective action  been verified by shore management?",
        "short_text": "Internal ISM audit",
        "vessel_types": [
          "Oil",
          "Chemical",
          "LPG",
          "LNG"
        ],
        "section": "2.2",
        "section_name": "Management Oversight",
        "objective": "To provide assurance that the vessel had been operated in compliance with the company Safety  Management System.  Industry Guidance  TMSA KPI 12A.1.1 requires that the company has documented audit procedures and standard audit formats. The  formats are designed, as required, for ISM, the ISPS Code, ",
        "risk": "high",
        "evidence": [
          "The company procedure for scheduling and performing internal ISM audits.",
          "The latest two internal ISM audit reports under the current operator.",
          "The system for recording and tracking non-conformities to closure."
        ],
        "negative_grounds": [
          "There was no company procedure for scheduling and performing internal ISM audits.",
          "No internal ISM audit had taken place for more than:",
          "o",
          "15 months",
          "o"
        ]
      },
      {
        "id": "C2Q2_2_3",
        "number": "2.2.3",
        "text": "Was the Master fully conversant with the company’s Safety Management System  and had Master’s Reviews of the system taken place in accordance with the ISM Code  and company procedures?",
        "short_text": "Master's Review of the SMS.",
        "vessel_types": [
          "Oil",
          "Chemical",
          "LPG",
          "LNG"
        ],
        "section": "2.2",
        "section_name": "Management Oversight",
        "objective": "To ensure the Master is fully conversant with the Safety Management System and that Master’s Reviews  contribute to the improvement of its effectiveness.  Industry Guidance  IACS Recommendation No.41 (Rev.5 Oct 2019) Guidance for Auditors to the ISM Code  ‘ISM Code - paragraph 5.1.5   5.1 The Compan",
        "risk": "high",
        "evidence": [
          "The Safety Management System.",
          "The last two Master’s Reviews.",
          "The company responses to the last two Master’s Reviews."
        ],
        "negative_grounds": [
          "The Master was not familiar with the layout and contents of the SMS.",
          "The Master was not proficient in accessing the information contained in the SMS, whether in hard copy or",
          "digital format.",
          "There was no company procedure requiring the periodic review of the Safety Management System (SMS)",
          "by the Master, including:"
        ]
      },
      {
        "id": "C2Q2_3_1",
        "number": "2.3.1",
        "text": "Were the Master and Chief Engineer familiar with the company procedure to  maintain the Enhanced Survey File in accordance with Classification Society rules, and  was the vessel free of any visible or documentary evidence of concerns with the  structural condition of the hull or cargo and ballast tank coatings?",
        "short_text": "Structural concerns and Enhanced Survey File.",
        "vessel_types": [
          "Oil",
          "Chemical"
        ],
        "section": "2.3",
        "section_name": "Structural Assessment",
        "objective": "To ensure that the structure of oil and chemical tankers was subject to enhanced survey and complete  historical records of any damage, deterioration and subsequent repairs to their hull structure were available  onboard.  Industry Guidance  IACS: Double Hull Tankers Guidelines for Surveys Assessmen",
        "risk": "high",
        "evidence": [
          "The Enhanced Survey File (which must be onboard for the lifetime of the ship from at least one year prior to",
          "the first special survey).",
          "The Coating Technical File, where required to be carried.",
          "Supporting documents required to be carried onboard according to the ESP Code.",
          "Inspection reports for cargo, ballast and void spaces by ships personnel.",
          "Incident investigation reports relevant to structural damage and repair within the scope of the enhanced hull"
        ],
        "negative_grounds": [
          "There was no company procedure which required that the enhanced survey file, or electronic record, was",
          "maintained in accordance with classification society guidance.",
          "There was no company procedure which required that the coating technical file was maintained in",
          "accordance with classification society guidance.",
          "The accompanying officer was unfamiliar with the company procedure for maintaining the enhanced survey"
        ]
      },
      {
        "id": "C2Q2_3_2",
        "number": "2.3.2",
        "text": "Were the Master and Chief Engineer familiar with the company procedure to  maintain the Class Survey File, and was the vessel free of any visible or documentary  evidence of concerns with the structural condition of the hull or hold space and ballast  tank coatings?",
        "short_text": "Structural concerns and Class Survey File.",
        "vessel_types": [
          "LPG",
          "LNG"
        ],
        "section": "2.3",
        "section_name": "Structural Assessment",
        "objective": "To ensure that the structure of gas carriers was subject to the required surveys and complete historical  records of any damage, deterioration and subsequent repairs to the hull structure were available on board.  Industry Guidance  IMO: SOLAS  Chapter II-1 Regulation 3-2  Protective coatings of ded",
        "risk": "high",
        "evidence": [
          "Survey File.",
          "Coating Technical File, where required to be carried.",
          "Inspection reports for cargo, ballast, hold and void space inspections by ship’s personnel.",
          "Incident investigation reports relevant to structural damage and repair."
        ],
        "negative_grounds": [
          "There was no company procedure to ensure the vessel’s Survey File is maintained complete and up to date.",
          "The Master and/or Chief Engineer were not familiar with the company procedure to ensure the vessel’s",
          "Survey File is maintained complete and up to date.",
          "The Survey File was incomplete and did not include:",
          "o"
        ]
      },
      {
        "id": "C2Q2_3_3",
        "number": "2.3.3",
        "text": "Were the Master and senior officers familiar with the company cargo, ballast & void  space inspection and reporting procedure and, were records available to demonstrate  that all inspections had been accomplished within the required time frame with reports  completed in accordance with company instructions?",
        "short_text": "Cargo, ballast & void space inspection",
        "vessel_types": [
          "Oil",
          "Chemical",
          "LPG",
          "LNG"
        ],
        "section": "2.3",
        "section_name": "Structural Assessment",
        "objective": "To ensure that the condition of cargo, ballast and void spaces was properly evaluated with defects to  structure, coating or fittings effectively managed.  Industry Guidance   IACS: Recommendation 87. Guidelines for Coating Maintenance and Repairs for Ballast Tanks and Combined  Cargo/Ballast Tanks ",
        "risk": "high",
        "evidence": [
          "Page 27 of 711 – SIRE 2.0 Question Library: Part 1 Version 1.0 (January 2022)",
          "The company procedures, and any referenced industry publications, for inspection of cargo, ballast and void",
          "spaces.",
          "The inspection reports for all cargo, ballast and void spaces for the previous full inspection cycle.",
          "Open defect reports for any defects to tank structure, coatings or fittings.",
          "Communications with class relating to any defects to tank structure since the previous renewal or"
        ],
        "negative_grounds": [
          "There were no company procedures for the inspection of cargo/ballast/void spaces which gave clear",
          "guidance on the inspection frequency, the inspection process and reporting criteria.",
          "The required inspection frequency for ballast and void spaces exceeded twelve months.",
          "The required inspection frequency for cargo spaces on oil and chemical tankers exceeded thirty-six months.",
          "The accompanying officer was unfamiliar with the company cargo/ballast/void space inspection procedure"
        ]
      },
      {
        "id": "C2Q2_3_4",
        "number": "2.3.4",
        "text": "Were the Master and deck officers familiar with the company procedures for  detecting leakage of liquids between cargo, bunker, ballast, void and cofferdam spaces  which included inspecting the surface of ballast water prior to discharge, and were  records available to show that the necessary checks had been performed?",
        "short_text": "Monitoring cargo, ballast & void spaces for leakage and contamination",
        "vessel_types": [
          "Oil",
          "Chemical",
          "LPG",
          "LNG"
        ],
        "section": "2.3",
        "section_name": "Structural Assessment",
        "objective": "To ensure that leakage of liquids between adjacent cargo, bunker, ballast, void and cofferdam spaces or  from pipelines passing through such spaces is detected.  Industry Guidance  OCIMF: International Safety Guide for Oil Tankers and Terminals. Sixth Edition  11.3.4 Monitoring of Void and Ballast S",
        "risk": "high",
        "evidence": [
          "The company procedure for sighting the surface of ballast water prior to discharge where the ballast tanks",
          "were adjacent to a cargo or bunker tank or where oil pipes and/or hydraulic lines pass through the tanks.",
          "The company procedure to periodically sound empty tanks to detect liquid migration due to structural failure",
          "or pipeline leakage.",
          "Records demonstrating that the surface of ballast water had been inspected prior to discharge.",
          "Records demonstrating that periodic soundings of empty spaces had been taken in accordance with"
        ],
        "negative_grounds": [
          "There was no company procedure to periodically check empty spaces for ingress of liquids from adjoining",
          "spaces or pipeline leakage or, to check the surface of ballast water for contamination prior to discharge.",
          "The accompanying deck officer was unfamiliar with the company procedure for periodically checking empty",
          "spaces for liquid ingress or monitoring the levels of full or partially full tanks for migration of liquid between",
          "spaces."
        ]
      },
      {
        "id": "C2Q2_3_5",
        "number": "2.3.5",
        "text": "Had the vessel been enrolled in a Classification Society Condition Assessment  Programme (CAP)?",
        "short_text": "Condition Assessment Program (CAP)",
        "vessel_types": [
          "Oil",
          "Chemical",
          "LPG",
          "LNG"
        ],
        "section": "2.3",
        "section_name": "Structural Assessment",
        "objective": "To provide an objective assessment of the operational reliability of a vessel in critical areas at the request of  a vessel’s owner, typically at the third special survey and periodically thereafter.  Industry Guidance  Each Classification Society has its own Condition Assessment Program criteria.  ",
        "risk": "high",
        "evidence": [
          "The CAP certificate showing the completion date of the assessment survey and the final ratings for the",
          "modules completed.",
          "Where the CAP certificate only showed the issue date rather than the survey completion date, evidence to",
          "support the date(s) that the onboard survey was completed.",
          "Any information or records that supplemented the CAP certificate."
        ],
        "negative_grounds": [
          "The information provided by the operator in the pre-inspection questionnaire was inaccurate.",
          "The vessel operator had claimed a CAP rating for modules that were still pending completion.",
          "The date of the CAP survey was inaccurately declared as the CAP certificate issue date.",
          "The operator did not upload the CAP certificate to the document store and the CAP certificate was not",
          "available onboard for review."
        ]
      },
      {
        "id": "C2Q2_4_1",
        "number": "2.4.1",
        "text": "Were the senior officers familiar with the company procedure for reporting defects  to vessel structure, machinery and equipment to shore-based management through the  company defect reporting system and was evidence available to demonstrate that all  defects had been reported accordingly?",
        "short_text": "Defect reporting system",
        "vessel_types": [
          "Oil",
          "Chemical",
          "LPG",
          "LNG"
        ],
        "section": "2.4",
        "section_name": "Defect Management",
        "objective": "To ensure that defects to vessel structure, machinery and equipment are documented and reviewed by  management.  Industry Guidance:  IACS Information Paper. Classification Societies – what, why and how?  Section B1 – The effectiveness of classification depends upon the shipbuilder, during constructi",
        "risk": "high",
        "evidence": [
          "The company procedure for managing defects to vessel structure, machinery and equipment through the",
          "defect reporting system.",
          "The defect reporting system or the planned maintenance system where the systems were integrated.",
          "Shore based acknowledgement of each defect entered into the defect reporting system.",
          "A printed list of all open defects reports entered into the defect reporting system."
        ],
        "negative_grounds": [
          "There was no defect reporting system.",
          "There was no company procedure for managing defects to vessel structure, machinery and equipment",
          "through the defect reporting system.",
          "The accompanying senior officer was unfamiliar with the company defect reporting procedure.",
          "Defects entered in the defect reporting system had not been acknowledged by shore management."
        ]
      },
      {
        "id": "C2Q2_4_2",
        "number": "2.4.2",
        "text": "Where defects existed to the vessel’s structure, machinery or equipment, had the  vessel operator notified class, flag and/or the authorities in the port of arrival, as  appropriate to the circumstances, and had short term certificates, waivers, exemptions  and/or permissions to proceed the voyage been issued where necessary?",
        "short_text": "Defect reporting to class, flag etc",
        "vessel_types": [
          "Oil",
          "Chemical",
          "LPG",
          "LNG"
        ],
        "section": "2.4",
        "section_name": "Defect Management",
        "objective": "To ensure that defects affecting statutory certification or class required equipment are reported to the  vessel’s Classification Society, Flag Administration and any affected stakeholders as appropriate.  Industry Guidance:    IACS: Information Paper. Classification societies – what, why and how?  ",
        "risk": "high",
        "evidence": [
          "The company procedure for notifying the vessel’s Classification Society, Flag Administration and/or other",
          "external stakeholders of defects to the vessel’s structure, machinery and equipment.",
          "The class status report – uploaded to the document portal.",
          "Page 38 of 711 – SIRE 2.0 Question Library: Part 1 Version 1.0 (January 2022)",
          "The defect reporting system, or the planned maintenance system where systems were integrated.",
          "A printed list of open defect reports identifying any defects which had been reported to the vessel’s"
        ],
        "negative_grounds": [
          "There was no company procedure which required that defects to vessel structure, machinery and equipment",
          "were evaluated by shore management to determine whether notifications to Class, Flag and/or other",
          "external stakeholders were required.",
          "The senior officers were not familiar with the company procedure for notifying Class, Flag and/or other",
          "external stakeholders of defects to the vessel’s structure, machinery or equipment after shore management"
        ]
      },
      {
        "id": "C2Q2_5_1",
        "number": "2.5.1",
        "text": "Had the company Management of Change procedure been effectively implemented  for changes affecting structure, machinery and equipment governed by Classification  Society rules or statutory survey?",
        "short_text": "Management of Change",
        "vessel_types": [
          "Oil",
          "Chemical",
          "LPG",
          "LNG"
        ],
        "section": "2.5",
        "section_name": "Management of Change",
        "objective": "To ensure that any change made to the vessel structure, machinery or equipment is properly managed to  avoid an undesirable outcome.  Industry Guidance  IACS Information Paper. Classification societies – what, why and how?  Section B1 – The effectiveness of classification depends upon the shipbuilde",
        "risk": "high",
        "evidence": [
          "The vessel’s MOC register or database index.",
          "The MOC requests for all changes to vessel structure, machinery and equipment conducted onboard the",
          "vessel during the previous twelve months.",
          "Supporting documents such as risk assessments, training plans, updated drawings lists etc. as identified",
          "within each MOC request form."
        ],
        "negative_grounds": [
          "There was no company MOC procedure covering changes affecting class and/or flag regulated structure,",
          "machinery and equipment.",
          "The accompanying senior officer was unfamiliar with the company MOC process, as it applied to changes",
          "falling within the scope of this question, to structure, machinery and equipment onboard the vessel.",
          "Changes falling within the scope of this question to vessel structure, machinery or equipment, regulated by"
        ]
      },
      {
        "id": "C2Q2_6_1",
        "number": "2.6.1",
        "text": "Were the Master, deck officers and engineer officers familiar with the vessel’s  Ballast Water Management Plan and were records available to demonstrate that ballast  handling had been conducted in accordance with the plan?",
        "short_text": "Ballast Water Management Plan",
        "vessel_types": [
          "Oil",
          "Chemical",
          "LPG",
          "LNG"
        ],
        "section": "2.6",
        "section_name": "Statutory Management Plans",
        "objective": "To ensure that ballast is always safely handled in accordance with the Ballast Water Management  Convention and BWMS Code.  Industry Guidance  OCIMF/ICS: International Safety Guide for Oil Tankers and Terminals. Sixth Edition.   Chapter 12.6 - Ballast operations  TMSA KPI 6.2.3 requires that compreh",
        "risk": "high",
        "evidence": [
          "The Ballast Water Management Plan along with a copy of the Ballast Water Management Certificate.",
          "The Ballast Water Record Book or equivalent.",
          "Recent cargo and ballast plans along with supporting operational records to verify the times and duration of",
          "ballast operations.",
          "Where ballast water exchange had taken place, the exchange plan showing the sequence of exchange and",
          "the longitudinal stresses, draughts and trim at each stage of the operation."
        ],
        "negative_grounds": [
          "The vessel did not have a Ballast Water Management Plan or a valid Ballast Water Management Certificate.",
          "The Ballast Water Management Plan was not approved by the Flag Sate or recognised organisation such as",
          "a class society.",
          "The Ballast Water Management Plan was not ship-specific.",
          "The officer designated in the Ballast Water Management Plan to be in charge of ensuring that the plan was"
        ]
      },
      {
        "id": "C2Q2_6_2",
        "number": "2.6.2",
        "text": "Were the Master and officers familiar with the VOC Management Plan, and had the  procedures for minimising VOC emissions set out in the Plan been implemented and  documented as required?",
        "short_text": "VOC Management Plan.",
        "vessel_types": [
          "Oil"
        ],
        "section": "2.6",
        "section_name": "Statutory Management Plans",
        "objective": "To ensure VOC emissions are minimised by implementation of the VOC Management Plan.  Industry Guidance  OCIMF: Volatile Organic Compound Emissions from Cargo Systems on Oil Tankers. First Edition 2019.  7. Operational procedures and Volatile Organic Compound Management Plan.  The purpose of the VOC ",
        "risk": "high",
        "evidence": [
          "The VOC Management Plan.",
          "VOC Management Plan training records.",
          "Records required to be maintained to demonstrate compliance with the Plan.",
          "The cargo plan for the ongoing cargo operation.",
          "The deck logbook."
        ],
        "negative_grounds": [
          "Page 47 of 711 – SIRE 2.0 Question Library: Part 1 Version 1.0 (January 2022)",
          "The VOC Management Plan was not approved by the Flag State or recognised organisation such as a Class",
          "Society.",
          "The VOC Management Plan was not ship specific.",
          "The VOC Management Plan was not in a language readily understood by the Master and officers."
        ]
      },
      {
        "id": "C2Q2_6_3",
        "number": "2.6.3",
        "text": "Were the Master and senior officers familiar with the contents and requirements of  the Ship Energy Efficiency Management Plan (SEEMP) and had these been fully  implemented?",
        "short_text": "Ship Energy Efficiency Management Plan (SEEMP).",
        "vessel_types": [
          "Oil",
          "Chemical",
          "LPG",
          "LNG"
        ],
        "section": "2.6",
        "section_name": "Statutory Management Plans",
        "objective": "To ensure the measures set out in the SEEMP to improve fuel efficiency and collect fuel consumption data  have been fully implemented.  Industry Guidance  IMO: Resolution MEPC.282(70) 2016 Guidelines for the development of a Ship Energy Efficiency Management  Plan (SEEMP)  3.6 Part I of the SEEMP sh",
        "risk": "high",
        "evidence": [
          "Ship Energy Efficiency Management Plan (SEEMP).",
          "Documentary evidence that the package of measures listed in the SEEMP Part I to improve the ship’s",
          "energy efficiency had been implemented and/or monitored, which may be contained in bridge and engine",
          "logbooks etc.",
          "On ships of 5,000 gross tonnage or above, records of the collection, aggregation, and reporting of ship data",
          "with regard to annual fuel oil consumption, distance travelled, hours underway and other data required by"
        ],
        "negative_grounds": [
          "The Master and/or the Chief Engineer were not familiar with the contents and requirements of the Ship",
          "Energy Efficiency Management Plan (SEEMP).",
          "The SEEMP Part I did not contain a package of measures to improve the ship's energy efficiency, and",
          "details for their implementation, such as:",
          "o"
        ]
      },
      {
        "id": "C2Q2_7_1",
        "number": "2.7.1",
        "text": "Was the relevant content of the SMS manuals easily accessible to all personnel on  board in a working language(s) understood by them?",
        "short_text": "Availability of SMS content to all crew.",
        "vessel_types": [
          "Oil",
          "Chemical",
          "LPG",
          "LNG"
        ],
        "section": "2.7",
        "section_name": "Safety Management System",
        "objective": "To ensure that all personnel on board can access and understand the procedures and instructions relevant  to them, set out in the ship’s SMS manuals.  Industry Guidance  TMSA KPI 1A.1.4 requires that procedures and instructions are easily accessible to personnel and available at  appropriate locatio",
        "risk": "high",
        "evidence": [
          "SMS manuals.",
          "Evidence that changes to the SMS are promptly brought to the attention of the appropriate on-board",
          "personnel and understood (which may be documentary or electronic)."
        ],
        "negative_grounds": [
          "The SMS manuals were not ‘user friendly’ and ship staff found it difficult and/or time consuming to navigate",
          "to the appropriate information.",
          "A significant proportion of the content of the SMS manuals was not relevant to the ship e.g. described",
          "procedures for general cargo ships, container ships or bulk carriers.",
          "Manuals were in hard-copy format but there were insufficient copies at appropriate locations."
        ]
      },
      {
        "id": "C2Q2_7_2",
        "number": "2.7.2",
        "text": "Did the SMS identify clear levels of authority and lines of communication between  the Master, ship's officers, ratings and the company, and were all onboard personnel  familiar with these arrangements as they related to their position?",
        "short_text": "Communication lines with the company and DPA.",
        "vessel_types": [
          "Oil",
          "Chemical",
          "LPG",
          "LNG"
        ],
        "section": "2.7",
        "section_name": "Safety Management System",
        "objective": "To ensure all onboard personnel understand the levels of authority and lines of communication between the  Master, ship's officers, ratings and the company as they relate to their position.  Industry Guidance  ICS: Bridge Procedures Guide – Fifth Edition  1.3 Company policy and procedures  The ISM C",
        "risk": "high",
        "evidence": [
          "The SMS manual showing documented levels of authority and lines of communication between the Master,",
          "ship's officers, ratings and the company.",
          "The means of informing all officers and ratings of the identity and contact details of the DPA."
        ],
        "negative_grounds": [
          "The SMS did not identify clear levels of authority and lines of communication between the Master, ship's",
          "officers, ratings and the Company.",
          "A senior officer was not familiar with the lines of communication with the key members of the operator’s",
          "organisation ashore.",
          "An interviewed junior officer or rating was not aware of the identity, contact details and role of the DPA."
        ]
      },
      {
        "id": "C2Q2_8_1",
        "number": "2.8.1",
        "text": "Was the OCIMF Harmonised Vessel Particulars Questionnaire (HVPQ) available  through the OCIMF SIRE Programme database completed accurately to reflect the  structure, outfitting, management and certification of the vessel?",
        "short_text": "HVPQ accurately completed.",
        "vessel_types": [
          "Oil",
          "Chemical",
          "LPG",
          "LNG"
        ],
        "section": "2.8",
        "section_name": "General Information",
        "objective": "To ensure that the information contained within the OCIMF HVPQ provides an accurate dataset for use by  SIRE 2.0 programme participants.",
        "risk": "high",
        "evidence": [
          "The following certificates and documents will be provided, as applicable to the vessel, through the inspection",
          "software:",
          "HVPQ.",
          "SIRE Crew matrix.",
          "Class Status Summary Report (CSSR) (Owners version).",
          "Ballast Water Management Certificate."
        ],
        "negative_grounds": [
          "Where the information provided within the HVPQ misrepresented the details of the vessel through multiple systemic",
          "inaccuracies or omissions relating to ownership, class status, validity of certification or outfitting of the vessel:",
          "Make an observation within the process response tool and add a comment to identify which questions were",
          "provided with inaccurate information.",
          "Page 59 of 711 – SIRE 2.0 Question Library: Part 1 Version 1.0 (January 2022)"
        ]
      },
      {
        "id": "C2Q2_8_2",
        "number": "2.8.2",
        "text": "Were records of the most recent Port State Control inspection available onboard,  and where deficiencies had been recorded had these been corrected and closed out in  accordance with the company procedure for defects or non-conformities?",
        "short_text": "Last Port State Control Inspection.",
        "vessel_types": [
          "Oil",
          "Chemical",
          "LPG",
          "LNG"
        ],
        "section": "2.8",
        "section_name": "General Information",
        "objective": "To provide an accurate record of the most recent Port State Control (PSC) Inspection.  Industry Guidance  OCIMF: PSC Inspection Repository.  The PSC inspection Repository is an addition to the SIRE database to provide a convenient way for ship operators to  disseminate details of PSC inspections on ",
        "risk": "high",
        "evidence": [
          "The company procedure for managing PSC inspections.",
          "All PSC inspection reports for the previous three years, or if no PSC inspections had been carried out in that",
          "period, the report for the last inspection conducted.",
          "Documented evidence that any deficiencies raised during the last PSC inspection had been corrected and",
          "closed out with approval from shore management through either the non-conformity reporting system or",
          "defect reporting system."
        ],
        "negative_grounds": [
          "There was no company procedure for managing PSC inspections.",
          "Where the vessel operator was utilising the OCIMF PSC Inspection Repository, the most recent PSC",
          "Inspection Report had not been uploaded (an allowance of five days since the completion of the inspection",
          "prior to the synchronisation of the inspection editor should be allowed)",
          "The PSC inspection reports available onboard did not include the most recent PSC inspection available on"
        ]
      }
    ]
  },
  {
    "id": "C3",
    "title": "Crew Management",
    "roles": [
      "Master",
      "Chief Officer"
    ],
    "questions": [
      {
        "id": "C3Q3_1_1",
        "number": "3.1.1",
        "text": "Were the officers and ratings suitably qualified to serve onboard the vessel and did  the officer matrix posted on the OCIMF website accurately reflect the qualifications,  experience and English language capabilities of the officers onboard at the time of the  inspection?",
        "short_text": "Crew qualifications and matrix verification.",
        "vessel_types": [
          "Oil",
          "Chemical",
          "LPG",
          "LNG"
        ],
        "section": "3.1",
        "section_name": "Crew Qualification",
        "objective": "To ensure that all officers and crew onboard are properly qualified for the type of vessel and the position  they hold onboard.  Industry Guidelines  OCIMF: Guidelines for the Completion of the On-Line Officer Matrix.  Available within the SIRE operator account.  TMSA KPI 3.2.3 requires that the com",
        "risk": "high",
        "evidence": [
          "The updated officer matrix available on the OCIMF website reflecting all changes in crew that had occurred",
          "more than four days before the inspection. (it is not expected that the vessel provides a paper or electronic",
          "copy)",
          "The relevant documentation for each person onboard, in the following order or a standard order as defined",
          "by the vessel operator, including:",
          "o"
        ],
        "negative_grounds": [
          "The officer matrix had not been updated to reflect the officers who were on board at the time of the",
          "inspection (an allowance will be made for any officer that had changed within the previous four days).",
          "The accompanying senior officer was unfamiliar with the maintenance of officer and rating certification",
          "records onboard.",
          "The details contained in the officer matrix were inaccurate in terms of:"
        ]
      },
      {
        "id": "C3Q3_1_2",
        "number": "3.1.2",
        "text": "Were procedures and instructions contained within the Safety Management System  and signs posted around the vessel available in the designated working language of the  vessel or a language(s) understood by the crew and, were the Master, officers and  ratings able to communicate verbally in the designated working language?",
        "short_text": "Designated working language.",
        "vessel_types": [
          "Oil",
          "Chemical",
          "LPG",
          "LNG"
        ],
        "section": "3.1",
        "section_name": "Crew Qualification",
        "objective": "To ensure that the Master, officers and ratings can read and understand procedures, instructions and safety  signs onboard, and can communicate verbally in the designated working language of the vessel.  Industry Guidance  UK MCA: Code of Safe Working Practices for Merchant Seafarers. 2015 Edition. ",
        "risk": "high",
        "evidence": [
          "The deck log book (or ship’s log book where different) which recorded the designated working language of",
          "the vessel.",
          "The Safety Management System documentation, checklists etc."
        ],
        "negative_grounds": [
          "The designated working language of the vessel had not been determined by the vessel operator.",
          "The designated working language in use during the inspection was not the same as declared through the",
          "HVPQ and/or entered in the logbook.",
          "An officer or rating was observed to be unable to communicate verbally in the designated working language",
          "of the vessel."
        ]
      },
      {
        "id": "C3Q3_1_3",
        "number": "3.1.3",
        "text": "Did the complement of officers and ratings onboard at the time of inspection meet  or exceed the requirements of the Minimum Safe Manning Document and the declared  company standard manning for routine operations, and had senior officers been relieved  to ensure continuity of operational knowledge?",
        "short_text": "Minimum, standard and enhanced manning levels.",
        "vessel_types": [
          "Oil",
          "Chemical",
          "LPG",
          "LNG"
        ],
        "section": "3.1",
        "section_name": "Crew Qualification",
        "objective": "To ensure that the vessel is always adequately manned for the operations expected to be undertaken based  on the normal trading pattern and any foreseeable specialist operations or periods of heightened workload.  Industry Guidance  IMO: Resolution A.1047(27) Principles of Safe Manning  Annex 2 Guid",
        "risk": "high",
        "evidence": [
          "The Minimum Safe Manning Document.",
          "A copy of the arrival crew list provided by the Master.",
          "The current OCIMF crew matrix available on the OCIMF SIRE database."
        ],
        "negative_grounds": [
          "The crew onboard on arrival at the port of inspection did not meet the requirements of the Safe Manning",
          "Document in any respect.",
          "The crew onboard on arrival at the port of inspection did not:",
          "o",
          "Meet the standard manning level declared through the pre-inspection questionnaire, or"
        ]
      },
      {
        "id": "C3Q3_2_1",
        "number": "3.2.1",
        "text": "Was a report available onboard which confirmed that a static navigational  assessment by a suitably qualified and experienced company representative had been  completed as declared through the pre-inspection questionnaire?",
        "short_text": "Static navigational assessment",
        "vessel_types": [
          "Oil",
          "Chemical",
          "LPG",
          "LNG"
        ],
        "section": "3.2",
        "section_name": "Crew Evaluation",
        "objective": "To verify the extent of company evaluation and oversight of navigational standards onboard managed  vessels  Industry Guidance  OCIMF: A Guide to Best Practice for Navigational Assessments and Audits.  3.2.1 Static Assessment.  A static assessment, which may be conducted in port, should include as a",
        "risk": "high",
        "evidence": [
          "The report for the static navigational assessment declared by the operator through the pre-inspection",
          "questionnaire.",
          "A corrective action plan with due dates for each area for improvement identified during the static",
          "navigational assessment.",
          "Supporting evidence for each closed area for improvement identified and included in the corrective action",
          "plan."
        ],
        "negative_grounds": [
          "The report for the static navigational assessment declared through the pre-inspection questionnaire was not",
          "available onboard.",
          "The details of the qualifications and pertinent seafaring experience of the assessor were not included within",
          "the report.",
          "Page 75 of 711 – SIRE 2.0 Question Library: Part 1 Version 1.0 (January 2022)"
        ]
      },
      {
        "id": "C3Q3_2_2",
        "number": "3.2.2",
        "text": "Was a report available onboard which confirmed that a dynamic navigational  assessment by a suitably qualified and experienced company representative had been  completed while on passage as declared through the pre-inspection questionnaire?",
        "short_text": "Dynamic navigational assessment by a company representative",
        "vessel_types": [
          "Oil",
          "Chemical",
          "LPG",
          "LNG"
        ],
        "section": "3.2",
        "section_name": "Crew Evaluation",
        "objective": "To verify the extent of company evaluation and oversight of navigational standards onboard managed  vessels  Industry Guidance  OCIMF: A Guide to Best Practice for Navigational Assessments and Audits.  2 Purpose of a navigational assessment  The purpose of a navigational assessment should be to iden",
        "risk": "high",
        "evidence": [],
        "negative_grounds": []
      },
      {
        "id": "C3Q3_2_3",
        "number": "3.2.3",
        "text": "Was a report available onboard which confirmed that a dynamic navigational  assessment by a suitably qualified specialist contractor had been completed while on  passage as declared through the pre-inspection questionnaire?",
        "short_text": "Dynamic navigational assessment by a specialist contractor",
        "vessel_types": [
          "Oil",
          "Chemical",
          "LPG",
          "LNG"
        ],
        "section": "3.2",
        "section_name": "Crew Evaluation",
        "objective": "To verify the extent of company evaluation and oversight of navigational standards onboard managed  vessels  Industry Guidance  OCIMF: A Guide to Best Practice for Navigational Assessments and Audits.  2 Purpose of a navigational assessment  The purpose of a navigational assessment should be to iden",
        "risk": "high",
        "evidence": [],
        "negative_grounds": []
      },
      {
        "id": "C3Q3_2_4",
        "number": "3.2.4",
        "text": "Was a report available onboard which confirmed that an unannounced remote  navigational assessment, which included review of VDR & ECDIS data by an independent  contractor or specialist company representative, had been completed as declared  through the pre-inspection questionnaire?",
        "short_text": "Unannounced remote navigational assessment",
        "vessel_types": [
          "Oil",
          "Chemical",
          "LPG",
          "LNG"
        ],
        "section": "3.2",
        "section_name": "Crew Evaluation",
        "objective": "To verify the extent of company evaluation and oversight of navigational standards onboard managed  vessels.  Industry Guidance  OCIMF: A Guide to Best Practice for Navigational Assessments and Audits.  5.2 Remote navigational assessments using Voyage Data Recorders  Companies may consider using Voy",
        "risk": "high",
        "evidence": [
          "The report for the remote navigational assessment conducted by either an independent contractor or",
          "specialist company representative as declared through the pre-inspection questionnaire.",
          "The Bridge Log Book to cover the period of the reported remote navigation assessment (for geographical",
          "verification purposes only).",
          "A corrective action plan with due dates for each area for improvement identified during the remote",
          "navigational assessment."
        ],
        "negative_grounds": [
          "The remote navigational assessment report for the assessment declared through the pre-inspection",
          "questionnaire was not available onboard.",
          "The remote navigational assessment did not include review of downloaded VDR and ECDIS data as well as",
          "supporting material such as passage plans, under-keel clearance calculations and copies (photos) of paper",
          "charts where no ECDIS was carried."
        ]
      },
      {
        "id": "C3Q3_2_5",
        "number": "3.2.5",
        "text": "Was a report available onboard which confirmed that a comprehensive cargo audit  by a suitably qualified and experienced company representative had been completed as  declared through the pre-inspection questionnaire?",
        "short_text": "Comprehensive cargo audit by a company representative",
        "vessel_types": [
          "Oil",
          "Chemical",
          "LPG",
          "LNG"
        ],
        "section": "3.2",
        "section_name": "Crew Evaluation",
        "objective": "To verify the extent of company evaluation and oversight of cargo, ballast and bunkering operational  standards onboard managed vessels  OCIMF Guidance: A Guide to Best Practice for Navigational Assessments and Audits.  To align the expectations for comprehensive operational audits across onboard di",
        "risk": "high",
        "evidence": [
          "The report for the comprehensive cargo audit conducted by a suitably qualified and experienced company",
          "representative as declared through the pre-inspection questionnaire.",
          "The Deck Log Book and/or Cargo Log Book to cover the period of the reported comprehensive cargo audit",
          "(for geographical and operational verification purposes only).",
          "A corrective action plan with due dates for each area for improvement identified during the comprehensive",
          "cargo audit."
        ],
        "negative_grounds": [
          "The report for the comprehensive cargo audit declared through the pre-inspection questionnaire was not",
          "available onboard.",
          "The comprehensive cargo audit did not cover the cargo or bunker operations or was not completed during",
          "the date range as declared by the operator through the pre-inspection questionnaire.",
          "The details of the qualifications and pertinent seafaring experience of the assessor were not included within"
        ]
      },
      {
        "id": "C3Q3_2_6",
        "number": "3.2.6",
        "text": "Was a report available onboard which confirmed that a comprehensive engineering  audit by a suitable qualified and experienced company representative had been  completed as declared in the pre-inspection questionnaire?",
        "short_text": "Comprehensive engineering audit by a company representative",
        "vessel_types": [
          "Oil",
          "Chemical",
          "LPG",
          "LNG"
        ],
        "section": "3.2",
        "section_name": "Crew Evaluation",
        "objective": "To verify the extent of company evaluation and oversight of machinery space management, engineering and  maintenance standards onboard managed vessels.  ICS: Engine Room Procedures Guide. First Edition.  11.8.2 Routine Operations  All routine operations on board should be covered by written procedur",
        "risk": "high",
        "evidence": [
          "The report for the comprehensive engineering audit conducted by a suitably qualified and experienced",
          "company representative as declared through the pre-inspection questionnaire.",
          "The Engine Room Log Book to cover the period of the reported comprehensive engineering audit (for",
          "geographical and operational verification purposes only).",
          "A corrective action plan with due dates for each area for improvement identified during the comprehensive",
          "engineering audit."
        ],
        "negative_grounds": [
          "The report for the comprehensive engineering audit declared through the pre-inspection questionnaire was",
          "not available onboard.",
          "The comprehensive engineering audit did not cover the machinery space operations or was not completed",
          "during the date range as declared by the operator through the pre-inspection questionnaire.",
          "The details of the qualifications and pertinent seafaring experience of the assessor were not included within"
        ]
      },
      {
        "id": "C3Q3_2_7",
        "number": "3.2.7",
        "text": "Was a report available onboard which confirmed that a comprehensive mooring  and anchoring audit by a suitably qualified and experienced company representative had  been completed as declared through the pre-inspection questionnaire?",
        "short_text": "Comprehensive mooring and anchoring audit by a company representative",
        "vessel_types": [
          "Oil",
          "Chemical",
          "LPG",
          "LNG"
        ],
        "section": "3.2",
        "section_name": "Crew Evaluation",
        "objective": "To verify the extent of company evaluation and oversight of mooring and anchoring operational standards  onboard managed vessels.  Industry Guidance:  Intertanko: Anchoring Guidelines: A Risk-Based Approach v.3 June 2020  Live anchoring audits  It is necessary to check and verify the behaviour of pe",
        "risk": "high",
        "evidence": [
          "The report for the comprehensive mooring and anchoring audit conducted by a suitably qualified and",
          "experienced company representative as declared through the pre-inspection questionnaire.",
          "The Deck Log Book to cover the period of the reported comprehensive mooring and anchoring audit (for",
          "geographical and operational verification purposes only).",
          "A corrective action plan with due dates for each area for improvement identified during the comprehensive",
          "mooring and anchoring audit."
        ],
        "negative_grounds": [
          "The report for the comprehensive mooring and anchoring audit declared through the pre-inspection",
          "questionnaire was not available onboard.",
          "The comprehensive mooring and anchoring audit did not cover the type of mooring and anchoring",
          "operations or was not completed during the date range as declared by the operator through the pre-",
          "inspection questionnaire."
        ]
      },
      {
        "id": "C3Q3_2_8",
        "number": "3.2.8",
        "text": "Had the vessel operator implemented a Behavioural Competency Assessment  Programme onboard and was there evidence available that assessments were being  conducted for navigation, cargo, mooring and engineering operations by approved  assessors?",
        "short_text": "Behavioural Competency Assessment Programme",
        "vessel_types": [
          "Oil",
          "Chemical",
          "LPG",
          "LNG"
        ],
        "section": "3.2",
        "section_name": "Crew Evaluation",
        "objective": "To verify the extent of company evaluation and oversight of competency standards onboard managed  vessels.  Industry Guidance  OCIMF/INTERTANKO: Behavioural Competency Assessment and Verification for Vessel Operators  4.3 Methods of competency-based assessment  While observation will usually be the ",
        "risk": "high",
        "evidence": [
          "The Behavioural Competency Assessment and Verification Programme Guide.",
          "The qualifications for any approved assessors onboard at the time of the inspection.",
          "The records (summary) of competency assessments completed for all staff onboard at the time of the",
          "inspection who were included in the competency assessment programme since they joined the company or",
          "the inception of the programme.",
          "Sample assessments for cargo, navigation, mooring and engineering competencies."
        ],
        "negative_grounds": [
          "There was no evidence that there was a functional Behavioural Competency Assessment and Verification",
          "Programme in operation onboard.",
          "The Behavioural Competency Assessment and Verification Programme did not cover navigation, cargo",
          "operations, mooring operations and engineering operations.",
          "Onboard staff identified as approved assessors were not in possession of the company defined training for"
        ]
      },
      {
        "id": "C3Q3_3_1",
        "number": "3.3.1",
        "text": "Had the Master and all navigation officers attended a shore-based Bridge Team  Management training course within the previous five years?",
        "short_text": "Shore-based Bridge Team Management training",
        "vessel_types": [
          "Oil",
          "Chemical",
          "LPG",
          "LNG"
        ],
        "section": "3.3",
        "section_name": "Crew Training",
        "objective": "To ensure that all navigation officers have been trained in the practical application of crew resource  management in a realistic navigational environment.  Industry Guidance  IMO Model Course 1.22 Ship Simulator and Bridge Teamwork.  TMSA KPI 5.4.4 requires that navigation officers undertake period",
        "risk": "high",
        "evidence": [
          "The Bridge Team Management training certificates for the Master and navigation officers.",
          "Where the Bridge Team Management training certificate did not state that it was in accordance with IMO",
          "Model Course 1.22, evidence that the training course included a bridge simulator element which required",
          "that simulator based navigational exercises were at least equivalent to the requirements of IMO Model",
          "Course 1.22. (19 hours simulator time)."
        ],
        "negative_grounds": [
          "The Master and/or any one of the navigation officers onboard during the inspection did not have evidence of",
          "attending a Bridge Team Simulator training course at least equivalent to IMO Model Course 1.22 within the",
          "previous five years.",
          "Page 99 of 711 – SIRE 2.0 Question Library: Part 1 Version 1.0 (January 2022)"
        ]
      },
      {
        "id": "C3Q3_3_2",
        "number": "3.3.2",
        "text": "Had the Master received formal ship handling training prior to promotion or when  being assigned to a new type of ship having significantly different handling  characteristics to ships in which they had recently served?",
        "short_text": "Formal ship handling training",
        "vessel_types": [
          "Oil",
          "Chemical",
          "LPG",
          "LNG"
        ],
        "section": "3.3",
        "section_name": "Crew Training",
        "objective": "To ensure the Master is familiar with the ship handling characteristics of the type of ship to which they have  been assigned.  Industry Guidance  TMSA KPI 5.3.2 requires that a formal program ensures that Senior Officers receive appropriate ship-handling  training before promotion to Master or assi",
        "risk": "high",
        "evidence": [
          "The Master’s sea service record and discharge book.",
          "The company training matrix showing the mandatory and non-mandatory training requirements for the",
          "Master.",
          "The company matrix of the handling characteristics of vessels under management considering the number",
          "and type of propellers, rudders and thrusters fitted to a vessel as well as the vessel size, and the training",
          "requirements for transfer between vessel types."
        ],
        "negative_grounds": [
          "The time in rank for the Master entered in the OCIMF Officer Matrix was inaccurate in that the time in rank",
          "declared was greater than thirty-six months sea service, but the Master had less than thirty-six months sea",
          "service in rank.",
          "There was no company training matrix available which clearly identified the circumstances in which ship",
          "handling training was required to be completed by a Master both at promotion and when being reassigned to"
        ]
      },
      {
        "id": "C3Q3_3_3",
        "number": "3.3.3",
        "text": "Had the Master, deck officers, and cargo/gas engineer where carried, attended a  shore-based simulator course covering routine and emergency cargo operations within  the previous five years?",
        "short_text": "Cargo operations shore-based simulator course",
        "vessel_types": [
          "Oil",
          "Chemical",
          "LPG",
          "LNG"
        ],
        "section": "3.3",
        "section_name": "Crew Training",
        "objective": "To establish whether all officers involved in cargo operations had been practically trained in routine and  emergency cargo operations in a realistic simulator environment.",
        "risk": "high",
        "evidence": [
          "The shore-based cargo system simulator training certificates for the Master, deck officers and cargo/gas",
          "engineer where carried.",
          "Where the shore-based cargo system simulator training had been completed more than five years",
          "previously, a certificate for a refresher training course with an appropriate cargo simulator element.",
          "Where a refresher training course was undertaken, the supporting full course certificate must also be",
          "available for review."
        ],
        "negative_grounds": [
          "The Master and/or any one of the deck officers or cargo/gas engineers onboard during the inspection did not",
          "have evidence of attending either a full or refresher cargo system simulator training course within the",
          "previous five years.",
          "The training courses attended by the Master and/or any one of the deck officers or cargo/gas engineers was",
          "for a vessel type other than the type of vessel being inspected."
        ]
      },
      {
        "id": "C3Q3_3_4",
        "number": "3.3.4",
        "text": "Had the Chief Engineer and all engineer officers attended a shore-based engine  room management simulator course covering routine and emergency machinery  operations within the previous five years?",
        "short_text": "Shore-based engine room management simulator course",
        "vessel_types": [
          "Oil",
          "Chemical",
          "LPG",
          "LNG"
        ],
        "section": "3.3",
        "section_name": "Crew Training",
        "objective": "To ensure that the Chief Engineer and all engineer officers involved in manoeuvring operations had been  practically trained in routine and emergency machinery operations in a realistic simulator environment.",
        "risk": "high",
        "evidence": [
          "The shore-based engine room management simulator training certificates for the Chief Engineer and all",
          "engineers.",
          "Where the shore-based engine room management simulator training had been completed more than five",
          "years previously, a certificate for a refresher training course with an appropriate engine room simulator",
          "element."
        ],
        "negative_grounds": [
          "The Chief Engineer and/or any one of the engineer officers onboard during the inspection did not have",
          "evidence of attending either a full or refresher engine room management simulator course within the",
          "previous five years.",
          "The training courses attended by the Chief Engineer and/or any one of the engineer officers was for a",
          "propulsion type other than the type fitted to the vessel being inspected."
        ]
      },
      {
        "id": "C3Q3_3_5",
        "number": "3.3.5",
        "text": "Did all key personnel onboard involved in Dynamically Positioned (DP) operations  have appropriate training in accordance with IMO and International Marine Contractors  Association (IMCA) guidelines and local regulations applicable to the area of operations?",
        "short_text": "Training for Dynamically Positioned (DP) operators",
        "vessel_types": [
          "Oil"
        ],
        "section": "3.3",
        "section_name": "Crew Training",
        "objective": "To ensure that all key personnel onboard are properly experienced, trained and qualified to participate in  Dynamically Positioned (DP) operations in accordance with industry recommended best practice and local  regulation.  Industry Guidance  IMCA: Guidelines for The Training and Experience of Key ",
        "risk": "high",
        "evidence": [
          "The company training matrix which identified the DP related certification and training requirements for each",
          "DP related role onboard.",
          "The vessel’s populated training matrix which showed the current status of all DP related certification and",
          "training for all onboard staff having a DP related role.",
          "The DP Operator certificates and DP logbooks for everyone identified as a qualified DP operator.",
          "The DP refresher training course certificates or scheme records where onboard refresher activities had"
        ],
        "negative_grounds": [
          "The vessel operator had not developed a training matrix which identified all DP related training and",
          "certification that was required to be completed by each onboard position with a DP related role.",
          "The vessel had not prepared a record of training and certification to demonstrate that all DP related",
          "certification and training had been completed by each individual onboard with a DP related role.",
          "The required training certificates or DP Operator certificates  were found to be missing, expired or outdated"
        ]
      },
      {
        "id": "C3Q3_3_6",
        "number": "3.3.6",
        "text": "Had the Master, officers and ratings received the required training and  familiarisation before being assigned duties related to handling LNG or other low- flashpoint fuel?",
        "short_text": "LNG or other low-flashpoint fuel training and familiarisation.",
        "vessel_types": [
          "Oil",
          "Chemical",
          "LPG"
        ],
        "section": "3.3",
        "section_name": "Crew Training",
        "objective": "To ensure that personnel on board ships using LNG or other low-flashpoint fuels are adequately qualified,  trained, and experienced.   Industry Guidance  ICS: Training requirements for personnel on ships subject to the IGF code   Amendments to the International Convention on Standards of Training, C",
        "risk": "high",
        "evidence": [
          "The company procedure which defined the requirement for Basic and Advanced Training for service on",
          "ships subject to the IGF Code, which may be in the form of a training matrix.",
          "Basic and Advanced Training Certificates of Proficiency for service in vessels subject to the IGF Code.",
          "On existing vessels, alternative certification as required by the flag state.",
          "Records of familiarisation for the LNG or low-flashpoint fuel system."
        ],
        "negative_grounds": [
          "There was no company procedure which defined the requirement for Basic and Advanced Training for",
          "service on ships subject to the IGF Code.",
          "A crew member with responsibilities associated with the fuel or fuel system on board had not received ship-",
          "specific familiarisation with the systems fitted before being assigned duties.",
          "On a vessel subject to the IGF Code:"
        ]
      },
      {
        "id": "C3Q3_4_1",
        "number": "3.4.1",
        "text": "Was there an effective system in place to record and monitor the hours of rest for  all personnel onboard in compliance with STCW, MLC or the regulatory requirements  applicable to the vessel?",
        "short_text": "Hours of rest, records and monitoring",
        "vessel_types": [
          "Oil",
          "Chemical",
          "LPG",
          "LNG"
        ],
        "section": "3.4",
        "section_name": "Crew Compliance",
        "objective": "To ensure that there is an effective system in place to manage crew rest hours and fatigue.  Industry Guidance:  OCIMF: Recommendations Relating to the Application of Requirements Governing Seafarers’ Hours of Work  and Rest.  IMO: MSC./Circ.1598. Guidelines on Fatigue.  IMO/ILO: Guidelines for the ",
        "risk": "high",
        "evidence": [
          "The company procedure that defined how hours of rest were to be managed and recorded.",
          "Completed hours of rest records for the preceding three months signed, physically or digitally as acceptable",
          "to the vessel’s Administration, by the individual crewmembers and approved by the Master or their",
          "authorised representative.",
          "The monthly hours of rest record summary reports for the previous three months showing each hours of rest",
          "non-conformance."
        ],
        "negative_grounds": [
          "There was no company procedure that defined how hours of rest were to be managed and recorded.",
          "The accompanying officer was not familiar with the company procedure that defined how hours of rest were",
          "to be managed and recorded and/or the process for recording and monitoring hours of rest and any non-",
          "conformance.",
          "The hours of rest records were not in the ILO/MLC format which clearly identified the hours of rest"
        ]
      },
      {
        "id": "C3Q3_4_2",
        "number": "3.4.2",
        "text": "Were the Master, officers and crew familiar with the company policy and  procedures for drug and alcohol abuse prevention and had unannounced drug and  alcohol testing taken place onboard in accordance with the policy?",
        "short_text": "Drug and alcohol abuse prevention",
        "vessel_types": [
          "Oil",
          "Chemical",
          "LPG",
          "LNG"
        ],
        "section": "3.4",
        "section_name": "Crew Compliance",
        "objective": "To ensure that no seafarer will navigate a ship or operate its onboard equipment whilst impaired by drugs or  alcohol.  Industry Guidance  OCIMF: Guidelines for the Control of Drugs and Alcohol Onboard Ship. 1995.  OCIMF recommends that officers and ratings observe a period of abstinence from alcoho",
        "risk": "high",
        "evidence": [
          "The company policy and supporting procedures to prevent the abuse of drugs and alcohol.",
          "Where alcohol was permitted onboard, the records of alcohol issue to onboard personnel and visitors.",
          "The alcohol breath testing device.",
          "The calibration or testing records for the alcohol breath testing device.",
          "Records, including results, of company initiated unannounced alcohol tests including initial instruction and",
          "vessel advice that tests were complete."
        ],
        "negative_grounds": [
          "There was no company policy or supporting procedures for the prevention of abuse of drugs and alcohol.",
          "The company policy to prevent the abuse of drugs and alcohol was not prominently displayed at appropriate",
          "locations onboard.",
          "The accompanying officer was unfamiliar with the company policy or supporting procedures for the",
          "prevention of abuse of drugs and alcohol."
        ]
      },
      {
        "id": "C3Q3_5_1",
        "number": "3.5.1",
        "text": "Had the company developed an effective familiarisation programme that covered  the personal safety and professional responsibilities of all onboard personnel, including  visitors and contractors, and were records available to demonstrate that the  familiarisation had been completed as required?",
        "short_text": "Familiarisation of crew, visitors and contractors",
        "vessel_types": [
          "Oil",
          "Chemical",
          "LPG",
          "LNG"
        ],
        "section": "3.5",
        "section_name": "Crew Management",
        "objective": "To ensure that all onboard personnel, including contractors and visitors, are fully familiarised with their  onboard duties, responsibilities and the equipment and machinery fitted to the vessel relevant to their role.  Industry Guidance  UK MCA: Code of Safe Working Practices for Merchant Seafarers",
        "risk": "high",
        "evidence": [
          "The company procedure which defined the onboard familiarisation process for each role onboard, including",
          "visitors and contractors.",
          "Records of completed familiarisation as follows:",
          "For all individuals",
          "Essential Initial safety training necessary prior to sailing on joining, or upon taking over new safety related",
          "assignments onboard."
        ],
        "negative_grounds": [
          "There was no company procedure which defined the familiarisation process for onboard staff, contractors",
          "and visitors.",
          "The accompanying officer was unfamiliar with the company familiarisation procedure and/or processes.",
          "Familiarisation records, in accordance with the company procedure, were not available for any one of the",
          "selected personnel."
        ]
      },
      {
        "id": "C3Q3_5_2",
        "number": "3.5.2",
        "text": "Were the Master, officers and ratings familiar with the ship’s lifesaving and fire  extinguishing appliances and, had ongoing onboard training and instruction taken place  to maintain familiarity?",
        "short_text": "Training and instruction LSA and FFA",
        "vessel_types": [
          "Oil",
          "Chemical",
          "LPG",
          "LNG"
        ],
        "section": "3.5",
        "section_name": "Crew Management",
        "objective": "To ensure that all crew can use the ship’s life- saving (LSA) and fire extinguishing (FFA) appliances in  accordance with the equipment manufacturer’s instructions to respond effectively to an emergency.  Industry Guidance  OCIMF: Survival Craft – A Seafarer’s Guide  Section 3 Familiarisation and Tr",
        "risk": "high",
        "evidence": [
          "A fire training manual, fire safety operational booklet and lifesaving training manual.",
          "The company procedures defining the requirement for delivering ongoing training and instruction for the LSA",
          "and FFA provided onboard.",
          "The instructions for delivering onboard training for the davit-launched liferaft and the use of a training liferaft,",
          "where provided.",
          "The records of LSA and FFA training and instruction provided to the crew within two weeks of joining the"
        ],
        "negative_grounds": [
          "There was no company procedure which defined the requirement for delivering and recording ongoing",
          "training and instruction for each piece of LSA & FFA provided onboard.",
          "The fire training manual, fire safety operational booklet or lifesaving manuals were not written in the working",
          "language of the ship.",
          "The fire training manual, fire safety operational booklet or lifesaving manual were not provided in each crew"
        ]
      },
      {
        "id": "C3Q3_5_3",
        "number": "3.5.3",
        "text": "Had the Master and navigation officers been familiarised with the ECDIS equipment  installed on board and were documented records of this familiarisation available?",
        "short_text": "Familiarisation with ECDIS equipment installed on board.",
        "vessel_types": [
          "Oil",
          "Chemical",
          "LPG",
          "LNG"
        ],
        "section": "3.5",
        "section_name": "Crew Management",
        "objective": "To ensure the Master and navigation officers are fully familiar with the specific type of ECDIS equipment  installed on board prior to taking charge of a navigational watch.  Industry Guidance  OCIMF: Recommendations on Usage of ECDIS and Preventing Incidents. First edition.  3.2 Recommendations  • ",
        "risk": "high",
        "evidence": [
          "Company procedures that ensured all watchkeeping officers are competent in the use of the onboard ECDIS",
          "prior to taking charge of a navigational watch.",
          "ECDIS installation specific training certificates, where required by the company familiarisation process",
          "Onboard ECDIS installation specific familiarisation checklists for the Master and deck officers."
        ],
        "negative_grounds": [
          "There were no company procedures that ensured all watchkeeping officers are competent in the use of the",
          "onboard ECDIS prior to taking charge of a navigational watch, that included the:",
          "o",
          "Time scale for the familiarisation.",
          "o"
        ]
      }
    ]
  },
  {
    "id": "C4",
    "title": "Navigation",
    "roles": [
      "Master",
      "Chief Officer",
      "2nd Officer"
    ],
    "questions": [
      {
        "id": "C4Q4_1_1",
        "number": "4.1.1",
        "text": "Were the Master and navigation officers familiar with the company procedures for  the set up and operation of the ECDIS units fitted to the vessel and were records       available to demonstrate that the ECDIS had been operated in accordance with company  procedures at all stages of a voyage?",
        "short_text": "ECDIS set up and operation",
        "vessel_types": [
          "Oil",
          "Chemical",
          "LPG",
          "LNG"
        ],
        "section": "4.1",
        "section_name": "Navigation - Bridge and Equipment",
        "objective": "To ensure that ECDIS units fitted to the vessel were used to effectively navigate the vessel.  Industry Guidance   OCIMF: Recommendations on Usage of ECDIS and Preventing Incidents. First Edition.  1.2 Analysis of ECDIS-related incident findings and SIRE observations  Table 1.1 summarises contributi",
        "risk": "high",
        "evidence": [
          "The company procedures that defined how ECDIS units should be operated and managed.",
          "ECDIS checklists and quick reference guides.",
          "Records to demonstrate that software updates had been completed in accordance with manufacturer’s",
          "instructions.",
          "Records to demonstrate periodic tests required by the manufacturer’s instructions had been completed.",
          "Records to demonstrate that the ECDIS settings had been checked periodically during each voyage."
        ],
        "negative_grounds": [
          "There were no company procedures for operating and managing the ECDIS fitted.",
          "The company procedures did not provide clear guidance regarding:",
          "o",
          "Display management",
          "o"
        ]
      },
      {
        "id": "C4Q4_1_2",
        "number": "4.1.2",
        "text": "Were the Master and navigation officers familiar with the company procedures for  managing and operating the radar/ARPA units fitted to the vessel, and were records  available to demonstrate that the units had been operated and tested in accordance with  company procedures?",
        "short_text": "Operation and testing of radar/ARPA",
        "vessel_types": [
          "Oil",
          "Chemical",
          "LPG",
          "LNG"
        ],
        "section": "4.1",
        "section_name": "Navigation - Bridge and Equipment",
        "objective": "To ensure that the radar/ARPA units fitted to the vessel are used effectively for navigation and collision  avoidance.  Industry Guidance:   ICS: Bridge Procedures Guide. Fifth Edition.  Chapter 4.11 Radar and Radar Plotting Aids.  TMSA KPI 5.1.2 requires that comprehensive procedures to ensure safe",
        "risk": "high",
        "evidence": [
          "Page 139 of 711 – SIRE 2.0 Question Library: Part 1 Version 1.0 (January 2022)",
          "The company procedures for managing and operating the radar/ARPA units fitted to the vessel.",
          "Any checklists or quick reference charts for the operation of the radar/ARPA units fitted to the vessel.",
          "Onboard records demonstrating that the radar/ARPA units had been in operation and tested in accordance",
          "with company procedures.",
          "Information relating to any blind sectors affecting the fitted radars."
        ],
        "negative_grounds": [
          "There were no company procedures for managing and operating the radar/ARPA units fitted to the vessel.",
          "The accompanying navigation officer was unfamiliar with the company procedure for managing and",
          "operating the radar/ARPA units fitted to the vessel.",
          "The accompanying navigation officer was unfamiliar with the hazards of using AIS data (vectors) for collision",
          "avoidance."
        ]
      },
      {
        "id": "C4Q4_1_3",
        "number": "4.1.3",
        "text": "Were the Master and navigation officers familiar with the company procedures for  operating and testing the steering control systems fitted to the vessel and were records  available to demonstrate that operation and testing had been carried out in accordance  with the procedures?",
        "short_text": "Operating and testing the steering control systems",
        "vessel_types": [
          "Oil",
          "Chemical",
          "LPG",
          "LNG"
        ],
        "section": "4.1",
        "section_name": "Navigation - Bridge and Equipment",
        "objective": "To ensure the steering control systems fitted to the vessel are tested and used in an appropriate manner with  changeover procedures understood.  Industry Guidance:   ICS Bridge Procedures Guide. Fifth Edition.  Chapter 4.2 Steering Gear and Automatic Pilot.  Annex 3 Checklists  Section B – Bridge  ",
        "risk": "high",
        "evidence": [
          "The company procedures for managing, testing and operating the steering control systems provided.",
          "The vessel specific procedures for changing between steering control modes and systems.",
          "The vessel specific procedure for changing over to emergency steering control.",
          "The block diagram showing the change-over procedures for remote steering gear control systems and",
          "steering gear power units.",
          "Records for a recent voyage to demonstrate that steering control system tests had been completed in"
        ],
        "negative_grounds": [
          "There was no company procedure for managing, testing and operating steering control systems fitted to the",
          "vessel.",
          "The accompanying navigation officer was unfamiliar with the company procedure for managing, testing and",
          "operating the steering control systems fitted to the vessel.",
          "Page 143 of 711 – SIRE 2.0 Question Library: Part 1 Version 1.0 (January 2022)"
        ]
      },
      {
        "id": "C4Q4_1_4",
        "number": "4.1.4",
        "text": "Were the Master and navigation officers familiar with the company procedures for  using the Automatic Identification System (AIS) fitted to the vessel and were records  available to confirm that periodic checks and tests had been carried out in accordance  with the procedures?",
        "short_text": "Automatic Identification System (AIS)",
        "vessel_types": [
          "Oil",
          "Chemical",
          "LPG",
          "LNG"
        ],
        "section": "4.1",
        "section_name": "Navigation - Bridge and Equipment",
        "objective": "To ensure that the Automatic Identification System (AIS) fitted to the vessel was used to safely enhance  situational awareness during navigation.  Industry Guidance   ICS: Bridge Procedures Guide. Fifth Edition.  Chapter 4.10 Automatic Identification System  It is important that AIS is operated cor",
        "risk": "high",
        "evidence": [
          "The company procedure for the operation and testing of the AIS equipment fitted onboard.",
          "Records of the checks and performance tests required to be carried out on the AIS equipment fitted.",
          "Company guidance related to the use of AIS information in collision avoidance situations."
        ],
        "negative_grounds": [
          "There were no procedures for the operation and testing of the AIS system fitted onboard.",
          "There was no company guidance related to the use of AIS information in collision avoidance situations.",
          "Page 147 of 711 – SIRE 2.0 Question Library: Part 1 Version 1.0 (January 2022)",
          "The accompanying navigation officer was unfamiliar with the company procedures for the operation and",
          "testing of the AIS system fitted onboard"
        ]
      },
      {
        "id": "C4Q4_1_5",
        "number": "4.1.5",
        "text": "Were the Master and navigation officers familiar with the company procedure for  the use of the Bridge Navigational Watch Alarm System (BNWAS) and were records  available to demonstrate that it had been operated and tested in accordance with the  procedure?",
        "short_text": "Bridge Navigational Watch Alarm System (BNWAS)",
        "vessel_types": [
          "Oil",
          "Chemical",
          "LPG",
          "LNG"
        ],
        "section": "4.1",
        "section_name": "Navigation - Bridge and Equipment",
        "objective": "To ensure that the bridge was continually manned throughout a voyage, and at anchor, by vigilant  watchkeeping staff.  Industry Guidance   ICS: Bridge Procedures Guide. Fifth Edition.  Chapter 3.5 Bridge Navigational Watch Alarm System  The Bridge Navigational Watch Alarm System (BNWAS) should be in",
        "risk": "high",
        "evidence": [
          "The company procedures for the use and testing of the BNWAS.",
          "Bridge Log Book.",
          "Bridge checklists."
        ],
        "negative_grounds": [
          "There was no company procedure for operating and testing the Bridge Navigation Watch Alarm System",
          "(BNWAS) fitted to the vessel.",
          "The accompanying navigation officer was unfamiliar with the company procedure for the operation and",
          "testing of the BNWAS.",
          "The BNWAS was defective in any respect."
        ]
      },
      {
        "id": "C4Q4_1_6",
        "number": "4.1.6",
        "text": "Were the Master and navigation officers familiar with the company procedures  governing the management and operation of the Global Navigation Satellite System  (GNSS) receivers fitted onboard and was the fitted equipment configured, used and  checked in accordance with the procedure?",
        "short_text": "Global Navigation Satellite System(s)",
        "vessel_types": [
          "Oil",
          "Chemical",
          "LPG",
          "LNG"
        ],
        "section": "4.1",
        "section_name": "Navigation - Bridge and Equipment",
        "objective": "To ensure that Global Navigation Satellite System (GNSS) receivers provide reliable and accurate positional  information.  Industry Guidance  ICS: Bridge Procedures Guide. Fifth Edition.  Chapter 4.9 Electronic Position Fixing Systems  4.9.3 GNSS receivers  Whether as stand-alone equipment or as par",
        "risk": "high",
        "evidence": [
          "The company procedure that defined how GNSS units should be operated and managed",
          "Onboard records to demonstrate that the required checks and tests had been completed",
          "The measurements to allow the checking / reprogramming of the antenna offset position in the GNSS",
          "receiver configuration."
        ],
        "negative_grounds": [
          "There were no company procedures for operating and managing the GNSS receivers fitted.",
          "The accompanying navigation officer was unfamiliar with the GNSS receiver management and operation",
          "procedures, or the equipment fitted to the vessel.",
          "The GNSS receiver(s) were not configured in accordance with company requirements, or the antennae",
          "coordinates were incorrectly entered."
        ]
      },
      {
        "id": "C4Q4_1_7",
        "number": "4.1.7",
        "text": "Were the Master and navigation officers familiar with the company procedures for  operating and managing the echo sounder and were records maintained to demonstrate  that the equipment fitted to the vessel had been tested and operated in accordance with  the company expectations?",
        "short_text": "Echo sounder",
        "vessel_types": [
          "Oil",
          "Chemical",
          "LPG",
          "LNG"
        ],
        "section": "4.1",
        "section_name": "Navigation - Bridge and Equipment",
        "objective": "To ensure that the echo sounder is used  effectively to monitor the under-keel clearance.  Industry Guidance:   ICS Bridge Procedures Guide. Fifth Edition.  Chapter 4.5 Echo Sounders  The echo sounder should always be used when making a landfall and kept switched on in coastal and pilotage  waters. ",
        "risk": "high",
        "evidence": [
          "The company procedures for managing and operating the echo sounder and its associated recording",
          "device.",
          "Onboard records demonstrating that the echo sounder and its recording device were in operation as",
          "required by the company procedures.",
          "Onboard records demonstrating that the accuracy of the echo sounder had been verified."
        ],
        "negative_grounds": [
          "There were no procedures for managing and operating the echo sounder and its associated recording",
          "device.",
          "The accompanying navigation officer was unfamiliar with the company procedures for managing and",
          "operating the echo sounder and its associated recording device.",
          "The accompanying navigation officer was unfamiliar with the process to calculate the depth under the keel"
        ]
      },
      {
        "id": "C4Q4_1_8",
        "number": "4.1.8",
        "text": "Were the Master and navigation officers familiar with the company procedures for  the operation and testing of the speed and distance measuring devices fitted to the  vessel and were records available to demonstrate that periodic tests had been completed  as required by the procedures?",
        "short_text": "Speed and distance measuring devices",
        "vessel_types": [
          "Oil",
          "Chemical",
          "LPG",
          "LNG"
        ],
        "section": "4.1",
        "section_name": "Navigation - Bridge and Equipment",
        "objective": "To ensure that accurate speed data is available to navigational equipment.  Industry Guidance  ICS: Bridge Procedures Guide. Fifth Edition.  Chapter 4.4.2 Types of Speed Log.  Electromagnetic and doppler type logs can be either single-axis and measure speed in the fore and aft direction  (longitudin",
        "risk": "high",
        "evidence": [
          "The company procedures for the operation and testing of the speed and distance measuring devices fitted to",
          "the vessel.",
          "Records of the periodic accuracy and function tests for the speed and distance measuring devices fitted to",
          "the vessel.",
          "Records of periodic verification that the speed input to navigational equipment such as ARPA, AIS and",
          "ECDIS was accurate."
        ],
        "negative_grounds": [
          "There was no company procedure for the operation and testing of the speed and distance measuring",
          "devices fitted to the vessel.",
          "The accompanying navigation officer was not familiar with the company procedures for the operation and",
          "testing of the speed and distance measuring devices fitted to the vessel.",
          "Periodic tests to verify the accuracy and/functionality of the speed and distance measuring devices fitted to"
        ]
      },
      {
        "id": "C4Q4_1_9",
        "number": "4.1.9",
        "text": "Were the Master and navigation officers familiar with the company procedures for  the use and testing of the navigation lights and shapes, and was there evidence that the  navigation lights had been tested to confirm full functionality and correct visibility?",
        "short_text": "Navigation lights and shapes",
        "vessel_types": [
          "Oil",
          "Chemical",
          "LPG",
          "LNG"
        ],
        "section": "4.1",
        "section_name": "Navigation - Bridge and Equipment",
        "objective": "To ensure that the vessel always displays navigation lights & shapes in accordance with the International  Regulations for Preventing Collisions at Sea.  Industry Guidance   ICS: Bridge Procedures Guide. Fifth Edition.  Chapter 4.7 Navigation Lights and Signalling Equipment  The OOW is responsible f",
        "risk": "high",
        "evidence": [
          "The company procedures which defined the checks and tests required to be carried out on the navigation",
          "lights, navigation light controller and navigational shapes.",
          "Page 160 of 711 – SIRE 2.0 Question Library: Part 1 Version 1.0 (January 2022)",
          "Checklists to confirm that the checks and tests required to be conducted on the navigation lights (fixed and",
          "portable), navigation light controller and navigational shapes had been completed as required.",
          "The inventory of spare navigational lamps identifying the luminosity or wattage and the navigation lights to"
        ],
        "negative_grounds": [
          "There was no company procedure defining the checks and tests required to be carried out on the",
          "navigational lights, the navigational light controller and navigational shapes.",
          "The accompanying navigation officer was unfamiliar with the company procedure for conducting checks and",
          "tests on the navigation lights, the navigation light controller or navigational shapes.",
          "The navigation lights and navigation light controller had not been tested in accordance with the company"
        ]
      },
      {
        "id": "C4Q4_1_10",
        "number": "4.1.10",
        "text": "Were the Master and navigation officers familiar with the company procedure for  managing Marine Safety Information broadcasts by NAVTEX and SafetyNET and were  warnings affecting the vessel’s route plotted on the voyage charts?",
        "short_text": "NAVTEX and SafetyNET",
        "vessel_types": [
          "Oil",
          "Chemical",
          "LPG",
          "LNG"
        ],
        "section": "4.1",
        "section_name": "Navigation - Bridge and Equipment",
        "objective": "To ensure that broadcast navigation warnings affecting a vessel’s planned route are effectively managed.  Industry Guidance  ICS: Bridge Procedures Guide. Fifth Edition.  2.4.9 Maritime Safety Information  Weather information (including gale warnings), NAVAREA warnings and coastal navigational warni",
        "risk": "high",
        "evidence": [
          "The company procedure for managing Marine Safety Information received through NAVTEX and",
          "SafetyNET.",
          "NAVTEX and SafetyNET broadcast warnings filed in accordance with company procedures.",
          "Paper and electronic charts showing charted Marine Safety Information warnings."
        ],
        "negative_grounds": [
          "Page 163 of 711 – SIRE 2.0 Question Library: Part 1 Version 1.0 (January 2022)",
          "There was no company procedure for managing Marine Safety Information received through NAVTEX and",
          "SafetyNET.",
          "The accompanying navigation officer was unfamiliar with the company procedure for managing Marine",
          "Safety Information received through NAVTEX and SafetyNET, or the equipment fitted to the vessel."
        ]
      },
      {
        "id": "C4Q4_1_11",
        "number": "4.1.11",
        "text": "Were the Master and navigation officers familiar with the company procedure for  preserving data from the VDR/S-VDR and were records available to demonstrate that  tests of the equipment had been completed as required?",
        "short_text": "Preserving data from the VDR/S-VDR",
        "vessel_types": [
          "Oil",
          "Chemical",
          "LPG",
          "LNG"
        ],
        "section": "4.1",
        "section_name": "Navigation - Bridge and Equipment",
        "objective": "To ensure that the VDR fitted to the vessel is continually recording all required data streams and procedures  are in place to preserve records in the event of an incident.  Industry Guidance:   ICS: Bridge Procedures Guide. Fifth Edition.  Chapter 4.8 Voyage Date Recorder.  4.8.3 Preserving Records",
        "risk": "high",
        "evidence": [
          "The company procedure which governed the setup, use and testing of the VDR / S-VDR system fitted",
          "onboard the vessel.",
          "The company procedure that defined when data was required to be preserved to support investigations into",
          "navigation and any other incidents onboard.",
          "At least one emergency response checklist from the vessel operator’s response plan indicating that VDR /",
          "S-VDR data preservation was required."
        ],
        "negative_grounds": [
          "There were no company procedure which governed the setup, use and testing of the VDR / S-VDR system",
          "fitted onboard the vessel.",
          "There was no company procedure which clearly defined the company expectation for data preservation in",
          "the event of an incident onboard.",
          "The accompanying navigation officer was unfamiliar with the company procedures for VDR / S-VDR"
        ]
      },
      {
        "id": "C4Q4_1_12",
        "number": "4.1.12",
        "text": "Were the Master and navigation officers familiar with the company procedures  relating to the magnetic and gyro compasses carried onboard, and were records  available to demonstrate their accuracy and reliability?",
        "short_text": "Magnetic and gyro compasses",
        "vessel_types": [
          "Oil",
          "Chemical",
          "LPG",
          "LNG"
        ],
        "section": "4.1",
        "section_name": "Navigation - Bridge and Equipment",
        "objective": "To ensure that standard, gyro and GNSS compasses and their heading output to navigational equipment are  accurate and reliable  Industry Guidance  ICS: Bridge Procedures Guide. Fifth Edition.  Chapter 4.3 Compass Systems  4.3.2 Gyro compass  The gyro compass should be run continuously. Should a gyro",
        "risk": "high",
        "evidence": [
          "The company procedures for standard, gyro and GNSS compass management",
          "The standard compass adjustment and residual deviation certificate.",
          "Compass error records.",
          "Service records for the gyro compass(s)."
        ],
        "negative_grounds": [
          "There were no company procedures for managing the standard magnetic, gyro and GNSS compasses as",
          "applicable.",
          "The accompanying navigation officer was unfamiliar with the company procedures, or the equipment fitted to",
          "the vessel.",
          "A record of compass error for each compass fitted to the vessel was not maintained as required by the"
        ]
      },
      {
        "id": "C4Q4_1_13",
        "number": "4.1.13",
        "text": "Were the Master and navigation officers familiar with the company procedures for  the operation and testing of the VHF/DSC transceivers fitted to the vessel, and were  records available to demonstrate that periodic tests and checks had been completed in  accordance with company expectations?",
        "short_text": "VHF/DSC transceivers",
        "vessel_types": [
          "Oil",
          "Chemical",
          "LPG",
          "LNG"
        ],
        "section": "4.1",
        "section_name": "Navigation - Bridge and Equipment",
        "objective": "To ensure that VHF radio is used to enhance navigation safety and support the obligations of the vessel  under SOLAS to render assistance to non-SOLAS vessels in distress.  Industry Guidance  ICS: Bridge Procedures Guide. Fifth Edition.  Section 3.15 GMDSS watchkeeping  3.15.1 Radio watchkeeping  Th",
        "risk": "high",
        "evidence": [
          "The company procedures for the use and operation of the VHF/DSC equipment fitted to the vessel.",
          "The GMDSS Radio Log Book or other records which documented which VHF channels were being",
          "monitored and details of significant communications.",
          "The Master’s standing orders.",
          "Checklists that demonstrated that periodic checks and tests required to be carried out on the",
          "communications equipment, including VHF/DSC units had been completed as required by the company"
        ],
        "negative_grounds": [
          "There was no company procedure which defined the expectations for the use and periodic testing of the",
          "VHF/DSC units fitted to the vessel.",
          "The accompanying navigation officer was unfamiliar with the company procedure for the use or testing of the",
          "VHF/DSC units fitted to the vessel.",
          "The accompanying navigation officer was unfamiliar with the operation of the VHF/DSC units fitted to the"
        ]
      },
      {
        "id": "C4Q4_1_14",
        "number": "4.1.14",
        "text": "Were the Master and navigation officers familiar with the company procedure for  testing and using the daylight signalling lamp?",
        "short_text": "Daylight signalling lamp",
        "vessel_types": [
          "Oil",
          "Chemical",
          "LPG",
          "LNG"
        ],
        "section": "4.1",
        "section_name": "Navigation - Bridge and Equipment",
        "objective": "To ensure that there is a means of attracting the attention of other vessels by visual means both during  daylight and during darkness.  Industry Guidance  ICS: Bridge Procedures Guide. Fifth Edition.  Chapter 3.12 Compliance with the COLREGs.  The conduct of a ship’s navigation should always comply",
        "risk": "high",
        "evidence": [
          "The procedure which defined the company expectations for the use and testing of the daylight signalling",
          "lamp.",
          "The bridge equipment testing records demonstrating that periodic tests had been carried out for the daylight",
          "signalling lamp."
        ],
        "negative_grounds": [
          "There was no procedure which defined the company expectations for the use and testing of the daylight",
          "signalling lamp.",
          "The accompanying navigation officer was unfamiliar with the company procedure for the use and testing of",
          "the daylight signalling lamp.",
          "The daylight signalling lamp was defective in any respect."
        ]
      },
      {
        "id": "C4Q4_1_15",
        "number": "4.1.15",
        "text": "Were the Master and navigation officers familiar with the company procedures for  the use and testing of the sound signalling equipment fitted to the vessel and were  records available to confirm that periodic tests had been completed and the equipment  used in accordance with company expectations?",
        "short_text": "Sound signalling equipment",
        "vessel_types": [
          "Oil",
          "Chemical",
          "LPG",
          "LNG"
        ],
        "section": "4.1",
        "section_name": "Navigation - Bridge and Equipment",
        "objective": "To ensure that the vessel was able to make sound signals to comply with the International Regulations for  Preventing Collisions at Sea (COLREG).  Industry Guidance  ICS: Bridge Procedures Guide. Fifth Edition.  Section 3.12 Compliance with the COLREGS.  The conduct of a ship’s navigation should alw",
        "risk": "high",
        "evidence": [
          "The company procedures which defined the expectations for the use and testing of sound signalling",
          "equipment fitted to the vessel.",
          "Bridge Log Book.",
          "Completed bridge checklists including restricted visibility and bridge equipment testing.",
          "The accompanying officer should be ready to show the inspector the evidence for the previous three occasions where",
          "the sound signalling equipment was used during restricted visibility."
        ],
        "negative_grounds": [
          "There was no company procedure which defined the company expectation for the use of sound signals",
          "during restricted visibility, collision avoidance and manoeuvring in compliance with the COLREGs.",
          "The accompanying navigation officer was unfamiliar with the company expectation for the use of sound",
          "signals during restricted visibility, collision avoidance and manoeuvring in compliance with the COLREGs.",
          "There were no records available to demonstrate that the sound signalling equipment and any automation"
        ]
      },
      {
        "id": "C4Q4_2_1",
        "number": "4.2.1",
        "text": "Were the Master and navigating officers familiar with the company passage  planning procedures and had all voyages been appraised, planned, executed and  monitored in accordance with company procedures, industry best practice and both  local and international rules?",
        "short_text": "Passage planning",
        "vessel_types": [
          "Oil",
          "Chemical",
          "LPG",
          "LNG"
        ],
        "section": "4.2",
        "section_name": "Navigation - Watchkeeping",
        "objective": "To ensure that passages are planned and executed from berth to berth in accordance with international/local  rules and industry best practice guidance.  Industry Guidance   OCIMF: Recommendations on Usage of ECDIS and Preventing Incidents. First Edition.  4.2.2 Berth-to-berth passage plan  The IMO A",
        "risk": "high",
        "evidence": [
          "The company passage planning procedures.",
          "The company record keeping procedures relating to navigational activities.",
          "The company passage plan appraisal form / checklist for a recently completed voyage.",
          "The passage plan for a recently completed voyage approved by the Master and signed by the navigation",
          "officers.",
          "The ECDIS passage planning station and/or paper charts showing the reviewed passage plan and"
        ],
        "negative_grounds": [
          "There were no company passage planning procedures.",
          "There were no company record keeping procedures relating to navigational activities.",
          "The accompanying navigation officer was not familiar with the company passage planning or navigational",
          "record keeping procedures.",
          "There was no standard passage planning form which required the passage plan to be documented in a"
        ]
      },
      {
        "id": "C4Q4_2_2",
        "number": "4.2.2",
        "text": "Were the Master and navigation officers familiar with the company under keel  clearance (UKC) policy and procedure, and were records available to demonstrate that  the required calculations had been completed at the appropriate points during each  voyage and the vessel had remained in compliance with the UKC policy?",
        "short_text": "Under keel clearance (UKC) policy",
        "vessel_types": [
          "Oil",
          "Chemical",
          "LPG",
          "LNG"
        ],
        "section": "4.2",
        "section_name": "Navigation - Watchkeeping",
        "objective": "To ensure that the vessel always maintains a safe under keel clearance.",
        "risk": "high",
        "evidence": [
          "The company procedure that defined the company under keel clearance (UKC) policy and the requirement",
          "for conducting calculations and recording the results.",
          "The passage planning documentation for recent voyages.",
          "The UKC calculation documentation to support recent voyages.",
          "Master/Pilot information exchange documentation which included the supporting UKC calculations.",
          "Bridge Log Books, bell books, echo sounder records and charted passage history to permit verification of"
        ],
        "negative_grounds": [
          "There was no procedure defining the company under keel clearance (UKC) policy and expectations for",
          "conducting UKC calculations at defined stages of the voyage.",
          "The accompanying officer was not familiar with the company procedure for conducting and documenting",
          "UKC calculations.",
          "Review of records indicated that the UKC calculations required to be carried out by the company procedures"
        ]
      },
      {
        "id": "C4Q4_2_3",
        "number": "4.2.3",
        "text": "Had the Master prepared Master's Standing Orders, supplemented by Daily Orders,  which emphasised and reinforced the company expectations with regards to navigational  requirements including restricted visibility, CPA/BCR and minimum passing distance  from navigational dangers and navigational aids and, if so, had all navigation officers  signed to acknowledge their understanding of the same?",
        "short_text": "Master's Standing Orders and Daily Orders",
        "vessel_types": [
          "Oil",
          "Chemical",
          "LPG",
          "LNG"
        ],
        "section": "4.2",
        "section_name": "Navigation - Watchkeeping",
        "objective": "To ensure that all deck/navigating officers are aware of the key expectations of both the company and the  Master with respect to the navigation of the vessel.  Industry Guidance  ICS: Bridge Procedures Guide. Fifth Edition.  1.3.2.1 Master’s Standing Orders  Lines of authority on board should be in",
        "risk": "high",
        "evidence": [
          "The company procedure defining the requirement for the Master to develop their own Standing and Daily",
          "Orders.",
          "The Master’s Standing Orders signed by the Master and all navigation officers.",
          "The Bridge Order Book with each dated and timed entry signed by the Master, and subsequently, each",
          "OOW before taking over their watch."
        ],
        "negative_grounds": [
          "There was no procedure which required the Master to prepare Standing or Daily Orders.",
          "The accompanying officer was unfamiliar with the content of the Master’s Standing or Daily Orders.",
          "The Master had not prepared their own Standing Orders which were signed and dated on being assigned to",
          "the vessel or at subsequent update.",
          "The navigation officers onboard at the time of the inspection had not signed the Master's Standing Orders"
        ]
      },
      {
        "id": "C4Q4_2_4",
        "number": "4.2.4",
        "text": "Were the Master and navigation officers familiar with the company electronic chart  management procedures and were onboard ENCs and RNCs managed, corrected and  used appropriately?",
        "short_text": "Electronic chart management.",
        "vessel_types": [
          "Oil",
          "Chemical",
          "LPG",
          "LNG"
        ],
        "section": "4.2",
        "section_name": "Navigation - Watchkeeping",
        "objective": "To ensure that only fully corrected official electronic charts are used for navigation where ECDIS is required  to be carried  Industry Guidance  ICS: Bridge Procedures Guide. Fifth Edition.  Chapter 4.12. Charts and Nautical Publications.  Only up to date official charts and publications should be ",
        "risk": "high",
        "evidence": [
          "The company procedure that defined how ENCs and RNCs were to be managed",
          "The onboard records identifying which ENCs and RNCs were active with current permits or were available",
          "on a Pay As You Sail (PAYS) basis.",
          "ENC Status Report, where available.",
          "The previous voyage passage plan records showing which ENCs and RNCs had been used.",
          "Where ENC coverage was incomplete for a recent voyage, passage planning records demonstrating how"
        ],
        "negative_grounds": [
          "There were no company procedures for managing ENCs and RNCs",
          "The declaration relating to the primary means of navigation was incorrect",
          "The accompanying navigation officer was unfamiliar with the electronic chart management and correction",
          "procedures.",
          "The accompanying navigation officer was unfamiliar with the process for applying T&P notices to ENCs and"
        ]
      },
      {
        "id": "C4Q4_2_5",
        "number": "4.2.5",
        "text": "Were the Master and navigation officers familiar with the company paper chart  management procedures and were onboard paper charts managed, corrected and used  appropriately?",
        "short_text": "Paper chart management",
        "vessel_types": [
          "Oil",
          "Chemical",
          "LPG",
          "LNG"
        ],
        "section": "4.2",
        "section_name": "Navigation - Watchkeeping",
        "objective": "To ensure that the only fully corrected official paper charts are used for navigation when required to be  carried or used.  Industry Guidance  ICS: Bridge Procedures Guide. Fifth Edition.  Chapter 4.12 Charts and Nautical Publications  4.12.1 Carriage Of Charts And Nautical Publications  It is requ",
        "risk": "high",
        "evidence": [
          "The company procedures for paper chart management.",
          "The paper chart portfolio records.",
          "Page 197 of 711 – SIRE 2.0 Question Library: Part 1 Version 1.0 (January 2022)",
          "The paper chart correction records.",
          "Recent passage plan records showing which paper charts had been used.",
          "The paper charts, where applicable, used on the previous passage"
        ],
        "negative_grounds": [
          "There was no company procedure for managing paper charts.",
          "The accompanying navigation officer was unfamiliar with the paper chart management and correction",
          "procedures.",
          "The vessel had completed a voyage with missing or inappropriate scale charts without any evidence that the",
          "company had been involved in identifying mitigating actions."
        ]
      },
      {
        "id": "C4Q4_2_6",
        "number": "4.2.6",
        "text": "Were the Master and navigation officers familiar with the company procedures for  testing the navigational equipment, main propulsion, steering gear and thrusters prior to  use and prior to critical phases of a passage or operation and, did checklists or logbook  entries confirm the required tests had been completed as required?",
        "short_text": "Testing navigational equipment, main propulsion, steering gear and thrusters",
        "vessel_types": [
          "Oil",
          "Chemical",
          "LPG",
          "LNG"
        ],
        "section": "4.2",
        "section_name": "Navigation - Watchkeeping",
        "objective": "To ensure that navigational equipment and manoeuvring machinery is confirmed as fully operational prior to  critical phases of a passage or operation.  Industry Guidance  ICS: Bridge Procedures Guide. Fifth Edition.  Chapter 3.18 Periodic Checks of Navigational Equipment.  3.18.1 Operational checks ",
        "risk": "high",
        "evidence": [
          "The company procedures which defined the requirements for testing navigational equipment and",
          "manoeuvring machinery.",
          "Completed checklists for the testing of navigational equipment and manoeuvring machinery for recent",
          "voyages.",
          "Bridge Log Book.",
          "Engine Log Book."
        ],
        "negative_grounds": [
          "There was no procedure that required navigational equipment and manoeuvring equipment to be",
          "functionally tested at defined points prior to and during a voyage or operation.",
          "The accompanying navigation officer was not familiar with the company procedures for testing navigational",
          "equipment and manoeuvring equipment.",
          "Page 201 of 711 – SIRE 2.0 Question Library: Part 1 Version 1.0 (January 2022)"
        ]
      },
      {
        "id": "C4Q4_2_7",
        "number": "4.2.7",
        "text": "Were the Master and navigation officers familiar with the company procedure for  the carriage and management of nautical publications and was evidence available to  demonstrate that publications had been managed in accordance with the procedure?",
        "short_text": "Nautical publications",
        "vessel_types": [
          "Oil",
          "Chemical",
          "LPG",
          "LNG"
        ],
        "section": "4.2",
        "section_name": "Navigation - Watchkeeping",
        "objective": "To ensure nautical publications used for navigational purposes provide the most accurate information  available.  Industry Guidance  ICS: Bridge Procedures Guide. Fifth Edition.  Chapter 2.3.2 Official Nautical Publications and Additional Information.  A full appraisal of the passage plan should inc",
        "risk": "high",
        "evidence": [
          "The nautical publications.",
          "The company procedure for managing, ordering and updating nautical publications.",
          "The inventory of nautical publications indicating their edition date and latest correction applied, where",
          "applicable.",
          "Where electronic publications were carried to comply with SOLAS Chapter V Regulation 27, evidence that",
          "the publications were approved by flag and the means of back up were in accordance with the Safety"
        ],
        "negative_grounds": [
          "There was no company procedure for managing, ordering and updating nautical publications.",
          "The accompanying navigation officer was unfamiliar with the company procedure for managing, ordering",
          "and updating nautical publications.",
          "There was no inventory of mandatory and discretionary nautical publications required to be carried.",
          "Nautical publications required to be carried, in either electronic or hard copy, in accordance with the"
        ]
      },
      {
        "id": "C4Q4_3_1",
        "number": "4.3.1",
        "text": "Were the Master and navigation officers familiar with the company procedures  defining the minimum bridge team composition and engine room operating mode and  were records available to demonstrate that recent voyages had been planned and  executed in accordance with company expectations?",
        "short_text": "Minimum bridge team composition",
        "vessel_types": [
          "Oil",
          "Chemical",
          "LPG",
          "LNG"
        ],
        "section": "4.3",
        "section_name": "Navigation - Passage Planning",
        "objective": "To ensure that the bridge team is adequately resourced, and the machinery space operated appropriately at  all stages of a voyage including while at anchor, conducting STS operations or drifting.  Industry Guidance   ICS: Bridge Procedures Guide. Fifth Edition.  Section 1 Effective Bridge Organizati",
        "risk": "high",
        "evidence": [
          "The company procedure(s) that defined bridge team composition and machinery space operating mode",
          "during all stages of a voyage .",
          "Passage plan documentation for recent voyages, (not necessarily the last voyage).",
          "Bridge Log Book, bell books, bridge checklists and any other supporting bridge records, either paper or",
          "electronic,"
        ],
        "negative_grounds": [
          "Page 207 of 711 – SIRE 2.0 Question Library: Part 1 Version 1.0 (January 2022)",
          "There was no procedure defining the required bridge team composition during all stages of a voyage,",
          "including while at anchor, drifting, or conducting “at sea” STS operations, DP operations or underway",
          "storing/personnel transfer operations, considering traffic density, proximity to navigational hazards, weather",
          "conditions and visibility."
        ]
      },
      {
        "id": "C4Q4_3_2",
        "number": "4.3.2",
        "text": "Were the engineer officers familiar with the company procedures defining  machinery space operating mode and, where required to be attended, the machinery  space team composition during the various stages of a voyage, and were records  available to confirm the machinery space had been operated accordingly?",
        "short_text": "Machinery space team composition",
        "vessel_types": [
          "Oil",
          "Chemical",
          "LPG",
          "LNG"
        ],
        "section": "4.3",
        "section_name": "Navigation - Passage Planning",
        "objective": "To ensure that the machinery space is adequately manned or monitored at all stages of a voyage or  operation.  Industry Guidance   ICS: Engine Room Procedures Guide. First Edition.  7.1 Manning Level Changes  The Chief Engineer or designated representative should increase manning levels when require",
        "risk": "high",
        "evidence": [
          "The company procedure that defined the required machinery space status during all stages of a voyage,",
          "including while at anchor, considering traffic density, proximity to navigational hazards and the state of",
          "visibility.",
          "The company procedure that defined the required machinery space team composition considering traffic",
          "density, proximity to navigational hazards and the state of visibility and, during other operations such drifting,",
          "“at sea” STS operations, Dynamically Positioned (DP) cargo operations or underway stores / personnel"
        ],
        "negative_grounds": [
          "There was no procedure defining company expectations for operating the machinery space in either the",
          "unattended or attended mode considering traffic density, proximity to navigational hazards and state of",
          "visibility and, other operations such as at while at anchor, drifting, “at sea” STS operations, Dynamically",
          "Positioned (DP) cargo operations or underway stores / personnel transfer operations.",
          "There was no company procedure which defined the required machinery space team composition"
        ]
      },
      {
        "id": "C4Q4_3_3",
        "number": "4.3.3",
        "text": "Were the Master and navigation officers familiar with the company procedures for  integrating a pilot (or similar role*) into the bridge team and were records available to  demonstrate that the process had been followed?",
        "short_text": "Integrating a pilot (or similar role) into the bridge team",
        "vessel_types": [
          "Oil",
          "Chemical",
          "LPG",
          "LNG"
        ],
        "section": "4.3",
        "section_name": "Navigation - Passage Planning",
        "objective": "To ensure that there is an effective process to integrate the pilot (or similar role*) into the bridge team.  Industry Guidance  ICS: Bridge Procedures Guide. Fifth Edition.  5 Pilotage  5.1 Overview  Efficient pilotage will depend on:  •  Effective communication between the Master, Bridge Team and ",
        "risk": "high",
        "evidence": [
          "The company procedure for integrating a pilot* into the bridge team.",
          "The Master/Pilot information exchange and pilot card checklists for recent operations.",
          "The Bridge Log Book, bell book and other operational records covering recent operations."
        ],
        "negative_grounds": [
          "There was no procedure for integrating a pilot* into the bridge team.",
          "The vessel operator had not developed Master/Pilot information and/or pilot card checklists for use onboard.",
          "The accompanying navigation officer was not fully familiar with the company procedure for integrating a",
          "pilot* into the bridge team.",
          "The accompanying navigation officer was not familiar with the practical requirements for each item included"
        ]
      },
      {
        "id": "C4Q4_3_4",
        "number": "4.3.4",
        "text": "Were the Master and navigation officers familiar with the company procedures to  prevent disruption and distraction on the bridge, and were these procedures being  complied with?",
        "short_text": "Bridge distractions.",
        "vessel_types": [
          "Oil",
          "Chemical",
          "LPG",
          "LNG"
        ],
        "section": "4.3",
        "section_name": "Navigation - Passage Planning",
        "objective": "To ensure that the bridge team can always maintain a safe navigational watch, free from disruption and  distraction.   Industry Guidance  ICS: Bridge Procedures Guide – Fifth Edition  1.2.7 Duties within the Bridge Team  Maintaining Bridge Team performance will be aided by a bridge environment which",
        "risk": "high",
        "evidence": [
          "Company procedures to prevent disruption and distraction on the bridge.",
          "Page 216 of 711 – SIRE 2.0 Question Library: Part 1 Version 1.0 (January 2022)"
        ],
        "negative_grounds": [
          "There were no company procedures to prevent disruption and distraction on the bridge including guidance",
          "on:",
          "o",
          "Bridge access by personnel with no operational bridge responsibilities.",
          "o"
        ]
      },
      {
        "id": "C4Q4_4_1",
        "number": "4.4.1",
        "text": "Were the Master and officers familiar with the operation of the Emergency Position  Indicating Radio Beacon (EPIRB) and was the EPIRB in good order with records available  to demonstrate that had it been inspected, tested and maintained as required?",
        "short_text": "Emergency Position Indicating Radio Beacon (EPIRB)",
        "vessel_types": [
          "Oil",
          "Chemical",
          "LPG",
          "LNG"
        ],
        "section": "4.4",
        "section_name": "Navigation - Anchoring",
        "objective": "To ensure the Emergency Position Indicating Radio Beacon (EPIRB) will function correctly in an emergency.  Industry Guidance  IMO: MSC.1/Circ.1039 Guidelines for shore-based maintenance of satellite EPIRBs  4 Maintenance service interval  4.1 406 MHz satellite EPIRBs should be inspected and tested i",
        "risk": "high",
        "evidence": [
          "The company procedure to ensure that EPIRBs were periodically inspected, tested and maintained and",
          "ready for immediate use in an emergency.",
          "The GMDSS Radio Log Book.",
          "Records of periodic inspections, tests and maintenance of the EPIRB."
        ],
        "negative_grounds": [
          "The accompanying officer was unfamiliar with the required inspection and testing of the EPIRB.",
          "The accompanying officer was unable to explain:",
          "o",
          "How to perform the self-test.",
          "o"
        ]
      },
      {
        "id": "C4Q4_4_2",
        "number": "4.4.2",
        "text": "Were the Master and officers familiar with the operation of the Search and Rescue  Transmitters (SARTs), and were the SARTs in good order with records available to  demonstrate that had they had been inspected and tested as required?",
        "short_text": "Search and Rescue Transmitters (SARTs)",
        "vessel_types": [
          "Oil",
          "Chemical",
          "LPG",
          "LNG"
        ],
        "section": "4.4",
        "section_name": "Navigation - Anchoring",
        "objective": "To ensure the Search and Rescue Transmitters (SARTs) will function correctly in an emergency.  Industry Guidance  IMO: Resolution A.802(19) Recommendation on performance standards for survival craft radar transponders  for use in search and rescue operations   2 General  The SART should be capable o",
        "risk": "high",
        "evidence": [
          "The company procedure to ensure that SARTs were periodically inspected, tested and ready for immediate",
          "use in an emergency.",
          "The GMDSS Radio Log Book.",
          "Records of periodic inspections and tests of the SART(s)."
        ],
        "negative_grounds": [
          "Page 224 of 711 – SIRE 2.0 Question Library: Part 1 Version 1.0 (January 2022)",
          "There was no company procedure to ensure that SARTs were periodically inspected, tested and ready for",
          "immediate use in an emergency.",
          "The accompanying officer was unfamiliar with the purpose and operation of the SARTs.",
          "The accompanying officer was unable to explain/demonstrate how to mount a SART on a lifeboat or liferaft."
        ]
      },
      {
        "id": "C4Q4_4_3",
        "number": "4.4.3",
        "text": "Were the Master and officers familiar with the location, purpose and operation of  the survival craft portable two-way VHF radios and were they in good order with records  available to demonstrate that had they been inspected and tested as required?",
        "short_text": "Survival craft portable two-way VHF radios",
        "vessel_types": [
          "Oil",
          "Chemical",
          "LPG",
          "LNG"
        ],
        "section": "4.4",
        "section_name": "Navigation - Anchoring",
        "objective": "To ensure the survival craft portable two-way VHF radios will function correctly in an emergency.  Industry Guidance  IMO: Resolution MSC.149(77) Adoption of the revised performance standards for survival craft portable two- way vhf radiotelephone apparatus  2.1 The equipment should be portable and ",
        "risk": "high",
        "evidence": [
          "The company procedure to ensure survival craft portable two-way vhf radios were periodically inspected and",
          "tested and ready for immediate use in an emergency.",
          "The GMDSS Radio Log Book.",
          "Records of periodic inspections and tests of the survival craft portable two-way VHF radios."
        ],
        "negative_grounds": [
          "There was no company procedure to ensure that survival craft portable two-way VHF radios were",
          "periodically inspected, tested and ready for immediate use in an emergency.",
          "Company procedures did not provide guidance on the use of the survival craft portable two-way VHF radios",
          "for non-emergency communications.",
          "The accompanying officer was unfamiliar with the purpose and operation of the survival craft portable two-"
        ]
      },
      {
        "id": "C4Q4_4_4",
        "number": "4.4.4",
        "text": "Were the Master and navigation officers familiar with the procedures for sending  and receiving distress, urgency and safety messages and were suitable instructions  posted by the GMDSS equipment?",
        "short_text": "Sending and receiving distress, urgency and safety messages",
        "vessel_types": [
          "Oil",
          "Chemical",
          "LPG",
          "LNG"
        ],
        "section": "4.4",
        "section_name": "Navigation - Anchoring",
        "objective": "To ensure effective communications will be made by the vessel in an emergency situation.  Industry Guidance  ICS: Bridge Procedures Guide – Fifth Edition  3.15 GMDSS Watchkeeping  To enable a ship to send and receive distress, urgency and safety information, the OOW should hold a General or  restric",
        "risk": "high",
        "evidence": [
          "The company procedures for emergency communications.",
          "The GMDSS Radio Log Book.",
          "International Aeronautical and Maritime Search and Rescue Manual (IAMSAR) Vol III.",
          "Page 230 of 711 – SIRE 2.0 Question Library: Part 1 Version 1.0 (January 2022)"
        ],
        "negative_grounds": [
          "There were no company procedures for emergency communications which gave guidance on, and",
          "designated responsibility for, distress communications in an emergency situation.",
          "A qualified GMDSS operator had not been designated in the emergency station bill as being responsible for",
          "radio communications in a distress.",
          "Instructions for the preparation and transmission of distress and urgency messages using the GMDSS"
        ]
      },
      {
        "id": "C4Q4_4_5",
        "number": "4.4.5",
        "text": "Were the Master and navigation officers familiar with the operation, testing and  maintenance of the GMDSS VHF, MF and HF radio and satellite communications  equipment and were records available to demonstrate the equipment was in good order?",
        "short_text": "Operation and testing of GMDSS station.",
        "vessel_types": [
          "Oil",
          "Chemical",
          "LPG",
          "LNG"
        ],
        "section": "4.4",
        "section_name": "Navigation - Anchoring",
        "objective": "To ensure effective communications in routine or emergency situations.  Industry Guidance  ICS: Bridge Procedures Guide. 5th Edition.  3.15.5 GMDSS Log keeping  A GMDSS radio log should be kept in order to provide a record of all events connected with the radio  communications facilities on board. A",
        "risk": "high",
        "evidence": [
          "The company procedures for the operation, testing, maintenance and log keeping of the GMDSS VHF, MF",
          "and HF radio and satellite communications equipment.",
          "The GMDSS Radio Log Book.",
          "A copy of the record of equipment for the cargo ship safety radio certificate Form R or Form C.",
          "Test and maintenance records for the GMDSS reserve batteries.",
          "Any shore-based maintenance agreement for the GMDSS equipment."
        ],
        "negative_grounds": [
          "There were no company procedures for the operation, testing, maintenance and log keeping of the GMDSS",
          "VHF, MF and HF radio and satellite communications equipment.",
          "The accompanying officer was unfamiliar with the operation of the GMDSS VHF, MF and HF radio and",
          "satellite communications equipment.",
          "The accompanying officer was unable to describe the daily, weekly and monthly radio tests required in"
        ]
      },
      {
        "id": "C4Q4_4_6",
        "number": "4.4.6",
        "text": "Were the Master, officers and crew aware of the potential danger of using radio or  mobile telephone equipment during cargo and ballast handling operations and was there  a sufficient number of intrinsically safe portable radios for use in operational areas?",
        "short_text": "Use of radio or mobile telephone equipment during cargo and ballast handling",
        "vessel_types": [
          "Oil",
          "Chemical",
          "LPG",
          "LNG"
        ],
        "section": "4.4",
        "section_name": "Navigation - Anchoring",
        "objective": "To ensure a hazard is never created by the inappropriate use of radio or mobile telephone equipment during  cargo or ballast operations.  Industry Guidance  OCIMF/ICS: International Safety Guide for Oil Tankers and Terminals. Sixth Edition  4.12.5 Mobile telephones and pagers  Most mobile telephones",
        "risk": "high",
        "evidence": [
          "The procedure for the safe use of radio and telephone equipment during cargo and ballast handling",
          "operations.",
          "Certification for any intrinsically safe mobile phones in use outside of the accommodation block.",
          "The inventory of intrinsically safe portable VHF/UHF radios used for cargo, ballast and bunker operations."
        ],
        "negative_grounds": [
          "Page 239 of 711 – SIRE 2.0 Question Library: Part 1 Version 1.0 (January 2022)",
          "There were no company procedures for the safe use of radio and telephone equipment during cargo and",
          "ballast handling operations.",
          "The Master, an officer or a rating was unfamiliar with the company procedures for the safe use of radio and",
          "telephone equipment during cargo and ballast handling operations."
        ]
      },
      {
        "id": "C4Q4_5_1",
        "number": "4.5.1",
        "text": "Was the latest Annual DP Trial report available on board, were the Master and  officers familiar with the contents, and had they taken part in onboard training and drills  involving various DP scenarios?",
        "short_text": "Annual DP Trial report and supporting exercises.",
        "vessel_types": [
          "Oil"
        ],
        "section": "4.5",
        "section_name": "Navigation - Emergency Procedures",
        "objective": "To ensure that the vessel’s DP system is fully operational, and that the vessel is fault tolerant according to  the equipment class requirements.  Industry Guidance  IMCA: M 190 Guidance for Developing and Conducting Annual DP Trials Programmes for DP Vessels. Rev 2.1  4 Development of the DP Annual",
        "risk": "high",
        "evidence": [
          "The latest Annual DP Trials report.",
          "If the Annual DP trials were being carried out as part of a rolling test programme over the year, test sheets",
          "and/or other documented evidence of compliance from the Planned Maintenance System.",
          "Previous Annual DP Trials reports.",
          "Records of training and/or drills involving DP scenarios."
        ],
        "negative_grounds": [
          "There were no company procedures giving guidance on the performance of Annual DP Trials.",
          "The latest DP Annual Trials report was not available on board.",
          "Previous Annual DP Trials reports were not available on board.",
          "The latest DP Annual Trials had not been carried out within three months before/after the anniversary date",
          "of the initial FMEA proving trial."
        ]
      },
      {
        "id": "C4Q4_5_2",
        "number": "4.5.2",
        "text": "Were the Master and officers familiar with the company procedures for the use of  Position Reference Systems (PRS), and was the equipment in satisfactory condition with  sensor offset data readily available to the DPO?",
        "short_text": "DP Position Reference Systems",
        "vessel_types": [
          "Oil"
        ],
        "section": "4.5",
        "section_name": "Navigation - Emergency Procedures",
        "objective": "To ensure Position Reference Systems are in satisfactory condition with sensor offset data readily available  to the DPO.  Industry Guidance  OCIMF Guidelines for Offshore Tanker Operations  6.6.8 Position Reference System  It is recommended that in accordance with other critical DP operations, when",
        "risk": "high",
        "evidence": [
          "Company procedures for the use of Position Reference Systems during DP operations at each offtake",
          "location.",
          "Sensor offset data file.",
          "DP logbook.",
          "DP data log."
        ],
        "negative_grounds": [
          "There were no company procedures for the use of Position Reference Systems during DP operations at",
          "each offtake location.",
          "The accompanying officer was not familiar with the company procedures for the use of Position Reference",
          "Systems during DP operations at each offtake location.",
          "One or more of the PRS was not in satisfactory operational condition."
        ]
      },
      {
        "id": "C4Q4_5_3",
        "number": "4.5.3",
        "text": "Were the Master and officers familiar with the company procedures for reporting  and recording DP events and incidents, and were all DP parameters being logged and  recorded?",
        "short_text": "DP events and incidents",
        "vessel_types": [
          "Oil"
        ],
        "section": "4.5",
        "section_name": "Navigation - Emergency Procedures",
        "objective": "To ensure DP events and incidents are recorded, reported and investigated, and lessons learnt from  incidents used to increase industry safety standards.  Industry Guidance  OCIMF: Dynamic Positioning Failure Mode Effect Analysis Assurance Framework Risk-based Guidance 1st  Ed 2020  2.1 Introduction",
        "risk": "high",
        "evidence": [
          "Company procedures for recording, reporting and investigating DP related incidents, undesired events and",
          "observations.",
          "Records of DP related incidents, undesired events and observations.",
          "Independent data logger records.",
          "DP fault log."
        ],
        "negative_grounds": [
          "Page 251 of 711 – SIRE 2.0 Question Library: Part 1 Version 1.0 (January 2022)",
          "There were no company procedures for recording, reporting and investigating DP related incidents,",
          "undesired events and observations.",
          "DP related incidents, undesired events and observations had not been reported according to the vessel’s",
          "ISM system or via the method set out in IMCA M 103, latest revision."
        ]
      },
      {
        "id": "C4Q4_5_4",
        "number": "4.5.4",
        "text": "Was the vessel provided with a comprehensive DP operations manual and were the  Master and officers familiar with its contents, including DP checklists, capability plots,  consequence analysis and activity specific operating guidelines (ASOG)?",
        "short_text": "DP operations manual",
        "vessel_types": [
          "Oil"
        ],
        "section": "4.5",
        "section_name": "Navigation - Emergency Procedures",
        "objective": "To ensure the Master and officers are provided with comprehensive procedures for conducting DP  operations.  Industry Guidance  IMCA: The Design and Operation of DP Vessels IMCA M 103 Rev. 4 January 2019  3.3.2 Recommended Documentation  4. DP Capability Plots - These should be hard copy plots of th",
        "risk": "high",
        "evidence": [
          "DP operations manual.",
          "Completed DP location checklists and watchkeeping checklists.",
          "Hard copy capability plots.",
          "DP footprint records.",
          "DP operations risk assessments."
        ],
        "negative_grounds": [
          "There was no DP operations manual available on board.",
          "The DP operations manual was not vessel specific.",
          "The DP operations manual was not in a language that could be understood by the DP operators.",
          "Procedures in the DP operations manual did not include:",
          "o"
        ]
      },
      {
        "id": "C4Q4_5_5",
        "number": "4.5.5",
        "text": "Were up to date Field Operations Manuals on board for each offshore terminal to  which the vessel trades, were the Master and officers familiar with their content, and  were records available of the regular communication checks with terminal installations  as required by Field Specific Operating Guidelines (FSOG)?",
        "short_text": "Field Operations Manuals",
        "vessel_types": [
          "Oil"
        ],
        "section": "4.5",
        "section_name": "Navigation - Emergency Procedures",
        "objective": "To ensure the Master and officers are aware of the procedures and regulations at each offshore terminal to  which the vessel trades, and that regular communications are established as required by Field Specific  Operating Guidelines (FSOG).  Industry Guidance  OCIMF Guidelines for Offshore Tanker Op",
        "risk": "high",
        "evidence": [
          "Company procedures to ensure that the most up-to-date editions of the field operations manuals are on",
          "board for each offshore terminal to which the vessel trades.",
          "Field operations manuals for each offshore terminal to which the vessel trades.",
          "Records of the regular communication checks with terminal installations as required by Field Specific",
          "Operating Guidelines (FSOG)."
        ],
        "negative_grounds": [
          "There were no company procedures to ensure that the most up-to-date editions of the field operations",
          "manuals for each offshore terminal to which the vessel trades are available on board.",
          "There was no field operations manual available on board for an offshore terminal to which the vessel trades.",
          "The accompanying officer was not familiar with the procedure for verifying that the field operation manual in",
          "use was the latest edition."
        ]
      }
    ]
  },
  {
    "id": "C5",
    "title": "Cargo, Ballast, Bunkering and Mooring",
    "roles": [
      "Master",
      "Chief Officer",
      "Chief Engineer",
      "2nd Engineer"
    ],
    "questions": [
      {
        "id": "C5Q5_1_1",
        "number": "5.1.1",
        "text": "Were the Master and officers familiar with the onboard emergency response plans,  and were records available to demonstrate that all mandatory and company defined  emergency drills had been completed and documented as required by company  procedures?",
        "short_text": "Records of mandatory and company defined emergency drills",
        "vessel_types": [
          "Oil",
          "Chemical",
          "LPG",
          "LNG"
        ],
        "section": "5.1",
        "section_name": "Cargo Operations",
        "objective": "To ensure that vessel staff can manage onboard emergencies through a consistent and structured process.  Industry Guidance  IMO Resolution A.1072(28) Revised Guidelines for the Structure of an Integrated System of Contingency Planning  for Shipboard Emergencies  2.1.1 The integrated system of shipbo",
        "risk": "high",
        "evidence": [
          "The company procedures which defined the requirements to conduct onboard emergency response drills,",
          "record the outcome and track drills to ensure completion within the defined time frame.",
          "The vessel’s system of shipboard emergency contingency plans.",
          "The tracking records for completed onboard emergency response drills.",
          "Where a drill had not been completed within the defined time frame, communications with the company",
          "describing the reasons for deferment."
        ],
        "negative_grounds": [
          "There was no company procedure which defined the requirements to conduct onboard emergency response",
          "drills, record the outcome and track drills to ensure completion within the defined time frame.",
          "There was no uniform system of shipboard emergency contingency plans available.",
          "There was no requirement to record the details of a drill which included:",
          "o"
        ]
      },
      {
        "id": "C5Q5_1_2",
        "number": "5.1.2",
        "text": "Were the Master and officers familiar with the shipboard emergency plans for the  principal fire scenarios for the vessel type, and had drills taken place to test the  effectiveness of the plans in accordance with the company procedures?",
        "short_text": "Emergency plans & drills for principal fire scenarios",
        "vessel_types": [
          "Oil",
          "Chemical",
          "LPG",
          "LNG"
        ],
        "section": "5.1",
        "section_name": "Cargo Operations",
        "objective": "To ensure that the crew will respond to a fire situation in accordance with the vessel’s shipboard emergency  response plans.  Industry Guidance  ICS: Bridge Procedures Guide. Fifth Edition.  Checklist C7 Fire  OCIMF/ICS: Peril at Sea and Salvage – A Guide for Masters. Sixth Edition.  Chapter 3 Impl",
        "risk": "high",
        "evidence": [
          "The shipboard emergency response plans for the principal fire scenarios as applicable to the vessel type.",
          "The records for completed fire drills during the previous six months.",
          "The vessel’s Bridge Log Book for the previous six months.",
          "Where a drill had been deferred due to poor weather or sea conditions, communications with the company",
          "relating to the deferment."
        ],
        "negative_grounds": [
          "There was no shipboard emergency plan available for fire for one or more of the principal fire scenarios",
          "applicable to the vessel type.",
          "The shipboard emergency plans for the principal fire scenarios were insufficiently ship-specific.",
          "The accompanying officer was unfamiliar with the shipboard emergency plans for the principal fire scenarios",
          "applicable to the vessel."
        ]
      },
      {
        "id": "C5Q5_1_3",
        "number": "5.1.3",
        "text": "Were the Master and officers familiar with the vessel’s SOPEP or SMPEP, and had  drills taken place to test the effectiveness of the onboard emergency response actions  required by the Plan and company procedures?",
        "short_text": "Pollution prevention drills required by SOPEP or SMPEP",
        "vessel_types": [
          "Oil",
          "Chemical",
          "LPG",
          "LNG"
        ],
        "section": "5.1",
        "section_name": "Cargo Operations",
        "objective": "To ensure that the crew will respond effectively to a spill situation in accordance with the vessel’s Shipboard  Oil Pollution Plan (SOPEP) or Shipboard Marine Pollution Emergency Plan (SMPEP).  Industry Guidance  IMO: Guidelines for the development of Shipboard Marine Pollution Emergency Plans. 201",
        "risk": "high",
        "evidence": [
          "The vessel’s SOPEP or SMPEP.",
          "The shipboard emergency response plans for defined spill situations, if not contained within the SOPEP or",
          "SMPEP.",
          "The list of specific contact details for the port of inspection.",
          "The records for completed spill emergency response drills.",
          "The vessel’s Bridge Log Book for the previous twelve months."
        ],
        "negative_grounds": [
          "There was no SOPEP or SMPEP available.",
          "The SOPEP or SMPEP had not been maintained up to date with national operational contact points or any",
          "other information that may have become outdated over time or at change of management.",
          "The vessel had not prepared a list of specific contact details for the port of inspection.",
          "The accompanying officer was unfamiliar with the content of the vessel’s SOPEP or SMPEP."
        ]
      },
      {
        "id": "C5Q5_1_4",
        "number": "5.1.4",
        "text": "Were the Master and officers familiar with the shipboard emergency plan for  enclosed space rescue, and had drills taken place to test the effectiveness of the  shipboard emergency response plan in accordance with company procedures?",
        "short_text": "Enclosed space rescue emergency response drill.",
        "vessel_types": [
          "Oil",
          "Chemical",
          "LPG",
          "LNG"
        ],
        "section": "5.1",
        "section_name": "Cargo Operations",
        "objective": "To ensure that the crew will respond to an enclosed space rescue situation in accordance with the vessel's  shipboard emergency response plan.  Industry Guidance  OCIMF: International Safety Guide for Oil Tankers and Terminals. Sixth Edition.  Chapter 10.2 Safety management for entering enclosed spa",
        "risk": "high",
        "evidence": [
          "The shipboard emergency response plan for enclosed space rescue.",
          "The records for completed enclosed space rescue drills, supplemented by enclosed space entry permits",
          "where appropriate.",
          "The vessel’s Bridge Log Book for the previous twelve months.",
          "Where a drill had been deferred due to poor weather or sea conditions, communications with the company",
          "relating to the postponement."
        ],
        "negative_grounds": [
          "There was no shipboard emergency plan for enclosed space rescue available.",
          "The shipboard emergency plan was insufficiently ship-specific.",
          "The accompanying officer was unfamiliar with the shipboard emergency plan for enclosed space rescue.",
          "An interviewed officer or rating was unfamiliar with the rigging and use of the provided enclosed space",
          "rescue hoisting arrangement(s)."
        ]
      },
      {
        "id": "C5Q5_1_5",
        "number": "5.1.5",
        "text": "Were the Master and Ship Security Officer (SSO) familiar with the vessel’s Ship  Security Plan (SSP), and had drills taken place to test the effectiveness of the measures  and procedures specified by the Ship Security Plan?",
        "short_text": "Drills required by the Ship Security Plan (SSP)",
        "vessel_types": [
          "Oil",
          "Chemical",
          "LPG",
          "LNG"
        ],
        "section": "5.1",
        "section_name": "Cargo Operations",
        "objective": "To ensure that the crew will respond effectively to a security threat in accordance with the vessel’s Ship  Security Plan.  Industry Guidance  IMO: Guide to Maritime Security and the ISPS Code. 2012 edition.  Planning and conducting ship security drills and exercises  4.8.12 The regular conduct of s",
        "risk": "high",
        "evidence": [
          "The schedule of security drills or exercises required to be carried out by the Ship Security Plan.",
          "The records for completed security drills or exercises.",
          "The vessel’s Bridge Log Book for the previous twelve months.",
          "Where a drill or exercise had been deferred due to poor weather or sea conditions, communications with the",
          "company relating to the deferment."
        ],
        "negative_grounds": [
          "There was no schedule of security drills or exercises required to be undertaken by the Ship Security Plan",
          "(SSP).",
          "The Master or Ship Security Officer was unfamiliar with security drills or exercises required to be undertaken",
          "to test the effectiveness of the SSP and its contingency plans.",
          "The drill records were not maintained in the format defined by the company procedure."
        ]
      },
      {
        "id": "C5Q5_1_6",
        "number": "5.1.6",
        "text": "Were the Master, officers and ratings familiar with the procedure for launching the  lifeboat(s), and had abandon ship drills taken place in accordance with company  procedures and the requirements of SOLAS and the Flag Administration?",
        "short_text": "Launching the lifeboat(s) and abandon ship drills",
        "vessel_types": [
          "Oil",
          "Chemical",
          "LPG",
          "LNG"
        ],
        "section": "5.1",
        "section_name": "Cargo Operations",
        "objective": "To ensure that the crew were able to safely launch the vessel’s lifeboat(s) in an emergency, and conduct  abandon ship drills strictly in accordance with manufacturer’s instructions and company procedures.  Industry Guidance  OCIMF: Survival Craft. A Seafarer’s Guide.  Familiarisation and Training  ",
        "risk": "high",
        "evidence": [
          "The shipboard emergency procedure for abandoning ship.",
          "The ship specific procedure for launching a lifeboat as part of an abandon ship drill.",
          "The records for completed abandon ship drills.",
          "The vessel’s Bridge Log Book for the previous twelve months.",
          "Where a drill had been deferred due to poor weather or sea conditions, communications with the company",
          "relating to the postponement."
        ],
        "negative_grounds": [
          "There was no emergency procedure for abandoning ship.",
          "There was no ship specific procedure for launching a lifeboat as part of an abandon ship drill.",
          "The shipboard procedures were insufficiently ship-specific.",
          "The drill records were not maintained in the format defined by the company procedure.",
          "The accompanying officer was unfamiliar with the procedure for abandon ship or the launching of a lifeboat"
        ]
      },
      {
        "id": "C5Q5_1_7",
        "number": "5.1.7",
        "text": "Were the Master and officers familiar with the shipboard emergency plan for a  cargo vapour or liquid release, Including potential fire,  and had drills taken place to test  the effectiveness of the shipboard emergency response plan in accordance with  company procedures?",
        "short_text": "Emergency plan & drills for a cargo vapour or liquid release, Including potential fire",
        "vessel_types": [
          "LPG",
          "LNG"
        ],
        "section": "5.1",
        "section_name": "Cargo Operations",
        "objective": "To ensure that the crew will respond effectively to a cargo vapour or liquid release, including potential fire, in  accordance with the vessel’s shipboard emergency response plans.  Industry Guidance  SIGTTO: Liquified Gas Handling Principles on Ships and Terminals. Fourth Edition  9.5.2 Ship Emerge",
        "risk": "high",
        "evidence": [
          "Page 282 of 711 – SIRE 2.0 Question Library: Part 1 Version 1.0 (January 2022)",
          "The shipboard emergency response plans for a cargo vapour or liquid release.",
          "The records for completed cargo vapour or liquid release drills.",
          "The vessel’s Bridge Log Book for the previous 12 months."
        ],
        "negative_grounds": [
          "There were no shipboard emergency plans for a cargo vapour or liquid release available.",
          "The shipboard emergency plans for cargo vapour or liquid release were insufficiently ship-specific.",
          "The accompanying officer was unfamiliar with the shipboard emergency plans for cargo vapour or liquid",
          "release.",
          "The drill records were not maintained in the format defined by the company procedure."
        ]
      },
      {
        "id": "C5Q5_1_8",
        "number": "5.1.8",
        "text": "Were the Master and officers familiar with the shipboard emergency plan for  collision, and had drills taken place to test the effectiveness of the shipboard emergency  response plan in accordance with company procedures?",
        "short_text": "Emergency plan & drills for collision",
        "vessel_types": [
          "Oil",
          "Chemical",
          "LPG",
          "LNG"
        ],
        "section": "5.1",
        "section_name": "Cargo Operations",
        "objective": "To ensure that the crew will respond effectively to a collision situation in accordance with the vessel’s  shipboard emergency response plan.  Industry Guidance  ICS: Bridge Procedures Guide. Fifth Edition.  Checklist C4 Collision  OCIMF/ICS: Peril at Sea and Salvage – A Guide for Masters. Sixth Edi",
        "risk": "high",
        "evidence": [
          "The shipboard emergency response plan for a collision situation.",
          "The records for completed collision emergency response drills.",
          "The vessel’s Bridge Log Book for the previous twelve months.",
          "Where a drill had been deferred due to poor weather or sea conditions, communications with the company",
          "relating to the deferment."
        ],
        "negative_grounds": [
          "There was no shipboard emergency plan developed for a collision situation.",
          "The shipboard emergency plan was insufficiently ship-specific.",
          "The accompanying officer was unfamiliar with the shipboard emergency plan for a collision situation.",
          "The drill scenario was unrealistic or inadequate to test the shipboard emergency plan.",
          "Drill dates were inconsistent with the vessel activities as recorded within the Bridge Log Book."
        ]
      },
      {
        "id": "C5Q5_1_9",
        "number": "5.1.9",
        "text": "Were the Master and officers familiar with the shipboard emergency plan for  grounding, and had drills taken place to test the effectiveness of the shipboard  emergency response plan in accordance with company procedures?",
        "short_text": "Emergency plan & drills for grounding",
        "vessel_types": [
          "Oil",
          "Chemical",
          "LPG",
          "LNG"
        ],
        "section": "5.1",
        "section_name": "Cargo Operations",
        "objective": "To ensure that the crew will respond effectively to a grounding situation in accordance with the vessel’s  shipboard emergency response plan.  Industry Guidance  ICS: Bridge Procedures Guide. Fifth Edition.  Checklist C5 Stranding or Grounding  OCIMF/ICS: Peril at Sea and Salvage – A Guide for Maste",
        "risk": "high",
        "evidence": [
          "The shipboard emergency response plan for a grounding situation.",
          "The records for completed grounding emergency response drills.",
          "The vessel’s Bridge Log Book for the previous twelve months.",
          "Where a drill had been deferred due to poor weather or sea conditions, communications with the company",
          "relating to the deferment."
        ],
        "negative_grounds": [
          "There was no shipboard emergency plan developed for a grounding situation.",
          "The shipboard emergency plan was insufficiently ship-specific.",
          "Page 288 of 711 – SIRE 2.0 Question Library: Part 1 Version 1.0 (January 2022)",
          "The shipboard emergency plan for grounding did not consider:",
          "o"
        ]
      },
      {
        "id": "C5Q5_1_10",
        "number": "5.1.10",
        "text": "Were the Master and officers familiar with the shipboard emergency plan for loss  of propulsion, and had drills taken place to test the effectiveness of the shipboard  emergency response plan in accordance with company procedures?",
        "short_text": "Emergency plan & drills for loss of propulsion",
        "vessel_types": [
          "Oil",
          "Chemical",
          "LPG",
          "LNG"
        ],
        "section": "5.1",
        "section_name": "Cargo Operations",
        "objective": "To ensure that the crew will respond effectively to a loss of propulsion in accordance with the vessel’s  shipboard emergency response plan.  Industry Guidance  ICS: Bridge Procedures Guide. Fifth Edition.  Checklist C1 Main engine failure.  OCIMF/ICS: Peril at Sea and Salvage – A Guide for Masters.",
        "risk": "high",
        "evidence": [
          "The shipboard emergency response plan for the loss of propulsion.",
          "The records for completed loss of propulsion emergency response drills.",
          "The vessel’s Bridge Log Book for the previous twelve months.",
          "Where a drill had been deferred due to poor weather or sea conditions, communications with the company",
          "relating to the postponement."
        ],
        "negative_grounds": [
          "There was no shipboard emergency plan for the loss of propulsion.",
          "The shipboard emergency plan was insufficiently ship-specific.",
          "The accompanying officer was unfamiliar with the shipboard emergency plan for the loss of propulsion.",
          "An interviewed navigation officer was unfamiliar with the process for estimating the predicted drift of a",
          "disabled tanker, taking into account the wind, current and ship’s head."
        ]
      },
      {
        "id": "C5Q5_1_11",
        "number": "5.1.11",
        "text": "Were the Master and officers familiar with the shipboard emergency plan for  failure of electrical power, and had drills taken place to test the effectiveness of the  shipboard emergency response plan in accordance with company procedures?",
        "short_text": "Emergency plan & drills for failure of electrical power",
        "vessel_types": [
          "Oil",
          "Chemical",
          "LPG",
          "LNG"
        ],
        "section": "5.1",
        "section_name": "Cargo Operations",
        "objective": "To ensure that the crew will respond effectively to a failure of electrical power in accordance with the  vessel’s shipboard emergency response plan.  Industry Guidance  ICS: Bridge Procedures Guide. Fifth Edition.  Checklist C3 Total electrical power failure (Blackout)  OCIMF/ICS: Peril at Sea and ",
        "risk": "high",
        "evidence": [
          "The shipboard emergency response plan for the failure of electrical power including any supplementary",
          "engineering procedures referenced by the plan.",
          "The records for completed failure of electrical power emergency response drills.",
          "The vessel’s Bridge Log Book for the previous twelve months.",
          "Where a drill had been deferred due to poor weather or sea conditions, communications with the company",
          "relating to the deferment."
        ],
        "negative_grounds": [
          "There was no shipboard emergency plan for the failure of electrical power available.",
          "The shipboard emergency plan was insufficiently ship-specific.",
          "The accompanying officer was unfamiliar with the shipboard emergency plan for the failure of electrical",
          "power.",
          "An interviewed navigation officer was unfamiliar with the process of estimating the predicted drift of a"
        ]
      },
      {
        "id": "C5Q5_1_12",
        "number": "5.1.12",
        "text": "Were the Master and officers familiar with the shipboard emergency plan for  steering gear failure, and had drills taken place to test the effectiveness of the shipboard  emergency response plan in accordance with company procedures.",
        "short_text": "Steering gear failure emergency drill.",
        "vessel_types": [
          "Oil",
          "Chemical",
          "LPG",
          "LNG"
        ],
        "section": "5.1",
        "section_name": "Cargo Operations",
        "objective": "To ensure that the crew will respond effectively to a failure of the steering gear in accordance with the  vessel’s shipboard emergency response plan.  Industry Guidance  ICS: Bridge Procedures Guide. Fifth Edition.  Checklist C2 Steering failure  OCIMF/ICS: Peril at Sea and Salvage – A Guide for Ma",
        "risk": "high",
        "evidence": [
          "The shipboard emergency response plan for steering gear failure.",
          "The records for completed steering gear failure and emergency steering drills.",
          "The vessel’s Bridge Log Book for the previous six months.",
          "Where a drill had been deferred due to poor weather or sea conditions, communications with the company",
          "relating to the deferment."
        ],
        "negative_grounds": [
          "The shipboard emergency plan for steering failure was insufficiently ship-specific.",
          "The accompanying officer was unfamiliar with the shipboard emergency plan for steering gear failure.",
          "An interviewed navigation officer was unfamiliar with the process for estimating a vessel’s drift rate taking",
          "into account the wind, current and ship's head.",
          "Page 298 of 711 – SIRE 2.0 Question Library: Part 1 Version 1.0 (January 2022)"
        ]
      },
      {
        "id": "C5Q5_1_13",
        "number": "5.1.13",
        "text": "Were the Master and officers familiar with the shipboard emergency plan for  emergency towing, including the Emergency Towing Booklet (ETB), and had drills taken  place to test the effectiveness of the shipboard emergency response plan in accordance  with company procedures?",
        "short_text": "Emergency plan & drills for emergency towing",
        "vessel_types": [
          "Oil",
          "Chemical",
          "LPG",
          "LNG"
        ],
        "section": "5.1",
        "section_name": "Cargo Operations",
        "objective": "To ensure that the crew will respond to an emergency towing situation in accordance with the vessel’s  shipboard emergency response plan and Emergency Towing Booklet.  Industry Guidance  OCIMF/ICS: Peril at Sea and Salvage – A Guide for Masters. Sixth Edition.  5 Towage and salvage  5.1 General  If ",
        "risk": "high",
        "evidence": [
          "The shipboard Emergency Towing Booklets.",
          "The records for completed emergency towing drills",
          "The vessel’s Bridge Log Book for the previous twelve months.",
          "Where a drill had been deferred due to poor weather or sea conditions, communications with the company",
          "relating to the deferment."
        ],
        "negative_grounds": [
          "There were no Emergency Towing Booklets available.",
          "Copies of the ETB were not available on the bridge, in a forecastle space or in the ship’s office or cargo",
          "control room.",
          "The emergency towing procedures were insufficiently ship-specific.",
          "The accompanying officer was unfamiliar with the emergency towing procedures."
        ]
      },
      {
        "id": "C5Q5_1_14",
        "number": "5.1.14",
        "text": "Were the Master, officers and ratings familiar with the shipboard emergency  response plan for man overboard, including the launching and recovering the rescue  boat, and had drills taken place to test the effectiveness of the shipboard emergency  response plan in accordance with company procedures?",
        "short_text": "Man overboard emergency drill.",
        "vessel_types": [
          "Oil",
          "Chemical",
          "LPG",
          "LNG"
        ],
        "section": "5.1",
        "section_name": "Cargo Operations",
        "objective": "To ensure that the crew will respond effectively to a man overboard situation in accordance with the vessel’s  shipboard emergency response plan.  Industry Guidance   OCIMF: Survival Craft. A Seafarer’s Guide.  Familiarisation and Training  A significant factor in survival craft incidents occurring ",
        "risk": "high",
        "evidence": [
          "The shipboard emergency response plan for man overboard.",
          "The ship specific procedure for launching and recovering the rescue boat as part of a drill.",
          "The records for completed man overboard and rescue boat launching drills.",
          "The vessel’s Bridge Log Book for the previous six months.",
          "Where a drill had been deferred due to poor weather or sea conditions, communications with the company",
          "relating to the postponement."
        ],
        "negative_grounds": [
          "There was no emergency response plan for man overboard.",
          "There was no ship specific procedure for launching and recovering the rescue boat as part of a drill.",
          "The shipboard procedures were insufficiently ship-specific.",
          "Page 306 of 711 – SIRE 2.0 Question Library: Part 1 Version 1.0 (January 2022)",
          "The accompanying officer was unfamiliar with the shipboard emergency response plan for man overboard."
        ]
      },
      {
        "id": "C5Q5_1_15",
        "number": "5.1.15",
        "text": "Were the Master, officers and ratings familiar with the shipboard emergency  response plan for recovery of persons from the water, and had drills taken place to test  the effectiveness of the shipboard emergency response plan in accordance with  company procedures?",
        "short_text": "Emergency response plan & drills for recovery of persons from the water",
        "vessel_types": [
          "Oil",
          "Chemical",
          "LPG",
          "LNG"
        ],
        "section": "5.1",
        "section_name": "Cargo Operations",
        "objective": "To ensure that the crew will be able to safely recover persons from the water in accordance with the vessel's  shipboard emergency response plan.  Industry Guidance  ICS: Recovery of persons from the water. Guidelines for the development of plans and procedures.  In the majority of cases, the carria",
        "risk": "high",
        "evidence": [
          "The shipboard emergency response plan for the recovery of persons from the water.",
          "The records for completed recovery of persons from the water drills.",
          "The vessel’s Bridge Log Book for the previous twelve months.",
          "Where a drill had been deferred due to poor weather or sea conditions, communications with the company",
          "relating to the deferment."
        ],
        "negative_grounds": [
          "There was no shipboard emergency response plan for the recovery of persons from the water available.",
          "The shipboard emergency response plan for the recovery of persons from the water was insufficiently ship-",
          "specific.",
          "The drill records were not maintained in the format defined by the company procedure.",
          "The accompanying officer was unfamiliar with the shipboard emergency response plan for the recovery of"
        ]
      },
      {
        "id": "C5Q5_1_16",
        "number": "5.1.16",
        "text": "Were the Master and officers familiar with the shipboard emergency plans for  flooding, and had drills taken place to test the effectiveness of the shipboard emergency  response plans in accordance with company procedures?",
        "short_text": "Emergency plans & drills for flooding",
        "vessel_types": [
          "Oil",
          "Chemical",
          "LPG",
          "LNG"
        ],
        "section": "5.1",
        "section_name": "Cargo Operations",
        "objective": "To ensure that the crew will respond effectively to a flooding situation in accordance with the vessel’s  shipboard emergency response plan.  Industry Guidance  ICS: Bridge Procedures Guide. Fifth Edition.  Checklist C8 Flooding / Hull Failure  OCIMF/ICS: Peril at Sea and Salvage: A Guide for Master",
        "risk": "high",
        "evidence": [
          "The shipboard emergency response plans for the flooding scenarios applicable to the vessel type.",
          "The records for completed flooding emergency response drills.",
          "The vessel’s Bridge Log Book for the previous twelve months.",
          "Where a drill had been deferred due to poor weather or sea conditions, communications with the company",
          "relating to the deferment."
        ],
        "negative_grounds": [
          "There was no shipboard emergency plan available for one or more of the flooding scenarios applicable to",
          "the vessel type.",
          "The shipboard emergency plans were insufficiently ship-specific.",
          "The accompanying officer was unfamiliar with the shipboard emergency plans for flooding situations.",
          "The drill records were not maintained in the format defined by the company procedure."
        ]
      },
      {
        "id": "C5Q5_1_17",
        "number": "5.1.17",
        "text": "Were the Master and officers familiar with the shipboard emergency plans  regarding LNG bunker operations, and had drills taken place to test the effectiveness of  the shipboard emergency response plans in accordance with company procedures?",
        "short_text": "Emergency plans and drills for LNG bunker operations",
        "vessel_types": [
          "Oil",
          "Chemical",
          "LPG"
        ],
        "section": "5.1",
        "section_name": "Cargo Operations",
        "objective": "To ensure that the crew will respond effectively to an emergency situation involving LNG bunker operations  in accordance with the vessel’s shipboard emergency response plans.  Industry Guidance  IACS: Rec 142 LNG Bunkering Guidelines (2016)  Chapter 1 Section 4.1.3.2 Emergency Response Plan  An Eme",
        "risk": "high",
        "evidence": [
          "The vessel’s fuel handling manual for LNG bunkers.",
          "The emergency response plans for LNG bunkers if not contained within the fuel handling manual.",
          "The records for completed LNG bunker related drills.",
          "The vessel’s Bridge Log Book for the previous twelve months."
        ],
        "negative_grounds": [
          "There was no fuel handling manual for LNG bunkers available.",
          "The fuel handling manual did not include emergency procedures.",
          "The emergency procedures were insufficiently ship-specific.",
          "The accompanying officer was unfamiliar with the emergency procedures contained in the fuel handling",
          "manual for LNG bunkers."
        ]
      },
      {
        "id": "C5Q5_1_18",
        "number": "5.1.18",
        "text": "Were the Master and officers familiar with the company procedures setting out the  actions to be taken in the event of a cargo leak into a double hull tank, and was all  required equipment available and in satisfactory condition?",
        "short_text": "Cargo leak into double hull spaces.",
        "vessel_types": [
          "Oil",
          "Chemical"
        ],
        "section": "5.1",
        "section_name": "Cargo Operations",
        "objective": "To ensure the crew can respond promptly and effectively in the event of a cargo leak into a double hull tank.  Industry Guidance  OCIMF/ICS: International Safety Guide for Oil Tankers and Terminals. Sixth Edition  12.7 Cargo leaks into double hull tanks  12.7.1 Action to be taken  If hydrocarbon gas",
        "risk": "high",
        "evidence": [
          "Page 319 of 711 – SIRE 2.0 Question Library: Part 1 Version 1.0 (January 2022)",
          "Company procedures setting out the actions to be taken in the event of a cargo leak into a double hull tank.",
          "If available, an inventory of the equipment required by these procedures.",
          "Records of tests for electrical continuity of flexible hoses designated for inerting double hull tanks."
        ],
        "negative_grounds": [
          "There were no company procedures setting out the actions to be taken in the event of a cargo leak into a",
          "double hull tank.",
          "The accompanying officer was not familiar with the company procedures setting out the actions to be taken",
          "in the event of a cargo leak into a double hull tank.",
          "The accompanying officer was not familiar with the location of the equipment required by company"
        ]
      },
      {
        "id": "C5Q5_1_19",
        "number": "5.1.19",
        "text": "Were the Master and officers familiar with the emergency arrangements to pump  out the spaces forward of the collision bulkhead in the event of flooding and were these  arrangements prominently marked and in good order?",
        "short_text": "OBO forward space emergency pumping arrangements",
        "vessel_types": [
          "Oil"
        ],
        "section": "5.1",
        "section_name": "Cargo Operations",
        "objective": "To ensure forward ballast tanks and dry spaces on OBO and Ore-Oil combination carriers can be pumped  out safely in the event of flooding.  Industry Guidance  IACS UI SC 179 Dewatering of forward spaces of bulk carriers (Resolution MSC.188(79))  2.1 The valve specified under SOLAS regulation II-1/12",
        "risk": "high",
        "evidence": [
          "The company procedures to pump out the spaces forward of the collision bulkhead in the event of flooding.",
          "The shipboard emergency response plan for forecastle space flooding."
        ],
        "negative_grounds": [
          "There were no company procedures to pump out the spaces forward of the collision bulkhead in the event of",
          "flooding.",
          "There was no shipboard emergency response plan for forecastle space flooding.",
          "The company procedures to pump out the spaces forward of the collision bulkhead in the event of flooding",
          "were not ship specific."
        ]
      },
      {
        "id": "C5Q5_2_1",
        "number": "5.2.1",
        "text": "Were the Master, officers and ratings familiar with the starting procedure for the  emergency fire pump, and were records available to demonstrate that the emergency fire  pump and its location had been maintained and tested in accordance with company  procedures?",
        "short_text": "Emergency fire pump",
        "vessel_types": [
          "Oil",
          "Chemical",
          "LPG",
          "LNG"
        ],
        "section": "5.2",
        "section_name": "Cargo Equipment",
        "objective": "To ensure that crewmembers can respond effectively to a fire situation in accordance with the shipboard  emergency plan.  Industry Guidance  IMO: MSC.1/Circ.1432 Revised guidelines for the maintenance and inspection of fire protection systems and  appliances.  2 Operational readiness   All fire prot",
        "risk": "high",
        "evidence": [
          "The company procedures for the operation and testing of the emergency fire pump.",
          "The ship-specific procedure for starting the emergency fire pump.",
          "Onboard records for the testing of the emergency fire pump and, where driven by a diesel engine, the",
          "engine and the fuel quick closing valve."
        ],
        "negative_grounds": [
          "There was no company procedure for starting and testing the emergency fire pump.",
          "Where the access to the emergency fire pump space was through the machinery space:",
          "o",
          "One or both air-lock doors were either open or there was evidence that they had been held open.",
          "o"
        ]
      },
      {
        "id": "C5Q5_2_2",
        "number": "5.2.2",
        "text": "Were the Master, officers and crew familiar with the location, purpose, testing and  operation of the vessel’s fire dampers, the means of closing the main inlets and outlets  of all ventilation systems and the means of stopping the power ventilation systems from  outside the space served?",
        "short_text": "Fire dampers & ventilation stops",
        "vessel_types": [
          "Oil",
          "Chemical",
          "LPG",
          "LNG"
        ],
        "section": "5.2",
        "section_name": "Cargo Equipment",
        "objective": "To ensure that crewmembers can respond effectively to a fire situation in accordance with the shipboard  emergency plan.  Industry Guidance  IMO: MSC.1/Circ.1432 Revised guidelines for the maintenance and inspection of fire protection systems and  appliances  2 Operational readiness  All fire protec",
        "risk": "high",
        "evidence": [
          "The vessel’s maintenance plan for vessel’s fire protection systems and fire-fighting systems and appliances.",
          "The records of inspections, tests and maintenance carried out on fire dampers, skylights, closing devices",
          "and remote fan stops.",
          "The vessel specific list of closing devices for ventilation inlets or outlets and their required status while",
          "conducting cargo operations."
        ],
        "negative_grounds": [
          "The Master, officers or crew were not familiar with the location, purpose and operation of the vessel’s fire",
          "dampers, skylights, closing devices or remote fan stops.",
          "Closing devices did not operate freely.",
          "Closing devices were ineffective due to corrosion, worn gaskets, seized dogs etc.",
          "Closing devices were not clearly marked with the spaces they served or their open/shut positions."
        ]
      },
      {
        "id": "C5Q5_2_3",
        "number": "5.2.3",
        "text": "Were the Master and officers familiar with the location, purpose and operation of  the vessel’s fixed fire detection and fire alarm system, and was the equipment in good  working order, regularly inspected, tested and maintained?",
        "short_text": "Fixed fire detection and fire alarm system",
        "vessel_types": [
          "Oil",
          "Chemical",
          "LPG",
          "LNG"
        ],
        "section": "5.2",
        "section_name": "Cargo Equipment",
        "objective": "To ensure that crewmembers can respond effectively to a fire situation in accordance with the shipboard  emergency plan.  Industry Guidance  OCIMF: International Safety Guide for Oil Tankers and Terminals. Sixth Edition  5.8 Automatic fire detection systems  5.8.1 General  Automatic fire detection a",
        "risk": "high",
        "evidence": [
          "The company procedure which defined the requirements for operating and testing the fixed fire detection",
          "and fire alarm system",
          "The manufacturer’s instruction manual for the fixed fire detection and fire alarm system.",
          "The inspection, calibration and maintenance records for the fixed fire detection and fire alarm system.",
          "The Engine Room Logbook."
        ],
        "negative_grounds": [
          "There was no company procedure which defined the operation and maintenance of the fixed fire detection",
          "and fire alarm system",
          "The Master or officers were not familiar with the location, purpose and operation of the vessel’s fixed fire",
          "detection and fire alarm system",
          "The responsible officer was not familiar with the maintenance and testing of the fixed fire detection and fire"
        ]
      },
      {
        "id": "C5Q5_2_4",
        "number": "5.2.4",
        "text": "Were the Master and officers familiar with the location, purpose and operation of  the vessel’s fixed carbon dioxide fire extinguishing system, and was the equipment in  good working order and available for immediate use, with the release procedure and  operating instructions displayed at the control stations?",
        "short_text": "Machinery space fixed carbon dioxide fire extinguishing system",
        "vessel_types": [
          "Oil",
          "Chemical",
          "LPG",
          "LNG"
        ],
        "section": "5.2",
        "section_name": "Cargo Equipment",
        "objective": "To ensure that crewmembers can respond effectively to a fire situation in accordance with the shipboard  emergency plan.   Industry Guidance  OCIMF: International Safety Guide for Oil Tankers and Terminals. Sixth Edition  5.3.2.2 Carbon dioxide  A CO2 system normally consists of a battery of large c",
        "risk": "high",
        "evidence": [
          "The vessel’s maintenance plan for the vessel’s fire protection systems and fire-fighting systems and",
          "appliances.",
          "The records of inspections, tests and maintenance for the machinery space fixed carbon dioxide firefighting",
          "system."
        ],
        "negative_grounds": [
          "There were no safety procedures for entering the CO2 space posted at each entrance door.",
          "The accompanying officer was unfamiliar with the safety precautions for entering the CO2 space.",
          "The CO2 space or release cabinets were locked but there were no keys provided.",
          "The machinery space carbon dioxide fire extinguishing system release procedure, operating instructions and",
          "warning notices were not posted at the release station."
        ]
      },
      {
        "id": "C5Q5_2_5",
        "number": "5.2.5",
        "text": "Were the Master and officers familiar with the location, purpose and operation of  the vessel’s machinery space fixed high-expansion foam fire extinguishing system, and  was the equipment in good working order, available for immediate use, and with  operating instructions clearly displayed at the control stations?",
        "short_text": "Machinery space fixed high-expansion foam fire extinguishing system",
        "vessel_types": [
          "Oil",
          "Chemical",
          "LPG",
          "LNG"
        ],
        "section": "5.2",
        "section_name": "Cargo Equipment",
        "objective": "To ensure that crewmembers can respond effectively to a fire situation in accordance with the shipboard  emergency plan.   Industry Guidelines  OCIMF/ICS: International Safety Guide for Oil Tankers and Terminals. Sixth Edition.  Chapter 5 Fire Protection  5.3.2.1.1 Categories of foam  Two categories",
        "risk": "high",
        "evidence": [
          "The vessel’s maintenance plan for the vessel’s fire protection systems and fire-fighting systems and",
          "appliances.",
          "The records of inspections, tests and maintenance carried out on the machinery space fixed high-expansion",
          "foam fire extinguishing system, including:",
          "o",
          "The annual foam concentrate test results."
        ],
        "negative_grounds": [
          "The machinery space fixed high-expansion foam fire extinguishing system release procedure, operating",
          "instructions and warning notices, in the working language of the ship, were not posted at the release station.",
          "The valves and/or system controls were not clearly identified to their purpose and required status during",
          "system operation.",
          "The foam concentrate test had not been carried out within the required time frame."
        ]
      },
      {
        "id": "C5Q5_2_6",
        "number": "5.2.6",
        "text": "Were the Master and officers familiar with the location, purpose and operation of  the vessel’s machinery space fixed pressure water-spraying fire extinguishing system,  and was the equipment in good working order and available for immediate use, with  operating instructions clearly displayed at the control stations?",
        "short_text": "Machinery space fixed pressure water-spraying fire extinguishing system",
        "vessel_types": [
          "Oil",
          "Chemical",
          "LPG",
          "LNG"
        ],
        "section": "5.2",
        "section_name": "Cargo Equipment",
        "objective": "To ensure that crewmembers can respond effectively to a fire situation in accordance with the shipboard  emergency plan.",
        "risk": "high",
        "evidence": [
          "The vessel’s maintenance plan for vessel’s fire protection systems and firefighting systems and appliances.",
          "The records of inspections, tests and maintenance carried out on the machinery space fixed pressure water-",
          "spraying fire extinguishing system, including quarterly system water quality assessments.",
          "Page 350 of 711 – SIRE 2.0 Question Library: Part 1 Version 1.0 (January 2022)"
        ],
        "negative_grounds": [
          "The machinery space fixed pressure water-spraying fire-extinguishing system or the equivalent water mist",
          "fire-extinguishing system release procedure, operating instructions and warning notices were not posted at",
          "the release stations in the working language of the ship.",
          "The valves and/or system controls were not clearly identified to their purpose and required status during",
          "system operation."
        ]
      },
      {
        "id": "C5Q5_2_7",
        "number": "5.2.7",
        "text": "Were the Master and officers familiar with the location, purpose and operation of  the vessel’s fire pumps, fire main, fire main isolating valves and fire hydrants, and was  the system and its components in good working order and available for immediate use?",
        "short_text": "Fire pumps, fire main, fire main isolating valves and fire hydrants",
        "vessel_types": [
          "Oil",
          "Chemical",
          "LPG",
          "LNG"
        ],
        "section": "5.2",
        "section_name": "Cargo Equipment",
        "objective": "To ensure that crewmembers can respond effectively to a fire situation in accordance with the shipboard  emergency plan.  Industry Guidance  OCIMF/ICS: International Safety Guide for Oil Tankers and Terminals. Sixth Edition.  5.3.1.1 Water  All tankers have a firefighting system that consists of pum",
        "risk": "high",
        "evidence": [
          "The vessel’s maintenance plan for vessel’s fire protection systems and fire-fighting systems and appliances.",
          "The records of inspections, tests and maintenance carried out on the fire mains, fire pumps, isolating valves",
          "and hydrants."
        ],
        "negative_grounds": [
          "The fire pumps could not be started remotely from the navigating bridge or fire control station.",
          "There was no means to verify the delivery pressure on the fire main either on the navigating bridge or at the",
          "fire control station.",
          "Fire hydrant valves or fire main isolating valves did not operate freely.",
          "Fire main isolation valves were found to be closed."
        ]
      },
      {
        "id": "C5Q5_2_8",
        "number": "5.2.8",
        "text": "Were the Master, officers and galley staff familiar with the location, purpose and  operation of the fixed and portable fire extinguishing systems provided in the galley,  were the systems in good working order and available for immediate use, and were  galley ranges, exhaust vents, filter cowls free of grease or combustible material?",
        "short_text": "Galley fixed and portable fire extinguishing systems & fire prevention",
        "vessel_types": [
          "Oil",
          "Chemical",
          "LPG",
          "LNG"
        ],
        "section": "5.2",
        "section_name": "Cargo Equipment",
        "objective": "To ensure that the fire protection measures provided in the galley are properly maintained and crewmembers  can respond effectively to a fire situation in accordance with the shipboard emergency plan.  Industry Guidance  OCIMF/ICS: International Safety Guide for Oil Tankers and Terminals. Sixth Edit",
        "risk": "high",
        "evidence": [
          "Page 358 of 711 – SIRE 2.0 Question Library: Part 1 Version 1.0 (January 2022)",
          "The vessel’s maintenance plan for vessel’s fire protection systems and fire-fighting systems and appliances.",
          "The records of inspections, tests and maintenance carried out on the galley fire extinguishing systems."
        ],
        "negative_grounds": [
          "There were no instructions posted in the galley describing the use of the fixed fire extinguishing systems",
          "provided.",
          "The interviewed galley staff were not familiar with the purpose and operation of the fixed or portable fire",
          "extinguishing or fire protection systems in the galley.",
          "Oily or fatty deposits were found on galley ranges, in grease traps, within flue pipes, around fire"
        ]
      },
      {
        "id": "C5Q5_2_9",
        "number": "5.2.9",
        "text": "Were the Master and officers familiar with the location, purpose and operation of  the water-spray system for cooling, fire prevention and crew protection on deck, and was  the equipment in good working order, regularly inspected, tested and maintained?",
        "short_text": "Water-spray system on deck",
        "vessel_types": [
          "LPG",
          "LNG"
        ],
        "section": "5.2",
        "section_name": "Cargo Equipment",
        "objective": "To ensure that crewmembers can respond effectively to a fire situation in accordance with the shipboard  emergency plan.  Industry Guidance  IMO: MSC.1/Circ.1432 Revised guidelines for the maintenance and inspection of fire protection systems and  appliances  2 Operational readiness  All fire protec",
        "risk": "high",
        "evidence": [
          "The vessel’s maintenance plan for vessel’s fire protection systems and fire-fighting systems and appliances.",
          "The records of inspections, tests and maintenance carried out on the water-spray system for cooling, fire",
          "prevention and crew protection on deck."
        ],
        "negative_grounds": [
          "The accompanying officer was not familiar with the location, purpose and operation of the vessel’s water-",
          "spray system for cooling, fire prevention and crew protection on deck.",
          "The accompanying officer was unfamiliar with the maintenance plan for the vessel’s fire protection systems",
          "and fire-fighting systems and appliances.",
          "The operating instructions for the water-spray system were not posted at the control station."
        ]
      },
      {
        "id": "C5Q5_2_10",
        "number": "5.2.10",
        "text": "Were the Master and officers familiar with the location, purpose and operation of  the fixed fire extinguishing system installed within enclosed spaces containing cargo  handling equipment, and was the equipment in good working order and available for  immediate use, with the release procedure and operating instructions displayed at the  control stations?",
        "short_text": "Cargo handling equipment space(s) fixed fire extinguishing system",
        "vessel_types": [
          "LPG",
          "LNG"
        ],
        "section": "5.2",
        "section_name": "Cargo Equipment",
        "objective": "To ensure that crewmembers can respond effectively to a fire situation in accordance with the shipboard  emergency plan.   Industry Guidance  IMO MSC.1/Circ.1318 Guidelines for the maintenance and inspection of fixed carbon dioxide fire- extinguishing systems.  1 General  These Guidelines provide th",
        "risk": "high",
        "evidence": [
          "The company procedures for the operation, inspection and maintenance of the fixed fire extinguishing",
          "system installed within enclosed spaces containing cargo handling equipment.",
          "Records of inspections, tests and maintenance of the fixed fire extinguishing system installed within",
          "enclosed spaces containing cargo handling equipment."
        ],
        "negative_grounds": [
          "There were no company procedures for the operation, inspection and maintenance of the fixed fire",
          "extinguishing system installed within enclosed spaces containing cargo handling equipment that included:",
          "o",
          "A description of the fixed fire extinguishing system, its components, and its functions.",
          "o"
        ]
      },
      {
        "id": "C5Q5_2_11",
        "number": "5.2.11",
        "text": "Were the Master and officers familiar with the location, purpose and operation of  the vessel’s fixed dry chemical powder fire extinguishing system, and was the equipment  in good working order and readily available for immediate use, with operating  instructions clearly displayed at the control stations.",
        "short_text": "Fixed dry chemical powder fire extinguishing system",
        "vessel_types": [
          "LPG",
          "LNG"
        ],
        "section": "5.2",
        "section_name": "Cargo Equipment",
        "objective": "To ensure that crewmembers can respond effectively to a fire situation in accordance with the shipboard  emergency plan.  Industry Guidance  IMO MSC.1/Circ.1432 Revised guidelines for the maintenance and inspection of fire protection systems and  appliances.    2 Operational readiness   All fire pro",
        "risk": "high",
        "evidence": [
          "The vessel’s maintenance plan for the vessel’s fire protection systems and fire-fighting systems and",
          "appliances.",
          "The records of inspections, tests and maintenance carried out on the cargo area fixed dry chemical powder",
          "extinguishing system including:",
          "Page 372 of 711 – SIRE 2.0 Question Library: Part 1 Version 1.0 (January 2022)",
          "o"
        ],
        "negative_grounds": [
          "The cargo area fixed dry chemical powder extinguishing system operating instructions were not posted at",
          "each operating station in the working language of the ship.",
          "The system controls and valves were not clearly marked in accordance with the operating instructions.",
          "There was no maintenance plan for the vessel’s fire protection systems and fire-fighting systems and",
          "appliances available."
        ]
      },
      {
        "id": "C5Q5_2_12",
        "number": "5.2.12",
        "text": "Were the Master and officers familiar with the location, purpose and operation of  the fixed fire-extinguishing system in the vessel’s paint locker and any other flammable  liquid locker, and was the system in good working order and available for immediate  use?",
        "short_text": "Paint locker fixed fire-extinguishing system",
        "vessel_types": [
          "Oil",
          "Chemical",
          "LPG",
          "LNG"
        ],
        "section": "5.2",
        "section_name": "Cargo Equipment",
        "objective": "To ensure that crewmembers can respond effectively to a fire situation in accordance with the shipboard  emergency plan.  Industry Guidance  OCIMF/ICS: International Safety Guide for Oil Tankers and Terminals. Sixth Edition   13.2.2 Paint  Stow paint, paint thinners and associated cleaners and harde",
        "risk": "high",
        "evidence": [
          "The vessel’s maintenance plan for vessel’s fire protection systems and fire-fighting systems and appliances.",
          "The records of inspections, tests and maintenance carried out on the paint or flammable liquid locker fixed",
          "fire extinguishing systems."
        ],
        "negative_grounds": [
          "There were no instructions posted outside a paint or flammable liquids locker describing the use of the fixed",
          "fire extinguishing system provided.",
          "The accompanying officer was not familiar with the purpose and operation of the fixed fire extinguishing",
          "system in a paint or other flammable liquid locker.",
          "Paints or flammable liquids were found stored in lockers or locations not designed to contain flammable"
        ]
      },
      {
        "id": "C5Q5_2_13",
        "number": "5.2.13",
        "text": "Were the Master and officers familiar with the location, purpose and operation of  the machinery space fixed water-based or equivalent local application fire-fighting  system, and was the equipment in good working order and readily available for  immediate use, with operating instructions clearly displayed at the control stations?",
        "short_text": "Machinery space fixed water-based or equivalent local application fire-fighting system",
        "vessel_types": [
          "Oil",
          "Chemical",
          "LPG",
          "LNG"
        ],
        "section": "5.2",
        "section_name": "Cargo Equipment",
        "objective": "To ensure that crewmembers can respond effectively to a fire situation in accordance with the shipboard  emergency plan",
        "risk": "high",
        "evidence": [
          "The vessel’s maintenance plan for the vessel’s fire protection systems and fire-fighting systems and",
          "appliances.",
          "The records of inspections, tests and maintenance carried out on the fixed water-based local application fire-",
          "fighting system."
        ],
        "negative_grounds": [
          "There was no company procedure which described the use of the automatic release mode of the fixed",
          "water-based local application fire-fighting system where this function was provided.",
          "The accompanying officer was not familiar with the purpose, operation and required operating mode of the",
          "system.",
          "The accompanying officer was unfamiliar with the maintenance plan for the vessel’s fire protection systems"
        ]
      },
      {
        "id": "C5Q5_2_14",
        "number": "5.2.14",
        "text": "Were the Master and officers familiar with the purpose of the cargo, ballast and  stripping pump temperature sensing devices, and was there evidence that alarm  activation points had been correctly set and tested in accordance with company  procedures and manufacturer's instructions?",
        "short_text": "Cargo, ballast and stripping pump temperature sensing devices",
        "vessel_types": [
          "Oil",
          "Chemical"
        ],
        "section": "5.2",
        "section_name": "Cargo Equipment",
        "objective": "To ensure that measures specifically designed to prevent fires in the cargo pump room are effective.  Industry Guidance  OCIMF/ICS: International Safety Guide for Oil Tankers and Terminals. Sixth Edition.  12.1.15.7 Miscellaneous  The safety of pump rooms can be enhanced in a number of other ways, s",
        "risk": "high",
        "evidence": [
          "The company procedures for the maintenance and operation of the cargo, ballast and stripping pump",
          "temperature sensing system.",
          "Page 384 of 711 – SIRE 2.0 Question Library: Part 1 Version 1.0 (January 2022)",
          "The records of temperature sensing device readings for cargo, ballast and stripping pumps while in",
          "operation.",
          "The manufacturer’s instruction manual for the cargo, ballast and stripping pump temperature sensing"
        ],
        "negative_grounds": [
          "There was no company procedure for the operation and maintenance of the cargo, ballast and stripping",
          "pump temperature sensing system.",
          "The accompanying officer was unfamiliar with the operation of the cargo, ballast and stripping pump",
          "temperature sensing system.",
          "The accompanying officer was unfamiliar with the alarm activation settings of the cargo, ballast and stripping"
        ]
      },
      {
        "id": "C5Q5_2_15",
        "number": "5.2.15",
        "text": "Were the Master, officers and ratings familiar with the purpose and operation of  the vessel’s deck foam system, including portable applicators, and was the system in  good working order and available for immediate use, with operating instructions  displayed at the control station?",
        "short_text": "Deck foam system, including portable applicators",
        "vessel_types": [
          "Oil",
          "Chemical"
        ],
        "section": "5.2",
        "section_name": "Cargo Equipment",
        "objective": "To ensure that crewmembers can respond effectively to a fire situation in accordance with the shipboard  emergency plan.  Industry Guidance  OCIMF: International Safety Guide for Oil Tankers and Terminals. Sixth Edition.  Chapter 5 Fire Protection  5.3.2.1.1 Categories of foam  Two categories of foa",
        "risk": "high",
        "evidence": [
          "The vessel’s maintenance plan for the vessel’s fire protection systems and fire-fighting systems and",
          "appliances.",
          "The records of inspections, tests and maintenance carried out on the deck foam system, including:",
          "o",
          "The annual foam concentrate test results.",
          "o"
        ],
        "negative_grounds": [
          "The deck foam system operating instructions, in the working language of the ship, were not posted in the",
          "space containing the foam concentrate tank, pumps and control station.",
          "The valves and/or system controls were not clearly identified to their purpose and required status during",
          "system operation.",
          "The foam storage tank was not filled to the required level."
        ]
      },
      {
        "id": "C5Q5_2_16",
        "number": "5.2.16",
        "text": "Were the Master, officers and crew familiar with the location, purpose, testing and  operation of the vessel’s fire doors?",
        "short_text": "Fire doors",
        "vessel_types": [
          "Oil",
          "Chemical",
          "LPG",
          "LNG"
        ],
        "section": "5.2",
        "section_name": "Cargo Equipment",
        "objective": "To ensure that crewmembers can respond effectively to a fire situation in accordance with the shipboard  emergency plan.  Industry Guidance  IMO: MSC.1/Circ.1432 Revised guidelines for the maintenance and inspection of fire protection systems and  appliances  2 Operational readiness  All fire protec",
        "risk": "high",
        "evidence": [
          "The vessel’s maintenance plan for vessel’s fire protection systems and fire-fighting systems and appliances.",
          "The records of inspections, tests and maintenance carried out on fire doors.",
          "The Fire Control Plan."
        ],
        "negative_grounds": [
          "There was no company procedure which defined the frequency of inspections, tests and maintenance for",
          "fire doors.",
          "The Master, officers or ratings were not familiar with the location, purpose and operation of the vessel’s fire",
          "doors.",
          "A replacement fire door did not meet the minimum fire rating as indicated on the Fire Control Plan."
        ]
      },
      {
        "id": "C5Q5_3_1",
        "number": "5.3.1",
        "text": "Were the Master, officers and ratings familiar with the location and use of the  vessel’s firefighter’s outfits including the self-contained breathing apparatus (SCBA), and  was the equipment maintained in good condition and ready for immediate use in  accordance with company procedures?",
        "short_text": "Firefighter’s outfits including self-contained breathing apparatus (SCBA)",
        "vessel_types": [
          "Oil",
          "Chemical",
          "LPG",
          "LNG"
        ],
        "section": "5.3",
        "section_name": "Cargo Documents",
        "objective": "To ensure that crewmembers can respond effectively to a fire or enclosed space rescue situation in  accordance with the shipboard emergency plans.  Industry Guidance  OCIMF/ICS: International Safety Guide for Oil Tankers and Terminals Sixth Edition  10.13.4    Equipment maintenance  A responsible pe",
        "risk": "high",
        "evidence": [
          "The vessel’s maintenance plan for vessel’s fire protection systems and firefighting systems and appliances.",
          "The records of inspections, tests and maintenance carried out on:",
          "o",
          "The firefighter’s outfits.",
          "o",
          "The SCBAs."
        ],
        "negative_grounds": [
          "The firefighter’s suits or SCBAs were not stored in the correct location in accordance with the fire plan;",
          "unless they were in position for cargo operations in accordance with company procedures.",
          "The firefighter’s outfits were incomplete or defective in any respect.",
          "The SCBAs and firefighter's outfits were not prepared for immediate use with a fully charged bottle and the",
          "required spare bottle(s)."
        ]
      },
      {
        "id": "C5Q5_3_2",
        "number": "5.3.2",
        "text": "Were the Master, officers and crew familiar with the location, purpose and  operation of the vessel’s fire hoses, nozzles and international shore connection, and was  the equipment in good working order and available for immediate use?",
        "short_text": "Fire hoses, nozzles and international shore connection",
        "vessel_types": [
          "Oil",
          "Chemical",
          "LPG",
          "LNG"
        ],
        "section": "5.3",
        "section_name": "Cargo Documents",
        "objective": "To ensure that crewmembers can respond effectively to a fire situation in accordance with the shipboard  emergency plan.  Industry Guidance  OCIMF/ICS: International Safety Guide for Oil Tankers and Terminals. Sixth Edition.  5.3.1.1 Water  All tankers have a firefighting system that consists of pum",
        "risk": "high",
        "evidence": [
          "The vessel’s maintenance plan for vessel’s fire protection systems and fire-fighting systems and appliances.",
          "The records of inspections, tests and maintenance carried out on the fire hoses, nozzles and international",
          "shore connections."
        ],
        "negative_grounds": [
          "Fire hoses, nozzles or international shore connections were missing from the locations shown on the fire",
          "control plan unless laid out for cargo or bunker operations.",
          "Fire hoses, nozzles or international shore connections were not ready for immediate use.",
          "Fire hoses were either less than 10m in length or longer than the maximum permitted for their location.",
          "The required gaskets, nuts, washers or recommended spanners were missing from the international shore"
        ]
      },
      {
        "id": "C5Q5_3_3",
        "number": "5.3.3",
        "text": "Were the Master, officers and ratings familiar with the location, purpose and  operation of the vessel’s portable fire extinguishers, and were the extinguishers in good  order and readily available for immediate use with operating instructions clearly marked?",
        "short_text": "Portable fire extinguishers",
        "vessel_types": [
          "Oil",
          "Chemical",
          "LPG",
          "LNG"
        ],
        "section": "5.3",
        "section_name": "Cargo Documents",
        "objective": "To ensure that crewmembers can respond effectively to a fire situation in accordance with the shipboard  emergency plan.   Industry Guidance  OCIMF: International Safety Guide for Oil Tankers and Terminals. Sixth Edition  All fire extinguishers should be maintained and available for immediate use. T",
        "risk": "high",
        "evidence": [
          "The Fire Control Plan.",
          "The maintenance plan for fire protection systems and fire-fighting systems and appliances.",
          "Records of inspections, tests and maintenance carried out on portable fire extinguishers required by the",
          "maintenance plan.",
          "Inventory of spare fire extinguisher charges and/or spare fire extinguishers."
        ],
        "negative_grounds": [
          "Fire extinguisher(s) were missing or not located as shown in the Fire Control Plan.",
          "The fire control plan did not comply with MSC.1/Circ.1275 with regards to the distribution of fire",
          "extinguishers. (for ships constructed before 1 January 2009 make a comment only in the Hardware",
          "response tool)",
          "Fire extinguisher(s) were not fully charged."
        ]
      },
      {
        "id": "C5Q5_3_4",
        "number": "5.3.4",
        "text": "Were the Master, officers and ratings familiar with the location and purpose of the  Emergency Escape Breathing Devices (EEBDs) carried on board, and were these devices  in good order, suitably located and ready for immediate use?",
        "short_text": "Emergency Escape Breathing Devices (EEBDs)",
        "vessel_types": [
          "Oil",
          "Chemical",
          "LPG",
          "LNG"
        ],
        "section": "5.3",
        "section_name": "Cargo Documents",
        "objective": "To ensure that Emergency Escape Breathing Devices (EEBDs) are readily available to personnel in the event  of a fire or any other emergency on the vessel.  Industry Guidance  OCIMF: International Safety Guide for Oil Tankers and Terminals. Sixth Edition  10.13.3 Emergency Escape Breathing Device  IM",
        "risk": "high",
        "evidence": [
          "The company procedure for the use and maintenance of EEBDs",
          "The inspection and maintenance records for the EEBDs contained within the onboard maintenance plan."
        ],
        "negative_grounds": [
          "There were no company procedures for the use and maintenance of EEBDs.",
          "The accompanying officer was not familiar with the location, inspection and maintenance of the EEBDs.",
          "The EEBDs were not positioned in accordance with the fire control plan.",
          "There were fewer spare EEBDs onboard than indicated on the fire control plan.",
          "An inspected EEBD was found defective in any respect, including:"
        ]
      },
      {
        "id": "C5Q5_3_5",
        "number": "5.3.5",
        "text": "Were the Master, officers and engine ratings familiar with the purpose and  operation of the vessel’s wheeled (mobile) fire extinguishers, and was the equipment in  good order and available for immediate use with operating instructions clearly marked?",
        "short_text": "Wheeled (mobile) fire extinguishers",
        "vessel_types": [
          "Oil",
          "Chemical",
          "LPG",
          "LNG"
        ],
        "section": "5.3",
        "section_name": "Cargo Documents",
        "objective": "To ensure that crewmembers can respond effectively to a fire situation in accordance with the shipboard  emergency plan.   Industry Guidance  OCIMF/ICS: International Safety Guide for Oil Tankers and Terminals Sixth Edition  Chapter 5 Fire Protection.  All fire extinguishers should be maintained and",
        "risk": "high",
        "evidence": [
          "Page 417 of 711 – SIRE 2.0 Question Library: Part 1 Version 1.0 (January 2022)",
          "The fire control plan",
          "The maintenance plan for fire protection systems and fire-fighting systems and appliances.",
          "Records of inspections, tests and maintenance carried out on wheeled fire extinguishers required by the",
          "maintenance plan.",
          "Inventory of spare charges."
        ],
        "negative_grounds": [
          "A wheeled fire extinguisher(s) was not:",
          "o",
          "Fully charged.",
          "o",
          "Readily available for immediate use."
        ]
      },
      {
        "id": "C5Q5_4_1",
        "number": "5.4.1",
        "text": "Were the Master and officers familiar with the operation of the davit-launched  lifeboats, release mechanisms and launching appliances, and were they in good order  with records available to demonstrate that they had been inspected and tested as  required?",
        "short_text": "Davit-launched lifeboats, release mechanisms and launching appliances",
        "vessel_types": [
          "Oil",
          "Chemical",
          "LPG",
          "LNG"
        ],
        "section": "5.4",
        "section_name": "Ballast Operations",
        "objective": "To ensure the lifeboats, release mechanisms and launching appliances will be ready for immediate use in an  emergency.  Industry Guidance  OCIMF: Survival Craft. A Seafarer’s Guide  Section 2.1 Maintenance and instruction manuals  Experience has revealed poor maintenance as a contributory factor to ",
        "risk": "high",
        "evidence": [
          "The company procedure to ensure lifeboats, release mechanisms and launching appliances were",
          "periodically inspected and tested and ready for immediate use in an emergency.",
          "A copy of the monthly inspection checklist required by SOLAS III/36.",
          "The Bridge Log Book.",
          "Records of periodic inspections and tests of the lifeboats, release mechanisms and launching appliances."
        ],
        "negative_grounds": [
          "There was no procedure to ensure the lifeboats, release mechanisms and launching appliances were",
          "periodically inspected and tested and ready for immediate use in an emergency.",
          "The accompanying officer was unfamiliar with the operation of the lifeboats, release mechanisms and",
          "launching appliances.",
          "The accompanying officer was unfamiliar with the required inspection and testing of the lifeboats, release"
        ]
      },
      {
        "id": "C5Q5_4_2",
        "number": "5.4.2",
        "text": "Were the Master and officers familiar with the operation of the free-fall lifeboat, its  release systems and its launching appliance, and was the equipment in satisfactory  condition with records available to demonstrate that it had been inspected and tested in  accordance with company procedures?",
        "short_text": "Free-fall lifeboat, its release systems and its launching appliance",
        "vessel_types": [
          "Oil",
          "Chemical",
          "LPG",
          "LNG"
        ],
        "section": "5.4",
        "section_name": "Ballast Operations",
        "objective": "To ensure the free-fall lifeboat, its release system and launching appliance will be ready for immediate use in  an emergency.  Industry Guidance  OCIMF: Survival Craft. A Seafarer’s Guide  Section 2.1 Maintenance and instruction manuals  Experience has revealed poor maintenance as a contributory fa",
        "risk": "high",
        "evidence": [
          "The company procedure to ensure the free-fall lifeboat, its release system and launching appliance were",
          "periodically inspected and tested and ready for immediate use in an emergency.",
          "A copy of the monthly inspection checklist required by SOLAS III/36.",
          "The Bridge Log Book.",
          "Records of thorough examination and operational tests of the free-fall lifeboat, its release systems,",
          "launching appliance and recovery equipment."
        ],
        "negative_grounds": [
          "Page 431 of 711 – SIRE 2.0 Question Library: Part 1 Version 1.0 (January 2022)",
          "There was no company procedure to ensure the free-fall lifeboat, its release systems, launching appliance",
          "and recovery equipment were periodically inspected and tested and ready for immediate use in an",
          "emergency.",
          "The accompanying officer was unfamiliar with the operation of the free-fall lifeboat, its release systems,"
        ]
      },
      {
        "id": "C5Q5_4_3",
        "number": "5.4.3",
        "text": "Were the Master and officers familiar with the operation of the dedicated rescue  boat and launching appliance, and were they in good order with records available to  demonstrate that they had been inspected and tested as required?",
        "short_text": "Dedicated rescue boat and launching appliance",
        "vessel_types": [
          "Oil",
          "Chemical",
          "LPG",
          "LNG"
        ],
        "section": "5.4",
        "section_name": "Ballast Operations",
        "objective": "To ensure the rescue boat will be ready for immediate use in an emergency.  Industry Guidance  OCIMF: Survival Craft. A Seafarer’s Guide  Section 2.1 Maintenance and instruction manuals  Experience has revealed poor maintenance as a contributory factor to many incidents and near misses involving  su",
        "risk": "high",
        "evidence": [
          "The company procedure to ensure the rescue boat and launching appliance were periodically inspected and",
          "tested and ready for immediate use in an emergency.",
          "The Bridge Log Book.",
          "Page 437 of 711 – SIRE 2.0 Question Library: Part 1 Version 1.0 (January 2022)",
          "Records of periodic inspections and tests of the rescue boat and launching appliance."
        ],
        "negative_grounds": [
          "The accompanying officer was unfamiliar with the operation of the rescue boat and launching appliance.",
          "The accompanying officer was unfamiliar with the required inspection and testing of the rescue boat and",
          "launching appliance.",
          "Records of weekly and monthly inspections and routine maintenance of the rescue boat and launching",
          "appliance were incomplete."
        ]
      },
      {
        "id": "C5Q5_4_4",
        "number": "5.4.4",
        "text": "Were the Master and Officers familiar with the location, purpose and operation of  the rocket parachute flares and line throwing appliances and were they in good order,  with records available to demonstrate that had they had been inspected as required?",
        "short_text": "Rocket parachute flares and line throwing appliances",
        "vessel_types": [
          "Oil",
          "Chemical",
          "LPG",
          "LNG"
        ],
        "section": "5.4",
        "section_name": "Ballast Operations",
        "objective": "To ensure the rocket parachute flares and line throwing appliances will function correctly in an emergency.  Industry Guidance  IMO: LSA Code  3.1 Rocket parachute flares  3.1.1 The rocket parachute flare shall:  1.  be contained in a water-resistant casing;  2.  have brief instructions or diagrams ",
        "risk": "high",
        "evidence": [
          "The company procedure to ensure that rocket parachute flares and line throwing appliances were",
          "periodically inspected and ready for immediate use in an emergency.",
          "Records of periodic inspections of the rocket parachute flares and line throwing appliances."
        ],
        "negative_grounds": [
          "There was no company procedure to ensure that rocket parachute flares and line throwing appliances were",
          "periodically inspected and ready for immediate use in an emergency.",
          "The accompanying officer was unfamiliar with the purpose and operation of the rocket parachute flares and",
          "line throwing appliances.",
          "The accompanying officer was unfamiliar with the required inspection of the rocket parachute flares and line"
        ]
      },
      {
        "id": "C5Q5_4_5",
        "number": "5.4.5",
        "text": "Were the Master and officers familiar with the operation of the liferafts, hydrostatic  releases and liferaft launching appliances, where provided, and were they in good order  with records available to demonstrate that they had been serviced, inspected and tested  as required?",
        "short_text": "Liferafts, hydrostatic releases and liferaft launching appliances",
        "vessel_types": [
          "Oil",
          "Chemical",
          "LPG",
          "LNG"
        ],
        "section": "5.4",
        "section_name": "Ballast Operations",
        "objective": "To ensure that liferafts, hydrostatic releases and, liferaft launching appliances, where fitted, will function  correctly in an emergency.  Industry Guidance  IMO: LSA Code  4.1.6 Float-free arrangements for liferafts,  4.1.6.3 Hydrostatic release units  If a hydrostatic release unit is used in the ",
        "risk": "high",
        "evidence": [
          "The company procedure to ensure liferafts, and launching appliances if fitted, were periodically inspected",
          "and tested and ready for immediate use in an emergency.",
          "The Bridge Log Book.",
          "Records of periodic servicing, inspection and tests of the liferafts, hydrostatic releases and, launching",
          "appliances, where provided."
        ],
        "negative_grounds": [
          "The accompanying officer was unfamiliar with the operation of the liferafts, hydrostatic releases and, liferaft",
          "launching appliances, where provided.",
          "The accompanying officer was unfamiliar with the required servicing, inspection and testing of the liferafts,",
          "hydrostatic releases and, liferaft launching appliances, where provided.",
          "There was insufficient liferaft capacity for the number of people on board."
        ]
      },
      {
        "id": "C5Q5_4_6",
        "number": "5.4.6",
        "text": "Were the lifebuoys, and associated lights, smoke floats and lifelines, in good order,  clearly marked and correctly distributed around the ship?",
        "short_text": "Lifebuoys, and associated lights, smoke floats and lifelines",
        "vessel_types": [
          "Oil",
          "Chemical",
          "LPG",
          "LNG"
        ],
        "section": "5.4",
        "section_name": "Ballast Operations",
        "objective": "To ensure that all life-saving appliances are in working order and ready for immediate use.  Industry Guidance  IMO: LSA Code 2.1.1  Every lifebuoy shall:  .7 If it is intended to operate the quick-release arrangement provided for the self-activated smoke signals and self- igniting lights, have a ma",
        "risk": "high",
        "evidence": [
          "The company procedure to ensure that lifebuoys, and associated lights, smoke floats and lifelines, were in",
          "good order, clearly marked and correctly distributed around the ship.",
          "The checklist and log for records of monthly inspections and maintenance of the lifebuoys."
        ],
        "negative_grounds": [
          "There was:",
          "o",
          "Less than the required number of lifebuoys.",
          "o",
          "An insufficient number of lifebuoys with lights"
        ]
      },
      {
        "id": "C5Q5_4_7",
        "number": "5.4.7",
        "text": "Were the Master, officers and ratings familiar with the immersion suits, and were  the immersion suits in good order, readily accessible and their location(s) clearly  indicated?",
        "short_text": "Immersion suits",
        "vessel_types": [
          "Oil",
          "Chemical",
          "LPG",
          "LNG"
        ],
        "section": "5.4",
        "section_name": "Ballast Operations",
        "objective": "To ensure that all life-saving appliances are in working order and ready for immediate use.  Industry Guidance  IMO: LSA Code  2.3 Immersion suits  2.3.1 General requirements for immersion suits  2.3.1.1 An immersion suit shall be constructed with waterproof materials such that:  .1 it can be unpack",
        "risk": "high",
        "evidence": [
          "The company procedures to ensure that immersion suits are in good order, readily accessible and their",
          "location(s) clearly indicated.",
          "Records of monthly inspections and periodic air-pressure tests of the ship’s immersion suits."
        ],
        "negative_grounds": [
          "There was no company procedure which defined the actions to be taken to ensure that immersion suits are",
          "in good order, readily accessible and their location(s) clearly indicated.",
          "The accompanying officer was unfamiliar with the required inspection and tests required to be carried out for",
          "the immersion suits in accordance with the company procedures.",
          "An interviewed officer or rating was not familiar with the instructions for donning an immersion suit."
        ]
      },
      {
        "id": "C5Q5_4_8",
        "number": "5.4.8",
        "text": "Were the Master, officers and ratings familiar with the lifejackets and personal  flotation devices (PFDs) provided on board, and was the equipment in good condition,  and properly maintained?",
        "short_text": "Lifejackets and personal flotation devices (PFDs)",
        "vessel_types": [
          "Oil",
          "Chemical",
          "LPG",
          "LNG"
        ],
        "section": "5.4",
        "section_name": "Ballast Operations",
        "objective": "To ensure that all life-saving appliances are in working order and ready for immediate use.  Industry Guidance  IMO: LSA Code  2.2.1.13 Each lifejacket shall be provided with means of securing a lifejacket light…  2.2.1.14 Each lifejacket shall be fitted with a whistle firmly secured by a lanyard.  ",
        "risk": "high",
        "evidence": [
          "The company procedures to ensure that the lifejackets required by SOLAS were in good order, readily",
          "accessible and their location(s) clearly indicated.",
          "The company procedures providing guidance on the use of “working lifejackets”, including the servicing of",
          "inflatable lifejackets, if carried.",
          "Records of monthly inspections of all lifejackets.",
          "Records of annual servicing of inflatable lifejackets, if carried."
        ],
        "negative_grounds": [
          "There were no company procedures  to ensure that the lifejackets required by SOLAS were in good order,",
          "readily accessible and their location(s) clearly indicated.",
          "Page 458 of 711 – SIRE 2.0 Question Library: Part 1 Version 1.0 (January 2022)",
          "The accompanying officer was not familiar with the company procedures to ensure that the lifejackets",
          "required by SOLAS were in good order, readily accessible and their location(s) clearly indicated."
        ]
      },
      {
        "id": "C5Q5_4_9",
        "number": "5.4.9",
        "text": "Were the Master and officers familiar with the company procedures for the periodic  testing and maintenance of the emergency lighting system, was there evidence of  periodic testing, and was the system in proper operating condition?",
        "short_text": "Emergency lighting.",
        "vessel_types": [
          "Oil",
          "Chemical",
          "LPG",
          "LNG"
        ],
        "section": "5.4",
        "section_name": "Ballast Operations",
        "objective": "To ensure that the emergency lighting system will operate correctly in the event of a loss of primary power  and lighting.  Industry Guidance  USCG: Code of Federal Regulations. Title 46.  97.15-30 Emergency lighting and power systems.  (a) Where fitted, it shall be the duty of the master to see tha",
        "risk": "high",
        "evidence": [
          "Company procedures for the inspection and testing of the emergency lighting system.",
          "Records of inspection and testing of the emergency lighting system."
        ],
        "negative_grounds": [
          "There were no company procedures for the inspection and testing of the emergency lighting system.",
          "Company procedures did not require the emergency lighting to be inspected and tested at least once per",
          "week.",
          "The responsible officer was not familiar with company procedures for the inspection and testing of the",
          "emergency lighting system."
        ]
      },
      {
        "id": "C5Q5_5_1",
        "number": "5.5.1",
        "text": "Were the Master, officers and ratings familiar with the company enclosed space  entry procedures, and was evidence available to demonstrate that all enclosed space  entries had been made in strict compliance with the procedures?",
        "short_text": "Enclosed space entry procedures",
        "vessel_types": [
          "Oil",
          "Chemical",
          "LPG",
          "LNG"
        ],
        "section": "5.5",
        "section_name": "Bunkering",
        "objective": "To ensure that enclosed space entry is always strictly controlled and conducted in accordance with industry  best practice.  Industry Guidance:  OCIMF/ICS: International Safety Guide for Oil Tankers and Terminals. Sixth Edition.  Chapter 1 Basic Properties and Hazards of Petroleum  1.4.3.2 Exposure ",
        "risk": "high",
        "evidence": [
          "The company procedures which defined the enclosed space entry requirements for the identified enclosed",
          "spaces found onboard.",
          "The enclosed space entry permits for the previous six months for:",
          "o",
          "Spaces under the control of the engineering department.",
          "o"
        ],
        "negative_grounds": [
          "There were no company enclosed space entry procedures.",
          "The company enclosed space entry procedures had not identified all spaces that were considered to be",
          "enclosed spaces along with corresponding precautions for entering each type of identified enclosed space.",
          "There was no evidence that documented risk assessments were completed and/or reviewed before each",
          "enclosed space entry."
        ]
      },
      {
        "id": "C5Q5_5_2",
        "number": "5.5.2",
        "text": "Were the Master, officers and, where directly involved, ratings familiar with the  company hot work procedure, and was evidence available to demonstrate that hot work  had been conducted in accordance with the procedure?",
        "short_text": "Hot work procedure",
        "vessel_types": [
          "Oil",
          "Chemical",
          "LPG",
          "LNG"
        ],
        "section": "5.5",
        "section_name": "Bunkering",
        "objective": "To ensure that hot work is always carried out in a controlled manner.  Industry Guidance:  OCIMF/ICS: International Safety Guide for Oil Tankers and Terminals. Sixth Edition.  Chapter 9.4 Hot work  9.4.1 Definition of hot work  Hot work is any work that involves sources of ignition or temperature hi",
        "risk": "high",
        "evidence": [
          "The company hot work procedures.",
          "The hot work permits issued onboard the vessel during the previous six months, supplemented by:",
          "o",
          "The risk assessment relating to the specific hot work task.",
          "o",
          "The work plan relating to the specific hot work task."
        ],
        "negative_grounds": [
          "There were no company hot work procedures.",
          "The company hot work procedures were not in alignment with the guidance provided by ISGOTT Chapter 9.",
          "Evidence was available that hot work had been conducted anywhere outside of the designated space",
          "without the issue of a hot work permit.",
          "Hot work permits had been issued without:"
        ]
      },
      {
        "id": "C5Q5_5_3",
        "number": "5.5.3",
        "text": "Were the Master, officers and ratings familiar with the company procedure for  working at height, and was there evidence that risk control measures such as permits to  work or documented risk assessments were consistently used whenever work was  undertaken at height?",
        "short_text": "Working at height",
        "vessel_types": [
          "Oil",
          "Chemical",
          "LPG",
          "LNG"
        ],
        "section": "5.5",
        "section_name": "Bunkering",
        "objective": "To ensure that work at height is always conducted in a controlled manner with procedures to manage and  mitigate risk to workers.  Industry Guidance  UK MCA: Code of Safe Working Practices for Merchant Seafarers.  Chapter 14.2 Permit to work systems  14.2.1 There are many types of operation on board",
        "risk": "high",
        "evidence": [
          "The company safe work procedures for working at height.",
          "The working at height permits or risk assessments for the previous two months.",
          "Records of the periodic checks of working at height PPE and specialist equipment."
        ],
        "negative_grounds": [
          "There was no company safe working procedure which included working at height.",
          "Page 475 of 711 – SIRE 2.0 Question Library: Part 1 Version 1.0 (January 2022)",
          "There was no requirement to complete a permit or risk assessment when working at height unless the",
          "company procedure provided specific exclusions.",
          "There was no requirement to check PPE and specialist working at height equipment periodically and record"
        ]
      },
      {
        "id": "C5Q5_5_4",
        "number": "5.5.4",
        "text": "Were the Master, officers and ratings familiar with the company procedures for  working over the side, and was there evidence that risk control measures such as  standard work procedures, permits to work or documented risk assessments were  consistently used whenever work was undertaken over the side?",
        "short_text": "Working over the side",
        "vessel_types": [
          "Oil",
          "Chemical",
          "LPG",
          "LNG"
        ],
        "section": "5.5",
        "section_name": "Bunkering",
        "objective": "To ensure that work over the side is always conducted in a controlled manner with procedures to manage  and mitigate risk to workers.  Industry Guidance  UK MCA: Code of Safe Working Practices for Merchant Seafarers.  Chapter 14.2 Permit to work systems  14.2.1 There are many types of operation on b",
        "risk": "high",
        "evidence": [
          "The company safe work procedures for working over the side.",
          "Standard work procedures for work over the side that did not require a permit or risk assessment to be",
          "prepared on each occasion.",
          "The work over the side permits or risk assessments for the previous six months.",
          "Records of the periodic checks of specialist working at height and over the side PPE and equipment."
        ],
        "negative_grounds": [
          "There was no company safe working procedure which included working over the side.",
          "There was no requirement to complete a permit or risk assessment when working over the side unless the",
          "company procedures provided specific exclusions.",
          "The accompanying officer was unfamiliar with the company working over the side safe work procedure.",
          "The accompanying officer was unfamiliar with the requirement to conduct periodic checks on specialist"
        ]
      },
      {
        "id": "C5Q5_5_5",
        "number": "5.5.5",
        "text": "Were the Master and officers familiar with the company procedures for working on  electrical equipment and systems, and was there evidence that risk control measures  such as permits to work and/or documented risk assessments were consistently used  whenever work was undertaken on electrical equipment and systems?",
        "short_text": "Working on electrical equipment and systems",
        "vessel_types": [
          "Oil",
          "Chemical",
          "LPG",
          "LNG"
        ],
        "section": "5.5",
        "section_name": "Bunkering",
        "objective": "To ensure that work on electrical equipment and systems is always conducted in a controlled manner with  procedures to manage and mitigate risk to workers.  Industry Guidance  UK MCA: Code of Safe Working Practices for Merchant Seafarers.  Chapter 14.2 Permit to work systems  14.2.1 There are many t",
        "risk": "high",
        "evidence": [
          "The company safe work procedure for working on electrical equipment or systems.",
          "The work on electrical equipment or systems permits and/or risk assessments for the previous two months.",
          "Access to the planned maintenance system.",
          "Access the daily work planning meeting records."
        ],
        "negative_grounds": [
          "There was no company safe working procedure which included working on electrical equipment or systems.",
          "There was no requirement to complete a permit and/or risk assessment when working on electrical",
          "equipment or systems.",
          "The accompanying officer was unfamiliar with the company safe work procedure for working on electrical",
          "equipment or systems."
        ]
      },
      {
        "id": "C5Q5_5_6",
        "number": "5.5.6",
        "text": "Were the Master and officers familiar with the company procedures for the control  of hazardous energy, and was evidence available, through documented risk assessment  or permits, that hazardous energy sources were routinely identified and isolated before  working on, or in, machinery, systems or spaces where hazardous energy could be  present?",
        "short_text": "Control of hazardous energy",
        "vessel_types": [
          "Oil",
          "Chemical",
          "LPG",
          "LNG"
        ],
        "section": "5.5",
        "section_name": "Bunkering",
        "objective": "To ensure that hazardous energy sources are always identified and effectively isolated before work starts on,  or in, machinery, systems or spaces where hazardous energy sources could be present.  Industry Guidance  OCIMF/ICS: International Safety Guide for Oil Tankers and Terminals. Sixth Edition. ",
        "risk": "high",
        "evidence": [
          "The company control of hazardous energy procedures.",
          "Permits, Safety Critical Task Assessments, risk assessments or other documented work processes that had",
          "been used to identify and control hazardous energy sources for the previous three months.",
          "The daily work planning records.",
          "The Bridge Log Book.",
          "The Engine Room Logbook."
        ],
        "negative_grounds": [
          "Page 485 of 711 – SIRE 2.0 Question Library: Part 1 Version 1.0 (January 2022)",
          "There were no company control of hazardous energy procedures.",
          "There was no specialist LO/TO equipment available onboard.",
          "There was no inventory of specialist LO/TO equipment.",
          "Work had been completed that required either a permit, risk assessment or other documented work"
        ]
      },
      {
        "id": "C5Q5_6_1",
        "number": "5.6.1",
        "text": "Were the Master and officers familiar with the purpose, operation, testing,  maintenance and calibration of the vessel’s portable and personal gas measurement  instruments, and was the equipment on board sufficient, in good working order, regularly  tested and periodically calibrated?",
        "short_text": "Portable and personal gas measurement instruments",
        "vessel_types": [
          "Oil",
          "Chemical",
          "LPG",
          "LNG"
        ],
        "section": "5.6",
        "section_name": "Mooring",
        "objective": "To ensure sufficient calibrated portable and personal gas measurement instruments are always available on  board to enable safe enclosed space entry and cargo operations.  Industry Guidance  OCIMF/ICS: International Safety Guide for Oil Tankers and Terminals. Sixth Edition  2.4.2 Gas measurement ins",
        "risk": "high",
        "evidence": [
          "The company procedures for the operation, testing, maintenance and calibration of the vessel’s portable and",
          "personal gas measurement instruments.",
          "The inventory of portable and personal gas measurement instruments, spare parts, test gases and tubes,",
          "chips or other consumables for measuring toxic gases.",
          "Instruction manuals for the portable and personal gas measurement instruments.",
          "Test and calibration records for the portable and personal gas measurement instruments."
        ],
        "negative_grounds": [
          "There were no company procedures for the operation, testing, maintenance and calibration of the portable",
          "and personal gas measurement instruments.",
          "The accompanying officer was unable to explain or demonstrate:",
          "o",
          "The type and number of portable and personal gas measurement instruments required to be"
        ]
      },
      {
        "id": "C5Q5_6_2",
        "number": "5.6.2",
        "text": "Were the Master and deck officers familiar with the company procedures for testing  the atmosphere in double-hull and double bottom spaces for flammable gas, and were  records available to confirm that appropriate measurements had been taken using the  equipment fitted to, or provided on, the vessel?",
        "short_text": "Testing the atmosphere in double-hull and double bottom spaces for flammable gas",
        "vessel_types": [
          "Oil",
          "Chemical"
        ],
        "section": "5.6",
        "section_name": "Mooring",
        "objective": "To ensure that structural failures between cargo tanks adjacent to ballast tanks and void spaces of double- hull and double-bottom spaces are promptly detected.  Industry Guidance   OCIMF/ICS: International Safety Guide for Oil Tankers and Terminals. Sixth Edition  11.3.4 Monitoring of Void and Ball",
        "risk": "high",
        "evidence": [
          "The company procedures for detecting and monitoring flammable gas concentrations in double-hull, double-",
          "bottom and void spaces.",
          "Records to demonstrate that hydrocarbon gas measurements had been undertaken in accordance with the",
          "company procedure.",
          "Records to demonstrate that the fixed gas detecting system, where fitted, had been in continuous operation",
          "and where individual tank sensors, or groups of sensors, had been isolated, the times of isolation and"
        ],
        "negative_grounds": [
          "There was no company procedure which defined the process and frequency for testing double-hull, double-",
          "bottom and void spaces. for hydrocarbon gas accumulation.",
          "The accompanying deck officer was unfamiliar with the company procedure for monitoring double-hull,",
          "double-bottom and void spaces for hydrocarbon gas accumulation.",
          "Records, or absence of records, indicated that gas measurements had not been taken and recorded in"
        ]
      },
      {
        "id": "C5Q5_6_3",
        "number": "5.6.3",
        "text": "Were the Master and officers familiar with the location, purpose and operation of  the vessel’s fixed gas detection systems required by the IGC Code, and was the  equipment in good working order, regularly maintained and calibrated?",
        "short_text": "Fixed gas detection systems required by the IGC Code",
        "vessel_types": [
          "LPG",
          "LNG"
        ],
        "section": "5.6",
        "section_name": "Mooring",
        "objective": "To ensure that the vessel staff can detect unintentional releases or leaks from the cargo system.  Industry Guidance  SIGTTO: Liquified Gas Handling Principles on Ships and in Terminals. Fourth Edition.  4.11.5 Gas detection systems  Releases of flammable or toxic gases pose an immediate threat to b",
        "risk": "high",
        "evidence": [
          "The company procedures for the operation and maintenance of the fixed gas detecting systems required",
          "under the IGC code.",
          "Inspection, calibration and maintenance records for the fixed gas detection systems.",
          "The list of fixed gas detector sensors and the corresponding alarm (and where appropriate, automatic",
          "shutdown) set points.",
          "The manufacturer's calibration instructions for the fixed gas detecting systems and sensors."
        ],
        "negative_grounds": [
          "There was no company procedure for the operation and maintenance of the fixed gas detecting systems",
          "required by the IGC code.",
          "The fixed gas detection systems required by the IGC code were:",
          "o",
          "Not monitoring all sensors provided by the systems."
        ]
      },
      {
        "id": "C5Q5_6_4",
        "number": "5.6.4",
        "text": "Were the Master and officers familiar with the location, purpose and operation of  the vessel’s fixed gas detection system required by the IGF Code, and was the  equipment in good working order, regularly maintained and calibrated in accordance  with company procedures and manufacturer’s instructions?",
        "short_text": "Fixed gas detection system required by the IGF Code",
        "vessel_types": [
          "Oil",
          "Chemical",
          "LPG"
        ],
        "section": "5.6",
        "section_name": "Mooring",
        "objective": "To ensure that the vessel is protected from the consequences of unintentional releases or leaks from the gas  or other low-flashpoint fuel system.  Industry Guidance  IMO: A 31/Res.1140 Survey guidelines under the harmonized system of survey and certification (HSSC)  (Cargo Ship Safety Construction ",
        "risk": "high",
        "evidence": [
          "The company procedure which defined the requirements for operating and testing the fixed gas detecting",
          "system required under the IGF Code.",
          "Page 503 of 711 – SIRE 2.0 Question Library: Part 1 Version 1.0 (January 2022)",
          "The manufacturer’s instruction manual for the fixed gas detecting system.",
          "The Inspection, calibration and maintenance records for the fixed gas detection system."
        ],
        "negative_grounds": [
          "There was no company procedure which defined the requirements for operating and testing the fixed gas",
          "detecting system required under the IGF Code.",
          "The vessel’s maintenance plan did not include the fixed gas detecting system required under the IGF Code.",
          "The maintenance plan did not define the frequency of sensor calibration and automated gas safety system",
          "shut down tests."
        ]
      },
      {
        "id": "C5Q5_6_5",
        "number": "5.6.5",
        "text": "Were the Master and officers familiar with the operation and maintenance of the  cargo pump room fixed gas detection system, and was the equipment fully operational  with sensors calibrated and alarm activation points set in accordance with company  procedures and manufacturer's instructions?",
        "short_text": "Cargo pump room fixed gas detection system",
        "vessel_types": [
          "Oil",
          "Chemical"
        ],
        "section": "5.6",
        "section_name": "Mooring",
        "objective": "To ensure that measures specifically designed to prevent fire in the pumproom are effective.  Industry Guidance  OCIMF/ICS: International Safety Guide for Oil Tankers and Terminals. Sixth Edition.  12.1.14.7  The safety of pump rooms can be enhanced in a number of other ways, some of which are manda",
        "risk": "high",
        "evidence": [
          "The company procedures for the maintenance and operation of the cargo pumproom gas detection system.",
          "The manufacturer’s instruction manual for the pumproom fixed gas detection system.",
          "The maintenance and calibration records for the cargo pumproom gas detection system.",
          "Where the fixed gas detection system was out of service, records of manual atmosphere measurements."
        ],
        "negative_grounds": [
          "There was no company procedure for the maintenance and operation of the pumproom gas detection",
          "system.",
          "The accompanying officer was unfamiliar with the operation and maintenance of the pumproom gas",
          "detection system.",
          "The alarm activation point of one or more hydrocarbon gas sensors was more than 10% LFL."
        ]
      },
      {
        "id": "C5Q5_6_6",
        "number": "5.6.6",
        "text": "Were the Master and officers familiar with the operation and maintenance of the  oxygen sensors and associated alarms fitted in the space, or spaces, containing the inert  gas system, and was the equipment fully operational with sensors calibrated and alarm  activation points set in accordance with company procedures and manufacturer's  instructions?",
        "short_text": "Oxygen sensors in inert gas system spaces.",
        "vessel_types": [
          "Oil",
          "Chemical"
        ],
        "section": "5.6",
        "section_name": "Mooring",
        "objective": "To ensure that entry into the space, or spaces, containing the inert gas plant is always made safely.  Industry Guidance  OCIMF/ICS: International Safety Guide for Oil Tankers and Terminals. Sixth Edition  10.4.3 Risk from inert gas including nitrogen  IG produced from boiler flue gas, or an IG gene",
        "risk": "high",
        "evidence": [
          "The company procedures for the maintenance and operation of the oxygen sensors and associated alarms",
          "fitted in the space or spaces containing the inert gas system.",
          "The manufacturer’s instruction manual for the oxygen sensors and associated alarms fitted in the space, or",
          "spaces, containing the inert gas system.",
          "The maintenance and calibration records for the oxygen sensors fitted in the space, or spaces, containing",
          "the inert gas system."
        ],
        "negative_grounds": [
          "There was no company procedure describing the maintenance and operation of the oxygen sensors and",
          "associated alarms fitted in the space, or spaces, containing the inert gas system.",
          "The accompanying officer was unfamiliar with the operation and maintenance of the oxygen sensors and",
          "associated alarms fitted in the space, or spaces, containing the inert gas system.",
          "The oxygen sensors had not been calibrated in accordance with manufacturer’s instructions at the frequency"
        ]
      },
      {
        "id": "C5Q5_7_1",
        "number": "5.7.1",
        "text": "Had all onboard incidents been reported and investigated in accordance with  company procedures, and was an incident investigation report or a summarised lessons  learned bulletin available for each incident at or above a defined threshold?",
        "short_text": "Incident investigation reports for defined incidents",
        "vessel_types": [
          "Oil",
          "Chemical",
          "LPG",
          "LNG"
        ],
        "section": "5.7",
        "section_name": "Deck Safety",
        "objective": "To ensure that seafarers can learn from incidents which occurred onboard their vessel to improve safety and  pollution prevention standards.  Industry Guidance  OCIMF / INTERTANKO: Sharing Lessons Learned from Incidents. First Edition 2018.  Purpose and Scope  The shipping industry has worked hard i",
        "risk": "high",
        "evidence": [
          "The company procedures that required incidents and near-misses were promptly reported and investigated.",
          "The system for tracking incident and near-miss reports to closure.",
          "Incident investigation reports or lessons learned for any of the incident types listed in the guidance notes",
          "which had occurred during the 12 months prior to the inspection."
        ],
        "negative_grounds": [
          "There was no incident investigation report or lessons learned bulletin available onboard for one or more of",
          "the incidents reported through the HVPQ or PIQ, unless the vessel operator had declared that the incident",
          "investigation was ongoing.",
          "Page 514 of 711 – SIRE 2.0 Question Library: Part 1 Version 1.0 (January 2022)",
          "There was evidence that the vessel had been involved in one of the incident types listed in the inspection"
        ]
      },
      {
        "id": "C5Q5_7_2",
        "number": "5.7.2",
        "text": "Were the Master, officers and ratings familiar with the company incident and near- miss reporting procedure and was evidence available to demonstrate that incidents and  near-misses had been investigated and closed out in accordance with the company  procedure?",
        "short_text": "Incident and near-miss reporting procedure",
        "vessel_types": [
          "Oil",
          "Chemical",
          "LPG",
          "LNG"
        ],
        "section": "5.7",
        "section_name": "Deck Safety",
        "objective": "To ensure that seafarers can learn from incidents and near-misses onboard their vessel to improve safety  and pollution prevention.  Industry Guidance  OCIMF / INTERTANKO: Sharing Lessons Learned from Incidents (First edition 2018)  1.1 Background: why we need guidelines  Vessel operators have diffe",
        "risk": "high",
        "evidence": [
          "The company procedure that required incidents and near-misses were promptly reported by all ranks and",
          "investigated.",
          "The system for tracking incident and near-miss reports to closure.",
          "Shore-based management acknowledgement of incident and near-miss reports.",
          "Incident and near-miss reports generated by the vessel during the previous three months.",
          "Incident and near-miss investigation reports where these were a separate document from the initial report."
        ],
        "negative_grounds": [
          "Page 518 of 711 – SIRE 2.0 Question Library: Part 1 Version 1.0 (January 2022)",
          "There was no company procedure that required incidents and near-misses were promptly reported by all",
          "ranks and investigated.",
          "The Master or accompanying officer was unfamiliar with the process to:",
          "o"
        ]
      },
      {
        "id": "C5Q5_7_3",
        "number": "5.7.3",
        "text": "Were the Master, officers and ratings familiar with the company procedure for  holding and documenting shipboard safety meetings and was evidence available that  safety concerns raised at the meetings were acknowledged and addressed by shore  management?",
        "short_text": "Shipboard safety meetings",
        "vessel_types": [
          "Oil",
          "Chemical",
          "LPG",
          "LNG"
        ],
        "section": "5.7",
        "section_name": "Deck Safety",
        "objective": "To ensure that there is an effective two-way dialogue between the vessel staff and shore-based management  in matters relating to safety and pollution prevention at both the fleet and individual vessel level.  UK MCA: Code of Safe Working Practices for Merchant Seafarers   1.2.2 Effective communicat",
        "risk": "high",
        "evidence": [
          "The company procedures relating to shipboard safety meetings.",
          "The safety committee meeting minutes for all meetings conducted during the previous six months.",
          "The shore management response to all safety committee meetings conducted during the previous six",
          "months except for minutes submitted within one week of the inspection."
        ],
        "negative_grounds": [
          "There were no company procedures which defined the process for holding shipboard safety meetings,",
          "recording the minutes and shore management review of the minutes of each meeting.",
          "Shipboard safety meetings had not been held at the frequency defined by the company procedure or at",
          "approximately monthly intervals.",
          "Extraordinary safety meetings had not been held after a serious incident onboard or during a shore"
        ]
      },
      {
        "id": "C5Q5_7_4",
        "number": "5.7.4",
        "text": "Were the Master, officers and ratings familiar with the company work planning  procedures and were records available to demonstrate that onboard work planning  meetings had been conducted and documented in accordance with the procedures?",
        "short_text": "Work planning procedure",
        "vessel_types": [
          "Oil",
          "Chemical",
          "LPG",
          "LNG"
        ],
        "section": "5.7",
        "section_name": "Deck Safety",
        "objective": "To ensure that all onboard work activities are planned to agree the scope of work and  specific safety  requirements applicable to each task, and to avoid operational, departmental or rest hour conflicts.  Industry Guidance  OCIMF/ICS: International Safety Guide for Oil Tankers and Terminals. Sixth ",
        "risk": "high",
        "evidence": [
          "The company procedure which defined the requirements for documented work planning meetings.",
          "The work planning meeting records for the previous month.",
          "Permits, risk assessments and detailed work plans referenced by work planning meeting records.",
          "The Bridge Log Book.",
          "Page 524 of 711 – SIRE 2.0 Question Library: Part 1 Version 1.0 (January 2022)"
        ],
        "negative_grounds": [
          "There was no company procedure which defined the requirements for documented work planning meetings.",
          "Work planning meetings were not being held at the frequency defined by the company procedure.",
          "Work planning meeting records had not been approved onboard in accordance with the company",
          "procedures.",
          "The outcome from work planning meetings was not being recorded in the format defined by the company"
        ]
      },
      {
        "id": "C5Q5_7_5",
        "number": "5.7.5",
        "text": "Were the Master, officers and ratings familiar with the purpose and implementation  of the company Stop Work Authority policy and procedure?",
        "short_text": "Stop Work Authority",
        "vessel_types": [
          "Oil",
          "Chemical",
          "LPG",
          "LNG"
        ],
        "section": "5.7",
        "section_name": "Deck Safety",
        "objective": "To ensure that vessel staff are aware of their responsibility and authority to stop unsafe work.  Industry Guidance  OCIMF/ICS: International Safety Guide for Oil Tankers and Terminals. Sixth Edition  Chapter 4.2 Stop Work Authority  It is recommended that tanker and terminal safety management syste",
        "risk": "high",
        "evidence": [
          "The company Stop Work Authority policy and procedure.",
          "Any onboard work planning tools such as tool-box talks, risk assessments, daily work planning meetings or",
          "safety meetings which highlight the use of Stop Work Authority."
        ],
        "negative_grounds": [
          "There was no company Stop Work Authority policy and procedure.",
          "There was no evidence that Stop Work Authority was included and discussed in work planning processes",
          "such as tool-box talks, risk assessments, daily work planning meetings or safety meetings.",
          "More than one crewmember was unfamiliar with the company Stop Work Authority policy and/or procedure.",
          "Page 527 of 711 – SIRE 2.0 Question Library: Part 1 Version 1.0 (January 2022)"
        ]
      },
      {
        "id": "C5Q5_7_6",
        "number": "5.7.6",
        "text": "Were the Master, officers and ratings familiar with the company procedures for risk  assessment, as appropriate to their duties, and was there evidence of the development  and review of risk assessments in accordance with the procedures?",
        "short_text": "Risk assessments for  new, non-routine, unplanned or specified tasks",
        "vessel_types": [
          "Oil",
          "Chemical",
          "LPG",
          "LNG"
        ],
        "section": "5.7",
        "section_name": "Deck Safety",
        "objective": "To ensure that new, non-routine or unplanned tasks, not covered by existing procedures, are subject to risk  assessment before work starts, and that risk assessments are reviewed before work starts on other specified  tasks such as enclosed space entry or hot-work.  Industry Guidance  OCIMF/ICS: Int",
        "risk": "high",
        "evidence": [
          "The company procedure describing the risk assessment development and review processes.",
          "The risk assessments used onboard during the previous three months."
        ],
        "negative_grounds": [
          "Page 530 of 711 – SIRE 2.0 Question Library: Part 1 Version 1.0 (January 2022)",
          "There was no company procedure describing the risk assessment development and review processes.",
          "The company risk assessment procedure did not define:",
          "o",
          "The circumstances in which a risk assessment must be developed or reviewed."
        ]
      },
      {
        "id": "C5Q5_7_7",
        "number": "5.7.7",
        "text": "Were Safety Data Sheets (SDS) available on board for all  cargo, bunkers,  chemicals, paints and other products being handled, and were crew members familiar  with their use?",
        "short_text": "Safety Data Sheets.",
        "vessel_types": [
          "Oil",
          "Chemical",
          "LPG",
          "LNG"
        ],
        "section": "5.7",
        "section_name": "Deck Safety",
        "objective": "To ensure crew members are provided with clear, accurate information on the health and environmental  effects of all hazardous and toxic substances carried on board, including guidance on their safe handling.  Industry Guidance  OCIMF/ICS: International Safety Guide for Oil Tankers and Terminals. Si",
        "risk": "high",
        "evidence": [
          "Company procedures to ensure that up to date Safety Data Sheets are readily available for all hazardous or",
          "toxic substances carried on board and to give guidance on the handling and stowage of these substances.",
          "SDSs for, where carried:",
          "o",
          "All oil, chemical and/or gas cargoes.",
          "o"
        ],
        "negative_grounds": [
          "There were no company procedures to ensure that up to date Safety Data Sheets are readily available for all",
          "hazardous or toxic substances carried on board and to give guidance on the handling and stowage of these",
          "substances, including PPE requirements.",
          "The accompanying officer was not familiar with the purpose and content of the relevant SDSs.",
          "There was no SDS available for a cargo or fuel oil on board at the time of the inspection."
        ]
      },
      {
        "id": "C5Q5_7_8",
        "number": "5.7.8",
        "text": "Were the Master, officers and ratings familiar with the company Simultaneous  Operations (SIMOPS) procedure and was there evidence that SIMOPS were considered  during work planning and the required controls implemented for the duration of such  operations?",
        "short_text": "Simultaneous Operations (SIMOPS) procedure",
        "vessel_types": [
          "Oil",
          "Chemical",
          "LPG",
          "LNG"
        ],
        "section": "5.7",
        "section_name": "Deck Safety",
        "objective": "To ensure that the impact of Simultaneous Operations (SIMOPS) is understood and managed effectively.  Industry Guidance  OCIMF/ICS: International Safety Guide for Oil Tankers and Terminals. Sixth Edition.  Chapter 4.6 Simultaneous Operations  Simultaneous Operations (SIMOPS) are activities that take",
        "risk": "high",
        "evidence": [
          "The company procedure which provided guidance and instruction on Simultaneous Operations (SIMOPS).",
          "The SIMOPS decision matrix, if provided as part of the SIMOPS procedure.",
          "The SIMOPS matrix of permitted operations, if provided as part of the SIMOPS procedure.",
          "The daily work planning meeting records.",
          "Risk assessments dealing with SIMOPS for the previous three months.",
          "SIMOPS plan/interface documents."
        ],
        "negative_grounds": [
          "There was no company procedure which gave guidance and instruction on Simultaneous Operations",
          "(SIMOPS).",
          "The accompanying officer was unfamiliar with the company SIMOPS procedure.",
          "Page 539 of 711 – SIRE 2.0 Question Library: Part 1 Version 1.0 (January 2022)",
          "The accompanying officer was unfamiliar with the decision matrix or the matrix of permitted operations,"
        ]
      },
      {
        "id": "C5Q5_8_1",
        "number": "5.8.1",
        "text": "Were the Master and officers familiar with the company procedure for safety  inspections of the main deck areas, and had inspections been effective in identifying  hazards to health, safety and the environment?",
        "short_text": "Safety inspection of the main deck and mooring areas.",
        "vessel_types": [
          "Oil",
          "Chemical",
          "LPG",
          "LNG"
        ],
        "section": "5.8",
        "section_name": "Fire Safety",
        "objective": "To ensure that the main deck areas are always maintained in a safe condition.  Industry Guidance  UK MCA: Code of Safe Working Practices for Merchant Seafarers  2.5 Good housekeeping  2.5.1 All ships move in a seaway and as space is very limited aboard any vessel, good housekeeping is essential for ",
        "risk": "high",
        "evidence": [
          "The company procedure which requires that safety inspections of the main deck areas are conducted at",
          "appropriate intervals by the designated Safety Officer to identify hazards and potential hazards to health,",
          "safety and the environment.",
          "Records of safety inspections of the main deck areas including associated checklists."
        ],
        "negative_grounds": [
          "There was no company procedure which required that safety inspections of the main deck areas were",
          "conducted at appropriate intervals by the designated Safety Officer to identify hazards and potential hazards",
          "to health, safety and the environment.",
          "Records of safety inspections of the main deck areas were missing or incomplete.",
          "There was no checklist provided to facilitate the safety inspections of the main deck areas."
        ]
      },
      {
        "id": "C5Q5_8_2",
        "number": "5.8.2",
        "text": "Were the Master and officers familiar with the company procedure for safety  inspections of the machinery spaces, and had inspections been effective in identifying  hazards to health, safety and the environment?",
        "short_text": "Safety inspection of the machinery space.",
        "vessel_types": [
          "Oil",
          "Chemical",
          "LPG",
          "LNG"
        ],
        "section": "5.8",
        "section_name": "Fire Safety",
        "objective": "To ensure that the machinery spaces are always maintained in a safe condition.  Industry Guidance  ICS: Engine Room Procedures Guide. First Edition.  11.14 Essential Engine Room Seamanship.  Good housekeeping is a routine matter that should not be neglected in an engine room, even during times of he",
        "risk": "high",
        "evidence": [
          "The company procedure which required that safety inspections of the machinery spaces were conducted at",
          "appropriate intervals by the designated Safety Officer to identify hazards and potential hazards to health,",
          "safety and the environment.",
          "Records of safety inspections of the machinery spaces including associated checklists."
        ],
        "negative_grounds": [
          "There was no company procedure which required that safety inspections of the machinery spaces were",
          "conducted at appropriate intervals by the designated Safety Officer to identify hazards and potential hazards",
          "to health, safety and the environment.",
          "Records of safety inspections of the machinery spaces were missing or incomplete.",
          "There was no checklist provided to facilitate the safety inspections of the machinery spaces."
        ]
      },
      {
        "id": "C5Q5_8_3",
        "number": "5.8.3",
        "text": "Were the Master and officers familiar with the company procedure for safety  inspections of the cargo pumproom, and had inspections been effective in identifying  hazards to health, safety and the environment?",
        "short_text": "Safety inspections of the cargo pumproom",
        "vessel_types": [
          "Oil",
          "Chemical"
        ],
        "section": "5.8",
        "section_name": "Fire Safety",
        "objective": "To ensure that the cargo pump room is always maintained in a safe condition.  Industry Guidance  OCIMF/ICS: International Safety Guide for Oil Tankers and Terminals. Sixth Edition  4.11.7 Inspection, maintenance and testing of electrical equipment  4.11.7.1 Inspection and checks  Typical inspections",
        "risk": "high",
        "evidence": [
          "The company procedure which required that safety inspections of the cargo pumproom were conducted at",
          "appropriate intervals by the designated Safety Officer to identify hazards and potential hazards to health,",
          "safety and the environment.",
          "Records of safety inspections of the cargo pumproom including associated checklists."
        ],
        "negative_grounds": [
          "There was no company procedure which required that safety inspections of the cargo pumproom be",
          "conducted at appropriate intervals by the designated Safety Officer to identify hazards and potential hazards",
          "to health, safety and the environment.",
          "Records of safety inspections of the cargo pumproom were missing or incomplete.",
          "There was no checklist provided to facilitate the safety inspections of the cargo pumproom."
        ]
      },
      {
        "id": "C5Q5_8_4",
        "number": "5.8.4",
        "text": "Were the Master and officers familiar with the procedure for safety inspections of  the cargo machinery rooms, and had inspections been effective in identifying hazards to  health, safety and the environment?",
        "short_text": "Cargo machinery rooms safety inspections",
        "vessel_types": [
          "LPG",
          "LNG"
        ],
        "section": "5.8",
        "section_name": "Fire Safety",
        "objective": "To ensure that cargo machinery rooms are always maintained in a safe condition.  Industry Guidance  OCIMF/ICS: International Safety Guide for Oil Tankers and Terminals. Sixth Edition  4.11.7 Inspection, maintenance and testing of electrical equipment  4.11.7.1 Inspection and checks  Typical inspecti",
        "risk": "high",
        "evidence": [
          "The company procedure which required that safety inspections of the cargo machinery rooms be conducted",
          "at appropriate intervals by the designated Safety Officer to identify hazards and potential hazards to health,",
          "safety and the environment.",
          "Records of safety inspections of the cargo machinery rooms including associated checklists.",
          "Records of regular testing of cargo machinery room air-lock audible and visual alarms and shut-down",
          "systems."
        ],
        "negative_grounds": [
          "There was no company procedure which required that safety inspections of the cargo machinery rooms be",
          "conducted at appropriate intervals by the designated Safety Officer to identify hazards and potential hazards",
          "to health, safety and the environment.",
          "Records of safety inspections of the cargo machinery rooms were missing or incomplete.",
          "There was no checklist(s) provided to facilitate the safety inspections of the cargo machinery rooms."
        ]
      },
      {
        "id": "C5Q5_8_5",
        "number": "5.8.5",
        "text": "Were the Master and officers familiar with the company procedure for safety  inspections of the forecastle, and had inspections been effective in identifying hazards to  health, safety and the environment?",
        "short_text": "Safety inspection of the forecastle spaces",
        "vessel_types": [
          "Oil",
          "Chemical",
          "LPG",
          "LNG"
        ],
        "section": "5.8",
        "section_name": "Fire Safety",
        "objective": "To ensure that the forecastle is always maintained in a safe condition.  Industry Guidance  UK MCA: Code of Safe Working Practices for Merchant Seafarers  2.5 Good housekeeping  2.5.1 All ships move in a seaway and as space is very limited aboard any vessel, good housekeeping is essential for  safe ",
        "risk": "high",
        "evidence": [
          "The company procedure which required that safety inspections of the forecastle were conducted at",
          "appropriate intervals by the designated Safety Officer to identify hazards and potential hazards to health,",
          "safety and the environment.",
          "Records of safety inspections of the forecastle including associated checklists."
        ],
        "negative_grounds": [
          "There was no company procedure which required that safety inspections of the forecastle were conducted at",
          "appropriate intervals by the designated Safety Officer to identify hazards and potential hazards to health,",
          "safety and the environment.",
          "Records of safety inspections of the forecastle were missing or incomplete.",
          "There was no checklist provided to facilitate the safety inspections of the forecastle."
        ]
      },
      {
        "id": "C5Q5_8_6",
        "number": "5.8.6",
        "text": "Were the Master and officers familiar with the company procedure for safety  inspections of the accommodation, and had inspections been effective in identifying  hazards to health, safety and the environment?",
        "short_text": "Safety inspections of the accommodation spaces",
        "vessel_types": [
          "Oil",
          "Chemical",
          "LPG",
          "LNG"
        ],
        "section": "5.8",
        "section_name": "Fire Safety",
        "objective": "To ensure that the accommodation is always maintained in a safe condition.  Industry Guidance  UK MCA: Code of Safe Working Practices for Merchant Seafarers  2.2.3 Fire aboard a vessel can be disastrous. Common causes are:  •  faulty electrical appliances/circuitry;  •  overloading of electrical cir",
        "risk": "high",
        "evidence": [
          "The company procedure which required that safety inspections of the accommodation were conducted at",
          "appropriate intervals by the designated Safety Officer to identify hazards and potential hazards to health,",
          "safety and the environment.",
          "Records of safety inspections of the accommodation including associated checklists.",
          "Records of regular testing of the refrigerated room alarm."
        ],
        "negative_grounds": [
          "There was no company procedure which required that safety inspections of the accommodation were",
          "conducted at appropriate intervals by the designated Safety Officer to identify hazards and potential hazards",
          "to health, safety and the environment.",
          "Records of safety inspections of the accommodation were missing or incomplete.",
          "There was no checklist provided to facilitate the safety inspections of the accommodation."
        ]
      },
      {
        "id": "C5Q5_8_7",
        "number": "5.8.7",
        "text": "Were the Master and officers familiar with the company procedure for safety  inspections of the ballast and/or bunker pumproom, and had inspections been effective  in identifying hazards to health, safety and the environment?",
        "short_text": "Ballast and/or bunker pumproom safety inspection",
        "vessel_types": [
          "Oil",
          "Chemical",
          "LPG",
          "LNG"
        ],
        "section": "5.8",
        "section_name": "Fire Safety",
        "objective": "To ensure that the ballast and/or bunker pump room is always maintained in a safe condition.  Industry Guidance  OCIMF/ICS: International Safety Guide for Oil Tankers and Terminals. Sixth Edition  4.11.7 Inspection, maintenance and testing of electrical equipment  4.11.7.1 Inspection and checks  Typ",
        "risk": "high",
        "evidence": [
          "The company procedure which required that safety inspections of the ballast and/or bunker pumproom were",
          "conducted at appropriate intervals by the designated Safety Officer to identify hazards and potential hazards",
          "to health, safety and the environment.",
          "Records of safety inspections of the ballast and/or bunker pumproom including associated checklists."
        ],
        "negative_grounds": [
          "There was no company procedure which required that safety inspections of the ballast and/or bunker",
          "pumproom be conducted at appropriate intervals by the designated Safety Officer to identify hazards and",
          "potential hazards to health, safety and the environment.",
          "Records of safety inspections of the ballast and/or bunker pumproom were missing or incomplete.",
          "There was no checklist provided to facilitate the safety inspections of the ballast and/or bunker pumproom."
        ]
      },
      {
        "id": "C5Q5_9_1",
        "number": "5.9.1",
        "text": "Were the Master, officers and ratings familiar with the company lifting and rigging  procedures, and was evidence available to demonstrate that each item of lifting and  rigging equipment had been maintained, inspected and tested in accordance with the  procedure?",
        "short_text": "Lifting and rigging equipment procedures, maintenance and inspection",
        "vessel_types": [
          "Oil",
          "Chemical",
          "LPG",
          "LNG"
        ],
        "section": "5.9",
        "section_name": "Emergency Equipment",
        "objective": "To ensure that all lifting and rigging equipment has been thoroughly inspected at least annually and is  always fit for purpose when used.  Industry Guidance  OCIMF: Recommendations for the Tagging/Labelling, Testing and Maintenance, Documentation/Certification  for Ships' Lifting Equipment  May 200",
        "risk": "high",
        "evidence": [
          "The company procedure for the management of lifting and rigging equipment.",
          "Page 573 of 711 – SIRE 2.0 Question Library: Part 1 Version 1.0 (January 2022)",
          "The certificates for each item of lifting equipment covered by a Classification Society programme.",
          "The records of periodic inspections by a competent person required to be maintained for each item of lifting",
          "equipment and loose gear covered by a Classification Society programme.",
          "The inventory of lifting and rigging equipment not covered by a Classification Society programme."
        ],
        "negative_grounds": [
          "There was no company procedure for the management of lifting and rigging equipment.",
          "The accompanying officer was unfamiliar with the company procedure for the management of lifting and",
          "rigging equipment.",
          "Certification for lifting equipment and loose gear covered by a Classification Society programme had not",
          "been maintained in accordance with the Classification Society requirements:"
        ]
      },
      {
        "id": "C5Q5_9_2",
        "number": "5.9.2",
        "text": "Where the vessel was fitted with a single cargo hose handling crane, was a risk  assessment available which identified the minimum spare parts that must be carried  onboard to ensure continued operation in the event of a single component failure, and  were the identified spare parts available onboard?",
        "short_text": "Spare parts for a single cargo hose handling crane.",
        "vessel_types": [
          "Oil",
          "Chemical",
          "LPG",
          "LNG"
        ],
        "section": "5.9",
        "section_name": "Emergency Equipment",
        "objective": "To ensure that a hose crane is always available to connect and disconnect cargo hoses.  Industry Guidance  TMSA KPI 4.1.1 requires that each vessel in the fleet is covered by a planned maintenance system and spare parts  inventory which reflects the company’s strategy.  The company identifies all eq",
        "risk": "high",
        "evidence": [
          "The risk assessment for the continued operation of a single hose crane.",
          "The inventory of spare parts for the hose crane including hydraulic hoses, with details of length, diameter",
          "and hose end fittings.",
          "The hose crane operations and maintenance manual which included the full list of hydraulic hoses, including",
          "diameter and length, fitted to the hose handling crane."
        ],
        "negative_grounds": [
          "There was no risk assessment available which identified the minimum spare parts that must be carried for a",
          "single hose handling crane.",
          "There was not at least one spare hydraulic hose suitable to replace any hydraulic hose fitted to the hose",
          "handling crane.",
          "Any other spare parts identified by the risk assessment as being essential for the continued use of the hose"
        ]
      },
      {
        "id": "C5Q5_10_1",
        "number": "5.10.1",
        "text": "Were the Master, deck officers and deck ratings familiar with the company  procedures for rigging the pilot boarding arrangements, and was the equipment provided  in satisfactory condition and used in accordance with industry best practice?",
        "short_text": "Pilot boarding arrangements",
        "vessel_types": [
          "Oil",
          "Chemical",
          "LPG",
          "LNG"
        ],
        "section": "5.10",
        "section_name": "Gas Detection",
        "objective": "To ensure pilot boarding arrangements are always correctly rigged under the supervision of a responsible  officer.  Industry Guidance  ICS: Bridge Procedures Guide. Fifth Edition.  5.3.2 Embarking the Pilot  The Master should ensure the availability of a properly maintained means of pilot embarkatio",
        "risk": "high",
        "evidence": [
          "The company procedure for the safe rigging of the pilot boarding arrangements.",
          "The manufacturer’s certificates for each pilot ladder.",
          "The manufacturer’s repair instructions, where provided.",
          "The maintenance records for each pilot ladder which included the date the ladder was put in service."
        ],
        "negative_grounds": [
          "There was no company procedure for the safe rigging of the pilot boarding arrangements.",
          "An inspected pilot ladder was found:",
          "o",
          "Without any identification to connect it to its manufacturer’s certificate or maintenance records.",
          "o"
        ]
      },
      {
        "id": "C5Q5_10_2",
        "number": "5.10.2",
        "text": "Were the Master, deck officers and deck ratings familiar with the company  procedures for rigging the accommodation ladders, and were the accommodation  ladders in good order and used in accordance with the company procedure and  manufacturer’s instructions?",
        "short_text": "Accommodation ladders",
        "vessel_types": [
          "Oil",
          "Chemical",
          "LPG",
          "LNG"
        ],
        "section": "5.10",
        "section_name": "Gas Detection",
        "objective": "To ensure accommodation ladders are always correctly rigged under the supervision of a responsible  person or officer.  Industry Guidance  IMO: MSC.1/Circ.1331 Guidelines for Construction, Installation, Maintenance and Inspection/Survey of Means  of Embarkation and Disembarkation.  3.3 Lifebuoy    A",
        "risk": "high",
        "evidence": [
          "The company procedure for the safe rigging of the accommodation ladders.",
          "The manufacturer’s instructions and/or design drawings for the accommodation ladders.",
          "The maintenance records for each accommodation ladder.",
          "The certificate and date of installation for each accommodation ladder fall wire.",
          "The certificate for the five-yearly load test for each accommodation ladder.",
          "Evidence of thorough examination of the portable gangway during annual surveys."
        ],
        "negative_grounds": [
          "There was no company procedure that described the safe rigging of an accommodation ladder.",
          "The maintenance records for the accommodation ladders were missing or incomplete.",
          "The certificate(s) for the five-yearly load test of an accommodation ladder was not available or the test had",
          "not been completed within the required time frame.",
          "There was no evidence that the accommodation ladder fall wires had been replaced within the previous five"
        ]
      },
      {
        "id": "C5Q5_10_3",
        "number": "5.10.3",
        "text": "Were the Master, officers and ratings familiar with the company procedure for  providing safe access to the vessel while alongside a terminal/berth, and was safe  access provided by the ship’s portable gangway, the vessel’s accommodation ladder or a  shore gangway?",
        "short_text": "Safe access to the vessel while alongside a terminal/berth",
        "vessel_types": [
          "Oil",
          "Chemical",
          "LPG",
          "LNG"
        ],
        "section": "5.10",
        "section_name": "Gas Detection",
        "objective": "To ensure safe access is always provided between the ship and a berth, whether by a ship’s portable  gangway, accommodation ladder or a gangway provided by the terminal.   Industry Guidance  OCIMF/ICS: International Safety Guide for Oil Tankers and Terminals. Sixth Edition.  Chapter 16.4 Tanker/term",
        "risk": "high",
        "evidence": [
          "The company procedure which described the requirements for providing safe access to the vessel while",
          "alongside a terminal/berth.",
          "Where a portable gangway was provided:",
          "o",
          "The manufacturer’s instructions and/or design drawings for the portable gangway.",
          "o"
        ],
        "negative_grounds": [
          "There was no company procedure which described the requirements for providing safe access to the vessel",
          "while alongside a terminal/berth.",
          "The maintenance records for the portable gangway, where provided, were missing or incomplete.",
          "Where a portable gangway was provided:",
          "o"
        ]
      },
      {
        "id": "C5Q5_10_4",
        "number": "5.10.4",
        "text": "Were the Master and officers familiar with the company personnel transfer by  crane procedure, and where a personnel transfer basket (PTB) and accessories were  provided, were these in satisfactory condition and used in accordance with company  procedures and manufacturer’s recommendations?",
        "short_text": "Personnel transfer by crane",
        "vessel_types": [
          "Oil",
          "Chemical",
          "LPG",
          "LNG"
        ],
        "section": "5.10",
        "section_name": "Gas Detection",
        "objective": "To ensure personnel transfer by crane is always conducted in accordance with industry best practice  guidance.  Industry Guidance   OCIMF: Transfer of Personnel by Crane between Vessels. First Edition  1 Introduction  …Crane transfers are typically completed using a Personnel Transfer Basket (PTB). ",
        "risk": "high",
        "evidence": [
          "The company procedure describing personnel transfer by crane.",
          "The manufacturer’s test certificates for the PTB and accessories.",
          "The crane certification for personnel transfer use, where HVPQ question 13.1.7 had been declared as",
          "affirmative.",
          "The training records for the personnel designated for personnel transfer by crane operations.",
          "The onboard maintenance and inspection records for the crane, PTB and accessories."
        ],
        "negative_grounds": [
          "Page 594 of 711 – SIRE 2.0 Question Library: Part 1 Version 1.0 (January 2022)",
          "There was no company procedure describing the requirements for transfer of personnel by crane.",
          "The accompanying officer was not familiar with:",
          "o",
          "The company procedure describing the requirements for transfer of personnel by crane."
        ]
      },
      {
        "id": "C5Q5_10_5",
        "number": "5.10.5",
        "text": "Were the Master and officers familiar with the company procedures for  helicopter/ship operations, and had these procedures been complied with?",
        "short_text": "Helicopter operations",
        "vessel_types": [
          "Oil",
          "Chemical",
          "LPG",
          "LNG"
        ],
        "section": "5.10",
        "section_name": "Gas Detection",
        "objective": "To ensure helicopter/ship operations are performed safely and in a controlled manner.  Industry Guidance   OCIMF: Guidelines for Offshore Tanker Operations   7.4 - Helicopter transfer  7.4.1 Conventional tankers  Conventional tankers do not usually have specialised offshore helicopter facilities. An",
        "risk": "high",
        "evidence": [
          "Company procedures providing guidance on helicopter/ship operations.",
          "Helicopter operations risk assessment and evidence of last review.",
          "ICS Guide to Helicopter/Ship Operations.",
          "Records of training and emergency drills in helicopter/ship operations.",
          "Completed ICS Shipboard Safety Checklists for Helicopter Operations (or equivalent).",
          "Inventory of helicopter tools and equipment required for routine and emergency operations."
        ],
        "negative_grounds": [
          "There were no procedures providing guidance on helicopter/ship operations including:",
          "o",
          "Helicopter operations risk assessment.",
          "Page 598 of 711 – SIRE 2.0 Question Library: Part 1 Version 1.0 (January 2022)",
          "o"
        ]
      },
      {
        "id": "C5Q5_10_6",
        "number": "5.10.6",
        "text": "Were the Master and officers familiar with the company procedures for  helicopter/ship operations, and had the crew involved received appropriate training?",
        "short_text": "Helicopter facilities",
        "vessel_types": [
          "Oil"
        ],
        "section": "5.10",
        "section_name": "Gas Detection",
        "objective": "To ensure helicopter/ship operations on vessels equipped with helicopter facilities are performed safely and  in a controlled manner.  Industry Guidance  OCIMF: Guidelines for Offshore Tanker Operations  7.4 - Helicopter transfer  7.4.2 DP bow loading tankers with helidecks  DP bow loading tankers a",
        "risk": "high",
        "evidence": [
          "Company procedures providing guidance on helicopter/ship operations.",
          "Helicopter operations risk assessment and evidence of last review.",
          "Helicopter Landing Area Certificate (HLAC) if available.",
          "If no HLAC is available, records of appropriate formal accredited training courses such as Offshore",
          "Helicopter Landing Officer (HLO) and Offshore Helideck Assistant (HDA) followed by ship-specific",
          "familiarisation of the helicopter facilities and operations."
        ],
        "negative_grounds": [
          "There were no procedures providing guidance on helicopter/ship operations including:",
          "o",
          "Helicopter operations risk assessment.",
          "o",
          "Identification of job roles and responsibilities for all personnel involved."
        ]
      },
      {
        "id": "C5Q5_10_7",
        "number": "5.10.7",
        "text": "Were the Master, officers and crew familiar with the escape routes from the  machinery spaces, pump rooms, compressor rooms, accommodation spaces and, when  in port, from the vessel, and were these routes clearly marked, unobstructed and well  illuminated?",
        "short_text": "Escape routes",
        "vessel_types": [
          "Oil",
          "Chemical",
          "LPG",
          "LNG"
        ],
        "section": "5.10",
        "section_name": "Gas Detection",
        "objective": "To ensure that there are marked escape routes available to ship and shore personnel in the event of an  emergency on the vessel.  Industry Guidance  OCIMF/ICS: International Safety Guide for Oil Tankers and Terminals. Sixth Edition.  12.1.15 Pumproom operational procedures  12.1.15.3 Routine mainten",
        "risk": "high",
        "evidence": [
          "The company procedure defining the requirements for identifying and marking emergency escape routes."
        ],
        "negative_grounds": [
          "There was no company procedure which defined the requirements for identifying and marking escape",
          "routes.",
          "The escape routes from within the accommodation spaces, machinery spaces, pump rooms, compressor",
          "rooms, thruster rooms or any other spaces where a person could become disorientated in an emergency",
          "were not marked with signs in accordance with IMO guidance."
        ]
      },
      {
        "id": "C5Q5_11_1",
        "number": "5.11.1",
        "text": "Were the Master and officers familiar with the company procedures addressing  the management of samples of bunker fuel oil and Annex I and/or Annex II cargoes as  applicable, and were samples being properly stored and eventually disposed of?",
        "short_text": "Cargo and bunker sample management.",
        "vessel_types": [
          "Oil",
          "Chemical",
          "LPG",
          "LNG"
        ],
        "section": "5.11",
        "section_name": "Sample Management",
        "objective": "To ensure cargo and bunker samples are safely stored on board and properly disposed of in a timely  manner.  Industry Guidance  OCIMF/ICS: International Safety Guide for Oil Tankers and Terminals  13.3 Cargo and bunker samples  The operator’s SMS should include guidance on managing and storing cargo",
        "risk": "high",
        "evidence": [
          "Page 613 of 711 – SIRE 2.0 Question Library: Part 1 Version 1.0 (January 2022)",
          "Company procedures addressing the management of samples of bunker fuel oil and Annex I and/or Annex II",
          "cargoes as applicable.",
          "Records of bunker fuel oil and cargo samples.",
          "Oil Record Book Part II or Cargo Record Book as applicable."
        ],
        "negative_grounds": [
          "There were no company procedures addressing the management of bunker fuel oil and Annex I and/or",
          "Annex II cargo samples as applicable, including:",
          "o",
          "Marking/labelling of samples.",
          "o"
        ]
      },
      {
        "id": "C5Q5_12_1",
        "number": "5.12.1",
        "text": "Were the Master, officers and ratings familiar with the company procedures that  addressed the use of respiratory protective equipment during cargo operations, and did  the procedures prohibit the use of filter type respirators for this purpose?",
        "short_text": "Respiratory protective equipment",
        "vessel_types": [
          "Oil",
          "Chemical",
          "LPG",
          "LNG"
        ],
        "section": "5.12",
        "section_name": "Safety Equipment",
        "objective": "To ensure the correct respiratory protective equipment is worn during cargo operations.  Industry Guidance  OCIMF/ICS: International Safety Guide for Oil Tankers and Terminals. Sixth Edition  10.13 Respiratory Protective Equipment  Cartridge or canister face masks will not protect the user against c",
        "risk": "high",
        "evidence": [
          "Company procedures for the use of respiratory protective equipment during cargo operations."
        ],
        "negative_grounds": [
          "There were no company procedures for the use of respiratory protective equipment during cargo operations.",
          "The company procedures for the use of respiratory protective equipment during cargo operations did not",
          "prohibit the use of filter type respirators during cargo operations.",
          "The accompanying officer was not familiar with the company procedures for the use of respiratory protective",
          "equipment during cargo operations."
        ]
      },
      {
        "id": "C5Q5_12_2",
        "number": "5.12.2",
        "text": "Were the Master, officers and ratings familiar with the location and operation of  the decontamination showers and eyewash stations on deck, and were these facilities  suitably marked, easily accessible and ready for use?",
        "short_text": "Decontamination showers and eyewash stations.",
        "vessel_types": [
          "Chemical",
          "LPG"
        ],
        "section": "5.12",
        "section_name": "Safety Equipment",
        "objective": "To ensure the decontamination showers and eyewash stations provided on deck are always ready to use in  an emergency.  Industry Guidance  ICS: Tanker Safety Guide (Chemicals) - Fifth Edition  2.7.3 Cold Weather  Special attention should be paid to emergency showers and eye wash stations to ensure th",
        "risk": "high",
        "evidence": [
          "Company procedure which ensures that decontamination showers and eye wash stations on deck were",
          "ready for use.",
          "Records of inspection and testing of the decontamination showers and eye wash stations on deck."
        ],
        "negative_grounds": [
          "There was no company procedure which  ensures that decontamination showers and eye wash stations on",
          "deck were ready for use.",
          "Page 618 of 711 – SIRE 2.0 Question Library: Part 1 Version 1.0 (January 2022)",
          "An interviewed rating was not familiar with the location and operation of the decontamination showers and",
          "eyewash stations on deck."
        ]
      }
    ]
  },
  {
    "id": "C6",
    "title": "Pollution Prevention",
    "roles": [
      "Chief Engineer",
      "Master"
    ],
    "questions": [
      {
        "id": "C6Q6_1_1",
        "number": "6.1.1",
        "text": "Were the Master and officers familiar with the company procedure for maintaining  the Cargo Record Book, and did the entries contained in the Cargo Record Book  accurately record the cargo related operations required to be documented by MARPOL  Annex II?",
        "short_text": "Cargo Record Book",
        "vessel_types": [
          "Chemical",
          "LPG"
        ],
        "section": "6.1",
        "section_name": "Pollution Prevention - Record Books",
        "objective": "To ensure that all cargo operations are conducted in compliance with the Procedures and Arrangements  Manual and recorded in accordance with MARPOL Annex II.  Industry Guidance  ICS: Tanker Safety Guide (Chemicals) Fifth edition  4.3.2 MARPOL Annex II Prevention of Pollution by Noxious Liquid Substa",
        "risk": "high",
        "evidence": [
          "The company procedures for maintaining the Cargo Record Book, either in paper or electronic format, in",
          "accordance with MARPOL Annex II and any Flag Administration instructions.",
          "Cargo Record Books for the previous six months.",
          "Cargo records for the previous six months.",
          "The Bridge Log Book for the previous six months.",
          "Where an electronic record book is in use, the Declaration from flag/class."
        ],
        "negative_grounds": [
          "There was no company procedure for maintaining the Cargo Record Book in accordance with MARPOL",
          "Annex II and any Flag Administration instructions.",
          "The accompanying officer was not familiar with company procedures for maintaining the CRB in accordance",
          "with MARPOL Annex II and any Flag Administration instructions.",
          "Where the vessel was using an electronic record book, there were no instructions available for the use of the"
        ]
      },
      {
        "id": "C6Q6_1_2",
        "number": "6.1.2",
        "text": "Were the Master and officers familiar with the company procedure for maintaining  the Oil Record Book Part II, and did the entries contained in the Oil Record Book Part II  accurately record the cargo related operations required to be documented by MARPOL  Annex I?",
        "short_text": "Oil Record Book Part II",
        "vessel_types": [
          "Oil",
          "Chemical"
        ],
        "section": "6.1",
        "section_name": "Pollution Prevention - Record Books",
        "objective": "To ensure that all cargo operations are conducted and recorded in compliance with MARPOL Annex I.  Industry Guidance  INTERTANKO: A Guide for Correct Entries in the Oil Record Book (Part II – Cargo/Ballast Operations).  Second Edition.  2.2 Objective of the Guide  The objective of this Guide is to p",
        "risk": "high",
        "evidence": [
          "The company procedures for maintaining the Oil Record Book Part II in accordance with MARPOL Annex I",
          "and any Flag Administration instructions.",
          "Oil Record Book Part II for the previous six months.",
          "Cargo records for the previous six months.",
          "The Bridge Log Book for the previous six months.",
          "Where an electronic record book is in use, the Declaration from flag/class."
        ],
        "negative_grounds": [
          "There was no company procedure for maintaining the Oil Record Book Part II (ORB II) in accordance with",
          "MARPOL Annex I and any Flag Administration instructions.",
          "The accompanying officer was not familiar with company procedure for maintaining the ORB II in",
          "accordance with MARPOL Annex I and any Flag Administration instructions.",
          "Where the vessel was using an electronic record book, there were no instructions available for the use of the"
        ]
      },
      {
        "id": "C6Q6_1_3",
        "number": "6.1.3",
        "text": "Were the Master and engineer officers familiar with the company procedure for  maintaining the Oil Record Book Part I, and did the entries contained in the Oil Record  Book Part I accurately record the machinery space operations required to be  documented by MARPOL Annex I?",
        "short_text": "Oil Record Book Part I",
        "vessel_types": [
          "Oil",
          "Chemical",
          "LPG",
          "LNG"
        ],
        "section": "6.1",
        "section_name": "Pollution Prevention - Record Books",
        "objective": "To ensure that all machinery space operations are conducted and recorded in compliance with MARPOL  Annex I.  Industry Guidance  INTERTANKO: A Guide for Correct Entries in the Oil Record Book (Part I – Machinery Space Operations).  Fourth Edition.  2.2 Objectives of the Guide  Assist ship operators ",
        "risk": "high",
        "evidence": [
          "The company procedures for maintaining the Oil Record Book Part I in accordance with MARPOL Annex I",
          "and any Flag Administration instructions.",
          "Oil Record Book Part I for the previous six months.",
          "The Engine Room Log Book for the previous six months.",
          "A copy of the supplement to the IOPP certificate (Form B)",
          "Where an electronic record book is in use, the Declaration from flag/class."
        ],
        "negative_grounds": [
          "There was no company procedure for maintaining the Oil Record Book Part I in accordance with MARPOL",
          "Annex I and any Flag Administration instructions.",
          "Where the vessel was using an electronic record book, there were no instructions available for the use of the",
          "electronic record book system.",
          "Where the vessel was using an electronic record book, there was no Declaration from flag/class authorising"
        ]
      },
      {
        "id": "C6Q6_1_4",
        "number": "6.1.4",
        "text": "Were the Master and officers familiar with the company procedures for maintaining  the Garbage Record Book in accordance with the Garbage Management Plan, and did the  entries contained in the Garbage Record Book accurately record the garbage  management activities required to be documented by MARPOL Annex V?",
        "short_text": "Garbage Record Book",
        "vessel_types": [
          "Oil",
          "Chemical",
          "LPG",
          "LNG"
        ],
        "section": "6.1",
        "section_name": "Pollution Prevention - Record Books",
        "objective": "To ensure that all garbage management activities are conducted and recorded in compliance with MARPOL  Annex V.  Industry Guidance  IMO: Guidelines for the Implementation of MARPOL Annex V. 2017 Edition.  Preface  The main objectives of these Guidelines are to assist:  .2 shipowners, ship operators,",
        "risk": "high",
        "evidence": [
          "The company procedures for developing a Garbage Management Plan and maintaining the Garbage Record",
          "Book (GRB), either in paper or electronic format, in accordance with MARPOL Annex V and any Flag",
          "Administration guidance.",
          "The Garbage Management Plan.",
          "Garbage Record Book for the previous six months.",
          "The Bridge Log Book for the previous six months."
        ],
        "negative_grounds": [
          "There was no company procedure  for maintaining the Garbage Record Book, either in paper or electronic",
          "format, in accordance with MARPOL Annex V and any Flag Administration instructions.",
          "Where the vessel was using an electronic record book, there were no instructions available for the use of the",
          "electronic record book system.",
          "Where the vessel was using an electronic record book, there was no Declaration from flag/class authorising"
        ]
      },
      {
        "id": "C6Q6_1_5",
        "number": "6.1.5",
        "text": "Were the Master and engineer officers familiar with the company procedure for  maintaining the Ozone-depleting Substances Record Book, and did the entries contained  in the Ozone-depleting Substances Record Book accurately record the operations and  emissions required to be documented by MARPOL Annex VI?",
        "short_text": "Ozone Depleting Substances Record Book",
        "vessel_types": [
          "Oil",
          "Chemical",
          "LPG",
          "LNG"
        ],
        "section": "6.1",
        "section_name": "Pollution Prevention - Record Books",
        "objective": "To ensure all operations involving ozone-depleting substances, including any deliberate and non-deliberate  emissions, are recorded in compliance with MARPOL Annex VI.  Industry Guidance  IMO: MEPC.312(74) Guidelines for the Use of Electronic Record Books under MARPOL  2.1 These Guidelines are only ",
        "risk": "high",
        "evidence": [
          "The company procedures that described the requirements for maintaining the Ozone-depleting Substances",
          "Record Book, either in paper or electronic format, in accordance with MARPOL Annex VI and any Flag",
          "Administration guidance.",
          "The Ozone-depleting Substances Record Book for the previous six months.",
          "The maintenance records for the equipment on board containing ozone-depleting substances for the",
          "previous six months."
        ],
        "negative_grounds": [
          "There was no company procedure that described the requirements for maintaining the Ozone-depleting",
          "Substances Record Book, either in paper or electronic format, in accordance with MARPOL Annex VI and",
          "any Flag Administration guidance.",
          "The accompanying officer was not familiar with the company procedures that described the requirements for",
          "maintaining the Ozone-depleting Substances Record Book, either in paper or electronic format, in"
        ]
      },
      {
        "id": "C6Q6_1_6",
        "number": "6.1.6",
        "text": "Were the documents and records required by MARPOL Annex VI Regulation 13 for  the control of NOx and associated emissions in good order?",
        "short_text": "MARPOL Annex VI NOx Compliance and Record Keeping.",
        "vessel_types": [
          "Oil",
          "Chemical",
          "LPG",
          "LNG"
        ],
        "section": "6.1",
        "section_name": "Pollution Prevention - Record Books",
        "objective": "To ensure the documents and records required by MARPOL Annex VI for the control of NOx and associated  emissions are maintained as required.  Industry Guidance  IMO: NOx Technical Code (2008) Technical Code on Control of Emission of Nitrogen Oxides from Marine  Diesel Engines  1.3.15 A Technical Fil",
        "risk": "high",
        "evidence": [
          "Company procedures for maintaining the documents and records required by MARPOL Annex VI Regulation",
          "13 and the NOx Technical Code.",
          "International Air Pollution Prevention (IAPP) Certificate.",
          "Technical Files for diesel engines listed in paragraph 2.2.1 of the vessel’s International Air Pollution",
          "Prevention (IAPP) Certificate.",
          "Record Books of Engine Parameters for those engines required to undergo Engine Parameter Checks at"
        ],
        "negative_grounds": [
          "There were no company procedures for maintaining the documents and records required by MARPOL",
          "Annex VI Regulation 13 and the NOx Technical Code.",
          "The accompanying officer was not familiar with the company procedures for maintaining the documents and",
          "records required by MARPOL Annex VI Regulation 13 and the NOx Technical Code.",
          "The accompanying officer was not familiar with the NOx abatement system installed on board, or its"
        ]
      },
      {
        "id": "C6Q6_2_1",
        "number": "6.2.1",
        "text": "Were the Master and officers familiar with the arrangements to drain the cargo  pumproom bilges in the event of flooding or accidental leakage, and were these  arrangements in good order?",
        "short_text": "Flooding or accidental leakage of cargo pumproom bilges",
        "vessel_types": [
          "Oil",
          "Chemical"
        ],
        "section": "6.2",
        "section_name": "Cargo and Bunker Operations",
        "objective": "To ensure that the cargo pumproom bilge pump could be operated when the pumproom was flooded.  Industry Guidance  USCG: Code of Federal Regulations. Title 46.  •  32.52-5   Bilge piping for pump rooms and adjacent cofferdams on tank vessels constructed or converted on  or after November 19, 1952—TB/",
        "risk": "high",
        "evidence": [
          "The company procedures for draining the pumproom bilges.",
          "The shipboard emergency response plan for pumproom flooding.",
          "The Oil Record Book Part II.",
          "Records of tests of the arrangements for draining the pumproom bilges."
        ],
        "negative_grounds": [
          "There was no company procedure for draining the pumproom bilges.",
          "There was no shipboard emergency response plan for pumproom flooding.",
          "The company procedures did not provide guidance on:",
          "o",
          "Transferring bilge contents to cargo/slop tanks or other containment tanks without risk of pollution."
        ]
      },
      {
        "id": "C6Q6_2_2",
        "number": "6.2.2",
        "text": "Were cargo system overboard and sea suction valves checked and verified as  closed and secured prior to commencement of cargo transfer, and where provided, were  sea valve-testing arrangements in order and regularly monitored for leakage?",
        "short_text": "Cargo system overboard and sea suction valves",
        "vessel_types": [
          "Oil",
          "Chemical"
        ],
        "section": "6.2",
        "section_name": "Cargo and Bunker Operations",
        "objective": "To ensure all precautions are taken to prevent cargo spillages through cargo system overboard and sea  suction valves.  Industry Guidance  OCIMF/ICS: International Safety Guide for Oil Tankers and Terminals. Sixth Edition  12.1.14.2 Line displacement with water  On ships with a segregated ballast sy",
        "risk": "high",
        "evidence": [
          "Company procedures to prevent cargo spillages through cargo system overboard and sea suction valves.",
          "Records of",
          "o",
          "Checks that cargo system overboard and sea suction valves are closed and secured prior to",
          "commencement of cargo transfer in the bridge or cargo logbook.",
          "o"
        ],
        "negative_grounds": [
          "There were no company procedures to prevent cargo spillages through cargo system overboard and sea",
          "suction valves that included detailed guidance on:",
          "o",
          "Taking ballast into cargo tanks via sea-valves.",
          "o"
        ]
      },
      {
        "id": "C6Q6_2_3",
        "number": "6.2.3",
        "text": "Were the Master and officers familiar with the company procedures for inspections  and pressure tests of the bunker oil (HFO and MDO) pipeline system, and had the tests  been performed and the results suitably recorded?",
        "short_text": "Bunker pipeline system pressure testing",
        "vessel_types": [
          "Oil",
          "Chemical",
          "LPG",
          "LNG"
        ],
        "section": "6.2",
        "section_name": "Cargo and Bunker Operations",
        "objective": "To ensure the bunker pipeline system is regularly inspected and tested.  Industry Guidance  USCG: Code of Federal Regulations. Title 33.   156.170 Equipment tests and inspections.  (a) Except as provided in paragraph (d) of this section, no person may use any equipment listed in paragraph (c) of  th",
        "risk": "high",
        "evidence": [
          "Company procedures for the inspection and pressure testing of the bunker pipeline system.",
          "Records of inspection and testing of the bunker pipeline system.",
          "Records of testing the bunker system relief valve, where fitted.",
          "Records of testing tank level alarms, where fitted.",
          "Records of the disposal of the liquid used to test the pipeline system."
        ],
        "negative_grounds": [
          "There were no company procedures for the inspection and pressure testing of the bunker pipeline system",
          "including guidance on the:",
          "o",
          "Equipment to be inspected/tested.",
          "o"
        ]
      },
      {
        "id": "C6Q6_3_1",
        "number": "6.3.1",
        "text": "Were the Master and officers familiar with the company procedures for the safe  operation of the ballast water management system (BWMS), and was the equipment in  satisfactory condition and used in accordance with the company procedures and  manufacturer’s instructions?",
        "short_text": "Ballast water management system (BWMS)",
        "vessel_types": [
          "Oil",
          "Chemical",
          "LPG",
          "LNG"
        ],
        "section": "6.3",
        "section_name": "Ballast Operations",
        "objective": "To ensure that ballast is always handled safely in accordance with company procedures and manufacturer’s  instructions.   Industry Guidance  OCIMF/ICS: International Safety Guide for Oil Tankers and Terminals. Sixth Edition.  10.3 Identifying enclosed spaces  Some spaces that do not meet the criteri",
        "risk": "high",
        "evidence": [
          "Company procedures for the operation, inspection and maintenance of the ballast water management",
          "system (BWMS).",
          "The operation and safety manual for the BWMS.",
          "Inspection and maintenance records of the BWMS.",
          "Records of the operation of the BWMS."
        ],
        "negative_grounds": [
          "There were no company procedures for the operation, inspection and maintenance of the ballast water",
          "management system (BWMS), including guidance on:",
          "o",
          "Who is responsible for supervising the use of the BWMS.",
          "o"
        ]
      },
      {
        "id": "C6Q6_4_1",
        "number": "6.4.1",
        "text": "Were the Master, officers and ratings familiar with the company procedures for the  removal of small quantities of oil or chemical spilled and contained on deck, and was  suitable response equipment available, in satisfactory condition and effectively  deployed?",
        "short_text": "Main deck oil or chemical spill clean up equipment.",
        "vessel_types": [
          "Oil",
          "Chemical",
          "LPG",
          "LNG"
        ],
        "section": "6.4",
        "section_name": "Deck Area Pollution Prevention",
        "objective": "To ensure any oil or chemical spills contained on deck are promptly and safely cleaned up.  Industry Guidance  OCIMF/ICS: International Safety Guide for Oil Tankers and Terminals. Sixth Edition.  23.7.5 Spill containment  A permanently fitted spill tank, with suitable means of draining, should be fi",
        "risk": "high",
        "evidence": [
          "The SOPEP or SMPEP",
          "Company procedures for the removal of oil or chemical spilled and contained on deck.",
          "The inventory of spill clean-up equipment and records of periodic inspections."
        ],
        "negative_grounds": [
          "There were no company procedures for the removal of oil or chemical spilled and contained on deck.",
          "There was no inventory of spill clean-up equipment on board.",
          "The records of periodic inspections of the inventory of spill clean-up equipment were missing or incomplete.",
          "There were no instructions available for the safe use of the spill clean-up equipment, including PPE",
          "requirements."
        ]
      },
      {
        "id": "C6Q6_4_2",
        "number": "6.4.2",
        "text": "Were the Master and officers familiar with the company procedures for the disposal  of accumulations of water contaminated with oil and/or marine pollutants in the  forecastle and other internal spaces, and had the procedures been implemented?",
        "short_text": "Disposal of oily water in the forecastle and other internal spaces",
        "vessel_types": [
          "Oil",
          "Chemical",
          "LPG",
          "LNG"
        ],
        "section": "6.4",
        "section_name": "Deck Area Pollution Prevention",
        "objective": "To ensure any water contaminated with oil or marine pollutants generated in the forecastle and other internal  spaces is disposed of properly.  Industry Guidance  IMO: MEPC.1/Circ.759 Guidelines for a shipboard oily waste pollution prevention plan  1.2 Key elements of the shipboard oily waste pollut",
        "risk": "high",
        "evidence": [
          "Company procedures to ensure proper disposal of oily waste or other marine pollutants accumulated in",
          "internal space bilge wells.",
          "Records of the disposal of oily waste or other marine pollutants accumulated in internal space bilge wells."
        ],
        "negative_grounds": [
          "There were no company procedures to ensure proper disposal of oily waste or other marine pollutants",
          "accumulated in internal space bilge wells including:",
          "o",
          "Identification of relevant spaces.",
          "o"
        ]
      },
      {
        "id": "C6Q6_5_1",
        "number": "6.5.1",
        "text": "Were the Master and officers familiar with the emergency arrangements to pump  out the machinery space bilges in the event of flooding, and were these arrangements  prominently marked and in good order?",
        "short_text": "Emergency arrangements to pump out the machinery space bilges",
        "vessel_types": [
          "Oil",
          "Chemical",
          "LPG",
          "LNG"
        ],
        "section": "6.5",
        "section_name": "Machinery Space Pollution Prevention",
        "objective": "To ensure that the machinery space bilges could be pumped out promptly in the event of a flooding  situation.  Industry Guidance  ICS: Engine Room Procedures Guide. First Edition.  5.4 Flooding  5.4.2 Prevention, Preparedness and Response  Though the engineering team cannot predict or prevent floodi",
        "risk": "high",
        "evidence": [],
        "negative_grounds": []
      },
      {
        "id": "C6Q6_5_2",
        "number": "6.5.2",
        "text": "Were the engineer officers familiar with the company procedure for the safe use of  the incinerator, and was the incinerator in satisfactory condition and used in accordance  with the company procedure and in compliance with MARPOL?",
        "short_text": "Incinerator operation.",
        "vessel_types": [
          "Oil",
          "Chemical",
          "LPG",
          "LNG"
        ],
        "section": "6.5",
        "section_name": "Machinery Space Pollution Prevention",
        "objective": "To ensure that the disposal of garbage and sludge using the incinerator is always carried out safely and in  accordance with the requirements of MARPOL.  Industry Guidance  ICS: Engine Room Procedures Guide. First Edition.  9.3.2 Incinerators  •  Incinerators are a potential fire hazard, therefore i",
        "risk": "high",
        "evidence": [
          "The company procedures which described the safe use of the incinerator.",
          "The risk assessment for the safe operation of the incinerator.",
          "The incinerator operation and maintenance manual."
        ],
        "negative_grounds": [
          "There was no company procedure which described the safe use of the incinerator.",
          "There was no risk assessment available for the safe operation of the incinerator.",
          "The accompanying officer was unfamiliar with the company procedure or risk assessment for the safe",
          "operation of the incinerator.",
          "An interviewed engineer officer was unfamiliar with:"
        ]
      },
      {
        "id": "C6Q6_6_1",
        "number": "6.6.1",
        "text": "Were the Master and engineer officers familiar with the company procedures for  the use of the oil filtering equipment, and was the oil filtering equipment in satisfactory  condition and used in accordance with the company procedure, manufacturer’s  instructions and MARPOL Annex I?",
        "short_text": "Oil filtering equipment.",
        "vessel_types": [
          "Oil",
          "Chemical",
          "LPG",
          "LNG"
        ],
        "section": "6.6",
        "section_name": "Oil Discharge Monitors",
        "objective": "To ensure that bilge discharges from machinery spaces are always within the limits permitted by MARPOL  Annex I.  Industry Guidance  ICS: Engine Room Procedures Guide. First Edition.  Chapter 9- Pollution Control  9.3 Equipment Operational Guidelines  9.3.1 Oily Water Separators (OWS)  •  Keep the O",
        "risk": "high",
        "evidence": [
          "The company procedures which described the use of the oil filtering equipment provided.",
          "The calibration certificate for the 15 ppm bilge alarm fitted to the oil filtering equipment.",
          "The manufacturer’s maintenance and operation manuals for the oil filtering equipment.",
          "Records of inspection and maintenance of the oil filtering equipment in the vessel’s maintenance plan.",
          "The Oil Record Book Part I."
        ],
        "negative_grounds": [
          "There was no company procedure which described the use of the oil filtering equipment provided.",
          "The 15 ppm bilge alarm sensor had not been calibrated within the previous five years or within the time",
          "frame specified by the manufacturer’s operation and maintenance manual, where this was less than five",
          "years.",
          "The oil filtering equipment overboard valve was not closed and/or was not secured and sealed to prevent"
        ]
      },
      {
        "id": "C6Q6_6_2",
        "number": "6.6.2",
        "text": "Were the Master and officers familiar with the company procedures for the use of  the oil discharge monitoring and control system, and was the oil discharge monitoring  and control system in satisfactory condition and used in accordance with the company  procedures, manufacturer’s instructions and MARPOL Annex I?",
        "short_text": "Oil discharge monitoring and control system (ODME)",
        "vessel_types": [
          "Oil",
          "Chemical"
        ],
        "section": "6.6",
        "section_name": "Oil Discharge Monitors",
        "objective": "To ensure that discharges from cargo and ballast spaces are always within the limits permitted by MARPOL  Annex I.  Industry Guidance  IMO: Resolution MEPC.108(49). Revised Guidelines and Specifications for Oil Discharge Monitoring and  Control System for Oil Tankers.  (Amended by resolution MEPC.24",
        "risk": "high",
        "evidence": [
          "The company procedures which described the use of the oil discharge monitoring and control system",
          "provided.",
          "The manufacturer’s maintenance and operation manuals for the oil discharge monitoring and control system.",
          "The maintenance and inspection records for the oil discharge monitoring and control system.",
          "Print-outs of ODME data or data displayed from memory.",
          "The Oil Record Book Part II."
        ],
        "negative_grounds": [
          "There was no company procedure which described the use of the oil discharge monitoring and control",
          "system provided.",
          "The oil discharge monitoring and control system was defective in any respect.",
          "Page 688 of 711 – SIRE 2.0 Question Library: Part 1 Version 1.0 (January 2022)",
          "The oil discharge monitoring and control system was apparently modified or fitted with connections which"
        ]
      }
    ]
  },
  {
    "id": "C7",
    "title": "Maritime Security",
    "roles": [
      "Master",
      "Chief Officer"
    ],
    "questions": [
      {
        "id": "C7Q7_1_1",
        "number": "7.1.1",
        "text": "Was security threat and risk assessment an integral part of voyage planning, and  did the passage plan contain security related information for each leg of the voyage?",
        "short_text": "Security threat and risk assessment during passage planning.",
        "vessel_types": [
          "Oil",
          "Chemical",
          "LPG",
          "LNG"
        ],
        "section": "7.1",
        "section_name": "Ship Routing",
        "objective": "To ensure voyage planning always addresses security considerations.  Industry Guidance  Industry: Global Counter Piracy Guidance for Companies, Masters and Seafarers  Fundamentals  The fundamental requirements of best practices to avoid attack by pirates and armed robbers are:  1.  Conduct thorough,",
        "risk": "high",
        "evidence": [
          "UKHO or equivalent security charts.",
          "Industry best management practice guidance (BMP) publications.",
          "Regional Security Guidance (e.g., ReCAAP Guidance)",
          "Company passage plan appraisal form checklist for a recently completed voyage.",
          "Passage plan for the same recently completed voyage.",
          "Security risk assessment for the same recently completed voyage."
        ],
        "negative_grounds": [
          "The vessel did not have the appropriate security information available such as:",
          "o",
          "Relevant security charts.",
          "o",
          "Industry best management practice guidance (BMP) publications."
        ]
      },
      {
        "id": "C7Q7_2_1",
        "number": "7.2.1",
        "text": "Were the Master and officers familiar with the company procedures for hardening  the vessel when entering areas of increased security risk, and was there a Vessel  Hardening Plan (VHP) available?",
        "short_text": "Vessel hardening.",
        "vessel_types": [
          "Oil",
          "Chemical",
          "LPG",
          "LNG"
        ],
        "section": "7.2",
        "section_name": "Ship Hardening and Access Control",
        "objective": "To ensure the vessel can be hardened effectively if scheduled to enter an area of increased security risk.  Industry Guidance  OCIMF: Guidelines to Harden Vessels. First Edition.  1.1 Assessing risks, detecting threats and defending the vessel  Vessel hardening is the physical measures taken to impr",
        "risk": "high",
        "evidence": [
          "Company procedures for hardening the vessel.",
          "Vessel Hardening plan (VHP).",
          "Inventory of hardening materials.",
          "Inspection and maintenance records for security equipment such as water cannons, CCTV, infrared",
          "detection cameras, etc.",
          "Bridge Log Book."
        ],
        "negative_grounds": [
          "There were no company procedures for hardening the vessel when entering areas of increased security risk.",
          "The Ship Security Officer was not familiar with the company procedures for hardening the vessel when",
          "entering areas of increased security risk.",
          "There was no Vessel Hardening Plan (VHP) available.",
          "The Vessel Hardening Plan was not ship-specific."
        ]
      },
      {
        "id": "C7Q7_2_2",
        "number": "7.2.2",
        "text": "Were the Master, officers and ratings familiar with the company procedures to  control access to the vessel in port and to ensure the safety of visitors, and were these  procedures effectively implemented?",
        "short_text": "Controlling access to the vessel",
        "vessel_types": [
          "Oil",
          "Chemical",
          "LPG",
          "LNG"
        ],
        "section": "7.2",
        "section_name": "Ship Hardening and Access Control",
        "objective": "To ensure access to the vessel is controlled at all times, and that all visitors are provided with an overview of  the hazards present and the safety precautions to observe while they are on board.  Industry Guidance  OCIMF/ICS: International Safety Guide for Oil Tankers and Terminals. Sixth Edition",
        "risk": "high",
        "evidence": [
          "Company procedures to control access to the vessel in port, and to ensure the safety of visitors, if available",
          "outside of the Ship Security Plan.",
          "Visitor Log.",
          "Visitor Information Card, if provided."
        ],
        "negative_grounds": [
          "There were no company procedures to control access to the vessel in port and to ensure the safety of",
          "visitors.",
          "The gangway watchman was unfamiliar with the company procedures to control access to the vessel in port",
          "and to ensure the safety of visitors.",
          "The Master had not provided the terminal with a list of approved visitors, including Agents, Surveyors,"
        ]
      },
      {
        "id": "C7Q7_3_1",
        "number": "7.3.1",
        "text": "Were the Master and officers familiar with regional maritime security reporting  requirements and operation of the ship security alert system (SSAS) and had this  equipment been regularly tested?",
        "short_text": "Ship security reporting and communications",
        "vessel_types": [
          "Oil",
          "Chemical",
          "LPG",
          "LNG"
        ],
        "section": "7.3",
        "section_name": "Communications and Monitoring",
        "objective": "To ensure that the vessel staff have knowledge of regional maritime security reporting and that the SSAS  works.  Industry Guidance  Industry: Global Counter Piracy Guidance for Companies, Masters and Seafarers  Section 3 Voluntary Reporting  A major lesson learnt from operations against piracy and ",
        "risk": "high",
        "evidence": [
          "Contact details of the CSO.",
          "Records of participation in voluntary security reporting."
        ],
        "negative_grounds": [
          "The accompanying officer was not familiar with the 24-hour contact details of the company security officer",
          "(CSO).",
          "The 24-hour contact details of the CSO were not posted appropriately.",
          "The Master and/or SSO were not familiar with the company procedures for voluntary security reporting in",
          "VRAs."
        ]
      },
      {
        "id": "C7Q7_4_1",
        "number": "7.4.1",
        "text": "Did the Ship Security Officer (SSO) have a valid Certificate of Proficiency and a full  understanding of their role, and were ship security records of port calls being maintained  as required by SOLAS?",
        "short_text": "Ship Security Officer (SSO).",
        "vessel_types": [
          "Oil",
          "Chemical",
          "LPG",
          "LNG"
        ],
        "section": "7.4",
        "section_name": "Ship Security Officer",
        "objective": "To ensure the SSO is trained and qualified and required security records are maintained.  Industry Guidance  OCIMF/ICS: International Safety Guide for Oil Tankers and Terminals. Sixth Edition.  6.6 Responsibilities under the International Ship and Port Facility Security Code  For tankers at a termin",
        "risk": "high",
        "evidence": [
          "SSO’s Certificate of Proficiency.",
          "Sections of the SMS relating to ship security.",
          "Evidence of regular security inspections of the vessel by the SSO.",
          "Ship security records as required by SOLAS."
        ],
        "negative_grounds": [
          "The SMS did not clearly designate who should be SSO.",
          "The SMS did not contain a description of the role of the SSO, and a list of their duties.",
          "The SSO did not have a valid Certificate of Proficiency.",
          "The designated SSO was not a member of the crew.",
          "The SSO did not have a full understanding of their role, responsibilities, and duties. For example, they were"
        ]
      },
      {
        "id": "C7Q7_5_1",
        "number": "7.5.1",
        "text": "Were the Master and officers familiar with the company procedures for cyber  security risk management, and had these procedures been fully implemented?",
        "short_text": "Cyber security risk management.",
        "vessel_types": [
          "Oil",
          "Chemical",
          "LPG",
          "LNG"
        ],
        "section": "7.5",
        "section_name": "Cyber Security",
        "objective": "To ensure the vessel has in place effective technical and procedural measures to protect against a cyber  incident and ensure continuity of operations.  Industry Guidance  OCIMF/ICS: International Safety Guide for Oil Tankers and Terminals. Sixth Edition  6.4 Cyber safety and security  Cyber securit",
        "risk": "high",
        "evidence": [
          "Company procedures for cyber risk management.",
          "The inventory/register of sensitive IT/OT systems fitted onboard.",
          "Records of approval for external local or remote access to sensitive IT/OT systems.",
          "Cyber contingency plans in hard copy.",
          "Contact details for technical support from the operator’s IT department or external IT contractors.",
          "Records of cyber security training."
        ],
        "negative_grounds": [
          "There were no company procedures for cyber risk management that:",
          "o",
          "Identified the roles and responsibilities of users, key personnel, and management both ashore and",
          "on board.",
          "o"
        ]
      }
    ]
  }
];

// ── SIRE API Routes ─────────────────────────────────────

// Get all chapters with readiness status for a vessel
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

      return {
        id: ch.id, title: ch.title, roles: ch.roles,
        total, ready, inProgress, gap, notStarted: total - ready - inProgress - gap,
        score, rag
      };
    });

    const overallScore = Math.round(summary.reduce((a,c) => a + c.score, 0) / summary.length);
    res.json({ summary, overallScore, vessel_id: vesselId });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// Get questions for a chapter
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

// Generate AI model answer for a question
app.post('/api/sire/generate-answer', requireAuth, async (req, res) => {
  if (!ANTHROPIC_API_KEY) return res.status(500).json({ error: 'API key not configured' });
  try {
    const { question_id, question_text, chapter_title, evidence_items, vessel_name, vessel_type } = req.body;

    // Look up the full question from our database for richer context
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

    const prompt = `You are an expert SIRE 2.0 inspector coach with deep knowledge of OCIMF SIRE 2.0 requirements.

SIRE 2.0 Question ${qNumber}: ${fullQuestion?.short_text || ''}
Chapter: ${chapter_title} — Section: ${sectionName}
Applies to: ${vesselTypes} vessel types
Vessel being prepared: ${vessel_name || 'LPG Tanker'} (${vessel_type || 'LPG Gas Carrier'})

FULL QUESTION TEXT:
${question_text}

OCIMF OBJECTIVE FOR THIS QUESTION:
${objective}

EXPECTED EVIDENCE (from OCIMF Question Library):
• ${expectedEvidence}

POTENTIAL GROUNDS FOR NEGATIVE OBSERVATION (what inspectors will flag):
• ${negativeGrounds}

Generate a comprehensive, inspector-ready coaching package. The model answer should be in the voice of a competent officer/engineer answering confidently and specifically. Reference the actual evidence items from the OCIMF question library. Flag the specific negative grounds so officers know what to avoid.

Return JSON only (no markdown):
{
  "model_answer": "The coached answer the officer should give (3-5 sentences, confident and specific)",
  "inspector_focus": "What the SIRE 2.0 inspector is specifically looking for based on the objective",
  "regulation_basis": "The ISM/MARPOL/SOLAS/STCW/OCIMF regulation and TMSA KPI behind this question",
  "evidence_to_show": ["Specific documents from the expected evidence list to have immediately ready"],
  "common_failures": ["Direct negative grounds from OCIMF that crews typically trigger"],
  "score_tips": ["2-3 actionable tips to avoid a negative observation"],
  "difficulty": "easy|medium|hard|critical"
}`;

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

// Save preparation for a question
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

// Drill mode — AI plays inspector
app.post('/api/sire/drill', requireAuth, async (req, res) => {
  if (!ANTHROPIC_API_KEY) return res.status(500).json({ error: 'API key not configured' });
  try {
    const { question_text, chapter_title, officer_answer, vessel_name } = req.body;

    const prompt = `You are a strict but fair SIRE 2.0 inspector conducting a vessel inspection on ${vessel_name||'an LPG tanker'}.

Chapter: ${chapter_title}
Question asked: ${question_text}
Officer's answer: ${officer_answer}

Score this answer as a real SIRE 2.0 inspector would. SIRE 2.0 uses Grades 1-5:
- Grade 5: Outstanding — exceeds expectations, clear evidence-based competency
- Grade 4: Good — meets requirements with clear understanding  
- Grade 3: Satisfactory — meets minimum requirements
- Grade 2: Deficient — partially meets requirements, notable gaps
- Grade 1: Unsatisfactory — fails to meet requirements, finding raised

Return JSON:
{
  "grade": 3,
  "grade_label": "Satisfactory",
  "what_was_good": "What the officer answered well",
  "what_was_missing": "Key points missing from the answer",
  "inspector_follow_up": "The follow-up question a SIRE inspector would ask next",
  "model_answer": "What a Grade 5 answer would look like",
  "score_color": "green|amber|red"
}`;

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

// SIRE Findings (post-inspection)
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

// Get SIRE chapters list (for frontend)
app.get('/api/sire/chapters', requireAuth, (req, res) => {
  const { vessel_type } = req.query; // e.g. 'LPG', 'LNG', 'Oil', 'Chemical'
  const chapters = SIRE_CHAPTERS.map(ch => {
    let qs = ch.questions;
    if (vessel_type && vessel_type !== 'all') {
      qs = qs.filter(q => !q.vessel_types.length || q.vessel_types.includes(vessel_type));
    }
    // Build section summary
    const sections = {};
    qs.forEach(q => {
      if (!sections[q.section]) sections[q.section] = { section: q.section, name: q.section_name, count: 0 };
      sections[q.section].count++;
    });
    return {
      id: ch.id, title: ch.title, roles: ch.roles,
      questionCount: qs.length,
      sections: Object.values(sections)
    };
  });
  res.json(chapters);
});

// Get single question detail
app.get('/api/sire/question/:question_id', requireAuth, (req, res) => {
  for (const ch of SIRE_CHAPTERS) {
    const q = ch.questions.find(q => q.id === req.params.question_id);
    if (q) return res.json({ ...q, chapter_id: ch.id, chapter_title: ch.title });
  }
  res.status(404).json({ error: 'Question not found' });
});

// Search questions across all chapters
app.get('/api/sire/search', requireAuth, (req, res) => {
  const { q: query, vessel_type, chapter } = req.query;
  if (!query || query.length < 2) return res.json([]);
  const qLower = query.toLowerCase();
  const results = [];
  for (const ch of SIRE_CHAPTERS) {
    if (chapter && ch.id !== chapter) continue;
    for (const question of ch.questions) {
      if (vessel_type && vessel_type !== 'all' && question.vessel_types.length && !question.vessel_types.includes(vessel_type)) continue;
      if (question.text.toLowerCase().includes(qLower) ||
          question.short_text.toLowerCase().includes(qLower) ||
          question.section_name.toLowerCase().includes(qLower)) {
        results.push({
          id: question.id, number: question.number,
          short_text: question.short_text,
          text: question.text.slice(0, 150),
          chapter_id: ch.id, chapter_title: ch.title,
          section: question.section, section_name: question.section_name,
          vessel_types: question.vessel_types
        });
      }
      if (results.length >= 30) break;
    }
    if (results.length >= 30) break;
  }
  res.json(results);
});

// ── SIRE Industry Intelligence (web search + fleet upload) ──────────────

// Search industry for SIRE findings on similar vessels
app.post('/api/sire/industry-search', requireAuth, async (req, res) => {
  if (!ANTHROPIC_API_KEY) return res.status(500).json({ error: 'API key not configured' });
  try {
    const { vessel_type, chapter_id, chapter_title } = req.body;

    const prompt = `You are a maritime SIRE 2.0 expert with deep knowledge of industry inspection findings.

Based on your training knowledge of OCIMF SIRE inspections, provide realistic and representative common findings for:
Vessel Type: ${vessel_type || 'LPG Gas Carrier'}
SIRE Chapter: ${chapter_id} — ${chapter_title}

Generate 6-8 realistic industry findings that are commonly observed on ${vessel_type || 'LPG Gas Carrier'} vessels during SIRE 2.0 inspections for this chapter. These should be based on known OCIMF inspection patterns, common deficiencies in the industry, and typical areas where tanker operators struggle.

Return JSON:
{
  "findings": [
    {
      "title": "Brief finding title",
      "description": "Detailed description of what inspectors typically observe",
      "severity": "obs|minor|major",
      "frequency": "very_common|common|occasional",
      "chapter": "${chapter_id}",
      "root_causes": ["Common root cause 1", "Common root cause 2"],
      "prevention": "How to prevent this finding on your vessel",
      "sire_reference": "The specific SIRE 2.0 question area this relates to"
    }
  ],
  "chapter_risk_areas": ["Top 3 risk areas for this vessel type in this chapter"],
  "industry_trend": "Current industry trend or recent focus area for this chapter"
}`;

    const aiRes = await fetch('https://api.anthropic.com/v1/messages', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'x-api-key': ANTHROPIC_API_KEY, 'anthropic-version': '2023-06-01' },
      body: JSON.stringify({ model: 'claude-sonnet-4-6', max_tokens: 3000,
        system: 'You are a SIRE 2.0 maritime inspection expert. You must respond with ONLY valid JSON — no preamble, no explanation, no markdown fences. Just the raw JSON object.',
        messages: [{
          role: 'user',
          content: prompt
        }]
      })
    });
    const aiData = await aiRes.json();
    const textBlocks = (aiData.content || []).filter(b => b.type === 'text');
    const text = textBlocks.map(b => b.text).join('\n');
    // Robust JSON extraction - find the outermost complete JSON object
    let parsed = { findings: [], chapter_risk_areas: [], industry_trend: '' };
    try {
      // Try to find JSON block between ```json fences first
      const fenced = text.match(/```json\s*([\s\S]*?)```/);
      if (fenced) {
        parsed = JSON.parse(fenced[1].trim());
      } else {
        // Find the first { and match to its closing }
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

// Upload fleet findings (bulk import)
app.post('/api/sire/upload-findings', requireAuth, (req, res) => {
  try {
    const db = readSireDB();
    db.findings = db.findings || [];
    const { findings } = req.body;
    if (!Array.isArray(findings)) return res.status(400).json({ error: 'findings must be an array' });

    let imported = 0, skipped = 0;
    findings.forEach(f => {
      if (!f.description) { skipped++; return; }
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
    res.json({ ok: true, imported, skipped });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// Get fleet-wide findings summary (all vessels)
app.get('/api/sire/fleet-findings', requireAuth, requireRole('admin', 'superintendent'), (req, res) => {
  try {
    const db = readSireDB();
    const mainDb = readDB();
    const findings = db.findings || [];
    // Enrich with vessel name
    const enriched = findings.map(f => {
      const vessel = mainDb.vessels.find(v => v.id === f.vessel_id);
      return { ...f, vessel_name: vessel?.name || f.vessel_name || 'Unknown' };
    });
    // Group by chapter
    const byChapter = {};
    enriched.forEach(f => {
      const ch = f.chapter || 'Unknown';
      if (!byChapter[ch]) byChapter[ch] = [];
      byChapter[ch].push(f);
    });
    // Unique inspectors list for filter suggestions
    const inspectors = [...new Set(enriched.map(f => [f.inspecting_company, f.inspector].filter(Boolean).join(' — ')).filter(Boolean))].sort();
    res.json({ findings: enriched, byChapter, total: enriched.length, inspectors });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// Get vessel details for SIRE context
app.get('/api/sire/vessel-context/:vessel_id', requireAuth, (req, res) => {
  try {
    const db = readDB();
    const vessel = db.vessels.find(v => v.id === req.params.vessel_id);
    if (!vessel) return res.status(404).json({ error: 'Vessel not found' });
    const { ...safe } = vessel;
    res.json(safe);
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// ── AI Report Parser ─────────────────────────────────────────────────────
app.post('/api/sire/parse-report', requireAuth, async (req, res) => {
  if (!ANTHROPIC_API_KEY) return res.status(500).json({ error: 'API key not configured' });
  try {
    const { file_data, file_type, vessel_id, vessel_name, inspector_override, company_override, date_override } = req.body;
    if (!file_data) return res.status(400).json({ error: 'No file data provided' });

    const mainDb = readDB();
    const vessel = mainDb.vessels.find(v => v.id === vessel_id) || { name: vessel_name || 'Unknown' };

    const prompt = `You are an expert maritime SIRE inspection analyst. You have been given a SIRE inspection report for vessel "${vessel.name}".

Extract ALL findings, observations, and deficiencies from this report. For each finding extract:
- The exact description of what was observed
- Which SIRE chapter it falls under (C1-C7)
- Severity (obs=observation, minor=minor finding, major=major finding)
- Inspector name/company if mentioned
- Inspection date if mentioned
- Any recommended corrective action mentioned
- The question number or reference if visible

If any information is missing or unclear, note it as null — do NOT guess.

Return ONLY valid JSON in this exact format:
{
  "inspection_date": "YYYY-MM-DD or null",
  "inspector": "name/company or null",
  "vessel_name": "vessel name from report or null",
  "total_findings": 0,
  "findings": [
    {
      "chapter": "C1",
      "severity": "obs|minor|major",
      "description": "exact finding description",
      "corrective_action": "recommended action or null",
      "question_ref": "question reference or null"
    }
  ],
  "missing_info": ["list of fields that could not be extracted"],
  "summary": "one sentence summary of the inspection"
}`;

    const messages = [{
      role: 'user',
      content: [
        {
          type: file_type === 'application/pdf' ? 'document' : 'image',
          source: {
            type: 'base64',
            media_type: file_type,
            data: file_data
          }
        },
        { type: 'text', text: prompt }
      ]
    }];

    const aiRes = await fetch('https://api.anthropic.com/v1/messages', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'x-api-key': ANTHROPIC_API_KEY, 'anthropic-version': '2023-06-01' },
      body: JSON.stringify({ model: 'claude-sonnet-4-6', max_tokens: 4000, messages })
    });

    const aiData = await aiRes.json();
    const text = aiData.content?.[0]?.text || '{}';
    const jsonMatch = text.match(/\{[\s\S]*\}/);
    if (!jsonMatch) return res.status(500).json({ error: 'Could not parse AI response', raw: text.substring(0, 300) });

    const parsed = JSON.parse(jsonMatch[0]);
    // Apply overrides — user-entered fields take priority over AI extraction
    if (inspector_override) parsed.inspector = inspector_override;
    if (company_override)   parsed.inspecting_company = company_override;
    if (date_override)      parsed.inspection_date = date_override;
    res.json({ ok: true, vessel_id, ...parsed });
  } catch(e) {
    console.error('Parse report error:', e);
    res.status(500).json({ error: e.message });
  }
});

// Batch CAP review — review multiple findings at once
app.post('/api/sire/review-cap-batch', requireAuth, async (req, res) => {
  if (!ANTHROPIC_API_KEY) return res.status(500).json({ error: 'API key not configured' });
  try {
    const { finding_ids, vessel_type } = req.body;
    if (!Array.isArray(finding_ids) || !finding_ids.length) return res.status(400).json({ error: 'finding_ids required' });

    const db = readSireDB();
    const mainDb = readDB();
    const findings = (db.findings || []).filter(f => finding_ids.includes(f.id));
    if (!findings.length) return res.status(404).json({ error: 'No findings found' });

    res.json({ ok: true, total: findings.length, message: 'Batch review started' });

    // Process in background — review each finding sequentially
    (async () => {
      for (const f of findings) {
        try {
          const prompt = `You are a maritime SIRE expert reviewing a Corrective Action Plan (CAP).
Finding: ${f.description}
Chapter: ${f.chapter} | Severity: ${f.severity}
Root Cause: ${f.root_cause || 'Not stated'}
Corrective Action: ${f.corrective_action || 'Not provided'}
Vessel Type: ${vessel_type || 'LPG Gas Carrier'}

Rate this CAP 1-5 and return JSON only:
{"score":3,"score_color":"amber","score_label":"Adequate","verdict":"One sentence verdict","weaknesses":["w1"],"improved_cap":"Better version","systemic_action":"Fleet-wide action if needed","evidence_required":["Doc1"],"timeline_suggestion":"30 days","inspector_response":"Formal 2-3 paragraph response for submission to inspector/OCIMF acknowledging the finding, corrective action taken, and preventive measures implemented."}`;

          const aiRes = await fetch('https://api.anthropic.com/v1/messages', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json', 'x-api-key': ANTHROPIC_API_KEY, 'anthropic-version': '2023-06-01' },
            body: JSON.stringify({ model: 'claude-sonnet-4-6', max_tokens: 1500, messages: [{ role: 'user', content: prompt }] })
          });
          const aiData = await aiRes.json();
          const text = (aiData.content || []).find(c => c.type === 'text')?.text || '';
          const clean = text.replace(/```json|```/g, '').trim();
          const review = JSON.parse(clean.match(/\{[\s\S]*\}/)[0]);

          // Save review to finding
          const db2 = readSireDB();
          const idx = (db2.findings || []).findIndex(x => x.id === f.id);
          if (idx >= 0) {
            db2.findings[idx].cap_review = { ...review, reviewed_at: new Date().toISOString() };
            writeSireDB(db2);
          }
          console.log('Batch review done:', f.id, 'score:', review.score);
          await new Promise(r => setTimeout(r, 1000)); // Rate limit
        } catch(e) { console.error('Batch review error for', f.id, ':', e.message); }
      }
      console.log('Batch review complete for', findings.length, 'findings');
    })();
  } catch(e) { res.status(500).json({ error: e.message }); }
});


// ── CAP Review ───────────────────────────────────────────────────────────
app.post('/api/sire/review-cap', requireAuth, async (req, res) => {
  if (!ANTHROPIC_API_KEY) return res.status(500).json({ error: 'API key not configured' });
  try {
    const { finding_id, description, chapter, severity, root_cause, corrective_action, vessel_type } = req.body;

    const prompt = `You are a senior maritime SIRE 2.0 expert and DPA reviewing corrective action plans for vessel deficiencies.

Vessel type: ${vessel_type || 'LPG Gas Carrier'}
Chapter: ${chapter}
Severity: ${severity}
Finding: ${description}
Root Cause: ${root_cause || 'Not stated'}
Proposed Corrective Action: ${corrective_action || 'None provided'}

Evaluate this corrective action plan against SIRE 2.0 standards. A good CAP must:
1. Directly address the root cause (not just the symptom)
2. Be specific and measurable
3. Include systemic prevention (not just a one-time fix)
4. Reference the specific procedure/SMS element to be updated
5. Be realistic and achievable

Return JSON:
{
  "score": 1-5,
  "score_label": "Inadequate|Weak|Adequate|Good|Excellent",
  "score_color": "red|amber|green",
  "verdict": "One sentence verdict on the CAP quality",
  "strengths": ["What is good about this CAP (if anything)"],
  "weaknesses": ["What is missing or inadequate"],
  "improved_cap": "A fully rewritten, SIRE-ready corrective action that would satisfy an inspector",
  "systemic_action": "The systemic/SMS-level action needed to prevent recurrence",
  "timeline_suggestion": "Realistic timeframe for completion",
  "evidence_required": ["Documents/records needed to demonstrate closure to inspector"],
  "inspector_response": "A formal 2-3 paragraph response written in professional maritime language, suitable for direct submission to OCIMF/the inspector to close the finding. It should acknowledge the finding, state the immediate corrective action taken, describe the systemic/preventive measures implemented, and confirm the evidence available for verification."
}`;

    const aiRes = await fetch('https://api.anthropic.com/v1/messages', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'x-api-key': ANTHROPIC_API_KEY, 'anthropic-version': '2023-06-01' },
      body: JSON.stringify({ model: 'claude-sonnet-4-6', max_tokens: 1500, messages: [{ role: 'user', content: prompt }] })
    });
    const aiData = await aiRes.json();
    const text = aiData.content?.[0]?.text || '{}';
    const jsonMatch = text.match(/\{[\s\S]*\}/);
    const parsed = JSON.parse(jsonMatch[0]);

    // Optionally save review to finding
    if (finding_id) {
      const db = readSireDB();
      const idx = (db.findings || []).findIndex(f => f.id === finding_id);
      if (idx !== -1) {
        db.findings[idx].cap_review = parsed;
        db.findings[idx].cap_review_at = new Date().toISOString();
        writeSireDB(db);
      }
    }
    res.json(parsed);
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// Save updated CAP text
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

// ══════════════════════════════════════════════════════
// KNOWLEDGE REPOSITORY
// ══════════════════════════════════════════════════════

const repoStorage = multer.diskStorage({
  destination: (req, file, cb) => {
    const dir = path.join(DATA_DIR, 'uploads', 'manuals');
    require('fs').mkdirSync(dir, { recursive: true });
    cb(null, dir);
  },
  filename: (req, file, cb) => {
    const safe = file.originalname.replace(/[^a-zA-Z0-9._-]/g, '_');
    cb(null, `${Date.now()}_${safe}`);
  }
});
const uploadManual = multer({
  storage: repoStorage,
  limits: { fileSize: 50 * 1024 * 1024 }, // 50MB
  fileFilter: (req, file, cb) => {
    if (file.mimetype === 'application/pdf') cb(null, true);
    else cb(new Error('Only PDF files are supported'));
  }
});

function readRepoDb() {
  try {
    const p = path.join(DATA_DIR, 'repo_db.json');
    if (!require('fs').existsSync(p)) return { manuals: [] };
    return JSON.parse(require('fs').readFileSync(p, 'utf8'));
  } catch(e) { return { manuals: [] }; }
}
function writeRepoDb(db) {
  require('fs').writeFileSync(
    path.join(DATA_DIR, 'repo_db.json'),
    JSON.stringify(db, null, 2)
  );
}

// GET manuals list
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

// POST upload + AI categorise

// ═══════════════════════════════════════════════════════
// OCR HELPERS — extract text from scanned PDFs via AI vision
// ═══════════════════════════════════════════════════════

// Check if PDF has real text layer or is image-only
function pdfHasTextLayer(buffer) {
  const str = buffer.toString('latin1');
  // Look for text operators in PDF content streams
  const textMatches = (str.match(/BT[\s\S]{1,500}ET/g) || []).length;
  return textMatches > 5;
}

// Extract text from a scanned PDF using Claude vision (processes in page batches)
// ── Text extraction pipeline ──────────────────────────────────────────
// Step 1: Try pdf-parse for native text layer (instant, free)
// Step 2: If scanned, use Google Vision OCR (reliable, ~$0.015/page)

async function extractPdfText(filePath) {
  const fs = require('fs');
  const buffer = fs.readFileSync(filePath);

  // Try native text extraction first
  try {
    const pdfParse = require('pdf-parse');
    const result = await pdfParse(buffer);
    const text = (result.text || '').trim();
    // Need meaningful text — not just a few stray characters
    const wordCount = text.split(/\s+/).filter(w => w.length > 2).length;
    if (wordCount > 50) {
      console.log(`pdf-parse: extracted ${wordCount} words from ${result.numpages} pages`);
      return { text, method: 'native', pages: result.numpages };
    }
    console.log(`pdf-parse: only ${wordCount} words — scanned PDF, switching to Vision OCR`);
  } catch(e) {
    console.log('pdf-parse failed:', e.message, '— trying Vision OCR');
  }

  // Scanned PDF — use Google Vision
  const apiKey = process.env.GOOGLE_VISION_KEY;
  if (!apiKey) {
    console.error('GOOGLE_VISION_KEY not set — cannot OCR scanned PDF');
    return null;
  }

  try {
    const base64 = buffer.toString('base64');
    const fileSizeMB = buffer.length / (1024 * 1024);

    // First: detect page count by reading first batch
    // files:annotate supports max 5 pages per request — batch in groups of 5
    // Page numbers are 1-indexed
    console.log(`Google Vision OCR: ${fileSizeMB.toFixed(1)}MB PDF — detecting pages...`);

    // Helper: call Vision for a specific set of pages (max 5)
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

    // Read first 5 pages to get started and estimate total pages
    const firstBatch = await visionPages([1,2,3,4,5]);
    if (!firstBatch.length) throw new Error('Vision returned no text for first 5 pages');

    const allText = [...firstBatch];
    console.log(`Vision batch 1/?: got ${firstBatch.length} pages`);

    // Continue in batches of 5 up to page 200 (safety limit)
    // Stop early if a batch returns fewer pages than requested (means we hit the end)
    const MAX_PAGES = 200;
    let pageNum = 6;
    let batchNum = 2;

    while (pageNum <= MAX_PAGES) {
      const batch = [pageNum, pageNum+1, pageNum+2, pageNum+3, pageNum+4];
      try {
        const results = await visionPages(batch);
        console.log(`Vision batch ${batchNum}: pages ${pageNum}-${pageNum+4}, got ${results.length} pages`);
        if (!results.length) break; // no more pages
        allText.push(...results);
        if (results.length < 5) break; // hit end of document
        pageNum += 5;
        batchNum++;
        // Small delay to avoid rate limiting
        await new Promise(r => setTimeout(r, 300));
      } catch(e) {
        console.log(`Vision batch ${batchNum} failed (likely end of doc):`, e.message);
        break;
      }
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


// Save extracted text as sidecar file
function saveSidecarText(storedName, text, uploadsDir) {
  const fs = require('fs');
  const txtPath = require('path').join(uploadsDir, 'manuals', storedName + '.txt');
  fs.writeFileSync(txtPath, text, 'utf8');
  return txtPath;
}

// Load sidecar text if it exists
function loadSidecarText(storedName, uploadsDir) {
  const fs = require('fs');
  const txtPath = require('path').join(uploadsDir, 'manuals', storedName + '.txt');
  if (fs.existsSync(txtPath)) {
    return fs.readFileSync(txtPath, 'utf8');
  }
  return null;
}


// AI categorisation from text or PDF
async function categoriseManual(apiKey, { base64, ocrText, filename }) {
  const catList = '"Main Engine","Auxiliary Engine","Cargo System","IGS/Inert Gas","Cargo Compressors","Pumps","Electrical","Navigation","Safety Systems","Fire Fighting","HVAC","Mooring","Crane/Deck Machinery","Boiler","Purifier","Regulatory/SIRE","OEM Service Letter","Maker Bulletin","SMS Procedure","General"';
  const prompt = `You are analysing a ship equipment manual for an LPG gas carrier.
Filename: ${filename}

Return ONLY a valid JSON object (no markdown, no explanation):
{
  "category": one of: ${catList},
  "equipment_name": "specific equipment name this manual covers, e.g. Oily Bilge Separator, Main Air Compressor",
  "maker": "manufacturer/maker name or empty string",
  "model": "model or type number or empty string",
  "rev_date": "revision or issue date as YYYY-MM-DD or empty string",
  "summary": "one sentence describing what this document covers",
  "sire_chapters": array of relevant SIRE 2.0 chapter numbers 1-7, e.g. [3,5]
}

Category guidance:
- Oily water separator, bilge separator, OWS → "Pumps"
- Main engine, propulsion engine → "Main Engine"  
- Generator, alternator, aux engine → "Auxiliary Engine"
- Cargo pump, stripping pump, deepwell pump → "Cargo System"
- Compressor for cargo/gas → "Cargo Compressors"
- Inert gas, IGS, N2 → "IGS/Inert Gas"
- Switchboard, transformer, motor → "Electrical"
- Boiler, economiser → "Boiler"
- Purifier, separator for lube/fuel → "Purifier"
- Air conditioner, HVAC, ventilation → "HVAC"
- Fire pump, CO2, foam → "Fire Fighting"
- GPS, radar, ECDIS → "Navigation"
- Winch, crane, windlass → "Crane/Deck Machinery"
- Mooring, anchor → "Mooring"`;

  let msgContent;
  if (ocrText) {
    // Use extracted text — faster and more accurate than sending PDF image
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

app.post('/api/repo/upload', requireAuth, uploadManual.single('file'), async (req, res) => {
  try {
    if (!req.file) return res.status(400).json({ error: 'No file uploaded' });

    const fs = require('fs');
    const fileData = fs.readFileSync(req.file.path);
    const base64   = fileData.toString('base64');

    // Detect if PDF is scanned (image-based) and run OCR if needed
    // Extract text from PDF (native or OCR)
    let extractedText = null;
    let extractMethod = 'none';
    try {
      const extracted = await extractPdfText(req.file.path);
      if (extracted) {
        extractedText = extracted.text;
        extractMethod = extracted.method;
        saveSidecarText(req.file.filename, extractedText, path.join(DATA_DIR, 'uploads'));
        console.log('Text extracted via', extractMethod, '—', extractedText.length, 'chars');
      }
    } catch(e) { console.error('Text extraction failed:', e.message); }

    // AI categorisation — use extracted text if available for better accuracy
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
      stored_name:  req.file.filename,
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
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// Re-run OCR on an existing manual
// Re-extract text for existing manuals (runs new pipeline)
app.post('/api/repo/manuals/:id/reextract', requireAuth, async (req, res) => {
  try {
    const db = readRepoDb();
    const manual = db.manuals.find(m => m.id === req.params.id);
    if (!manual) return res.status(404).json({ error: 'Manual not found' });

    const fp = path.join(DATA_DIR, 'uploads', 'manuals', manual.stored_name);
    if (!require('fs').existsSync(fp)) return res.status(404).json({ error: 'File not found on disk — re-upload the manual' });

    res.json({ message: 'Extraction started', filename: manual.filename });

    // Run in background
    (async () => {
      try {
        const extracted = await extractPdfText(fp);
        if (!extracted || !extracted.text) {
          console.error('Re-extract failed for:', manual.filename);
          return;
        }
        // Save sidecar
        saveSidecarText(manual.stored_name, extracted.text, path.join(DATA_DIR, 'uploads'));

        // Re-categorise using extracted text
        let meta = {};
        try {
          meta = await categoriseManual(process.env.ANTHROPIC_API_KEY, {
            ocrText: extracted.text, filename: manual.filename
          });
        } catch(e) { console.error('Re-categorise failed:', e.message); }

        // Update manual record
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
        }
      } catch(e) { console.error('Background re-extract error:', e.message); }
    })();
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// Search web for OEM service letters/bulletins for a manual
app.post('/api/repo/manuals/:id/search-sl', requireAuth, async (req, res) => {
  try {
    const db = readRepoDb();
    const manual = db.manuals.find(m => m.id === req.params.id);
    if (!manual) return res.status(404).json({ error: 'Manual not found' });

    const maker     = manual.maker || '';
    const model     = manual.model || '';
    const equipment = manual.equipment_name || '';
    if (!maker && !equipment) return res.json({ results: [], message: 'Add maker/equipment name to this manual first' });

    const aiRes = await fetch('https://api.anthropic.com/v1/messages', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'x-api-key': process.env.ANTHROPIC_API_KEY, 'anthropic-version': '2023-06-01' },
      body: JSON.stringify({
        model: 'claude-sonnet-4-6',
        max_tokens: 2000,
        tools: [{ type: 'web_search_20250305', name: 'web_search' }],
        messages: [{
          role: 'user',
          content: `Search for service letters, technical bulletins, and service notifications for this ship equipment:
Maker: ${maker || 'unknown'}
Model/Type: ${model || 'unknown'}  
Equipment: ${equipment || 'unknown'}

Search the maker's official website and maritime industry sources. Look for service letters, technical bulletins, safety notices, and mandatory modifications.

Return ONLY a JSON array, no other text:
[{"ref":"SL reference","title":"title","date":"YYYY-MM-DD or empty","action":"for_information or action_required or mandatory","summary":"what it covers","url":"direct URL if found"}]

If nothing found, return [].`
        }]
      })
    });

    const aiData = await aiRes.json();
    if (aiData.error) return res.json({ results: [], message: 'Search failed: ' + aiData.error.message });

    const textBlock = (aiData.content||[]).find(c => c.type === 'text');
    let results = [];
    let raw = '';
    if (textBlock) {
      raw = textBlock.text;
      try {
        const clean = raw.replace(/```json|```/g, '').trim();
        const parsed = JSON.parse(clean);
        results = Array.isArray(parsed) ? parsed : [];
      } catch(e) { /* return raw if not JSON */ }
    }
    res.json({ results, raw: results.length ? '' : raw });
  } catch(e) { res.status(500).json({ error: e.message }); }
});


// DELETE manual
app.delete('/api/repo/manuals/:id', requireAuth, (req, res) => {
  try {
    if (!isSuperLevel(req.user.role) && !isCEorMaster(req.user)) return res.status(403).json({ error: 'Forbidden' });
    const db = readRepoDb();
    const manual = db.manuals.find(m => m.id === req.params.id);
    if (!manual) return res.status(404).json({ error: 'Not found' });
    // Remove file from disk
    try {
      const fp = path.join(DATA_DIR, 'uploads', 'manuals', manual.stored_name);
      if (require('fs').existsSync(fp)) require('fs').unlinkSync(fp);
    } catch(e) {}
    db.manuals = db.manuals.filter(m => m.id !== req.params.id);
    writeRepoDb(db);
    res.json({ ok: true });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// PATCH manual (mark superseded, add service letter, update version)
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

// Serve manual PDF file
app.get('/api/repo/manuals/:id/file', requireAuth, (req, res) => {
  try {
    const db = readRepoDb();
    const manual = db.manuals.find(m => m.id === req.params.id);
    if (!manual) return res.status(404).json({ error: 'Not found' });
    const fp = path.join(DATA_DIR, 'uploads', 'manuals', manual.stored_name);
    if (!require('fs').existsSync(fp)) return res.status(404).json({ error: 'File not found on disk' });
    res.setHeader('Content-Type', 'application/pdf');
    res.setHeader('Content-Disposition', `inline; filename="${manual.filename}"`);
    require('fs').createReadStream(fp).pipe(res);
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// Q&A search within a category
// Debug endpoint — check extraction status by filename (no auth for easy browser testing)
app.get('/api/repo/extract-check', (req, res) => {
  try {
    const db = readRepoDb();
    const name = (req.query.name || '').toLowerCase();
    const manual = name
      ? db.manuals.find(m => m.filename.toLowerCase().includes(name))
      : db.manuals[db.manuals.length - 1]; // last uploaded if no name
    if (!manual) return res.json({ error: 'Manual not found', available: db.manuals.map(m => m.filename) });

    const sidecar = loadSidecarText(manual.stored_name, path.join(DATA_DIR, 'uploads'));
    const fp = path.join(DATA_DIR, 'uploads', 'manuals', manual.stored_name);
    const fileExists = fs.existsSync(fp);
    const fileSize = fileExists ? fs.statSync(fp).size : 0;

    res.json({
      filename: manual.filename,
      manual_id: manual.id,
      text_extracted: manual.text_extracted,
      extract_method: manual.extract_method,
      file_on_disk: fileExists,
      file_size_mb: (fileSize / 1024 / 1024).toFixed(1),
      sidecar_exists: !!sidecar,
      sidecar_chars: sidecar ? sidecar.length : 0,
      sidecar_words: sidecar ? sidecar.split(' ').filter(w => w.length > 2).length : 0,
      sidecar_preview: sidecar ? sidecar.substring(0, 500) : 'NO SIDECAR FILE FOUND'
    });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// Debug endpoint — check extraction status for a manual
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
      filename: manual.filename,
      text_extracted: manual.text_extracted,
      extract_method: manual.extract_method,
      file_exists: fileExists,
      file_size_mb: (fileSize / 1024 / 1024).toFixed(1),
      sidecar_exists: !!sidecar,
      sidecar_chars: sidecar ? sidecar.length : 0,
      sidecar_words: sidecar ? sidecar.split(/\s+/).filter(w => w.length > 2).length : 0,
      sidecar_preview: sidecar ? sidecar.substring(0, 300) : null
    });
  } catch(e) { res.status(500).json({ error: e.message }); }
});


// Q&A search — uses extracted sidecar text, fast and reliable
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

    // Score by keyword relevance
    const qWords = question.toLowerCase().split(/\s+/).filter(w => w.length > 3);
    const scored = manuals.map(m => {
      let score = 0;
      const meta = ((m.filename||'') + ' ' + (m.summary||'') + ' ' + (m.equipment_name||'') + ' ' + (m.maker||'')).toLowerCase();
      qWords.forEach(w => { if (meta.includes(w)) score += 2; });
      // Bonus for manuals with extracted text
      if (m.text_extracted) score += 1;
      return { m, score };
    }).sort((a, b) => b.score - a.score);

    const toScan = scored.slice(0, 3).map(s => s.m);
    const contentParts = [];
    const noText = [];

    for (const m of toScan) {
      // Load sidecar text
      const sidecar = loadSidecarText(m.stored_name, path.join(DATA_DIR, 'uploads'));
      if (sidecar) {
        // Smart chunking — find the most relevant section based on question keywords
        // rather than blindly taking the first N chars (which may be just drawings/cover pages)
        const MAX_CHARS = 60000;
        let chunk;

        if (sidecar.length <= MAX_CHARS) {
          chunk = sidecar;
        } else {
          // Score positions by keyword proximity
          const qLower = question.toLowerCase();
          const words = qLower.split(/\s+/).filter(w => w.length > 3);
          const sideLower = sidecar.toLowerCase();

          // Find best window by scanning for keyword hits
          const WINDOW = MAX_CHARS;
          const STEP = 5000;
          let bestScore = -1;
          let bestStart = 0;

          for (let pos = 0; pos < sidecar.length - WINDOW; pos += STEP) {
            const window = sideLower.substring(pos, pos + WINDOW);
            let score = 0;
            words.forEach(w => {
              let idx = 0;
              while ((idx = window.indexOf(w, idx)) !== -1) { score++; idx++; }
            });
            if (score > bestScore) { bestScore = score; bestStart = pos; }
          }

          // Always include a small header from the start for context
          const header = sidecar.substring(0, 1000);
          const body = sidecar.substring(bestStart, bestStart + WINDOW - 1000);
          chunk = bestStart > 1000
            ? header + '\n\n[... pages skipped ...]\n\n' + body
            : sidecar.substring(0, WINDOW);
        }

        contentParts.push({ type: 'text', text: '=== ' + m.filename + ' ===\n' + chunk });
        continue;
      }
      // No sidecar — try sending PDF directly if small enough
      try {
        const fp = path.join(DATA_DIR, 'uploads', 'manuals', m.stored_name);
        if (fs.existsSync(fp)) {
          const stat = fs.statSync(fp);
          if (stat.size < 10 * 1024 * 1024) { // under 10MB
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

    contentParts.push({ type: 'text', text: `You are a senior marine engineer answering a question from an officer or engineer onboard.

Question: "${question}"

Respond in exactly two sections:

**MANUAL SAYS:**
Search the manual content above and extract the relevant answer. Be specific — reproduce exact steps, values, or fault tables if present. If genuinely not covered, write: "Not covered in this manual."
Cite the section or page reference if visible.

**TECHNICAL INSIGHT:**
Now give your own expert explanation as a senior marine engineer. Expand on the manual answer — explain the underlying reason why, what to check first in practice, common causes or mistakes, and anything the manual may not mention. Keep it practical and specific to this equipment type. 2-5 sentences.` });

    // Build messages — include conversation history for follow-ups
    let messages;
    if (is_follow_up && history && history.length >= 2) {
      // First message always has the manual content
      const firstUserContent = [...contentParts];
      // Replace the last prompt with a follow-up prompt
      firstUserContent[firstUserContent.length - 1] = {
        type: 'text',
        text: firstUserContent[firstUserContent.length - 1].text
          .replace('Question: "' + question + '"', 'Question: "' + (history[0]?.content || question) + '"')
      };
      messages = [{ role: 'user', content: firstUserContent }];
      // Add prior turns
      for (let i = 1; i < history.length; i++) {
        messages.push({ role: history[i].role, content: history[i].content });
      }
      // Add current follow-up question
      messages.push({ role: 'user', content: 'Follow-up question: ' + question + '\n\nAnswer based on the manual content and our conversation so far. Be concise and direct.' });
    } else {
      messages = [{ role: 'user', content: contentParts }];
    }

    const aiRes = await fetch('https://api.anthropic.com/v1/messages', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'x-api-key': process.env.ANTHROPIC_API_KEY, 'anthropic-version': '2023-06-01' },
      body: JSON.stringify({
        model: 'claude-sonnet-4-6',
        max_tokens: 2000,
        messages
      })
    });
    const aiData = await aiRes.json();
    if (aiData.error) return res.json({ answer: 'AI error: ' + aiData.error.message, sources: [] });

    const answer = (aiData.content||[]).find(c => c.type === 'text')?.text || 'No answer returned';
    const sources = toScan.filter((m,i) => contentParts[i]).map(m => ({ id: m.id, filename: m.filename }));
    res.json({ answer, sources });

  } catch(e) { res.status(500).json({ error: e.message }); }
});

// Defect suggestion — find relevant manuals for a given equipment/defect
app.post('/api/repo/suggest-for-defect', requireAuth, async (req, res) => {
  try {
    const { vessel_id, equipment_name, defect_title } = req.body;
    const db = readRepoDb();
    let manuals = db.manuals.filter(m => !m.superseded);
    if (vessel_id) manuals = manuals.filter(m => m.vessel_id === vessel_id);

    if (!manuals.length) return res.json({ suggestions: [] });

    // Simple text match on equipment_name and category — no AI needed
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

function isCEorMaster(user) {
  const d = (user?.designation||'').toLowerCase().trim();
  return ['chief engineer','ce','c/e','chief eng','c.e.','master','captain'].includes(d);
}

// ══════════════════════════════════════════════════════
// PMS MODULE — PLANNED MAINTENANCE SYSTEM
// ══════════════════════════════════════════════════════

const PMS_EQUIP_PATH = fs.existsSync(path.join(DATA_DIR,'equipment_register.json')) ? path.join(DATA_DIR,'equipment_register.json') : path.join(__dirname,'equipment_register.json');
const PMS_STATS_PATH = fs.existsSync(path.join(DATA_DIR,'pms_stats.json')) ? path.join(DATA_DIR,'pms_stats.json') : path.join(__dirname,'pms_stats.json');

function readPmsDb() {
  const p = path.join(DATA_DIR, 'pms.json');
  try { if (fs.existsSync(p)) return JSON.parse(fs.readFileSync(p, 'utf8')); } catch(e) {}
  return { worksheets: [], running_hours: [], defects: [], assignments: [] };
}
function savePmsDb(data) {
  const p = path.join(DATA_DIR, 'pms.json');
  try { fs.writeFileSync(p, JSON.stringify(data, null, 2)); } catch(e) { console.error(e); }
}

// GET /api/pms/overview — fleet-wide dashboard stats
app.get('/api/pms/overview', requireAuth, (req, res) => {
  try {
    const pms = readPmsDb();
    const vessels = readDB().vessels || [];
    const stats = fs.existsSync(PMS_STATS_PATH) ? JSON.parse(fs.readFileSync(PMS_STATS_PATH, 'utf8')) : {};

    // Build per-vessel summary
    const vesselStats = vessels.map(v => {
      const ws = pms.worksheets.filter(w => w.vessel_id === v.id);
      const now = new Date();
      const msMonth = 30*24*3600*1000;
      // Count any issued/wip worksheet past its due date as overdue
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
      // Fuzzy-match vessel name against stats keys
      const statKey = Object.keys(stats).find(k =>
        k.toLowerCase().includes(v.name.toLowerCase().split(' ')[0]) ||
        v.name.toLowerCase().includes(k.toLowerCase().split(' ')[0])
      );
      const hist = statKey ? stats[statKey] : {};
      return {
        vessel_id: v.id,
        vessel_name: v.name,
        vessel_type: v.vessel_type || 'LNG-DFDE',
        issued, wip, awaiting, deferred,
        overdue_1m: overdue1, overdue_2m: overdue2, overdue_3m: overdue3,
        tmsa_pct: parseFloat(tmsa_pct),
        historical_total: hist.total_records || 0,
        historical_adhoc: hist.adhoc_count || 0,
        failure_hotspots: hist.failure_hotspots || []
      };
    });

    const totals = vesselStats.reduce((acc, v) => ({
      issued: acc.issued + v.issued,
      wip: acc.wip + v.wip,
      awaiting: acc.awaiting + v.awaiting,
      deferred: acc.deferred + v.deferred,
      overdue_1m: acc.overdue_1m + v.overdue_1m,
      overdue_2m: acc.overdue_2m + v.overdue_2m,
      overdue_3m: acc.overdue_3m + v.overdue_3m,
    }), { issued:0, wip:0, awaiting:0, deferred:0, overdue_1m:0, overdue_2m:0, overdue_3m:0 });

    res.json({ vessels: vesselStats, totals, historical_records: 119357 });
  } catch(e) { res.status(500).json({ error: e.message }); }
});


// GET /api/pms/equipment/all — lightweight component list for dropdowns (code + desc + role)
app.get('/api/pms/equipment/all', requireAuth, (req, res) => {
  try {
    const { vessel_name } = req.query;
    if (!fs.existsSync(PMS_EQUIP_PATH)) return res.json([]);
    const register = JSON.parse(fs.readFileSync(PMS_EQUIP_PATH, 'utf8'));
    const vesselData = register[vessel_name];
    if (!vesselData) {
      // Return vessel list if no vessel specified
      return res.json({ vessels: Object.keys(register) });
    }
    // Return compact list: code, description, role, criticality, frequency
    const comps = (vesselData.components || []).map(c => ({
      code: c.code,
      description: c.description,
      primary_role: c.primary_role,
      criticality: c.criticality,
      frequency: c.frequency,
    }));
    res.json(comps);
  } catch(e) { res.status(500).json({ error: e.message }); }
});
// GET /api/pms/equipment — equipment register for a vessel
app.get('/api/pms/equipment', requireAuth, (req, res) => {
  try {
    const { vessel_name, search, criticality, role, page = 1, limit = 50 } = req.query;
    if (!fs.existsSync(PMS_EQUIP_PATH)) return res.json({ components: [], total: 0 });

    const register = JSON.parse(fs.readFileSync(PMS_EQUIP_PATH, 'utf8'));
    const vesselData = register[vessel_name];
    if (!vesselData) return res.json({ components: [], total: 0, vessels: Object.keys(register) });

    let comps = vesselData.components || [];
    if (search) {
      const s = search.toLowerCase();
      comps = comps.filter(c => c.code.toLowerCase().includes(s) || c.description.toLowerCase().includes(s));
    }
    if (criticality && criticality !== 'all') comps = comps.filter(c => c.criticality === criticality);
    if (role && role !== 'all') comps = comps.filter(c => c.primary_role === role);

    const total = comps.length;
    const start = (parseInt(page) - 1) * parseInt(limit);
    const paginated = comps.slice(start, start + parseInt(limit));

    // Get unique roles for filter dropdown
    const roles = [...new Set((vesselData.components || []).map(c => c.primary_role))].sort();

    res.json({ components: paginated, total, page: parseInt(page), limit: parseInt(limit), roles, vessel_type: vesselData.vessel_type });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// GET /api/pms/vessels — list vessels available in equipment register
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


// POST /api/pms/issue-month — bulk issue worksheets for a vessel/month from equipment register
app.post('/api/pms/issue-month', requireAuth, (req, res) => {
  try {
    const { vessel_name, year, month } = req.body; // month = 1-12
    if (!vessel_name || !year || !month) return res.status(400).json({ error: 'vessel_name, year, month required' });

    if (!fs.existsSync(PMS_EQUIP_PATH)) return res.status(404).json({ error: 'Equipment register not found' });
    const register = JSON.parse(fs.readFileSync(PMS_EQUIP_PATH, 'utf8'));
    const vesselData = register[vessel_name];
    if (!vesselData) return res.status(404).json({ error: 'Vessel not found in equipment register: ' + vessel_name });

    const components = vesselData.components || [];

    // Determine which components are due this month
    function isDue(freqStr, y, m) {
      if (!freqStr) return false;
      const match = freqStr.match(/(\d+)\s*Month/);
      if (!match) return false;
      const interval = parseInt(match[1]);
      const absMonth = (y - 2020) * 12 + (m - 1); // months since Jan 2020
      return absMonth % interval === 0;
    }

    const dueComponents = components.filter(c => isDue(c.frequency, parseInt(year), parseInt(month)));
    if (!dueComponents.length) return res.json({ issued: 0, message: 'No components due this month' });

    // Build due date = last day of the month
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
      if (existing.has(c.code)) return; // already issued for this month
      const ws = {
        id: 'ws_' + Date.now() + '_' + Math.random().toString(36).slice(2,6),
        vessel_name,
        component_code: c.code,
        component_description: c.description,
        short_description: `${c.frequency} planned maintenance`,
        full_description: '',
        assigned_role: c.primary_role || '2nd Eng',
        criticality: c.criticality || 'Standard',
        due_date: dueDate,
        type: 'planned',
        frequency: c.frequency,
        status: 'issued',
        created_at: new Date().toISOString(),
        created_by: req.user.name,
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
// GET /api/pms/worksheets — get worksheets for a vessel
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

// POST /api/pms/worksheets — create worksheet
app.post('/api/pms/worksheets', requireAuth, (req, res) => {
  try {
    const pms = readPmsDb();
    const ws = {
      id: 'ws_' + Date.now(),
      ...req.body,
      status: 'issued',
      created_at: new Date().toISOString(),
      created_by: req.user.name,
      history: [{ action: 'issued', by: req.user.name, at: new Date().toISOString() }]
    };
    pms.worksheets.push(ws);
    savePmsDb(pms);
    res.json(ws);
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// PUT /api/pms/worksheets/:id — update worksheet (complete, defer, authorise, return)
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

// GET /api/pms/running-hours — get running hours for vessel
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

// POST /api/pms/running-hours — log new running hours reading
app.post('/api/pms/running-hours', requireAuth, (req, res) => {
  try {
    const pms = readPmsDb();
    const { vessel_id, component_code, assembly_name, new_reading, previous_reading } = req.body;
    const hours_run = new_reading - (previous_reading || 0);
    const entry = {
      id: 'rh_' + Date.now(),
      vessel_id, component_code, assembly_name,
      previous_reading: previous_reading || 0,
      new_reading, hours_run,
      recorded_at: new Date().toISOString(),
      recorded_by: req.user.name
    };
    pms.running_hours.push(entry);
    savePmsDb(pms);
    res.json(entry);
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// GET /api/pms/defects — defect log
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

// POST /api/pms/defects — log new defect
app.post('/api/pms/defects', requireAuth, (req, res) => {
  try {
    const pms = readPmsDb();
    const defect = {
      id: 'def_' + Date.now(),
      ...req.body,
      status: 'open',
      raised_at: new Date().toISOString(),
      raised_by: req.user.name,
      updates: []
    };
    pms.defects.push(defect);
    savePmsDb(pms);
    res.json(defect);
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// PUT /api/pms/defects/:id — update defect
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

// GET /api/pms/history — job history search
app.get('/api/pms/history', requireAuth, (req, res) => {
  try {
    const { vessel_name, search, component, from_date, to_date, page = 1, limit = 30 } = req.query;
    if (!fs.existsSync(PMS_EQUIP_PATH)) return res.json({ records: [], total: 0 });

    // For now return from live pms worksheets (authorised)
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

// GET /api/pms/stats — historical stats per vessel
app.get('/api/pms/stats', requireAuth, (req, res) => {
  try {
    if (!fs.existsSync(PMS_STATS_PATH)) return res.json({});
    res.json(JSON.parse(fs.readFileSync(PMS_STATS_PATH, 'utf8')));
  } catch(e) { res.status(500).json({ error: e.message }); }
});
