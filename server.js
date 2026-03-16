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
    "id": "C1",
    "title": "Vessel, Operator and Inspection Particulars",
    "roles": [
      "Master",
      "DPA"
    ],
    "questions": [
      {
        "id": "1.1.4",
        "number": "1.1.4",
        "chapter": "1",
        "section": "1.1",
        "text": "",
        "short_text": "",
        "vessel_types": [],
        "objective": "",
        "negative_grounds": [],
        "evidence": [],
        "risk": "low",
        "status": "not_started"
      }
    ]
  },
  {
    "id": "C2",
    "title": "Certification and Documentation",
    "roles": [
      "Master",
      "CE",
      "DPA"
    ],
    "questions": [
      {
        "id": "2.1.1",
        "number": "2.1.1",
        "chapter": "2",
        "section": "2.1",
        "text": "Were the Master and senior officers familiar with the company procedure for maintaining the vessel’s statutory certification up to date, were all certificates and documents carried onboard up to date and was the vessel free of conditions of class or significant memoranda?",
        "short_text": "Maintenance of Statutory Certification",
        "vessel_types": [
          "Oil",
          "Chemical",
          "LPG",
          "LNG"
        ],
        "objective": "To ensure that the vessel had been surveyed in accordance with all statutory requirements and that\ncertification is onboard to confirm compliance.\nIndustry guidance:\nIACS: Information Paper. Classification societies – what, why and how?\nTMSA KPI 4.2.1 requires that a procedure is in place to ensure the validity and accuracy of statutory and/or\nclassification certificates.\nIMO: ISM Code\n11.1 The Company should establish and maintain procedures to control all documents and data which are relevant ",
        "negative_grounds": [
          "There was no company procedure which defined the process for managing (indexing and filing) vessel",
          "certificates and documents to ensure compliance with SOLAS, Class and Flag requirements."
        ],
        "evidence": [
          "The company procedure for managing statutory certification and supporting documents.",
          "Folders containing statutory and classification certificates and supporting surveys/test reports.",
          "Certificate index indicating the expiry date all statutory certification, supporting surveys and inspections.",
          "The Class Survey Status Report (CSSR)*.",
          "List of open defects as reported in the defect reporting system.",
          "Details of class attendance during the past twelve months."
        ],
        "risk": "medium",
        "status": "not_started"
      },
      {
        "id": "2.2.1",
        "number": "2.2.1",
        "chapter": "2",
        "section": "2.2",
        "text": "Had the vessel been attended by a company Superintendent at approximately six- monthly intervals and were reports available to demonstrate that a systematic vessel inspection had been completed during each attendance declared through the pre- inspection questionnaire?",
        "short_text": "Superintendent vessel inspection and report",
        "vessel_types": [
          "Oil",
          "Chemical",
          "LPG",
          "LNG"
        ],
        "objective": "To ensure that the vessel had been periodically and systematically inspected by company Marine and\nTechnical Superintendents to provide shore management with a complete technical and operational\nappraisal of their managed vessel.\nTMSA KPI 12.1.2 requires that an inspection plan covers all vessels in a fleet, with at least two inspections onboard\neach vessel a year.\n• The inspection is conducted by suitably experienced superintendent(s) and may be carried out in\nconjunction with other inspections",
        "negative_grounds": [
          "Reports were not available onboard for each declared qualifying vessel inspection conducted by a company",
          "Marine or Technical Superintendent."
        ],
        "evidence": [
          "Qualifying vessel inspection reports completed by company Marine or Technical Superintendents during the",
          "previous eighteen months.",
          "Evidence that defects and areas for improvement had been followed up through the company defect",
          "reporting or non-conformity reporting systems.",
          "The company procedure for conducting remote inspections, if applicable."
        ],
        "risk": "medium",
        "status": "not_started"
      },
      {
        "id": "2.2.2",
        "number": "2.2.2",
        "chapter": "2",
        "section": "2.2",
        "text": "Were recent ISM internal audit reports available on board, had corrective action been taken on board to close-out any non-conformities and had this corrective action been verified by shore management?",
        "short_text": "Internal ISM audit",
        "vessel_types": [
          "Oil",
          "Chemical",
          "LPG",
          "LNG"
        ],
        "objective": "To provide assurance that the vessel had been operated in compliance with the company Safety\nManagement System.",
        "negative_grounds": [
          "There was no company procedure for scheduling and performing internal ISM audits.",
          "No internal ISM audit had taken place for more than:",
          "12 months, with no documentation supporting exceptional circumstances.",
          "The latest two internal ISM audit reports under the current operator, where completed, were not available on",
          "There was no system for recording and tracking any non-conformities to closure.",
          "Records in the system for recording and tracking any non-conformities to closure were incomplete.",
          "The system for recording and tracking any non-conformities to closure:",
          "Was not readily available to those responsible for implementing corrective action for any non-"
        ],
        "evidence": [
          "The company procedure for scheduling and performing internal ISM audits.",
          "The latest two internal ISM audit reports under the current operator.",
          "The system for recording and tracking non-conformities to closure."
        ],
        "risk": "medium",
        "status": "not_started"
      },
      {
        "id": "2.2.3",
        "number": "2.2.3",
        "chapter": "2",
        "section": "2.2",
        "text": "Was the Master fully conversant with the company’s Safety Management System and had Master’s Reviews of the system taken place in accordance with the ISM Code and company procedures?",
        "short_text": "Master's Review of the SMS.",
        "vessel_types": [
          "Oil",
          "Chemical",
          "LPG",
          "LNG"
        ],
        "objective": "To ensure the Master is fully conversant with the Safety Management System and that Master’s Reviews\ncontribute to the improvement of its effectiveness.",
        "negative_grounds": [
          "The Master was not familiar with the layout and contents of the SMS.",
          "The Master was not proficient in accessing the information contained in the SMS, whether in hard copy or",
          "There was no company procedure requiring the periodic review of the Safety Management System (SMS)",
          "by the Master, including:"
        ],
        "evidence": [
          "The Safety Management System.",
          "The last two Master’s Reviews.",
          "The company responses to the last two Master’s Reviews."
        ],
        "risk": "medium",
        "status": "not_started"
      },
      {
        "id": "2.3.1",
        "number": "2.3.1",
        "chapter": "2",
        "section": "2.3",
        "text": "Were the Master and Chief Engineer familiar with the company procedure to maintain the Enhanced Survey File in accordance with Classification Society rules, and was the vessel free of any visible or documentary evidence of concerns with the structural condition of the hull or cargo and ballast tank coatings?",
        "short_text": "Structural concerns and Enhanced Survey File.",
        "vessel_types": [
          "Oil",
          "Chemical"
        ],
        "objective": "To ensure that the structure of oil and chemical tankers was subject to enhanced survey and complete\nhistorical records of any damage, deterioration and subsequent repairs to their hull structure were available\nonboard.",
        "negative_grounds": [
          "There was no company procedure which required that the enhanced survey file, or electronic record, was",
          "maintained in accordance with classification society guidance.",
          "There was no company procedure which required that the coating technical file was maintained in",
          "accordance with classification society guidance.",
          "The accompanying officer was unfamiliar with the company procedure for maintaining the enhanced survey",
          "file, or electronic record, and the coating technical file.",
          "The enhanced survey file was found to be missing required surveys and/or reports.",
          "Inspections by ship’s staff had not been recorded."
        ],
        "evidence": [
          "The Enhanced Survey File (which must be onboard for the lifetime of the ship from at least one year prior to",
          "the first special survey).",
          "The Coating Technical File, where required to be carried.",
          "Supporting documents required to be carried onboard according to the ESP Code.",
          "Inspection reports for cargo, ballast and void spaces by ships personnel.",
          "Incident investigation reports relevant to structural damage and repair within the scope of the enhanced hull"
        ],
        "risk": "medium",
        "status": "not_started"
      },
      {
        "id": "2.3.2",
        "number": "2.3.2",
        "chapter": "2",
        "section": "2.3",
        "text": "Were the Master and Chief Engineer familiar with the company procedure to maintain the Class Survey File, and was the vessel free of any visible or documentary evidence of concerns with the structural condition of the hull or hold space and ballast tank coatings?",
        "short_text": "Structural concerns and Class Survey File.",
        "vessel_types": [
          "LPG",
          "LNG"
        ],
        "objective": "To ensure that the structure of gas carriers was subject to the required surveys and complete historical\nrecords of any damage, deterioration and subsequent repairs to the hull structure were available on board.",
        "negative_grounds": [
          "There was no company procedure to ensure the vessel’s Survey File is maintained complete and up to date.",
          "The Master and/or Chief Engineer were not familiar with the company procedure to ensure the vessel’s",
          "Survey File is maintained complete and up to date.",
          "The Survey File was incomplete and did not include:",
          "Class status reports.",
          "Coating Technical File, where required to be carried.",
          "Maintenance of the protective coating system was not included in the overall ship’s maintenance plan.",
          "Structural repairs were recorded within the Survey File as having taken place during the previous twelve"
        ],
        "evidence": [
          "Survey File.",
          "Coating Technical File, where required to be carried.",
          "Inspection reports for cargo, ballast, hold and void space inspections by ship’s personnel.",
          "Incident investigation reports relevant to structural damage and repair."
        ],
        "risk": "medium",
        "status": "not_started"
      },
      {
        "id": "2.3.3",
        "number": "2.3.3",
        "chapter": "2",
        "section": "2.3",
        "text": "Were the Master and senior officers familiar with the company cargo, ballast & void space inspection and reporting procedure and, were records available to demonstrate that all inspections had been accomplished within the required time frame with reports completed in accordance with company instructions?",
        "short_text": "Cargo, ballast & void space inspection",
        "vessel_types": [
          "Oil",
          "Chemical",
          "LPG",
          "LNG"
        ],
        "objective": "To ensure that the condition of cargo, ballast and void spaces was properly evaluated with defects to\nstructure, coating or fittings effectively managed.",
        "negative_grounds": [
          "There were no company procedures for the inspection of cargo/ballast/void spaces which gave clear",
          "guidance on the inspection frequency, the inspection process and reporting criteria.",
          "The required inspection frequency for ballast and void spaces exceeded twelve months.",
          "The required inspection frequency for cargo spaces on oil and chemical tankers exceeded thirty-six months.",
          "The accompanying officer was unfamiliar with the company cargo/ballast/void space inspection procedure",
          "and/or reporting criteria.",
          "Cargo, ballast or void space inspection(s) for any single space was overdue by more than a month",
          "according to the company defined inspection period for the space(s) in question."
        ],
        "evidence": [
          "The company procedures, and any referenced industry publications, for inspection of cargo, ballast and void",
          "The inspection reports for all cargo, ballast and void spaces for the previous full inspection cycle.",
          "Open defect reports for any defects to tank structure, coatings or fittings.",
          "Communications with class relating to any defects to tank structure since the previous renewal or",
          "intermediate survey."
        ],
        "risk": "medium",
        "status": "not_started"
      },
      {
        "id": "2.3.4",
        "number": "2.3.4",
        "chapter": "2",
        "section": "2.3",
        "text": "Were the Master and deck officers familiar with the company procedures for detecting leakage of liquids between cargo, bunker, ballast, void and cofferdam spaces which included inspecting the surface of ballast water prior to discharge, and were records available to show that the necessary checks had been performed?",
        "short_text": "Monitoring cargo, ballast & void spaces for leakage and contamination",
        "vessel_types": [
          "Oil",
          "Chemical",
          "LPG",
          "LNG"
        ],
        "objective": "To ensure that leakage of liquids between adjacent cargo, bunker, ballast, void and cofferdam spaces or\nfrom pipelines passing through such spaces is detected.",
        "negative_grounds": [
          "There was no company procedure to periodically check empty spaces for ingress of liquids from adjoining",
          "spaces or pipeline leakage or, to check the surface of ballast water for contamination prior to discharge.",
          "The accompanying deck officer was unfamiliar with the company procedure for periodically checking empty",
          "spaces for liquid ingress or monitoring the levels of full or partially full tanks for migration of liquid between",
          "The accompanying officer was unfamiliar with the company procedure for inspecting the surface of ballast",
          "water prior to discharge when a ballast tank adjoined a cargo or bunker tank or had piping containing oil",
          "Records determined that periodic checks to identify the ingress of liquids into empty spaces had not been"
        ],
        "evidence": [
          "The company procedure for sighting the surface of ballast water prior to discharge where the ballast tanks",
          "were adjacent to a cargo or bunker tank or where oil pipes and/or hydraulic lines pass through the tanks.",
          "The company procedure to periodically sound empty tanks to detect liquid migration due to structural failure",
          "or pipeline leakage.",
          "Records demonstrating that the surface of ballast water had been inspected prior to discharge.",
          "Records demonstrating that periodic soundings of empty spaces had been taken in accordance with"
        ],
        "risk": "medium",
        "status": "not_started"
      },
      {
        "id": "2.3.5",
        "number": "2.3.5",
        "chapter": "2",
        "section": "2.3",
        "text": "Had the vessel been enrolled in a Classification Society Condition Assessment Programme (CAP)?",
        "short_text": "Condition Assessment Program (CAP)",
        "vessel_types": [
          "Oil",
          "Chemical",
          "LPG",
          "LNG"
        ],
        "objective": "To provide an objective assessment of the operational reliability of a vessel in critical areas at the request of\na vessel’s owner, typically at the third special survey and periodically thereafter.",
        "negative_grounds": [
          "The information provided by the operator in the pre-inspection questionnaire was inaccurate.",
          "The vessel operator had claimed a CAP rating for modules that were still pending completion.",
          "The date of the CAP survey was inaccurately declared as the CAP certificate issue date.",
          "The operator did not upload the CAP certificate to the document store and the CAP certificate was not",
          "available onboard for review."
        ],
        "evidence": [
          "The CAP certificate showing the completion date of the assessment survey and the final ratings for the",
          "modules completed.",
          "Where the CAP certificate only showed the issue date rather than the survey completion date, evidence to",
          "support the date(s) that the onboard survey was completed.",
          "Any information or records that supplemented the CAP certificate."
        ],
        "risk": "medium",
        "status": "not_started"
      },
      {
        "id": "2.4.1",
        "number": "2.4.1",
        "chapter": "2",
        "section": "2.4",
        "text": "Were the senior officers familiar with the company procedure for reporting defects to vessel structure, machinery and equipment to shore-based management through the company defect reporting system and was evidence available to demonstrate that all defects had been reported accordingly?",
        "short_text": "Defect reporting system",
        "vessel_types": [
          "Oil",
          "Chemical",
          "LPG",
          "LNG"
        ],
        "objective": "To ensure that defects to vessel structure, machinery and equipment are documented and reviewed by\nmanagement.",
        "negative_grounds": [
          "There was no defect reporting system.",
          "There was no company procedure for managing defects to vessel structure, machinery and equipment",
          "through the defect reporting system.",
          "The accompanying senior officer was unfamiliar with the company defect reporting procedure.",
          "Defects entered in the defect reporting system had not been acknowledged by shore management.",
          "Defects were evident onboard the vessel during the inspection that were required to be entered in the defect",
          "reporting system but were not.",
          "In such cases identify the defective equipment in the negative observation module of the Hardware"
        ],
        "evidence": [
          "The company procedure for managing defects to vessel structure, machinery and equipment through the",
          "defect reporting system.",
          "The defect reporting system or the planned maintenance system where the systems were integrated.",
          "Shore based acknowledgement of each defect entered into the defect reporting system.",
          "A printed list of all open defects reports entered into the defect reporting system."
        ],
        "risk": "medium",
        "status": "not_started"
      },
      {
        "id": "2.4.2",
        "number": "2.4.2",
        "chapter": "2",
        "section": "2.4",
        "text": "Where defects existed to the vessel’s structure, machinery or equipment, had the vessel operator notified class, flag and/or the authorities in the port of arrival, as appropriate to the circumstances, and had short term certificates, waivers, exemptions and/or permissions to proceed the voyage been issued where necessary?",
        "short_text": "Defect reporting to class, flag etc",
        "vessel_types": [
          "Oil",
          "Chemical",
          "LPG",
          "LNG"
        ],
        "objective": "To ensure that defects affecting statutory certification or class required equipment are reported to the\nvessel’s Classification Society, Flag Administration and any affected stakeholders as appropriate.",
        "negative_grounds": [
          "There was no company procedure which required that defects to vessel structure, machinery and equipment",
          "were evaluated by shore management to determine whether notifications to Class, Flag and/or other",
          "external stakeholders were required.",
          "The senior officers were not familiar with the company procedure for notifying Class, Flag and/or other",
          "external stakeholders of defects to the vessel’s structure, machinery or equipment after shore management",
          "There were open defect reports in the defect reporting system which were of a significant nature but there",
          "was no evidence that class, flag and/or external stakeholders had been informed in accordance with the",
          "company procedure. In this case identify the defective equipment in the negative observation module of the"
        ],
        "evidence": [
          "The company procedure for notifying the vessel’s Classification Society, Flag Administration and/or other",
          "external stakeholders of defects to the vessel’s structure, machinery and equipment.",
          "The class status report – uploaded to the document portal.",
          "The defect reporting system, or the planned maintenance system where systems were integrated.",
          "A printed list of open defect reports identifying any defects which had been reported to the vessel’s",
          "Classification Society and/or Flag Administration."
        ],
        "risk": "medium",
        "status": "not_started"
      },
      {
        "id": "2.5.1",
        "number": "2.5.1",
        "chapter": "2",
        "section": "2.5",
        "text": "Had the company Management of Change procedure been effectively implemented for changes affecting structure, machinery and equipment governed by Classification Society rules or statutory survey?",
        "short_text": "Management of Change",
        "vessel_types": [
          "Oil",
          "Chemical",
          "LPG",
          "LNG"
        ],
        "objective": "To ensure that any change made to the vessel structure, machinery or equipment is properly managed to\navoid an undesirable outcome.",
        "negative_grounds": [
          "There was no company MOC procedure covering changes affecting class and/or flag regulated structure,",
          "machinery and equipment.",
          "The accompanying senior officer was unfamiliar with the company MOC process, as it applied to changes",
          "falling within the scope of this question, to structure, machinery and equipment onboard the vessel.",
          "Changes falling within the scope of this question to vessel structure, machinery or equipment, regulated by",
          "class and/or flag, had been conducted within the previous twelve months but had not been declared on the",
          "pre-inspection questionnaire.",
          "Changes to vessel structure, fittings or equipment, within the scope of this question, had been conducted"
        ],
        "evidence": [
          "The vessel’s MOC register or database index.",
          "The MOC requests for all changes to vessel structure, machinery and equipment conducted onboard the",
          "vessel during the previous twelve months.",
          "Supporting documents such as risk assessments, training plans, updated drawings lists etc. as identified",
          "within each MOC request form."
        ],
        "risk": "medium",
        "status": "not_started"
      },
      {
        "id": "2.6.1",
        "number": "2.6.1",
        "chapter": "2",
        "section": "2.6",
        "text": "Were the Master, deck officers and engineer officers familiar with the vessel’s Ballast Water Management Plan and were records available to demonstrate that ballast handling had been conducted in accordance with the plan?",
        "short_text": "Ballast Water Management Plan",
        "vessel_types": [
          "Oil",
          "Chemical",
          "LPG",
          "LNG"
        ],
        "objective": "To ensure that ballast is always safely handled in accordance with the Ballast Water Management\nConvention and BWMS Code.",
        "negative_grounds": [
          "The vessel did not have a Ballast Water Management Plan or a valid Ballast Water Management Certificate.",
          "The Ballast Water Management Plan was not approved by the Flag Sate or recognised organisation such as",
          "The Ballast Water Management Plan was not ship-specific.",
          "The officer designated in the Ballast Water Management Plan to be in charge of ensuring that the plan was",
          "properly implemented was not familiar with its contents.",
          "The Ballast Water Management Plan was not written in the working language of the ship.",
          "The accompanying deck or engineering officer was unfamiliar with the Ballast Water Management Plan, or"
        ],
        "evidence": [
          "The Ballast Water Management Plan along with a copy of the Ballast Water Management Certificate.",
          "The Ballast Water Record Book or equivalent.",
          "Recent cargo and ballast plans along with supporting operational records to verify the times and duration of",
          "ballast operations.",
          "Where ballast water exchange had taken place, the exchange plan showing the sequence of exchange and",
          "the longitudinal stresses, draughts and trim at each stage of the operation."
        ],
        "risk": "medium",
        "status": "not_started"
      },
      {
        "id": "2.6.2",
        "number": "2.6.2",
        "chapter": "2",
        "section": "2.6",
        "text": "Were the Master and officers familiar with the VOC Management Plan, and had the procedures for minimising VOC emissions set out in the Plan been implemented and documented as required?",
        "short_text": "VOC Management Plan.",
        "vessel_types": [
          "Oil"
        ],
        "objective": "To ensure VOC emissions are minimised by implementation of the VOC Management Plan.",
        "negative_grounds": [
          "The VOC Management Plan was not approved by the Flag State or recognised organisation such as a Class",
          "The VOC Management Plan was not ship specific.",
          "The VOC Management Plan was not in a language readily understood by the Master and officers.",
          "The person identified as responsible for implementing the VOC Management Plan was not familiar with its",
          "The accompanying officer was not aware of the VOC Management Plan or familiar with the actions",
          "necessary to comply with the provisions of the Plan (which may be incorporated in the cargo transfer plan).",
          "There was no evidence that the training programmes set out in the VOC Management Plan had been",
          "There was no evidence that the procedures for minimising VOC emissions set out in the Plan had been"
        ],
        "evidence": [
          "The VOC Management Plan.",
          "VOC Management Plan training records.",
          "Records required to be maintained to demonstrate compliance with the Plan.",
          "The cargo plan for the ongoing cargo operation.",
          "The deck logbook."
        ],
        "risk": "medium",
        "status": "not_started"
      },
      {
        "id": "2.6.3",
        "number": "2.6.3",
        "chapter": "2",
        "section": "2.6",
        "text": "Were the Master and senior officers familiar with the contents and requirements of the Ship Energy Efficiency Management Plan (SEEMP) and had these been fully implemented?",
        "short_text": "Ship Energy Efficiency Management Plan (SEEMP).",
        "vessel_types": [
          "Oil",
          "Chemical",
          "LPG",
          "LNG"
        ],
        "objective": "To ensure the measures set out in the SEEMP to improve fuel efficiency and collect fuel consumption data\nhave been fully implemented.",
        "negative_grounds": [
          "The Master and/or the Chief Engineer were not familiar with the contents and requirements of the Ship",
          "Energy Efficiency Management Plan (SEEMP).",
          "The SEEMP Part I did not contain a package of measures to improve the ship's energy efficiency, and",
          "details for their implementation, such as:",
          "Improved voyage planning.",
          "Just in time arrival."
        ],
        "evidence": [
          "Ship Energy Efficiency Management Plan (SEEMP).",
          "Documentary evidence that the package of measures listed in the SEEMP Part I to improve the ship’s",
          "energy efficiency had been implemented and/or monitored, which may be contained in bridge and engine",
          "logbooks etc.",
          "On ships of 5,000 gross tonnage or above, records of the collection, aggregation, and reporting of ship data",
          "with regard to annual fuel oil consumption, distance travelled, hours underway and other data required by"
        ],
        "risk": "medium",
        "status": "not_started"
      },
      {
        "id": "2.7.1",
        "number": "2.7.1",
        "chapter": "2",
        "section": "2.7",
        "text": "Was the relevant content of the SMS manuals easily accessible to all personnel on board in a working language(s) understood by them?",
        "short_text": "Availability of SMS content to all crew.",
        "vessel_types": [
          "Oil",
          "Chemical",
          "LPG",
          "LNG"
        ],
        "objective": "To ensure that all personnel on board can access and understand the procedures and instructions relevant\nto them, set out in the ship’s SMS manuals.",
        "negative_grounds": [
          "The SMS manuals were not ‘user friendly’ and ship staff found it difficult and/or time consuming to navigate",
          "to the appropriate information.",
          "A significant proportion of the content of the SMS manuals was not relevant to the ship e.g. described",
          "procedures for general cargo ships, container ships or bulk carriers.",
          "Manuals were in hard-copy format but there were insufficient copies at appropriate locations.",
          "Manuals were only available in electronic format, but not all personnel had ready access to a work-station",
          "and/or adequate training in accessing the SMS.",
          "The operator’s navigation procedures and instructions were not available on the bridge."
        ],
        "evidence": [
          "SMS manuals.",
          "Evidence that changes to the SMS are promptly brought to the attention of the appropriate on-board",
          "personnel and understood (which may be documentary or electronic)."
        ],
        "risk": "medium",
        "status": "not_started"
      },
      {
        "id": "2.7.2",
        "number": "2.7.2",
        "chapter": "2",
        "section": "2.7",
        "text": "Did the SMS identify clear levels of authority and lines of communication between the Master, ship's officers, ratings and the company, and were all onboard personnel familiar with these arrangements as they related to their position?",
        "short_text": "Communication lines with the company and DPA.",
        "vessel_types": [
          "Oil",
          "Chemical",
          "LPG",
          "LNG"
        ],
        "objective": "To ensure all onboard personnel understand the levels of authority and lines of communication between the\nMaster, ship's officers, ratings and the company as they relate to their position.",
        "negative_grounds": [
          "The SMS did not identify clear levels of authority and lines of communication between the Master, ship's",
          "fficers, ratings and the Company.",
          "A senior officer was not familiar with the lines of communication with the key members of the operator’s",
          "An interviewed junior officer or rating was not aware of the identity, contact details and role of the DPA."
        ],
        "evidence": [
          "The SMS manual showing documented levels of authority and lines of communication between the Master,",
          "ship's officers, ratings and the company.",
          "The means of informing all officers and ratings of the identity and contact details of the DPA."
        ],
        "risk": "medium",
        "status": "not_started"
      },
      {
        "id": "2.8.1",
        "number": "2.8.1",
        "chapter": "2",
        "section": "2.8",
        "text": "Was the OCIMF Harmonised Vessel Particulars Questionnaire (HVPQ) available through the OCIMF SIRE Programme database completed accurately to reflect the structure, outfitting, management and certification of the vessel?",
        "short_text": "HVPQ accurately completed.",
        "vessel_types": [
          "Oil",
          "Chemical",
          "LPG",
          "LNG"
        ],
        "objective": "To ensure that the information contained within the OCIMF HVPQ provides an accurate dataset for use by\nSIRE 2.0 programme participants.",
        "negative_grounds": [
          "Where the information provided within the HVPQ misrepresented the details of the vessel through multiple systemic",
          "inaccuracies or omissions relating to ownership, class status, validity of certification or outfitting of the vessel:",
          "Make an observation within the process response tool and add a comment to identify which questions were",
          "provided with inaccurate information."
        ],
        "evidence": [
          "The following certificates and documents will be provided, as applicable to the vessel, through the inspection",
          "software: SIRE Crew matrix.",
          "Class Status Summary Report (CSSR) (Owners version).",
          "Ballast Water Management Certificate.",
          "Certificate of Fitness for the Carriage of Chemicals or Gas."
        ],
        "risk": "medium",
        "status": "not_started"
      },
      {
        "id": "2.8.2",
        "number": "2.8.2",
        "chapter": "2",
        "section": "2.8",
        "text": "Were records of the most recent Port State Control inspection available onboard, and where deficiencies had been recorded had these been corrected and closed out in accordance with the company procedure for defects or non-conformities?",
        "short_text": "Last Port State Control Inspection.",
        "vessel_types": [
          "Oil",
          "Chemical",
          "LPG",
          "LNG"
        ],
        "objective": "To provide an accurate record of the most recent Port State Control (PSC) Inspection.",
        "negative_grounds": [
          "There was no company procedure for managing PSC inspections.",
          "Where the vessel operator was utilising the OCIMF PSC Inspection Repository, the most recent PSC",
          "Inspection Report had not been uploaded (an allowance of five days since the completion of the inspection",
          "prior to the synchronisation of the inspection editor should be allowed) The PSC inspection reports available onboard did not include the most recent PSC inspection available on",
          "ne of the PSC MOU databases.",
          "Where there were documented deficiencies during the last PSC inspection, there was no documented",
          "evidence that the deficiencies had been corrected and closed out with shore management approval."
        ],
        "evidence": [
          "The company procedure for managing PSC inspections.",
          "All PSC inspection reports for the previous three years, or if no PSC inspections had been carried out in that",
          "period, the report for the last inspection conducted.",
          "Documented evidence that any deficiencies raised during the last PSC inspection had been corrected and",
          "closed out with approval from shore management through either the non-conformity reporting system or",
          "defect reporting system."
        ],
        "risk": "medium",
        "status": "not_started"
      },
      {
        "id": "2.3.7",
        "number": "2.3.7",
        "chapter": "2",
        "section": "2.3",
        "text": "",
        "short_text": "",
        "vessel_types": [],
        "objective": "",
        "negative_grounds": [
          "There were no company procedures for maintaining the documents and records required by MARPOL",
          "Annex VI Regulation 13 and the NOx Technical Code.",
          "The accompanying officer was not familiar with the company procedures for maintaining the documents and",
          "records required by MARPOL Annex VI Regulation 13 and the NOx Technical Code.",
          "The accompanying officer was not familiar with the NOx abatement system installed on board, or its",
          "The accompanying officer was not familiar with the actions to be taken in the event that a NOx abatement",
          "system fitted suffered a failure that could not be rectified within one hour.",
          "Technical Files were not available for all diesel engines listed in paragraph 2.2.1 of the vessel’s International"
        ],
        "evidence": [
          "Company procedures for maintaining the documents and records required by MARPOL Annex VI Regulation",
          "13 and the NOx Technical Code.",
          "International Air Pollution Prevention (IAPP) Certificate.",
          "Technical Files for diesel engines listed in paragraph 2.2.1 of the vessel’s International Air Pollution",
          "Prevention (IAPP) Certificate.",
          "Record Books of Engine Parameters for those engines required to undergo Engine Parameter Checks at"
        ],
        "risk": "medium",
        "status": "not_started"
      }
    ]
  },
  {
    "id": "C3",
    "title": "Crew Management",
    "roles": [
      "Master",
      "Officers"
    ],
    "questions": [
      {
        "id": "3.1.1",
        "number": "3.1.1",
        "chapter": "3",
        "section": "3.1",
        "text": "Were the officers and ratings suitably qualified to serve onboard the vessel and did the officer matrix posted on the OCIMF website accurately reflect the qualifications, experience and English language capabilities of the officers onboard at the time of the inspection?",
        "short_text": "Crew qualifications and matrix verification.",
        "vessel_types": [
          "Oil",
          "Chemical",
          "LPG",
          "LNG"
        ],
        "objective": "To ensure that all officers and crew onboard are properly qualified for the type of vessel and the position\nthey hold onboard.\nIndustry Guidelines\nOCIMF: Guidelines for the Completion of the On-Line Officer Matrix.\nAvailable within the SIRE operator account.\nTMSA KPI 3.2.3 requires that the company verifies that vessel personnel quality requirements are consistently met.\nIrrespective of whether this function is performed internally or by a manning agency, verification may include:\n• Certificatio",
        "negative_grounds": [
          "The officer matrix had not been updated to reflect the officers who were on board at the time of the",
          "inspection (an allowance will be made for any officer that had changed within the previous four days).",
          "The accompanying senior officer was unfamiliar with the maintenance of officer and rating certification",
          "The details contained in the officer matrix were inaccurate in terms of:",
          "National Certificate of Competency (CoC)."
        ],
        "evidence": [
          "The updated officer matrix available on the OCIMF website reflecting all changes in crew that had occurred",
          "more than four days before the inspection. (it is not expected that the vessel provides a paper or electronic",
          "The relevant documentation for each person onboard, in the following order or a standard order as defined",
          "by the vessel operator, including: o National certificate of competency (CoC).",
          "o National certificate of basic or advanced training in oil, chemical or liquified gas tanker operations."
        ],
        "risk": "medium",
        "status": "not_started"
      },
      {
        "id": "3.1.2",
        "number": "3.1.2",
        "chapter": "3",
        "section": "3.1",
        "text": "Were procedures and instructions contained within the Safety Management System and signs posted around the vessel available in the designated working language of the vessel or a language(s) understood by the crew and, were the Master, officers and ratings able to communicate verbally in the designated working language?",
        "short_text": "Designated working language.",
        "vessel_types": [
          "Oil",
          "Chemical",
          "LPG",
          "LNG"
        ],
        "objective": "To ensure that the Master, officers and ratings can read and understand procedures, instructions and safety\nsigns onboard, and can communicate verbally in the designated working language of the vessel.",
        "negative_grounds": [],
        "evidence": [],
        "risk": "low",
        "status": "not_started"
      },
      {
        "id": "3.1.3",
        "number": "3.1.3",
        "chapter": "3",
        "section": "3.1",
        "text": "Did the complement of officers and ratings onboard at the time of inspection meet or exceed the requirements of the Minimum Safe Manning Document and the declared company standard manning for routine operations, and had senior officers been relieved to ensure continuity of operational knowledge?",
        "short_text": "Minimum, standard and enhanced manning levels.",
        "vessel_types": [
          "Oil",
          "Chemical",
          "LPG",
          "LNG"
        ],
        "objective": "To ensure that the vessel is always adequately manned for the operations expected to be undertaken based\non the normal trading pattern and any foreseeable specialist operations or periods of heightened workload.",
        "negative_grounds": [
          "The crew onboard on arrival at the port of inspection did not meet the requirements of the Safe Manning",
          "Document in any respect.",
          "The crew onboard on arrival at the port of inspection did not:",
          "Meet the standard manning level declared through the pre-inspection questionnaire, or",
          "Meet the company enhanced manning provision when conducting:",
          " Continuous/extended/repeated STS operations.",
          " Continuous/extended/repeated inter-harbour operations and/or short voyages of less than",
          " Operations requiring implementation of additional security measures."
        ],
        "evidence": [
          "The Minimum Safe Manning Document.",
          "A copy of the arrival crew list provided by the Master.",
          "The current OCIMF crew matrix available on the OCIMF SIRE database."
        ],
        "risk": "medium",
        "status": "not_started"
      },
      {
        "id": "3.2.1",
        "number": "3.2.1",
        "chapter": "3",
        "section": "3.2",
        "text": "Was a report available onboard which confirmed that a static navigational assessment by a suitably qualified and experienced company representative had been completed as declared through the pre-inspection questionnaire?",
        "short_text": "Static navigational assessment",
        "vessel_types": [
          "Oil",
          "Chemical",
          "LPG",
          "LNG"
        ],
        "objective": "To verify the extent of company evaluation and oversight of navigational standards onboard managed\nvessels",
        "negative_grounds": [
          "The report for the static navigational assessment declared through the pre-inspection questionnaire was not",
          "The details of the qualifications and pertinent seafaring experience of the assessor were not included within"
        ],
        "evidence": [
          "The report for the static navigational assessment declared by the operator through the pre-inspection",
          "questionnaire.",
          "A corrective action plan with due dates for each area for improvement identified during the static",
          "navigational assessment.",
          "Supporting evidence for each closed area for improvement identified and included in the corrective action"
        ],
        "risk": "medium",
        "status": "not_started"
      },
      {
        "id": "3.2.2",
        "number": "3.2.2",
        "chapter": "3",
        "section": "3.2",
        "text": "Was a report available onboard which confirmed that a dynamic navigational assessment by a suitably qualified and experienced company representative had been completed while on passage as declared through the pre-inspection questionnaire?",
        "short_text": "Dynamic navigational assessment by a company representative",
        "vessel_types": [
          "Oil",
          "Chemical",
          "LPG",
          "LNG"
        ],
        "objective": "To verify the extent of company evaluation and oversight of navigational standards onboard managed\nvessels",
        "negative_grounds": [
          "The report for the dynamic navigational assessment declared through the pre-inspection questionnaire was",
          "not available onboard.",
          "The dynamic navigational assessment did not cover the stages of the voyage or was not completed during",
          "the date range as declared by the operator through the pre-inspection questionnaire.",
          "The details of the qualifications and pertinent seafaring experience of the assessor were not included within",
          "The assessor did not hold or had not held a senior deck officer licence and/or had not sailed as a senior",
          "The dynamic navigational assessment report was not substantially in alignment with the guidance document",
          "“A Guide to Best Practice for Navigational Assessments and Audits” and the best practice guidance under"
        ],
        "evidence": [
          "The report for the dynamic navigational assessment conducted by a suitably qualified and experienced",
          "company representative as declared in the pre-inspection questionnaire.",
          "The Bridge Log Book to cover the period of the reported dynamic navigation assessment (for geographical",
          "verification purposes only).",
          "A corrective action plan with due dates for each area for improvement identified during the navigational",
          "assessment."
        ],
        "risk": "medium",
        "status": "not_started"
      },
      {
        "id": "3.2.3",
        "number": "3.2.3",
        "chapter": "3",
        "section": "3.2",
        "text": "Was a report available onboard which confirmed that a dynamic navigational assessment by a suitably qualified specialist contractor had been completed while on passage as declared through the pre-inspection questionnaire?",
        "short_text": "Dynamic navigational assessment by a specialist contractor",
        "vessel_types": [
          "Oil",
          "Chemical",
          "LPG",
          "LNG"
        ],
        "objective": "To verify the extent of company evaluation and oversight of navigational standards onboard managed\nvessels",
        "negative_grounds": [
          "The report for the dynamic navigational assessment declared through the pre-inspection questionnaire was",
          "not available onboard.",
          "The dynamic navigational assessment did not cover the stages of the voyage or was not completed during",
          "the date range as declared by the operator through the pre-inspection questionnaire.",
          "The details of the qualifications and pertinent seafaring experience of the assessor were not included within",
          "The assessor did not hold or had not held a senior deck officer licence and/or had not sailed as a senior",
          "The dynamic navigational assessment report was not substantially in alignment with the guidance document",
          "“A Guide to Best Practice for Navigational Assessments and Audits” and the best practice guidance under"
        ],
        "evidence": [
          "The report for the dynamic navigational assessment conducted by a suitably qualified specialist contractor",
          "as declared in the pre-inspection questionnaire.",
          "The Bridge Log Book to cover the period of the reported dynamic navigation assessment. (for geographical",
          "verification purposes only) A corrective action plan with due dates for each area for improvement identified during the navigational",
          "assessment."
        ],
        "risk": "medium",
        "status": "not_started"
      },
      {
        "id": "3.2.4",
        "number": "3.2.4",
        "chapter": "3",
        "section": "3.2",
        "text": "Was a report available onboard which confirmed that an unannounced remote navigational assessment, which included review of VDR & ECDIS data by an independent contractor or specialist company representative, had been completed as declared through the pre-inspection questionnaire?",
        "short_text": "Unannounced remote navigational assessment",
        "vessel_types": [
          "Oil",
          "Chemical",
          "LPG",
          "LNG"
        ],
        "objective": "To verify the extent of company evaluation and oversight of navigational standards onboard managed\nvessels.",
        "negative_grounds": [
          "The remote navigational assessment report for the assessment declared through the pre-inspection",
          "questionnaire was not available onboard.",
          "The remote navigational assessment did not include review of downloaded VDR and ECDIS data as well as",
          "supporting material such as passage plans, under-keel clearance calculations and copies (photos) of paper",
          "charts where no ECDIS was carried.",
          "The remote navigational assessment covered a period solely at anchor or open sea navigation where no",
          "navigational challenges were present.",
          "The remote navigational assessment did not cover the phases of the voyage as declared by the operator"
        ],
        "evidence": [
          "The report for the remote navigational assessment conducted by either an independent contractor or",
          "specialist company representative as declared through the pre-inspection questionnaire.",
          "The Bridge Log Book to cover the period of the reported remote navigation assessment (for geographical",
          "verification purposes only).",
          "A corrective action plan with due dates for each area for improvement identified during the remote",
          "navigational assessment."
        ],
        "risk": "medium",
        "status": "not_started"
      },
      {
        "id": "3.2.5",
        "number": "3.2.5",
        "chapter": "3",
        "section": "3.2",
        "text": "Was a report available onboard which confirmed that a comprehensive cargo audit by a suitably qualified and experienced company representative had been completed as declared through the pre-inspection questionnaire?",
        "short_text": "Comprehensive cargo audit by a company representative",
        "vessel_types": [
          "Oil",
          "Chemical",
          "LPG",
          "LNG"
        ],
        "objective": "To verify the extent of company evaluation and oversight of cargo, ballast and bunkering operational\nstandards onboard managed vessels\nOCIMF Guidance: A Guide to Best Practice for Navigational Assessments and Audits.\nTo align the expectations for comprehensive operational audits across onboard disciplines, the guidance provided in\nthe OCIMF document “A Guide to Best Practice for Navigational Assessments and Audits” is adapted to reflect the\nrequirements for a comprehensive cargo audit.\nTMSA KPI ",
        "negative_grounds": [
          "The report for the comprehensive cargo audit declared through the pre-inspection questionnaire was not",
          "The comprehensive cargo audit did not cover the cargo or bunker operations or was not completed during",
          "the date range as declared by the operator through the pre-inspection questionnaire.",
          "The details of the qualifications and pertinent seafaring experience of the assessor were not included within",
          "The assessor did not hold or had not held a senior deck officer licence and/or had not sailed as a senior",
          "deck officer onboard tankers.",
          "The comprehensive cargo audit report was not substantially in alignment with the suggested best practice"
        ],
        "evidence": [
          "The report for the comprehensive cargo audit conducted by a suitably qualified and experienced company",
          "representative as declared through the pre-inspection questionnaire.",
          "The Deck Log Book and/or Cargo Log Book to cover the period of the reported comprehensive cargo audit",
          "(for geographical and operational verification purposes only).",
          "A corrective action plan with due dates for each area for improvement identified during the comprehensive",
          "cargo audit."
        ],
        "risk": "medium",
        "status": "not_started"
      },
      {
        "id": "3.2.6",
        "number": "3.2.6",
        "chapter": "3",
        "section": "3.2",
        "text": "Was a report available onboard which confirmed that a comprehensive engineering audit by a suitable qualified and experienced company representative had been completed as declared in the pre-inspection questionnaire?",
        "short_text": "Comprehensive engineering audit by a company representative",
        "vessel_types": [
          "Oil",
          "Chemical",
          "LPG",
          "LNG"
        ],
        "objective": "To verify the extent of company evaluation and oversight of machinery space management, engineering and\nmaintenance standards onboard managed vessels.\nICS: Engine Room Procedures Guide. First Edition.\n11.8.2 Routine Operations\nAll routine operations on board should be covered by written procedures as part of the company’s SMS.\nThese procedures should be based on applicable statutory requirements, classification society requirements, industry\ngood practice guidance and recognised standards. They ",
        "negative_grounds": [
          "The report for the comprehensive engineering audit declared through the pre-inspection questionnaire was",
          "not available onboard.",
          "The comprehensive engineering audit did not cover the machinery space operations or was not completed",
          "during the date range as declared by the operator through the pre-inspection questionnaire.",
          "The details of the qualifications and pertinent seafaring experience of the assessor were not included within",
          "The assessor did not hold or had not held a senior engineering officer licence and/or had not sailed as a",
          "senior engineer officer onboard tankers.",
          "The comprehensive engineering audit report was not substantially in alignment with the suggested best"
        ],
        "evidence": [
          "The report for the comprehensive engineering audit conducted by a suitably qualified and experienced",
          "company representative as declared through the pre-inspection questionnaire.",
          "The Engine Room Log Book to cover the period of the reported comprehensive engineering audit (for",
          "geographical and operational verification purposes only).",
          "A corrective action plan with due dates for each area for improvement identified during the comprehensive",
          "engineering audit."
        ],
        "risk": "medium",
        "status": "not_started"
      },
      {
        "id": "3.2.7",
        "number": "3.2.7",
        "chapter": "3",
        "section": "3.2",
        "text": "Was a report available onboard which confirmed that a comprehensive mooring and anchoring audit by a suitably qualified and experienced company representative had been completed as declared through the pre-inspection questionnaire?",
        "short_text": "Comprehensive mooring and anchoring audit by a company representative",
        "vessel_types": [
          "Oil",
          "Chemical",
          "LPG",
          "LNG"
        ],
        "objective": "To verify the extent of company evaluation and oversight of mooring and anchoring operational standards\nonboard managed vessels.",
        "negative_grounds": [
          "The report for the comprehensive mooring and anchoring audit declared through the pre-inspection",
          "questionnaire was not available onboard.",
          "The comprehensive mooring and anchoring audit did not cover the type of mooring and anchoring",
          "perations or was not completed during the date range as declared by the operator through the pre-",
          "inspection questionnaire."
        ],
        "evidence": [
          "The report for the comprehensive mooring and anchoring audit conducted by a suitably qualified and",
          "experienced company representative as declared through the pre-inspection questionnaire.",
          "The Deck Log Book to cover the period of the reported comprehensive mooring and anchoring audit (for",
          "geographical and operational verification purposes only).",
          "A corrective action plan with due dates for each area for improvement identified during the comprehensive",
          "mooring and anchoring audit."
        ],
        "risk": "medium",
        "status": "not_started"
      },
      {
        "id": "3.2.8",
        "number": "3.2.8",
        "chapter": "3",
        "section": "3.2",
        "text": "Had the vessel operator implemented a Behavioural Competency Assessment Programme onboard and was there evidence available that assessments were being conducted for navigation, cargo, mooring and engineering operations by approved assessors?",
        "short_text": "Behavioural Competency Assessment Programme",
        "vessel_types": [
          "Oil",
          "Chemical",
          "LPG",
          "LNG"
        ],
        "objective": "To verify the extent of company evaluation and oversight of competency standards onboard managed\nvessels.",
        "negative_grounds": [
          "There was no evidence that there was a functional Behavioural Competency Assessment and Verification",
          "Programme in operation onboard.",
          "The Behavioural Competency Assessment and Verification Programme did not cover navigation, cargo",
          "perations, mooring operations and engineering operations.",
          "Onboard staff identified as approved assessors were not in possession of the company defined training for",
          "There were no summary records available for the staff included in the Behavioural Competency Assessment",
          "and Verification Programme which showed their achievements since joining the company or the inception of"
        ],
        "evidence": [
          "The Behavioural Competency Assessment and Verification Programme Guide.",
          "The qualifications for any approved assessors onboard at the time of the inspection.",
          "The records (summary) of competency assessments completed for all staff onboard at the time of the",
          "inspection who were included in the competency assessment programme since they joined the company or",
          "the inception of the programme.",
          "Sample assessments for cargo, navigation, mooring and engineering competencies."
        ],
        "risk": "medium",
        "status": "not_started"
      },
      {
        "id": "3.3.1",
        "number": "3.3.1",
        "chapter": "3",
        "section": "3.3",
        "text": "Had the Master and all navigation officers attended a shore-based Bridge Team Management training course within the previous five years?",
        "short_text": "Shore-based Bridge Team Management training",
        "vessel_types": [
          "Oil",
          "Chemical",
          "LPG",
          "LNG"
        ],
        "objective": "To ensure that all navigation officers have been trained in the practical application of crew resource\nmanagement in a realistic navigational environment.",
        "negative_grounds": [
          "The Master and/or any one of the navigation officers onboard during the inspection did not have evidence of",
          "attending a Bridge Team Simulator training course at least equivalent to IMO Model Course 1.22 within the"
        ],
        "evidence": [
          "The Bridge Team Management training certificates for the Master and navigation officers.",
          "Where the Bridge Team Management training certificate did not state that it was in accordance with IMO",
          "Model Course 1.22, evidence that the training course included a bridge simulator element which required",
          "that simulator based navigational exercises were at least equivalent to the requirements of IMO Model",
          "Course 1.22. (19 hours simulator time)."
        ],
        "risk": "medium",
        "status": "not_started"
      },
      {
        "id": "3.3.2",
        "number": "3.3.2",
        "chapter": "3",
        "section": "3.3",
        "text": "Had the Master received formal ship handling training prior to promotion or when being assigned to a new type of ship having significantly different handling characteristics to ships in which they had recently served?",
        "short_text": "Formal ship handling training",
        "vessel_types": [
          "Oil",
          "Chemical",
          "LPG",
          "LNG"
        ],
        "objective": "To ensure the Master is familiar with the ship handling characteristics of the type of ship to which they have\nbeen assigned.",
        "negative_grounds": [
          "The time in rank for the Master entered in the OCIMF Officer Matrix was inaccurate in that the time in rank",
          "declared was greater than thirty-six months sea service, but the Master had less than thirty-six months sea",
          "There was no company training matrix available which clearly identified the circumstances in which ship",
          "handling training was required to be completed by a Master both at promotion and when being reassigned to",
          "a vessel having significantly different handling characteristics.",
          "The vessel operator had not provided an evaluation of the handling characteristics of vessels under",
          "management and identified where training was necessary when transferring between vessel identified as"
        ],
        "evidence": [
          "The Master’s sea service record and discharge book.",
          "The company training matrix showing the mandatory and non-mandatory training requirements for the",
          "The company matrix of the handling characteristics of vessels under management considering the number",
          "and type of propellers, rudders and thrusters fitted to a vessel as well as the vessel size, and the training",
          "requirements for transfer between vessel types."
        ],
        "risk": "medium",
        "status": "not_started"
      },
      {
        "id": "3.3.3",
        "number": "3.3.3",
        "chapter": "3",
        "section": "3.3",
        "text": "Had the Master, deck officers, and cargo/gas engineer where carried, attended a shore-based simulator course covering routine and emergency cargo operations within the previous five years?",
        "short_text": "Cargo operations shore-based simulator course",
        "vessel_types": [
          "Oil",
          "Chemical",
          "LPG",
          "LNG"
        ],
        "objective": "To establish whether all officers involved in cargo operations had been practically trained in routine and\nemergency cargo operations in a realistic simulator environment.\nIndustry guidance:\nIMO: Model Course 1.35 – Liquified Petroleum Gas (LPG) Tanker Cargo & Ballast Handling Simulator.\nIMO: Model Course 1.36 – Liquified Natural Gas (LNG) Tanker Cargo & Ballast Handling Simulator.\nIMO: Model Course 1.37 – Chemical Tanker Cargo & Ballast Handling Simulator.\nIMO: Model Course 2.06 – Oil Tanker Ca",
        "negative_grounds": [
          "The Master and/or any one of the deck officers or cargo/gas engineers onboard during the inspection did not",
          "have evidence of attending either a full or refresher cargo system simulator training course within the",
          "The training courses attended by the Master and/or any one of the deck officers or cargo/gas engineers was",
          "for a vessel type other than the type of vessel being inspected."
        ],
        "evidence": [
          "The shore-based cargo system simulator training certificates for the Master, deck officers and cargo/gas",
          "engineer where carried.",
          "Where the shore-based cargo system simulator training had been completed more than five years",
          "previously, a certificate for a refresher training course with an appropriate cargo simulator element.",
          "Where a refresher training course was undertaken, the supporting full course certificate must also be",
          "available for review."
        ],
        "risk": "medium",
        "status": "not_started"
      },
      {
        "id": "3.3.4",
        "number": "3.3.4",
        "chapter": "3",
        "section": "3.3",
        "text": "Had the Chief Engineer and all engineer officers attended a shore-based engine room management simulator course covering routine and emergency machinery operations within the previous five years?",
        "short_text": "Shore-based engine room management simulator course",
        "vessel_types": [
          "Oil",
          "Chemical",
          "LPG",
          "LNG"
        ],
        "objective": "To ensure that the Chief Engineer and all engineer officers involved in manoeuvring operations had been\npractically trained in routine and emergency machinery operations in a realistic simulator environment.\nIndustry guidance:\nIMO: Model Course 2.07 – Engine-Room Simulator.\nTMSA KPI 3.2.2 requires that procedures are in place to provide company specific additional training for all\nranks. The procedures may include:\n• The type of training.\n• Frequency of refresher training.\n• Records of training.",
        "negative_grounds": [
          "The Chief Engineer and/or any one of the engineer officers onboard during the inspection did not have",
          "evidence of attending either a full or refresher engine room management simulator course within the",
          "The training courses attended by the Chief Engineer and/or any one of the engineer officers was for a",
          "propulsion type other than the type fitted to the vessel being inspected."
        ],
        "evidence": [
          "The shore-based engine room management simulator training certificates for the Chief Engineer and all",
          "Where the shore-based engine room management simulator training had been completed more than five",
          "years previously, a certificate for a refresher training course with an appropriate engine room simulator"
        ],
        "risk": "medium",
        "status": "not_started"
      },
      {
        "id": "3.3.5",
        "number": "3.3.5",
        "chapter": "3",
        "section": "3.3",
        "text": "Did all key personnel onboard involved in Dynamically Positioned (DP) operations have appropriate training in accordance with IMO and International Marine Contractors Association (IMCA) guidelines and local regulations applicable to the area of operations?",
        "short_text": "Training for Dynamically Positioned (DP) operators",
        "vessel_types": [
          "Oil"
        ],
        "objective": "To ensure that all key personnel onboard are properly experienced, trained and qualified to participate in\nDynamically Positioned (DP) operations in accordance with industry recommended best practice and local\nregulation.",
        "negative_grounds": [
          "The vessel operator had not developed a training matrix which identified all DP related training and",
          "certification that was required to be completed by each onboard position with a DP related role.",
          "The vessel had not prepared a record of training and certification to demonstrate that all DP related",
          "certification and training had been completed by each individual onboard with a DP related role.",
          "The required training certificates or DP Operator certificates were found to be missing, expired or outdated",
          "for any individual with a DP related role.",
          "There was no process to provide DP refresher training to the DP operators through a periodic shore-based",
          "course or an approved onboard process."
        ],
        "evidence": [
          "The company training matrix which identified the DP related certification and training requirements for each",
          "DP related role onboard.",
          "The vessel’s populated training matrix which showed the current status of all DP related certification and",
          "training for all onboard staff having a DP related role.",
          "The DP Operator certificates and DP logbooks for everyone identified as a qualified DP operator.",
          "The DP refresher training course certificates or scheme records where onboard refresher activities had"
        ],
        "risk": "medium",
        "status": "not_started"
      },
      {
        "id": "3.3.6",
        "number": "3.3.6",
        "chapter": "3",
        "section": "3.3",
        "text": "Had the Master, officers and ratings received the required training and familiarisation before being assigned duties related to handling LNG or other low- flashpoint fuel?",
        "short_text": "LNG or other low-flashpoint fuel training and familiarisation.",
        "vessel_types": [
          "Oil",
          "Chemical",
          "LPG"
        ],
        "objective": "To ensure that personnel on board ships using LNG or other low-flashpoint fuels are adequately qualified,\ntrained, and experienced.",
        "negative_grounds": [
          "There was no company procedure which defined the requirement for Basic and Advanced Training for",
          "service on ships subject to the IGF Code.",
          "A crew member with responsibilities associated with the fuel or fuel system on board had not received ship-",
          "specific familiarisation with the systems fitted before being assigned duties.",
          "On a vessel subject to the IGF Code:",
          "A crew member responsible for designated safety duties associated with the care, use or",
          "emergency response to the fuel on board had not received the required Basic Training.",
          "The Master, an engineer officer or any other person with immediate responsibility for the care and"
        ],
        "evidence": [
          "The company procedure which defined the requirement for Basic and Advanced Training for service on",
          "ships subject to the IGF Code, which may be in the form of a training matrix.",
          "Basic and Advanced Training Certificates of Proficiency for service in vessels subject to the IGF Code.",
          "On existing vessels, alternative certification as required by the flag state.",
          "Records of familiarisation for the LNG or low-flashpoint fuel system."
        ],
        "risk": "medium",
        "status": "not_started"
      },
      {
        "id": "3.4.1",
        "number": "3.4.1",
        "chapter": "3",
        "section": "3.4",
        "text": "Was there an effective system in place to record and monitor the hours of rest for all personnel onboard in compliance with STCW, MLC or the regulatory requirements applicable to the vessel?",
        "short_text": "Hours of rest, records and monitoring",
        "vessel_types": [
          "Oil",
          "Chemical",
          "LPG",
          "LNG"
        ],
        "objective": "To ensure that there is an effective system in place to manage crew rest hours and fatigue.",
        "negative_grounds": [
          "There was no company procedure that defined how hours of rest were to be managed and recorded.",
          "The accompanying officer was not familiar with the company procedure that defined how hours of rest were",
          "to be managed and recorded and/or the process for recording and monitoring hours of rest and any non-",
          "The hours of rest records were not in the ILO/MLC format which clearly identified the hours of rest",
          "conformance in any twenty-four hour or seven-day period.",
          "Physically or digitally signed hours of rest records were not available for all crew members onboard which",
          "had been approved by the Master or their authorised representative."
        ],
        "evidence": [
          "The company procedure that defined how hours of rest were to be managed and recorded.",
          "Completed hours of rest records for the preceding three months signed, physically or digitally as acceptable",
          "to the vessel’s Administration, by the individual crewmembers and approved by the Master or their",
          "authorised representative.",
          "The monthly hours of rest record summary reports for the previous three months showing each hours of rest",
          "non-conformance."
        ],
        "risk": "medium",
        "status": "not_started"
      },
      {
        "id": "3.4.2",
        "number": "3.4.2",
        "chapter": "3",
        "section": "3.4",
        "text": "Were the Master, officers and crew familiar with the company policy and procedures for drug and alcohol abuse prevention and had unannounced drug and alcohol testing taken place onboard in accordance with the policy?",
        "short_text": "Drug and alcohol abuse prevention",
        "vessel_types": [
          "Oil",
          "Chemical",
          "LPG",
          "LNG"
        ],
        "objective": "To ensure that no seafarer will navigate a ship or operate its onboard equipment whilst impaired by drugs or\nalcohol.",
        "negative_grounds": [
          "There was no company policy or supporting procedures for the prevention of abuse of drugs and alcohol.",
          "The company policy to prevent the abuse of drugs and alcohol was not prominently displayed at appropriate",
          "The accompanying officer was unfamiliar with the company policy or supporting procedures for the",
          "prevention of abuse of drugs and alcohol.",
          "The accompanying officer or responsible individual was unfamiliar with the use and testing of the alcohol",
          "breath testing device.",
          "The vessel did not have a breath testing device."
        ],
        "evidence": [
          "The company policy and supporting procedures to prevent the abuse of drugs and alcohol.",
          "Where alcohol was permitted onboard, the records of alcohol issue to onboard personnel and visitors.",
          "The alcohol breath testing device.",
          "The calibration or testing records for the alcohol breath testing device.",
          "Records, including results, of company initiated unannounced alcohol tests including initial instruction and",
          "vessel advice that tests were complete."
        ],
        "risk": "medium",
        "status": "not_started"
      },
      {
        "id": "3.5.1",
        "number": "3.5.1",
        "chapter": "3",
        "section": "3.5",
        "text": "Had the company developed an effective familiarisation programme that covered the personal safety and professional responsibilities of all onboard personnel, including visitors and contractors, and were records available to demonstrate that the familiarisation had been completed as required?",
        "short_text": "Familiarisation of crew, visitors and contractors",
        "vessel_types": [
          "Oil",
          "Chemical",
          "LPG",
          "LNG"
        ],
        "objective": "To ensure that all onboard personnel, including contractors and visitors, are fully familiarised with their\nonboard duties, responsibilities and the equipment and machinery fitted to the vessel relevant to their role.",
        "negative_grounds": [
          "There was no company procedure which defined the familiarisation process for onboard staff, contractors",
          "The accompanying officer was unfamiliar with the company familiarisation procedure and/or processes.",
          "Familiarisation records, in accordance with the company procedure, were not available for any one of the",
          "Evidence was available that contractors, as defined by company procedures, had worked onboard but there",
          "was no documented record of their familiarisation prior to commencing work.",
          "The necessary familiarisation had not been carried out within the required time frame or prior to the",
          "crewmember starting the first duty period utilising the equipment fitted to the vessel."
        ],
        "evidence": [
          "The company procedure which defined the onboard familiarisation process for each role onboard, including",
          "visitors and contractors.",
          "Records of completed familiarisation as follows: For all individuals Essential Initial safety training necessary prior to sailing on joining, or upon taking over new safety related",
          "assignments onboard."
        ],
        "risk": "medium",
        "status": "not_started"
      },
      {
        "id": "3.5.2",
        "number": "3.5.2",
        "chapter": "3",
        "section": "3.5",
        "text": "Were the Master, officers and ratings familiar with the ship’s lifesaving and fire extinguishing appliances and, had ongoing onboard training and instruction taken place to maintain familiarity?",
        "short_text": "Training and instruction LSA and FFA",
        "vessel_types": [
          "Oil",
          "Chemical",
          "LPG",
          "LNG"
        ],
        "objective": "To ensure that all crew can use the ship’s life- saving (LSA) and fire extinguishing (FFA) appliances in\naccordance with the equipment manufacturer’s instructions to respond effectively to an emergency.",
        "negative_grounds": [
          "There was no company procedure which defined the requirement for delivering and recording ongoing",
          "training and instruction for each piece of LSA & FFA provided onboard.",
          "The fire training manual, fire safety operational booklet or lifesaving manuals were not written in the working",
          "language of the ship.",
          "The fire training manual, fire safety operational booklet or lifesaving manual were not provided in each crew",
          "mess room and recreation room, or in each crew cabin.",
          "The fire training manual, fire safety operational booklet or lifesaving manuals were not updated to reflect the",
          "LSA & FFA provided onboard."
        ],
        "evidence": [
          "A fire training manual, fire safety operational booklet and lifesaving training manual.",
          "The company procedures defining the requirement for delivering ongoing training and instruction for the LSA",
          "and FFA provided onboard.",
          "The instructions for delivering onboard training for the davit-launched liferaft and the use of a training liferaft,",
          "where provided.",
          "The records of LSA and FFA training and instruction provided to the crew within two weeks of joining the"
        ],
        "risk": "high",
        "status": "not_started"
      },
      {
        "id": "3.5.3",
        "number": "3.5.3",
        "chapter": "3",
        "section": "3.5",
        "text": "Had the Master and navigation officers been familiarised with the ECDIS equipment installed on board and were documented records of this familiarisation available?",
        "short_text": "Familiarisation with ECDIS equipment installed on board.",
        "vessel_types": [
          "Oil",
          "Chemical",
          "LPG",
          "LNG"
        ],
        "objective": "To ensure the Master and navigation officers are fully familiar with the specific type of ECDIS equipment\ninstalled on board prior to taking charge of a navigational watch.",
        "negative_grounds": [
          "There were no company procedures that ensured all watchkeeping officers are competent in the use of the",
          "nboard ECDIS prior to taking charge of a navigational watch, that included the:",
          "Time scale for the familiarisation.",
          "Method of familiarisation with the ECDIS equipment.",
          "Location of the familiarisation, on board or ashore.",
          "Identity of the appropriately trained crew or training personnel authorised to deliver the",
          "Means of demonstrating competency upon completion of the familiarisation and before taking"
        ],
        "evidence": [
          "Company procedures that ensured all watchkeeping officers are competent in the use of the onboard ECDIS",
          "prior to taking charge of a navigational watch.",
          "ECDIS installation specific training certificates, where required by the company familiarisation process",
          "Onboard ECDIS installation specific familiarisation checklists for the Master and deck officers."
        ],
        "risk": "medium",
        "status": "not_started"
      },
      {
        "id": "3.7.2",
        "number": "3.7.2",
        "chapter": "3",
        "section": "3.7",
        "text": "",
        "short_text": "",
        "vessel_types": [],
        "objective": "",
        "negative_grounds": [
          "There was no company procedure for the use of the emergency bilge pumping arrangements in the",
          "There was no shipboard emergency response plan for machinery space flooding.",
          "The company procedures did not include guidance on:",
          "The use of the various pumps connected to the bilge system, their direct suctions and overboard",
          "The use of the emergency bilge suction.",
          "MARPOL requirements concerning the discharge into the sea of oil or oily mixtures necessary for",
          "the purpose of securing the safety of the ship or saving life at sea or resulting from damage to a"
        ],
        "evidence": [
          "The company procedure for the use of the emergency bilge pumping arrangements in the machinery",
          "The shipboard emergency response plan for machinery space flooding.",
          "The Oil Record Book Part I.",
          "The Engine Room Log Book."
        ],
        "risk": "medium",
        "status": "not_started"
      },
      {
        "id": "3.14.10",
        "number": "3.14.10",
        "chapter": "3",
        "section": "3.14",
        "text": "",
        "short_text": "",
        "vessel_types": [],
        "objective": "",
        "negative_grounds": [
          "There were no company procedures for the operation, inspection, testing and maintenance of the vessel’s",
          "inert gas system which included the indicators and alarms.",
          "The accompanying officer was not familiar with the purpose, operation, inspection, testing and maintenance",
          "f the inert gas system indicators and alarms including the:",
          "Method and frequency of testing and calibration of the indicators and alarms.",
          "Actions to be taken in the event of a failure of any of the indicators and alarms.",
          "The record of inspection and maintenance of the inert gas plant, including defects and their rectification, was",
          "missing or incomplete."
        ],
        "evidence": [
          "The company procedures for the operation, inspection, maintenance and testing of the inert gas system.",
          "The records of inspection, testing and maintenance of the inert gas system.",
          "The manufacturer’s instruction manuals for the operation, calibration and testing of all inert gas system",
          "instruments and alarms.",
          "The test and calibration records for the inert gas system instruments and alarms."
        ],
        "risk": "medium",
        "status": "not_started"
      },
      {
        "id": "3.7.1",
        "number": "3.7.1",
        "chapter": "3",
        "section": "3.7",
        "text": "",
        "short_text": "",
        "vessel_types": [],
        "objective": "",
        "negative_grounds": [],
        "evidence": [],
        "risk": "low",
        "status": "not_started"
      },
      {
        "id": "3.7.2",
        "number": "3.7.2",
        "chapter": "3",
        "section": "3.7",
        "text": "",
        "short_text": "",
        "vessel_types": [],
        "objective": "",
        "negative_grounds": [
          "There were no ship-specific company procedures for detecting water leakage into a hold or insulation space",
          "and for dealing with any water or liquid cargo that may have accumulated in these spaces that included",
          "Means of detecting any water leakage into hold or insulation spaces.",
          "Pumping arrangements for removing any water leakage into these spaces.",
          "Where required, arrangements for removing any liquid cargo leakage into these spaces.",
          "Testing requirements for the water detection and pumping arrangements.",
          "The accompanying officer was not familiar with the ship-specific company procedures for detecting water"
        ],
        "evidence": [
          "Company procedures for detecting water leakage into a hold or insulation space and for dealing with any",
          "water or liquid cargo that may have accumulated in these spaces.",
          "Records of tests of the water detection and pumping arrangements.",
          "Where required, the inventory of portable equipment required for the pumping arrangements."
        ],
        "risk": "medium",
        "status": "not_started"
      }
    ]
  },
  {
    "id": "C4",
    "title": "Navigation",
    "roles": [
      "Master",
      "Officers"
    ],
    "questions": [
      {
        "id": "4.1.1",
        "number": "4.1.1",
        "chapter": "4",
        "section": "4.1",
        "text": "Were the Master and navigation officers familiar with the company procedures for the set up and operation of the ECDIS units fitted to the vessel and were records Page 132 of 711 – SIRE 2.0 Question Library: Part 1 Version 1.0 (January 2022) available to demonstrate that the ECDIS had been operated in accordance with company procedures at all stages of a voyage?",
        "short_text": "ECDIS set up and operation",
        "vessel_types": [
          "Oil",
          "Chemical",
          "LPG",
          "LNG"
        ],
        "objective": "To ensure that ECDIS units fitted to the vessel were used to effectively navigate the vessel.",
        "negative_grounds": [
          "There were no company procedures for operating and managing the ECDIS fitted.",
          "The company procedures did not provide clear guidance regarding:",
          "Display management Alarms & warnings.",
          "Safety contours and depths.",
          "Safety frame or safety cone.",
          "The accompanying navigation officer was unfamiliar with the company ECDIS management and operation",
          "The accompanying navigation officer was unfamiliar with the operation of the ECDIS units fitted to the vessel"
        ],
        "evidence": [
          "The company procedures that defined how ECDIS units should be operated and managed.",
          "ECDIS checklists and quick reference guides.",
          "Records to demonstrate that software updates had been completed in accordance with manufacturer’s",
          "instructions.",
          "Records to demonstrate periodic tests required by the manufacturer’s instructions had been completed.",
          "Records to demonstrate that the ECDIS settings had been checked periodically during each voyage."
        ],
        "risk": "medium",
        "status": "not_started"
      },
      {
        "id": "4.1.2",
        "number": "4.1.2",
        "chapter": "4",
        "section": "4.1",
        "text": "Were the Master and navigation officers familiar with the company procedures for managing and operating the radar/ARPA units fitted to the vessel, and were records available to demonstrate that the units had been operated and tested in accordance with company procedures?",
        "short_text": "Operation and testing of radar/ARPA",
        "vessel_types": [
          "Oil",
          "Chemical",
          "LPG",
          "LNG"
        ],
        "objective": "To ensure that the radar/ARPA units fitted to the vessel are used effectively for navigation and collision\navoidance.",
        "negative_grounds": [
          "There were no company procedures for managing and operating the radar/ARPA units fitted to the vessel.",
          "The accompanying navigation officer was unfamiliar with the company procedure for managing and",
          "perating the radar/ARPA units fitted to the vessel.",
          "The accompanying navigation officer was unfamiliar with the hazards of using AIS data (vectors) for collision",
          "The accompanying navigation officer was unfamiliar with the difference between the performance",
          "characteristics of X-band (9 GHz) and S-band (3 GHz) radars.",
          "The radar/ARPA units had not been in operation in accordance with company procedures.",
          "The radar/ARPA units had not been tested in accordance with company procedures."
        ],
        "evidence": [
          "The company procedures for managing and operating the radar/ARPA units fitted to the vessel.",
          "Any checklists or quick reference charts for the operation of the radar/ARPA units fitted to the vessel.",
          "Onboard records demonstrating that the radar/ARPA units had been in operation and tested in accordance",
          "with company procedures.",
          "Information relating to any blind sectors affecting the fitted radars.",
          "Onboard records relating to the routine changing of the magnetrons for each radar fitted."
        ],
        "risk": "high",
        "status": "not_started"
      },
      {
        "id": "4.1.3",
        "number": "4.1.3",
        "chapter": "4",
        "section": "4.1",
        "text": "Were the Master and navigation officers familiar with the company procedures for operating and testing the steering control systems fitted to the vessel and were records available to demonstrate that operation and testing had been carried out in accordance with the procedures?",
        "short_text": "Operating and testing the steering control systems",
        "vessel_types": [
          "Oil",
          "Chemical",
          "LPG",
          "LNG"
        ],
        "objective": "To ensure the steering control systems fitted to the vessel are tested and used in an appropriate manner with\nchangeover procedures understood.",
        "negative_grounds": [
          "There was no company procedure for managing, testing and operating steering control systems fitted to the",
          "The accompanying navigation officer was unfamiliar with the company procedure for managing, testing and",
          "perating the steering control systems fitted to the vessel."
        ],
        "evidence": [
          "The company procedures for managing, testing and operating the steering control systems provided.",
          "The vessel specific procedures for changing between steering control modes and systems.",
          "The vessel specific procedure for changing over to emergency steering control.",
          "The block diagram showing the change-over procedures for remote steering gear control systems and",
          "steering gear power units.",
          "Records for a recent voyage to demonstrate that steering control system tests had been completed in"
        ],
        "risk": "medium",
        "status": "not_started"
      },
      {
        "id": "4.1.4",
        "number": "4.1.4",
        "chapter": "4",
        "section": "4.1",
        "text": "Were the Master and navigation officers familiar with the company procedures for using the Automatic Identification System (AIS) fitted to the vessel and were records available to confirm that periodic checks and tests had been carried out in accordance with the procedures?",
        "short_text": "Automatic Identification System (AIS)",
        "vessel_types": [
          "Oil",
          "Chemical",
          "LPG",
          "LNG"
        ],
        "objective": "To ensure that the Automatic Identification System (AIS) fitted to the vessel was used to safely enhance\nsituational awareness during navigation.",
        "negative_grounds": [
          "There were no procedures for the operation and testing of the AIS system fitted onboard.",
          "There was no company guidance related to the use of AIS information in collision avoidance situations."
        ],
        "evidence": [
          "The company procedure for the operation and testing of the AIS equipment fitted onboard.",
          "Records of the checks and performance tests required to be carried out on the AIS equipment fitted.",
          "Company guidance related to the use of AIS information in collision avoidance situations."
        ],
        "risk": "high",
        "status": "not_started"
      },
      {
        "id": "4.1.5",
        "number": "4.1.5",
        "chapter": "4",
        "section": "4.1",
        "text": "Were the Master and navigation officers familiar with the company procedure for the use of the Bridge Navigational Watch Alarm System (BNWAS) and were records available to demonstrate that it had been operated and tested in accordance with the procedure?",
        "short_text": "Bridge Navigational Watch Alarm System (BNWAS)",
        "vessel_types": [
          "Oil",
          "Chemical",
          "LPG",
          "LNG"
        ],
        "objective": "To ensure that the bridge was continually manned throughout a voyage, and at anchor, by vigilant\nwatchkeeping staff.",
        "negative_grounds": [
          "There was no company procedure for operating and testing the Bridge Navigation Watch Alarm System",
          "(BNWAS) fitted to the vessel.",
          "The accompanying navigation officer was unfamiliar with the company procedure for the operation and",
          "testing of the BNWAS.",
          "The BNWAS was defective in any respect.",
          "The password or activation key was available to others beyond the Master and their authorised deputy.",
          "There were no records available to confirm that the BNWAS had been in operation in accordance with"
        ],
        "evidence": [
          "The company procedures for the use and testing of the BNWAS.",
          "Bridge Log Book.",
          "Bridge checklists."
        ],
        "risk": "medium",
        "status": "not_started"
      },
      {
        "id": "4.1.6",
        "number": "4.1.6",
        "chapter": "4",
        "section": "4.1",
        "text": "Were the Master and navigation officers familiar with the company procedures governing the management and operation of the Global Navigation Satellite System (GNSS) receivers fitted onboard and was the fitted equipment configured, used and checked in accordance with the procedure?",
        "short_text": "Global Navigation Satellite System(s)",
        "vessel_types": [
          "Oil",
          "Chemical",
          "LPG",
          "LNG"
        ],
        "objective": "To ensure that Global Navigation Satellite System (GNSS) receivers provide reliable and accurate positional\ninformation.",
        "negative_grounds": [
          "There were no company procedures for operating and managing the GNSS receivers fitted.",
          "The accompanying navigation officer was unfamiliar with the GNSS receiver management and operation",
          "procedures, or the equipment fitted to the vessel.",
          "The GNSS receiver(s) were not configured in accordance with company requirements, or the antennae",
          "coordinates were incorrectly entered.",
          "Periodic checks and tests had not been carried out in accordance with procedures.",
          "A GNSS receiver was defective in any respect.",
          "The positional data provided to another piece of navigation or communication equipment such as AIS, ARPA"
        ],
        "evidence": [
          "The company procedure that defined how GNSS units should be operated and managed",
          "Onboard records to demonstrate that the required checks and tests had been completed",
          "The measurements to allow the checking / reprogramming of the antenna offset position in the GNSS",
          "receiver configuration."
        ],
        "risk": "medium",
        "status": "not_started"
      },
      {
        "id": "4.1.7",
        "number": "4.1.7",
        "chapter": "4",
        "section": "4.1",
        "text": "Were the Master and navigation officers familiar with the company procedures for operating and managing the echo sounder and were records maintained to demonstrate that the equipment fitted to the vessel had been tested and operated in accordance with the company expectations?",
        "short_text": "Echo sounder",
        "vessel_types": [
          "Oil",
          "Chemical",
          "LPG",
          "LNG"
        ],
        "objective": "To ensure that the echo sounder is used effectively to monitor the under-keel clearance.",
        "negative_grounds": [
          "There were no procedures for managing and operating the echo sounder and its associated recording",
          "The accompanying navigation officer was unfamiliar with the company procedures for managing and",
          "perating the echo sounder and its associated recording device.",
          "The accompanying navigation officer was unfamiliar with the process to calculate the depth under the keel",
          "and verify the accuracy of the echo sounder.",
          "The echo sounder had not been operated or tested in accordance with the company procedures and",
          "manufacturer’s instructions.",
          "The echo sounder was not showing the expected depth indication under the keel at the time of the"
        ],
        "evidence": [
          "The company procedures for managing and operating the echo sounder and its associated recording",
          "Onboard records demonstrating that the echo sounder and its recording device were in operation as",
          "required by the company procedures.",
          "Onboard records demonstrating that the accuracy of the echo sounder had been verified."
        ],
        "risk": "medium",
        "status": "not_started"
      },
      {
        "id": "4.1.8",
        "number": "4.1.8",
        "chapter": "4",
        "section": "4.1",
        "text": "Were the Master and navigation officers familiar with the company procedures for the operation and testing of the speed and distance measuring devices fitted to the vessel and were records available to demonstrate that periodic tests had been completed as required by the procedures?",
        "short_text": "Speed and distance measuring devices",
        "vessel_types": [
          "Oil",
          "Chemical",
          "LPG",
          "LNG"
        ],
        "objective": "To ensure that accurate speed data is available to navigational equipment.",
        "negative_grounds": [
          "There was no company procedure for the operation and testing of the speed and distance measuring",
          "devices fitted to the vessel.",
          "The accompanying navigation officer was not familiar with the company procedures for the operation and",
          "testing of the speed and distance measuring devices fitted to the vessel.",
          "Periodic tests to verify the accuracy and/functionality of the speed and distance measuring devices fitted to",
          "the vessel required by the company procedures had not been completed as required.",
          "Periodic checks to verify the accuracy of the speed input to navigational equipment had not been completed",
          "in accordance with company procedures."
        ],
        "evidence": [
          "The company procedures for the operation and testing of the speed and distance measuring devices fitted to",
          "the vessel.",
          "Records of the periodic accuracy and function tests for the speed and distance measuring devices fitted to",
          "the vessel.",
          "Records of periodic verification that the speed input to navigational equipment such as ARPA, AIS and",
          "ECDIS was accurate."
        ],
        "risk": "medium",
        "status": "not_started"
      },
      {
        "id": "4.1.9",
        "number": "4.1.9",
        "chapter": "4",
        "section": "4.1",
        "text": "Were the Master and navigation officers familiar with the company procedures for the use and testing of the navigation lights and shapes, and was there evidence that the navigation lights had been tested to confirm full functionality and correct visibility?",
        "short_text": "Navigation lights and shapes",
        "vessel_types": [
          "Oil",
          "Chemical",
          "LPG",
          "LNG"
        ],
        "objective": "To ensure that the vessel always displays navigation lights & shapes in accordance with the International\nRegulations for Preventing Collisions at Sea.",
        "negative_grounds": [
          "There was no company procedure defining the checks and tests required to be carried out on the",
          "navigational lights, the navigational light controller and navigational shapes.",
          "The accompanying navigation officer was unfamiliar with the company procedure for conducting checks and",
          "tests on the navigation lights, the navigation light controller or navigational shapes.",
          "The navigation lights and navigation light controller had not been tested in accordance with the company",
          "The navigation lights or navigation light controller were defective in any respect. (a single bulb failure on a",
          "single light would not generate an observation).",
          "Navigation lights or their screens were damaged, relocated or obscured in such a way that the required"
        ],
        "evidence": [
          "The company procedures which defined the checks and tests required to be carried out on the navigation",
          "lights, navigation light controller and navigational shapes.",
          "Checklists to confirm that the checks and tests required to be conducted on the navigation lights (fixed and",
          "portable), navigation light controller and navigational shapes had been completed as required.",
          "The inventory of spare navigational lamps identifying the luminosity or wattage and the navigation lights to",
          "which they may be fitted."
        ],
        "risk": "medium",
        "status": "not_started"
      },
      {
        "id": "4.1.10",
        "number": "4.1.10",
        "chapter": "4",
        "section": "4.1",
        "text": "Were the Master and navigation officers familiar with the company procedure for managing Marine Safety Information broadcasts by NAVTEX and SafetyNET and were warnings affecting the vessel’s route plotted on the voyage charts?",
        "short_text": "NAVTEX and SafetyNET",
        "vessel_types": [
          "Oil",
          "Chemical",
          "LPG",
          "LNG"
        ],
        "objective": "To ensure that broadcast navigation warnings affecting a vessel’s planned route are effectively managed.",
        "negative_grounds": [
          "There was no company procedure for managing Marine Safety Information received through NAVTEX and",
          "The accompanying navigation officer was unfamiliar with the company procedure for managing Marine",
          "Safety Information received through NAVTEX and SafetyNET, or the equipment fitted to the vessel.",
          "The NAVTEX and/or SafetyNET EGC receiver was defective in any respect.",
          "The NAVTEX receiver was not programmed to receive Marine Safety Information broadcasts from coast",
          "radio stations appropriate to the vessel’s route.",
          "The SafetyNET EGC receiver was not programmed to receive Marine Safety Information broadcasts for",
          "NAVAREAs and Coastal Warning Areas appropriate to the vessel’s route."
        ],
        "evidence": [
          "The company procedure for managing Marine Safety Information received through NAVTEX and",
          "NAVTEX and SafetyNET broadcast warnings filed in accordance with company procedures.",
          "Paper and electronic charts showing charted Marine Safety Information warnings."
        ],
        "risk": "medium",
        "status": "not_started"
      },
      {
        "id": "4.1.11",
        "number": "4.1.11",
        "chapter": "4",
        "section": "4.1",
        "text": "Were the Master and navigation officers familiar with the company procedure for preserving data from the VDR/S-VDR and were records available to demonstrate that tests of the equipment had been completed as required?",
        "short_text": "Preserving data from the VDR/S-VDR",
        "vessel_types": [
          "Oil",
          "Chemical",
          "LPG",
          "LNG"
        ],
        "objective": "To ensure that the VDR fitted to the vessel is continually recording all required data streams and procedures\nare in place to preserve records in the event of an incident.",
        "negative_grounds": [
          "There were no company procedure which governed the setup, use and testing of the VDR / S-VDR system",
          "fitted onboard the vessel.",
          "There was no company procedure which clearly defined the company expectation for data preservation in",
          "the event of an incident onboard.",
          "The accompanying navigation officer was unfamiliar with the company procedures for VDR / S-VDR",
          "management and data preservation.",
          "The VDR / S-VDR was defective in any respect.",
          "Annual performance checks by an authorised service agent or facility had not been carried out."
        ],
        "evidence": [
          "The company procedure which governed the setup, use and testing of the VDR / S-VDR system fitted",
          "onboard the vessel.",
          "The company procedure that defined when data was required to be preserved to support investigations into",
          "navigation and any other incidents onboard.",
          "At least one emergency response checklist from the vessel operator’s response plan indicating that VDR /",
          "S-VDR data preservation was required."
        ],
        "risk": "medium",
        "status": "not_started"
      },
      {
        "id": "4.1.12",
        "number": "4.1.12",
        "chapter": "4",
        "section": "4.1",
        "text": "Were the Master and navigation officers familiar with the company procedures relating to the magnetic and gyro compasses carried onboard, and were records available to demonstrate their accuracy and reliability?",
        "short_text": "Magnetic and gyro compasses",
        "vessel_types": [
          "Oil",
          "Chemical",
          "LPG",
          "LNG"
        ],
        "objective": "To ensure that standard, gyro and GNSS compasses and their heading output to navigational equipment are\naccurate and reliable",
        "negative_grounds": [
          "There were no company procedures for managing the standard magnetic, gyro and GNSS compasses as",
          "The accompanying navigation officer was unfamiliar with the company procedures, or the equipment fitted to",
          "A record of compass error for each compass fitted to the vessel was not maintained as required by the",
          "The compass error log book recorded a deviation of the standard magnetic compass consistently exceeding",
          "the tolerance permitted by the company procedure as compared to the deviation certificate from the",
          "previous official compass adjustment.",
          "The heading shown by a compass, or a repeater, was erroneous."
        ],
        "evidence": [
          "The company procedures for standard, gyro and GNSS compass management The standard compass adjustment and residual deviation certificate.",
          "Compass error records.",
          "Service records for the gyro compass(s)."
        ],
        "risk": "medium",
        "status": "not_started"
      },
      {
        "id": "4.1.13",
        "number": "4.1.13",
        "chapter": "4",
        "section": "4.1",
        "text": "Were the Master and navigation officers familiar with the company procedures for the operation and testing of the VHF/DSC transceivers fitted to the vessel, and were records available to demonstrate that periodic tests and checks had been completed in accordance with company expectations?",
        "short_text": "VHF/DSC transceivers",
        "vessel_types": [
          "Oil",
          "Chemical",
          "LPG",
          "LNG"
        ],
        "objective": "To ensure that VHF radio is used to enhance navigation safety and support the obligations of the vessel\nunder SOLAS to render assistance to non-SOLAS vessels in distress.",
        "negative_grounds": [
          "There was no company procedure which defined the expectations for the use and periodic testing of the",
          "VHF/DSC units fitted to the vessel.",
          "The accompanying navigation officer was unfamiliar with the company procedure for the use or testing of the",
          "VHF/DSC units fitted to the vessel.",
          "The accompanying navigation officer was unfamiliar with the operation of the VHF/DSC units fitted to the",
          "The accompanying navigation officer was unfamiliar with the hazards and limitations of using VHF radio",
          "during collision avoidance situations.",
          "Records indicated that periodic checks and tests required to be carried out for the VHF/DSC units had not"
        ],
        "evidence": [
          "The company procedures for the use and operation of the VHF/DSC equipment fitted to the vessel.",
          "The GMDSS Radio Log Book or other records which documented which VHF channels were being",
          "monitored and details of significant communications.",
          "The Master’s standing orders.",
          "Checklists that demonstrated that periodic checks and tests required to be carried out on the",
          "communications equipment, including VHF/DSC units had been completed as required by the company"
        ],
        "risk": "high",
        "status": "not_started"
      },
      {
        "id": "4.1.14",
        "number": "4.1.14",
        "chapter": "4",
        "section": "4.1",
        "text": "Were the Master and navigation officers familiar with the company procedure for testing and using the daylight signalling lamp?",
        "short_text": "Daylight signalling lamp",
        "vessel_types": [
          "Oil",
          "Chemical",
          "LPG",
          "LNG"
        ],
        "objective": "To ensure that there is a means of attracting the attention of other vessels by visual means both during\ndaylight and during darkness.",
        "negative_grounds": [
          "There was no procedure which defined the company expectations for the use and testing of the daylight",
          "The accompanying navigation officer was unfamiliar with the company procedure for the use and testing of",
          "the daylight signalling lamp.",
          "The daylight signalling lamp was defective in any respect.",
          "There were less than three spare bulbs on board and/or the spare bulbs did not meet the manufacturer’s"
        ],
        "evidence": [
          "The procedure which defined the company expectations for the use and testing of the daylight signalling",
          "The bridge equipment testing records demonstrating that periodic tests had been carried out for the daylight",
          "signalling lamp."
        ],
        "risk": "medium",
        "status": "not_started"
      },
      {
        "id": "4.1.15",
        "number": "4.1.15",
        "chapter": "4",
        "section": "4.1",
        "text": "Were the Master and navigation officers familiar with the company procedures for the use and testing of the sound signalling equipment fitted to the vessel and were records available to confirm that periodic tests had been completed and the equipment used in accordance with company expectations?",
        "short_text": "Sound signalling equipment",
        "vessel_types": [
          "Oil",
          "Chemical",
          "LPG",
          "LNG"
        ],
        "objective": "To ensure that the vessel was able to make sound signals to comply with the International Regulations for\nPreventing Collisions at Sea (COLREG).",
        "negative_grounds": [
          "There was no company procedure which defined the company expectation for the use of sound signals",
          "during restricted visibility, collision avoidance and manoeuvring in compliance with the COLREGs.",
          "The accompanying navigation officer was unfamiliar with the company expectation for the use of sound",
          "signals during restricted visibility, collision avoidance and manoeuvring in compliance with the COLREGs.",
          "There were no records available to demonstrate that the sound signalling equipment and any automation",
          "provided had been periodically tested to verify its effectiveness and compliance with the COLREGs.",
          "The sound signalling equipment, or its automation, was defective in any way.",
          "There was no documented evidence that the sound signalling equipment had been used in accordance with"
        ],
        "evidence": [
          "The company procedures which defined the expectations for the use and testing of sound signalling",
          "equipment fitted to the vessel.",
          "Bridge Log Book.",
          "Completed bridge checklists including restricted visibility and bridge equipment testing.",
          "The accompanying officer should be ready to show the inspector the evidence for the previous three occasions where",
          "the sound signalling equipment was used during restricted visibility."
        ],
        "risk": "high",
        "status": "not_started"
      },
      {
        "id": "4.2.1",
        "number": "4.2.1",
        "chapter": "4",
        "section": "4.2",
        "text": "Were the Master and navigating officers familiar with the company passage planning procedures and had all voyages been appraised, planned, executed and monitored in accordance with company procedures, industry best practice and both local and international rules?",
        "short_text": "Passage planning",
        "vessel_types": [
          "Oil",
          "Chemical",
          "LPG",
          "LNG"
        ],
        "objective": "To ensure that passages are planned and executed from berth to berth in accordance with international/local\nrules and industry best practice guidance.",
        "negative_grounds": [
          "There were no company passage planning procedures.",
          "There were no company record keeping procedures relating to navigational activities.",
          "The accompanying navigation officer was not familiar with the company passage planning or navigational",
          "record keeping procedures.",
          "There was no standard passage planning form which required the passage plan to be documented in a",
          "consistent manner, capturing all data identified within the procedures.",
          "There was no passage plan appraisal form / checklist to verify that all information pertinent to the passage"
        ],
        "evidence": [
          "The company passage planning procedures.",
          "The company record keeping procedures relating to navigational activities.",
          "The company passage plan appraisal form / checklist for a recently completed voyage.",
          "The passage plan for a recently completed voyage approved by the Master and signed by the navigation",
          "The ECDIS passage planning station and/or paper charts showing the reviewed passage plan and"
        ],
        "risk": "high",
        "status": "not_started"
      },
      {
        "id": "4.2.2",
        "number": "4.2.2",
        "chapter": "4",
        "section": "4.2",
        "text": "Were the Master and navigation officers familiar with the company under keel clearance (UKC) policy and procedure, and were records available to demonstrate that the required calculations had been completed at the appropriate points during each voyage and the vessel had remained in compliance with the UKC policy?",
        "short_text": "Under keel clearance (UKC) policy",
        "vessel_types": [
          "Oil",
          "Chemical",
          "LPG",
          "LNG"
        ],
        "objective": "To ensure that the vessel always maintains a safe under keel clearance.\nIndustry guidance\nIMO: Resolution A.893(21). Guidelines for Voyage Planning.\n3 Planning\n3.1 On the basis of the fullest possible appraisal, a detailed voyage or passage plan should be prepared which should\ncover the entire voyage or passage from berth to berth, including those areas where the services of a pilot will be\nused.\n3.2 The detailed voyage or passage plan should include the following factors:\n3.2.2.2 necessary spee",
        "negative_grounds": [
          "There was no procedure defining the company under keel clearance (UKC) policy and expectations for",
          "conducting UKC calculations at defined stages of the voyage.",
          "The accompanying officer was not familiar with the company procedure for conducting and documenting",
          "Review of records indicated that the UKC calculations required to be carried out by the company procedures",
          "had not been completed.",
          "Review of records indicated that the UKC policy had been violated without explicit permission from the"
        ],
        "evidence": [
          "The company procedure that defined the company under keel clearance (UKC) policy and the requirement",
          "for conducting calculations and recording the results.",
          "The passage planning documentation for recent voyages.",
          "The UKC calculation documentation to support recent voyages.",
          "Master/Pilot information exchange documentation which included the supporting UKC calculations.",
          "Bridge Log Books, bell books, echo sounder records and charted passage history to permit verification of"
        ],
        "risk": "medium",
        "status": "not_started"
      },
      {
        "id": "4.2.3",
        "number": "4.2.3",
        "chapter": "4",
        "section": "4.2",
        "text": "Had the Master prepared Master's Standing Orders, supplemented by Daily Orders, which emphasised and reinforced the company expectations with regards to navigational requirements including restricted visibility, CPA/BCR and minimum passing distance from navigational dangers and navigational aids and, if so, had all navigation officers signed to acknowledge their understanding of the same?",
        "short_text": "Master's Standing Orders and Daily Orders",
        "vessel_types": [
          "Oil",
          "Chemical",
          "LPG",
          "LNG"
        ],
        "objective": "To ensure that all deck/navigating officers are aware of the key expectations of both the company and the\nMaster with respect to the navigation of the vessel.",
        "negative_grounds": [
          "There was no procedure which required the Master to prepare Standing or Daily Orders.",
          "The accompanying officer was unfamiliar with the content of the Master’s Standing or Daily Orders.",
          "The Master had not prepared their own Standing Orders which were signed and dated on being assigned to",
          "the vessel or at subsequent update.",
          "The navigation officers onboard at the time of the inspection had not signed the Master's Standing Orders",
          "(unless they had only joined that day).",
          "The content of the Master’s Standing Orders degraded the company expectations documented anywhere",
          "within the Safety Management System."
        ],
        "evidence": [
          "The company procedure defining the requirement for the Master to develop their own Standing and Daily",
          "The Master’s Standing Orders signed by the Master and all navigation officers.",
          "The Bridge Order Book with each dated and timed entry signed by the Master, and subsequently, each",
          "OOW before taking over their watch."
        ],
        "risk": "high",
        "status": "not_started"
      },
      {
        "id": "4.2.4",
        "number": "4.2.4",
        "chapter": "4",
        "section": "4.2",
        "text": "Were the Master and navigation officers familiar with the company electronic chart management procedures and were onboard ENCs and RNCs managed, corrected and used appropriately?",
        "short_text": "Electronic chart management.",
        "vessel_types": [
          "Oil",
          "Chemical",
          "LPG",
          "LNG"
        ],
        "objective": "To ensure that only fully corrected official electronic charts are used for navigation where ECDIS is required\nto be carried",
        "negative_grounds": [
          "There were no company procedures for managing ENCs and RNCs The declaration relating to the primary means of navigation was incorrect",
          "The accompanying navigation officer was unfamiliar with the electronic chart management and correction",
          "The accompanying navigation officer was unfamiliar with the process for applying T&P notices to ENCs and",
          "There was no onboard management system to track the permits held by the vessel for ENCs and RNCs.",
          "Individual ENC or RNC permits had expired prior to or during the predicted phase of a voyage.",
          "The vessel had completed a voyage with missing ENC or RNC coverage.",
          "The vessel had not updated the ENCs and RNCs to the latest available notice to mariners (subject to a"
        ],
        "evidence": [
          "The company procedure that defined how ENCs and RNCs were to be managed The onboard records identifying which ENCs and RNCs were active with current permits or were available",
          "on a Pay As You Sail (PAYS) basis.",
          "ENC Status Report, where available.",
          "The previous voyage passage plan records showing which ENCs and RNCs had been used.",
          "Where ENC coverage was incomplete for a recent voyage, passage planning records demonstrating how"
        ],
        "risk": "medium",
        "status": "not_started"
      },
      {
        "id": "4.2.5",
        "number": "4.2.5",
        "chapter": "4",
        "section": "4.2",
        "text": "Were the Master and navigation officers familiar with the company paper chart management procedures and were onboard paper charts managed, corrected and used appropriately?",
        "short_text": "Paper chart management",
        "vessel_types": [
          "Oil",
          "Chemical",
          "LPG",
          "LNG"
        ],
        "objective": "To ensure that the only fully corrected official paper charts are used for navigation when required to be\ncarried or used.",
        "negative_grounds": [
          "There was no company procedure for managing paper charts.",
          "The accompanying navigation officer was unfamiliar with the paper chart management and correction",
          "The vessel had completed a voyage with missing or inappropriate scale charts without any evidence that the",
          "company had been involved in identifying mitigating actions.",
          "There was no systematic process to apply and remove T&P notices and NAVTEX and NAVAREA warnings.",
          "The vessel had not updated voyage paper charts to the latest available Notice to Mariners (subject to a",
          "reasonable allowance for vessel activities and workload) or had used outdated editions.",
          "Paper charts in use were torn, stained or worn such that detail was likely to be obscured from the user."
        ],
        "evidence": [
          "The company procedures for paper chart management.",
          "The paper chart portfolio records.",
          "The paper chart correction records.",
          "Recent passage plan records showing which paper charts had been used.",
          "The paper charts, where applicable, used on the previous passage Communications and mitigation plan agreed with the company where a vessel had been directed to a port"
        ],
        "risk": "medium",
        "status": "not_started"
      },
      {
        "id": "4.2.6",
        "number": "4.2.6",
        "chapter": "4",
        "section": "4.2",
        "text": "Were the Master and navigation officers familiar with the company procedures for testing the navigational equipment, main propulsion, steering gear and thrusters prior to use and prior to critical phases of a passage or operation and, did checklists or logbook entries confirm the required tests had been completed as required?",
        "short_text": "Testing navigational equipment, main propulsion, steering gear and thrusters",
        "vessel_types": [
          "Oil",
          "Chemical",
          "LPG",
          "LNG"
        ],
        "objective": "To ensure that navigational equipment and manoeuvring machinery is confirmed as fully operational prior to\ncritical phases of a passage or operation.",
        "negative_grounds": [
          "There was no procedure that required navigational equipment and manoeuvring equipment to be",
          "functionally tested at defined points prior to and during a voyage or operation.",
          "The accompanying navigation officer was not familiar with the company procedures for testing navigational",
          "equipment and manoeuvring equipment."
        ],
        "evidence": [
          "The company procedures which defined the requirements for testing navigational equipment and",
          "manoeuvring machinery.",
          "Completed checklists for the testing of navigational equipment and manoeuvring machinery for recent",
          "Bridge Log Book.",
          "Engine Log Book."
        ],
        "risk": "medium",
        "status": "not_started"
      },
      {
        "id": "4.2.7",
        "number": "4.2.7",
        "chapter": "4",
        "section": "4.2",
        "text": "Were the Master and navigation officers familiar with the company procedure for the carriage and management of nautical publications and was evidence available to demonstrate that publications had been managed in accordance with the procedure?",
        "short_text": "Nautical publications",
        "vessel_types": [
          "Oil",
          "Chemical",
          "LPG",
          "LNG"
        ],
        "objective": "To ensure nautical publications used for navigational purposes provide the most accurate information\navailable.",
        "negative_grounds": [
          "There was no company procedure for managing, ordering and updating nautical publications.",
          "The accompanying navigation officer was unfamiliar with the company procedure for managing, ordering",
          "and updating nautical publications.",
          "There was no inventory of mandatory and discretionary nautical publications required to be carried.",
          "Nautical publications required to be carried, in either electronic or hard copy, in accordance with the",
          "company procedure were found to be missing, obsolete or uncorrected.",
          "Where electronic nautical publications were carried, there was no evidence that the publications were",
          "approved by flag or that the required back up publications were available and maintained as required."
        ],
        "evidence": [
          "The nautical publications.",
          "The company procedure for managing, ordering and updating nautical publications.",
          "The inventory of nautical publications indicating their edition date and latest correction applied, where",
          "applicable.",
          "Where electronic publications were carried to comply with SOLAS Chapter V Regulation 27, evidence that",
          "the publications were approved by flag and the means of back up were in accordance with the Safety"
        ],
        "risk": "medium",
        "status": "not_started"
      },
      {
        "id": "4.3.1",
        "number": "4.3.1",
        "chapter": "4",
        "section": "4.3",
        "text": "Were the Master and navigation officers familiar with the company procedures defining the minimum bridge team composition and engine room operating mode and were records available to demonstrate that recent voyages had been planned and executed in accordance with company expectations?",
        "short_text": "Minimum bridge team composition",
        "vessel_types": [
          "Oil",
          "Chemical",
          "LPG",
          "LNG"
        ],
        "objective": "To ensure that the bridge team is adequately resourced, and the machinery space operated appropriately at\nall stages of a voyage including while at anchor, conducting STS operations or drifting.",
        "negative_grounds": [
          "There was no procedure defining the required bridge team composition during all stages of a voyage,",
          "including while at anchor, drifting, or conducting “at sea” STS operations, DP operations or underway",
          "storing/personnel transfer operations, considering traffic density, proximity to navigational hazards, weather",
          "conditions and visibility.",
          "There was no procedure defining the engine room status, and when required to be manned the engine room",
          "team composition, during all stages of a voyage including while at anchor or drifting, or conducting “at sea”",
          "STS operations, DP operations or underway storing/personnel transfer operations, considering traffic",
          "density, proximity to navigational hazards, weather conditions and visibility."
        ],
        "evidence": [
          "The company procedure(s) that defined bridge team composition and machinery space operating mode",
          "during all stages of a voyage .",
          "Passage plan documentation for recent voyages, (not necessarily the last voyage).",
          "Bridge Log Book, bell books, bridge checklists and any other supporting bridge records, either paper or",
          "electronic,"
        ],
        "risk": "medium",
        "status": "not_started"
      },
      {
        "id": "4.3.2",
        "number": "4.3.2",
        "chapter": "4",
        "section": "4.3",
        "text": "Were the engineer officers familiar with the company procedures defining machinery space operating mode and, where required to be attended, the machinery space team composition during the various stages of a voyage, and were records available to confirm the machinery space had been operated accordingly?",
        "short_text": "Machinery space team composition",
        "vessel_types": [
          "Oil",
          "Chemical",
          "LPG",
          "LNG"
        ],
        "objective": "To ensure that the machinery space is adequately manned or monitored at all stages of a voyage or\noperation.",
        "negative_grounds": [
          "There was no procedure defining company expectations for operating the machinery space in either the",
          "unattended or attended mode considering traffic density, proximity to navigational hazards and state of",
          "visibility and, other operations such as at while at anchor, drifting, “at sea” STS operations, Dynamically",
          "Positioned (DP) cargo operations or underway stores / personnel transfer operations.",
          "There was no company procedure which defined the required machinery space team composition",
          "considering traffic density, proximity to navigational hazards and environmental conditions.",
          "The accompanying engineer officer was not familiar with the company procedures which defined the",
          "expectations for the operating status of the machinery space or when required to be attended, the"
        ],
        "evidence": [
          "The company procedure that defined the required machinery space status during all stages of a voyage,",
          "including while at anchor, considering traffic density, proximity to navigational hazards and the state of",
          "visibility.",
          "The company procedure that defined the required machinery space team composition considering traffic",
          "density, proximity to navigational hazards and the state of visibility and, during other operations such drifting,",
          "“at sea” STS operations, Dynamically Positioned (DP) cargo operations or underway stores / personnel"
        ],
        "risk": "medium",
        "status": "not_started"
      },
      {
        "id": "4.3.3",
        "number": "4.3.3",
        "chapter": "4",
        "section": "4.3",
        "text": "Were the Master and navigation officers familiar with the company procedures for integrating a pilot (or similar role*) into the bridge team and were records available to demonstrate that the process had been followed?",
        "short_text": "Integrating a pilot (or similar role) into the bridge team",
        "vessel_types": [
          "Oil",
          "Chemical",
          "LPG",
          "LNG"
        ],
        "objective": "To ensure that there is an effective process to integrate the pilot (or similar role*) into the bridge team.",
        "negative_grounds": [
          "There was no procedure for integrating a pilot* into the bridge team.",
          "The vessel operator had not developed Master/Pilot information and/or pilot card checklists for use onboard.",
          "The accompanying navigation officer was not fully familiar with the company procedure for integrating a",
          "pilot* into the bridge team.",
          "The accompanying navigation officer was not familiar with the practical requirements for each item included",
          "n the Master/Pilot information and/or pilot card checklists.",
          "The Master/Pilot information and/or pilot card checklists were not available for all operations where a pilot*",
          "The Master/Pilot information and/or pilot card checklists reviewed were either missing, incomplete or"
        ],
        "evidence": [
          "The company procedure for integrating a pilot* into the bridge team.",
          "The Master/Pilot information exchange and pilot card checklists for recent operations.",
          "The Bridge Log Book, bell book and other operational records covering recent operations."
        ],
        "risk": "medium",
        "status": "not_started"
      },
      {
        "id": "4.3.4",
        "number": "4.3.4",
        "chapter": "4",
        "section": "4.3",
        "text": "Were the Master and navigation officers familiar with the company procedures to prevent disruption and distraction on the bridge, and were these procedures being complied with?",
        "short_text": "Bridge distractions.",
        "vessel_types": [
          "Oil",
          "Chemical",
          "LPG",
          "LNG"
        ],
        "objective": "To ensure that the bridge team can always maintain a safe navigational watch, free from disruption and\ndistraction.",
        "negative_grounds": [
          "There were no company procedures to prevent disruption and distraction on the bridge including guidance",
          "Bridge access by personnel with no operational bridge responsibilities.",
          "The use of mobile phones and other personal electronic devices.",
          "Internal and external communications.",
          "Non-essential activity.",
          "Internet and email access on the bridge.",
          "The effective management of the bridge space where it was combined with the cargo and/or",
          "machinery control and monitoring functions."
        ],
        "evidence": [
          "Company procedures to prevent disruption and distraction on the bridge."
        ],
        "risk": "medium",
        "status": "not_started"
      },
      {
        "id": "4.4.1",
        "number": "4.4.1",
        "chapter": "4",
        "section": "4.4",
        "text": "Were the Master and officers familiar with the operation of the Emergency Position Indicating Radio Beacon (EPIRB) and was the EPIRB in good order with records available to demonstrate that had it been inspected, tested and maintained as required?",
        "short_text": "Emergency Position Indicating Radio Beacon (EPIRB)",
        "vessel_types": [
          "Oil",
          "Chemical",
          "LPG",
          "LNG"
        ],
        "objective": "To ensure the Emergency Position Indicating Radio Beacon (EPIRB) will function correctly in an emergency.",
        "negative_grounds": [
          "The accompanying officer was unfamiliar with the required inspection and testing of the EPIRB.",
          "The accompanying officer was unable to explain:",
          "How to perform the self-test.",
          "The procedure to follow if the EPIRB was accidentally activated in a non-emergency situation.",
          "How to manually operate the EPIRB.",
          "Armed and ready for automatic activation.",
          "Capable of floating-free unimpeded or being easily manually released."
        ],
        "evidence": [
          "The company procedure to ensure that EPIRBs were periodically inspected, tested and maintained and",
          "ready for immediate use in an emergency.",
          "The GMDSS Radio Log Book.",
          "Records of periodic inspections, tests and maintenance of the EPIRB."
        ],
        "risk": "medium",
        "status": "not_started"
      },
      {
        "id": "4.4.2",
        "number": "4.4.2",
        "chapter": "4",
        "section": "4.4",
        "text": "Were the Master and officers familiar with the operation of the Search and Rescue Transmitters (SARTs), and were the SARTs in good order with records available to demonstrate that had they had been inspected and tested as required?",
        "short_text": "Search and Rescue Transmitters (SARTs)",
        "vessel_types": [
          "Oil",
          "Chemical",
          "LPG",
          "LNG"
        ],
        "objective": "To ensure the Search and Rescue Transmitters (SARTs) will function correctly in an emergency.",
        "negative_grounds": [
          "There was no company procedure to ensure that SARTs were periodically inspected, tested and ready for",
          "immediate use in an emergency.",
          "The accompanying officer was unfamiliar with the purpose and operation of the SARTs.",
          "The accompanying officer was unable to explain/demonstrate how to mount a SART on a lifeboat or liferaft.",
          "The accompanying officer was unable to describe how a SART transmission would be displayed on a radar",
          "The accompanying officer was unfamiliar with the required inspection and testing of the SARTs.",
          "The accompanying officer was unable to explain how to perform the self-tests on the SART units provided",
          "The stowage location(s) of SARTs were not clearly marked with the recommended symbols."
        ],
        "evidence": [
          "The company procedure to ensure that SARTs were periodically inspected, tested and ready for immediate",
          "use in an emergency.",
          "The GMDSS Radio Log Book.",
          "Records of periodic inspections and tests of the SART(s)."
        ],
        "risk": "medium",
        "status": "not_started"
      },
      {
        "id": "4.4.3",
        "number": "4.4.3",
        "chapter": "4",
        "section": "4.4",
        "text": "Were the Master and officers familiar with the location, purpose and operation of the survival craft portable two-way VHF radios and were they in good order with records available to demonstrate that had they been inspected and tested as required?",
        "short_text": "Survival craft portable two-way VHF radios",
        "vessel_types": [
          "Oil",
          "Chemical",
          "LPG",
          "LNG"
        ],
        "objective": "To ensure the survival craft portable two-way VHF radios will function correctly in an emergency.",
        "negative_grounds": [
          "There was no company procedure to ensure that survival craft portable two-way VHF radios were",
          "periodically inspected, tested and ready for immediate use in an emergency.",
          "Company procedures did not provide guidance on the use of the survival craft portable two-way VHF radios",
          "for non-emergency communications.",
          "The accompanying officer was unfamiliar with the purpose and operation of the survival craft portable two-",
          "The accompanying officer was unfamiliar with the required inspection and testing of the survival craft",
          "portable two-way VHF radios.",
          "There were insufficient survival craft portable two-way VHF radios on board."
        ],
        "evidence": [
          "The company procedure to ensure survival craft portable two-way vhf radios were periodically inspected and",
          "tested and ready for immediate use in an emergency.",
          "The GMDSS Radio Log Book.",
          "Records of periodic inspections and tests of the survival craft portable two-way VHF radios."
        ],
        "risk": "medium",
        "status": "not_started"
      },
      {
        "id": "4.4.4",
        "number": "4.4.4",
        "chapter": "4",
        "section": "4.4",
        "text": "Were the Master and navigation officers familiar with the procedures for sending and receiving distress, urgency and safety messages and were suitable instructions posted by the GMDSS equipment?",
        "short_text": "Sending and receiving distress, urgency and safety messages",
        "vessel_types": [
          "Oil",
          "Chemical",
          "LPG",
          "LNG"
        ],
        "objective": "To ensure effective communications will be made by the vessel in an emergency situation.",
        "negative_grounds": [
          "There were no company procedures for emergency communications which gave guidance on, and",
          "designated responsibility for, distress communications in an emergency situation.",
          "A qualified GMDSS operator had not been designated in the emergency station bill as being responsible for",
          "radio communications in a distress.",
          "Instructions for the preparation and transmission of distress and urgency messages using the GMDSS",
          "equipment were not clearly displayed by the equipment.",
          "There was no copy of the International Aeronautical and Maritime Search and Rescue Manual Volume III,",
          "latest edition, (IAMSAR Vol III) available at the GMDSS radio station."
        ],
        "evidence": [
          "The company procedures for emergency communications.",
          "The GMDSS Radio Log Book.",
          "International Aeronautical and Maritime Search and Rescue Manual (IAMSAR) Vol III."
        ],
        "risk": "medium",
        "status": "not_started"
      },
      {
        "id": "4.4.5",
        "number": "4.4.5",
        "chapter": "4",
        "section": "4.4",
        "text": "Were the Master and navigation officers familiar with the operation, testing and maintenance of the GMDSS VHF, MF and HF radio and satellite communications equipment and were records available to demonstrate the equipment was in good order?",
        "short_text": "Operation and testing of GMDSS station.",
        "vessel_types": [
          "Oil",
          "Chemical",
          "LPG",
          "LNG"
        ],
        "objective": "To ensure effective communications in routine or emergency situations.",
        "negative_grounds": [
          "There were no company procedures for the operation, testing, maintenance and log keeping of the GMDSS",
          "VHF, MF and HF radio and satellite communications equipment.",
          "The accompanying officer was unfamiliar with the operation of the GMDSS VHF, MF and HF radio and",
          "satellite communications equipment.",
          "The accompanying officer was unable to describe the daily, weekly and monthly radio tests required in",
          "accordance with the SMS (including flag state requirements) and the manufacturers’ maintenance and",
          "There was no evidence that the required daily, weekly and monthly radio tests had been performed."
        ],
        "evidence": [
          "The company procedures for the operation, testing, maintenance and log keeping of the GMDSS VHF, MF",
          "and HF radio and satellite communications equipment.",
          "The GMDSS Radio Log Book.",
          "A copy of the record of equipment for the cargo ship safety radio certificate Form R or Form C.",
          "Test and maintenance records for the GMDSS reserve batteries.",
          "Any shore-based maintenance agreement for the GMDSS equipment."
        ],
        "risk": "medium",
        "status": "not_started"
      },
      {
        "id": "4.4.6",
        "number": "4.4.6",
        "chapter": "4",
        "section": "4.4",
        "text": "Were the Master, officers and crew aware of the potential danger of using radio or mobile telephone equipment during cargo and ballast handling operations and was there a sufficient number of intrinsically safe portable radios for use in operational areas?",
        "short_text": "Use of radio or mobile telephone equipment during cargo and ballast handling",
        "vessel_types": [
          "Oil",
          "Chemical",
          "LPG",
          "LNG"
        ],
        "objective": "To ensure a hazard is never created by the inappropriate use of radio or mobile telephone equipment during\ncargo or ballast operations.",
        "negative_grounds": [
          "There were no company procedures for the safe use of radio and telephone equipment during cargo and",
          "ballast handling operations.",
          "The Master, an officer or a rating was unfamiliar with the company procedures for the safe use of radio and",
          "telephone equipment during cargo and ballast handling operations.",
          "There were insufficient intrinsically safe VHF or UHF portable radios available in good working order to",
          "properly coordinate cargo, ballast and bunker handling operations.",
          "MF/HF radio or radar equipment was under repair/service, but this had not been discussed at the pre-",
          "transfer conference and a safe system of work agreed."
        ],
        "evidence": [
          "The procedure for the safe use of radio and telephone equipment during cargo and ballast handling",
          "operations.",
          "Certification for any intrinsically safe mobile phones in use outside of the accommodation block.",
          "The inventory of intrinsically safe portable VHF/UHF radios used for cargo, ballast and bunker operations."
        ],
        "risk": "medium",
        "status": "not_started"
      },
      {
        "id": "4.5.1",
        "number": "4.5.1",
        "chapter": "4",
        "section": "4.5",
        "text": "Was the latest Annual DP Trial report available on board, were the Master and officers familiar with the contents, and had they taken part in onboard training and drills involving various DP scenarios?",
        "short_text": "Annual DP Trial report and supporting exercises.",
        "vessel_types": [
          "Oil"
        ],
        "objective": "To ensure that the vessel’s DP system is fully operational, and that the vessel is fault tolerant according to\nthe equipment class requirements.",
        "negative_grounds": [
          "There were no company procedures giving guidance on the performance of Annual DP Trials.",
          "The latest DP Annual Trials report was not available on board.",
          "Previous Annual DP Trials reports were not available on board.",
          "The latest DP Annual Trials had not been carried out within three months before/after the anniversary date",
          "f the initial FMEA proving trial.",
          "The Annual DP Trials date had not been synchronised following a new FMEA proving trial conducted after a",
          "major upgrade or conversion.",
          "There was no evidence that the Annual DP Trials had been witnessed by a competent and independent third"
        ],
        "evidence": [
          "The latest Annual DP Trials report.",
          "If the Annual DP trials were being carried out as part of a rolling test programme over the year, test sheets",
          "and/or other documented evidence of compliance from the Planned Maintenance System.",
          "Previous Annual DP Trials reports.",
          "Records of training and/or drills involving DP scenarios."
        ],
        "risk": "medium",
        "status": "not_started"
      },
      {
        "id": "4.5.2",
        "number": "4.5.2",
        "chapter": "4",
        "section": "4.5",
        "text": "Were the Master and officers familiar with the company procedures for the use of Position Reference Systems (PRS), and was the equipment in satisfactory condition with sensor offset data readily available to the DPO?",
        "short_text": "DP Position Reference Systems",
        "vessel_types": [
          "Oil"
        ],
        "objective": "To ensure Position Reference Systems are in satisfactory condition with sensor offset data readily available\nto the DPO.",
        "negative_grounds": [
          "There were no company procedures for the use of Position Reference Systems during DP operations at",
          "each offtake location.",
          "The accompanying officer was not familiar with the company procedures for the use of Position Reference",
          "Systems during DP operations at each offtake location.",
          "One or more of the PRS was not in satisfactory operational condition.",
          "On a DP2 or DP3 vessel, fewer than three different, operational, Position Reference Systems (PRS) had",
          "been available to the DP operator during an offtake operation.",
          "The DP system was not equipped with a minimum of two independent differential satellite positioning"
        ],
        "evidence": [
          "Company procedures for the use of Position Reference Systems during DP operations at each offtake",
          "Sensor offset data file.",
          "DP logbook.",
          "DP data log."
        ],
        "risk": "medium",
        "status": "not_started"
      },
      {
        "id": "4.5.3",
        "number": "4.5.3",
        "chapter": "4",
        "section": "4.5",
        "text": "Were the Master and officers familiar with the company procedures for reporting and recording DP events and incidents, and were all DP parameters being logged and recorded?",
        "short_text": "DP events and incidents",
        "vessel_types": [
          "Oil"
        ],
        "objective": "To ensure DP events and incidents are recorded, reported and investigated, and lessons learnt from\nincidents used to increase industry safety standards.",
        "negative_grounds": [
          "There were no company procedures for recording, reporting and investigating DP related incidents,",
          "undesired events and observations.",
          "DP related incidents, undesired events and observations had not been reported according to the vessel’s",
          "ISM system or via the method set out in IMCA M 103, latest revision.",
          "DP related incident, undesired event and observation reports had not been retained on board.",
          "An investigation into a DP related incident, undesired event or observation had not been closed out within a",
          "reasonable time frame.",
          "Records of faults related to the DP system had not been retained on board."
        ],
        "evidence": [
          "Company procedures for recording, reporting and investigating DP related incidents, undesired events and",
          "observations.",
          "Records of DP related incidents, undesired events and observations.",
          "Independent data logger records.",
          "DP fault log."
        ],
        "risk": "medium",
        "status": "not_started"
      },
      {
        "id": "4.5.4",
        "number": "4.5.4",
        "chapter": "4",
        "section": "4.5",
        "text": "Was the vessel provided with a comprehensive DP operations manual and were the Master and officers familiar with its contents, including DP checklists, capability plots, consequence analysis and activity specific operating guidelines (ASOG)?",
        "short_text": "DP operations manual",
        "vessel_types": [
          "Oil"
        ],
        "objective": "To ensure the Master and officers are provided with comprehensive procedures for conducting DP\noperations.",
        "negative_grounds": [
          "There was no DP operations manual available on board.",
          "The DP operations manual was not vessel specific.",
          "The DP operations manual was not in a language that could be understood by the DP operators.",
          "Procedures in the DP operations manual did not include:",
          "DP location checklists and watchkeeping checklists.",
          "DP operating instructions.",
          "Risk assessment reviews.",
          "Guidance on the use of:"
        ],
        "evidence": [
          "DP operations manual.",
          "Completed DP location checklists and watchkeeping checklists.",
          "Hard copy capability plots.",
          "DP footprint records.",
          "DP operations risk assessments."
        ],
        "risk": "medium",
        "status": "not_started"
      },
      {
        "id": "4.5.5",
        "number": "4.5.5",
        "chapter": "4",
        "section": "4.5",
        "text": "Were up to date Field Operations Manuals on board for each offshore terminal to which the vessel trades, were the Master and officers familiar with their content, and were records available of the regular communication checks with terminal installations as required by Field Specific Operating Guidelines (FSOG)?",
        "short_text": "Field Operations Manuals",
        "vessel_types": [
          "Oil"
        ],
        "objective": "To ensure the Master and officers are aware of the procedures and regulations at each offshore terminal to\nwhich the vessel trades, and that regular communications are established as required by Field Specific\nOperating Guidelines (FSOG).",
        "negative_grounds": [
          "There were no company procedures to ensure that the most up-to-date editions of the field operations",
          "manuals for each offshore terminal to which the vessel trades are available on board.",
          "There was no field operations manual available on board for an offshore terminal to which the vessel trades.",
          "The accompanying officer was not familiar with the procedure for verifying that the field operation manual in",
          "use was the latest edition.",
          "The accompanying officer was not familiar with the content of the field operation manual, including Field",
          "Specific Operating Guidelines (FSOG) and contact numbers, call signs and communications channels for",
          "both operational and emergency use, for the last offshore terminal visited."
        ],
        "evidence": [
          "Company procedures to ensure that the most up-to-date editions of the field operations manuals are on",
          "board for each offshore terminal to which the vessel trades.",
          "Field operations manuals for each offshore terminal to which the vessel trades.",
          "Records of the regular communication checks with terminal installations as required by Field Specific",
          "Operating Guidelines (FSOG)."
        ],
        "risk": "medium",
        "status": "not_started"
      }
    ]
  },
  {
    "id": "C5",
    "title": "Safety Management",
    "roles": [
      "Master",
      "CE",
      "Officers",
      "Crew"
    ],
    "questions": [
      {
        "id": "5.1.1",
        "number": "5.1.1",
        "chapter": "5",
        "section": "5.1",
        "text": "Were the Master and officers familiar with the onboard emergency response plans, and were records available to demonstrate that all mandatory and company defined emergency drills had been completed and documented as required by company procedures?",
        "short_text": "Records of mandatory and company defined emergency drills",
        "vessel_types": [
          "Oil",
          "Chemical",
          "LPG",
          "LNG"
        ],
        "objective": "To ensure that vessel staff can manage onboard emergencies through a consistent and structured process.",
        "negative_grounds": [
          "There was no company procedure which defined the requirements to conduct onboard emergency response",
          "drills, record the outcome and track drills to ensure completion within the defined time frame.",
          "There was no uniform system of shipboard emergency contingency plans available.",
          "There was no requirement to record the details of a drill which included:",
          "The contingency plan(s) used for a drill.",
          "Any safety considerations for conducting the drill.",
          "A summary of the drill activities."
        ],
        "evidence": [
          "The company procedures which defined the requirements to conduct onboard emergency response drills,",
          "record the outcome and track drills to ensure completion within the defined time frame.",
          "The vessel’s system of shipboard emergency contingency plans.",
          "The tracking records for completed onboard emergency response drills.",
          "Where a drill had not been completed within the defined time frame, communications with the company",
          "describing the reasons for deferment."
        ],
        "risk": "medium",
        "status": "not_started"
      },
      {
        "id": "5.1.2",
        "number": "5.1.2",
        "chapter": "5",
        "section": "5.1",
        "text": "Were the Master and officers familiar with the shipboard emergency plans for the principal fire scenarios for the vessel type, and had drills taken place to test the effectiveness of the plans in accordance with the company procedures?",
        "short_text": "Emergency plans & drills for principal fire scenarios",
        "vessel_types": [
          "Oil",
          "Chemical",
          "LPG",
          "LNG"
        ],
        "objective": "To ensure that the crew will respond to a fire situation in accordance with the vessel’s shipboard emergency\nresponse plans.",
        "negative_grounds": [
          "There was no shipboard emergency plan available for fire for one or more of the principal fire scenarios",
          "applicable to the vessel type.",
          "The shipboard emergency plans for the principal fire scenarios were insufficiently ship-specific.",
          "The accompanying officer was unfamiliar with the shipboard emergency plans for the principal fire scenarios",
          "applicable to the vessel.",
          "The drill records were not maintained in the format defined by the company procedure.",
          "The drill scenarios were unrealistic or inadequate to test the shipboard emergency plans for the principal fire",
          "scenarios applicable to the vessel type."
        ],
        "evidence": [
          "The shipboard emergency response plans for the principal fire scenarios as applicable to the vessel type.",
          "The records for completed fire drills during the previous six months.",
          "The vessel’s Bridge Log Book for the previous six months.",
          "Where a drill had been deferred due to poor weather or sea conditions, communications with the company",
          "relating to the deferment."
        ],
        "risk": "high",
        "status": "not_started"
      },
      {
        "id": "5.1.3",
        "number": "5.1.3",
        "chapter": "5",
        "section": "5.1",
        "text": "Were the Master and officers familiar with the vessel’s SOPEP or SMPEP, and had drills taken place to test the effectiveness of the onboard emergency response actions required by the Plan and company procedures?",
        "short_text": "Pollution prevention drills required by SOPEP or SMPEP",
        "vessel_types": [
          "Oil",
          "Chemical",
          "LPG",
          "LNG"
        ],
        "objective": "To ensure that the crew will respond effectively to a spill situation in accordance with the vessel’s Shipboard\nOil Pollution Plan (SOPEP) or Shipboard Marine Pollution Emergency Plan (SMPEP).",
        "negative_grounds": [
          "There was no SOPEP or SMPEP available.",
          "The SOPEP or SMPEP had not been maintained up to date with national operational contact points or any",
          "ther information that may have become outdated over time or at change of management.",
          "The vessel had not prepared a list of specific contact details for the port of inspection.",
          "The accompanying officer was unfamiliar with the content of the vessel’s SOPEP or SMPEP.",
          "An interviewed officer was unfamiliar with their duties during a spill incident.",
          "The drill scenarios were unrealistic or inadequate to test the Plan.",
          "The drill scenarios did not cover operational spills for both cargo and bunker operations."
        ],
        "evidence": [
          "The vessel’s SOPEP or SMPEP.",
          "The shipboard emergency response plans for defined spill situations, if not contained within the SOPEP or",
          "The list of specific contact details for the port of inspection.",
          "The records for completed spill emergency response drills.",
          "The vessel’s Bridge Log Book for the previous twelve months."
        ],
        "risk": "medium",
        "status": "not_started"
      },
      {
        "id": "5.1.4",
        "number": "5.1.4",
        "chapter": "5",
        "section": "5.1",
        "text": "Were the Master and officers familiar with the shipboard emergency plan for enclosed space rescue, and had drills taken place to test the effectiveness of the shipboard emergency response plan in accordance with company procedures?",
        "short_text": "Enclosed space rescue emergency response drill.",
        "vessel_types": [
          "Oil",
          "Chemical",
          "LPG",
          "LNG"
        ],
        "objective": "To ensure that the crew will respond to an enclosed space rescue situation in accordance with the vessel's\nshipboard emergency response plan.",
        "negative_grounds": [
          "There was no shipboard emergency plan for enclosed space rescue available.",
          "The shipboard emergency plan was insufficiently ship-specific.",
          "The accompanying officer was unfamiliar with the shipboard emergency plan for enclosed space rescue.",
          "An interviewed officer or rating was unfamiliar with the rigging and use of the provided enclosed space",
          "rescue hoisting arrangement(s).",
          "The drill scenario was unrealistic or inadequate to test the shipboard emergency plan.",
          "The drill records had not been completed in accordance with the company procedures or were missing the",
          "associated enclosed space entry permit, where required."
        ],
        "evidence": [
          "The shipboard emergency response plan for enclosed space rescue.",
          "The records for completed enclosed space rescue drills, supplemented by enclosed space entry permits",
          "where appropriate.",
          "The vessel’s Bridge Log Book for the previous twelve months.",
          "Where a drill had been deferred due to poor weather or sea conditions, communications with the company",
          "relating to the postponement."
        ],
        "risk": "medium",
        "status": "not_started"
      },
      {
        "id": "5.1.5",
        "number": "5.1.5",
        "chapter": "5",
        "section": "5.1",
        "text": "Were the Master and Ship Security Officer (SSO) familiar with the vessel’s Ship Security Plan (SSP), and had drills taken place to test the effectiveness of the measures and procedures specified by the Ship Security Plan?",
        "short_text": "Drills required by the Ship Security Plan (SSP)",
        "vessel_types": [
          "Oil",
          "Chemical",
          "LPG",
          "LNG"
        ],
        "objective": "To ensure that the crew will respond effectively to a security threat in accordance with the vessel’s Ship\nSecurity Plan.",
        "negative_grounds": [
          "There was no schedule of security drills or exercises required to be undertaken by the Ship Security Plan",
          "The Master or Ship Security Officer was unfamiliar with security drills or exercises required to be undertaken",
          "to test the effectiveness of the SSP and its contingency plans.",
          "The drill records were not maintained in the format defined by the company procedure.",
          "Drill or exercise dates were inconsistent with the vessel activities as recorded within the Bridge Log Book.",
          "The latest security drill or exercise was overdue for completion.",
          "Security drill or exercise scenarios required to be undertaken according to the company drill schedule had",
          "not been completed within the defined time frame."
        ],
        "evidence": [
          "The schedule of security drills or exercises required to be carried out by the Ship Security Plan.",
          "The records for completed security drills or exercises.",
          "The vessel’s Bridge Log Book for the previous twelve months.",
          "Where a drill or exercise had been deferred due to poor weather or sea conditions, communications with the",
          "company relating to the deferment."
        ],
        "risk": "medium",
        "status": "not_started"
      },
      {
        "id": "5.1.6",
        "number": "5.1.6",
        "chapter": "5",
        "section": "5.1",
        "text": "Were the Master, officers and ratings familiar with the procedure for launching the lifeboat(s), and had abandon ship drills taken place in accordance with company procedures and the requirements of SOLAS and the Flag Administration?",
        "short_text": "Launching the lifeboat(s) and abandon ship drills",
        "vessel_types": [
          "Oil",
          "Chemical",
          "LPG",
          "LNG"
        ],
        "objective": "To ensure that the crew were able to safely launch the vessel’s lifeboat(s) in an emergency, and conduct\nabandon ship drills strictly in accordance with manufacturer’s instructions and company procedures.",
        "negative_grounds": [
          "There was no emergency procedure for abandoning ship.",
          "There was no ship specific procedure for launching a lifeboat as part of an abandon ship drill.",
          "The shipboard procedures were insufficiently ship-specific.",
          "The drill records were not maintained in the format defined by the company procedure.",
          "The accompanying officer was unfamiliar with the procedure for abandon ship or the launching of a lifeboat",
          "during an abandon ship drill.",
          "An interviewed rating was unfamiliar with the ship specific procedure for the launching of a lifeboat during an"
        ],
        "evidence": [
          "The shipboard emergency procedure for abandoning ship.",
          "The ship specific procedure for launching a lifeboat as part of an abandon ship drill.",
          "The records for completed abandon ship drills.",
          "The vessel’s Bridge Log Book for the previous twelve months.",
          "Where a drill had been deferred due to poor weather or sea conditions, communications with the company",
          "relating to the postponement."
        ],
        "risk": "medium",
        "status": "not_started"
      },
      {
        "id": "5.1.7",
        "number": "5.1.7",
        "chapter": "5",
        "section": "5.1",
        "text": "Were the Master and officers familiar with the shipboard emergency plan for a cargo vapour or liquid release, Including potential fire, and had drills taken place to test the effectiveness of the shipboard emergency response plan in accordance with company procedures?",
        "short_text": "Emergency plan & drills for a cargo vapour or liquid release, Including potential fire",
        "vessel_types": [
          "LPG",
          "LNG"
        ],
        "objective": "To ensure that the crew will respond effectively to a cargo vapour or liquid release, including potential fire, in\naccordance with the vessel’s shipboard emergency response plans.",
        "negative_grounds": [
          "There were no shipboard emergency plans for a cargo vapour or liquid release available.",
          "The shipboard emergency plans for cargo vapour or liquid release were insufficiently ship-specific.",
          "The accompanying officer was unfamiliar with the shipboard emergency plans for cargo vapour or liquid",
          "The drill records were not maintained in the format defined by the company procedure.",
          "The drill scenario was unrealistic or inadequate to test the shipboard emergency plan.",
          "Drill dates were inconsistent with the vessel activities as recorded within the Bridge Log Book.",
          "The latest drill for cargo vapour or liquid release was overdue for completion.",
          "One or more of the emergency response plans for cargo vapour or liquid release scenarios had not been"
        ],
        "evidence": [
          "The shipboard emergency response plans for a cargo vapour or liquid release.",
          "The records for completed cargo vapour or liquid release drills.",
          "The vessel’s Bridge Log Book for the previous 12 months."
        ],
        "risk": "medium",
        "status": "not_started"
      },
      {
        "id": "5.1.8",
        "number": "5.1.8",
        "chapter": "5",
        "section": "5.1",
        "text": "Were the Master and officers familiar with the shipboard emergency plan for collision, and had drills taken place to test the effectiveness of the shipboard emergency response plan in accordance with company procedures?",
        "short_text": "Emergency plan & drills for collision",
        "vessel_types": [
          "Oil",
          "Chemical",
          "LPG",
          "LNG"
        ],
        "objective": "To ensure that the crew will respond effectively to a collision situation in accordance with the vessel’s\nshipboard emergency response plan.",
        "negative_grounds": [
          "There was no shipboard emergency plan developed for a collision situation.",
          "The shipboard emergency plan was insufficiently ship-specific.",
          "The accompanying officer was unfamiliar with the shipboard emergency plan for a collision situation.",
          "The drill scenario was unrealistic or inadequate to test the shipboard emergency plan.",
          "Drill dates were inconsistent with the vessel activities as recorded within the Bridge Log Book."
        ],
        "evidence": [
          "The shipboard emergency response plan for a collision situation.",
          "The records for completed collision emergency response drills.",
          "The vessel’s Bridge Log Book for the previous twelve months.",
          "Where a drill had been deferred due to poor weather or sea conditions, communications with the company",
          "relating to the deferment."
        ],
        "risk": "high",
        "status": "not_started"
      },
      {
        "id": "5.1.9",
        "number": "5.1.9",
        "chapter": "5",
        "section": "5.1",
        "text": "Were the Master and officers familiar with the shipboard emergency plan for grounding, and had drills taken place to test the effectiveness of the shipboard emergency response plan in accordance with company procedures?",
        "short_text": "Emergency plan & drills for grounding",
        "vessel_types": [
          "Oil",
          "Chemical",
          "LPG",
          "LNG"
        ],
        "objective": "To ensure that the crew will respond effectively to a grounding situation in accordance with the vessel’s\nshipboard emergency response plan.",
        "negative_grounds": [
          "There was no shipboard emergency plan developed for a grounding situation.",
          "The shipboard emergency plan was insufficiently ship-specific."
        ],
        "evidence": [
          "The shipboard emergency response plan for a grounding situation.",
          "The records for completed grounding emergency response drills.",
          "The vessel’s Bridge Log Book for the previous twelve months.",
          "Where a drill had been deferred due to poor weather or sea conditions, communications with the company",
          "relating to the deferment."
        ],
        "risk": "high",
        "status": "not_started"
      },
      {
        "id": "5.1.10",
        "number": "5.1.10",
        "chapter": "5",
        "section": "5.1",
        "text": "Were the Master and officers familiar with the shipboard emergency plan for loss of propulsion, and had drills taken place to test the effectiveness of the shipboard emergency response plan in accordance with company procedures?",
        "short_text": "Emergency plan & drills for loss of propulsion",
        "vessel_types": [
          "Oil",
          "Chemical",
          "LPG",
          "LNG"
        ],
        "objective": "To ensure that the crew will respond effectively to a loss of propulsion in accordance with the vessel’s\nshipboard emergency response plan.",
        "negative_grounds": [
          "There was no shipboard emergency plan for the loss of propulsion.",
          "The shipboard emergency plan was insufficiently ship-specific.",
          "The accompanying officer was unfamiliar with the shipboard emergency plan for the loss of propulsion.",
          "An interviewed navigation officer was unfamiliar with the process for estimating the predicted drift of a",
          "disabled tanker, taking into account the wind, current and ship’s head.",
          "An interviewed engineer officer was unfamiliar with the location and content of the vessel’s loss of",
          "propulsion emergency response plan.",
          "The drill records were not maintained in the format defined by the company procedure."
        ],
        "evidence": [
          "The shipboard emergency response plan for the loss of propulsion.",
          "The records for completed loss of propulsion emergency response drills.",
          "The vessel’s Bridge Log Book for the previous twelve months.",
          "Where a drill had been deferred due to poor weather or sea conditions, communications with the company",
          "relating to the postponement."
        ],
        "risk": "medium",
        "status": "not_started"
      },
      {
        "id": "5.1.11",
        "number": "5.1.11",
        "chapter": "5",
        "section": "5.1",
        "text": "Were the Master and officers familiar with the shipboard emergency plan for failure of electrical power, and had drills taken place to test the effectiveness of the shipboard emergency response plan in accordance with company procedures?",
        "short_text": "Emergency plan & drills for failure of electrical power",
        "vessel_types": [
          "Oil",
          "Chemical",
          "LPG",
          "LNG"
        ],
        "objective": "To ensure that the crew will respond effectively to a failure of electrical power in accordance with the\nvessel’s shipboard emergency response plan.",
        "negative_grounds": [
          "There was no shipboard emergency plan for the failure of electrical power available.",
          "The shipboard emergency plan was insufficiently ship-specific.",
          "The accompanying officer was unfamiliar with the shipboard emergency plan for the failure of electrical",
          "An interviewed navigation officer was unfamiliar with the process of estimating the predicted drift of a",
          "disabled tanker taking into account the wind, current and ship’s head.",
          "An interviewed engineer officer was unfamiliar with the location and content of the vessel’s failure of",
          "electrical power emergency response plan.",
          "The drill records were not maintained in the format defined by the company procedure."
        ],
        "evidence": [
          "The shipboard emergency response plan for the failure of electrical power including any supplementary",
          "engineering procedures referenced by the plan.",
          "The records for completed failure of electrical power emergency response drills.",
          "The vessel’s Bridge Log Book for the previous twelve months.",
          "Where a drill had been deferred due to poor weather or sea conditions, communications with the company",
          "relating to the deferment."
        ],
        "risk": "medium",
        "status": "not_started"
      },
      {
        "id": "5.1.12",
        "number": "5.1.12",
        "chapter": "5",
        "section": "5.1",
        "text": "Were the Master and officers familiar with the shipboard emergency plan for steering gear failure, and had drills taken place to test the effectiveness of the shipboard emergency response plan in accordance with company procedures.",
        "short_text": "Steering gear failure emergency drill.",
        "vessel_types": [
          "Oil",
          "Chemical",
          "LPG",
          "LNG"
        ],
        "objective": "To ensure that the crew will respond effectively to a failure of the steering gear in accordance with the\nvessel’s shipboard emergency response plan.",
        "negative_grounds": [
          "The shipboard emergency plan for steering failure was insufficiently ship-specific.",
          "The accompanying officer was unfamiliar with the shipboard emergency plan for steering gear failure.",
          "An interviewed navigation officer was unfamiliar with the process for estimating a vessel’s drift rate taking",
          "into account the wind, current and ship's head."
        ],
        "evidence": [
          "The shipboard emergency response plan for steering gear failure.",
          "The records for completed steering gear failure and emergency steering drills.",
          "The vessel’s Bridge Log Book for the previous six months.",
          "Where a drill had been deferred due to poor weather or sea conditions, communications with the company",
          "relating to the deferment."
        ],
        "risk": "medium",
        "status": "not_started"
      },
      {
        "id": "5.1.13",
        "number": "5.1.13",
        "chapter": "5",
        "section": "5.1",
        "text": "Were the Master and officers familiar with the shipboard emergency plan for emergency towing, including the Emergency Towing Booklet (ETB), and had drills taken place to test the effectiveness of the shipboard emergency response plan in accordance with company procedures?",
        "short_text": "Emergency plan & drills for emergency towing",
        "vessel_types": [
          "Oil",
          "Chemical",
          "LPG",
          "LNG"
        ],
        "objective": "To ensure that the crew will respond to an emergency towing situation in accordance with the vessel’s\nshipboard emergency response plan and Emergency Towing Booklet.",
        "negative_grounds": [
          "There were no Emergency Towing Booklets available.",
          "Copies of the ETB were not available on the bridge, in a forecastle space or in the ship’s office or cargo",
          "The emergency towing procedures were insufficiently ship-specific.",
          "The accompanying officer was unfamiliar with the emergency towing procedures.",
          "An interviewed navigation or engineer officer was unfamiliar with the location of the ETB or the deployment",
          "process for the emergency towing arrangements fitted to the vessel.",
          "The drill records were not maintained in the format defined by the company procedure.",
          "The drill scenario was unrealistic or inadequate to test the emergency towing procedures."
        ],
        "evidence": [
          "The shipboard Emergency Towing Booklets.",
          "The records for completed emergency towing drills The vessel’s Bridge Log Book for the previous twelve months.",
          "Where a drill had been deferred due to poor weather or sea conditions, communications with the company",
          "relating to the deferment."
        ],
        "risk": "medium",
        "status": "not_started"
      },
      {
        "id": "5.1.14",
        "number": "5.1.14",
        "chapter": "5",
        "section": "5.1",
        "text": "Were the Master, officers and ratings familiar with the shipboard emergency response plan for man overboard, including the launching and recovering the rescue boat, and had drills taken place to test the effectiveness of the shipboard emergency response plan in accordance with company procedures?",
        "short_text": "Man overboard emergency drill.",
        "vessel_types": [
          "Oil",
          "Chemical",
          "LPG",
          "LNG"
        ],
        "objective": "To ensure that the crew will respond effectively to a man overboard situation in accordance with the vessel’s\nshipboard emergency response plan.",
        "negative_grounds": [
          "There was no emergency response plan for man overboard.",
          "There was no ship specific procedure for launching and recovering the rescue boat as part of a drill.",
          "The shipboard procedures were insufficiently ship-specific."
        ],
        "evidence": [
          "The shipboard emergency response plan for man overboard.",
          "The ship specific procedure for launching and recovering the rescue boat as part of a drill.",
          "The records for completed man overboard and rescue boat launching drills.",
          "The vessel’s Bridge Log Book for the previous six months.",
          "Where a drill had been deferred due to poor weather or sea conditions, communications with the company",
          "relating to the postponement."
        ],
        "risk": "medium",
        "status": "not_started"
      },
      {
        "id": "5.1.15",
        "number": "5.1.15",
        "chapter": "5",
        "section": "5.1",
        "text": "Were the Master, officers and ratings familiar with the shipboard emergency response plan for recovery of persons from the water, and had drills taken place to test the effectiveness of the shipboard emergency response plan in accordance with company procedures?",
        "short_text": "Emergency response plan & drills for recovery of persons from the water",
        "vessel_types": [
          "Oil",
          "Chemical",
          "LPG",
          "LNG"
        ],
        "objective": "To ensure that the crew will be able to safely recover persons from the water in accordance with the vessel's\nshipboard emergency response plan.",
        "negative_grounds": [
          "There was no shipboard emergency response plan for the recovery of persons from the water available.",
          "The shipboard emergency response plan for the recovery of persons from the water was insufficiently ship-",
          "The drill records were not maintained in the format defined by the company procedure.",
          "The accompanying officer was unfamiliar with the shipboard emergency response plan for the recovery of",
          "persons from the water.",
          "An interviewed deck rating was unfamiliar with the recovery of persons from the water plan and their",
          "expected role in such an emergency response.",
          "The drill scenario was unrealistic or inadequate to test the shipboard emergency response plan for the"
        ],
        "evidence": [
          "The shipboard emergency response plan for the recovery of persons from the water.",
          "The records for completed recovery of persons from the water drills.",
          "The vessel’s Bridge Log Book for the previous twelve months.",
          "Where a drill had been deferred due to poor weather or sea conditions, communications with the company",
          "relating to the deferment."
        ],
        "risk": "medium",
        "status": "not_started"
      },
      {
        "id": "5.1.16",
        "number": "5.1.16",
        "chapter": "5",
        "section": "5.1",
        "text": "Were the Master and officers familiar with the shipboard emergency plans for flooding, and had drills taken place to test the effectiveness of the shipboard emergency response plans in accordance with company procedures?",
        "short_text": "Emergency plans & drills for flooding",
        "vessel_types": [
          "Oil",
          "Chemical",
          "LPG",
          "LNG"
        ],
        "objective": "To ensure that the crew will respond effectively to a flooding situation in accordance with the vessel’s\nshipboard emergency response plan.",
        "negative_grounds": [
          "There was no shipboard emergency plan available for one or more of the flooding scenarios applicable to",
          "The shipboard emergency plans were insufficiently ship-specific.",
          "The accompanying officer was unfamiliar with the shipboard emergency plans for flooding situations.",
          "The drill records were not maintained in the format defined by the company procedure.",
          "The drill scenarios were unrealistic or inadequate to test the shipboard emergency plan.",
          "Drill dates were inconsistent with the vessel activities as recorded within the Bridge Log Book.",
          "One or more of the emergency response drills for a flooding scenario required by the company onboard"
        ],
        "evidence": [
          "The shipboard emergency response plans for the flooding scenarios applicable to the vessel type.",
          "The records for completed flooding emergency response drills.",
          "The vessel’s Bridge Log Book for the previous twelve months.",
          "Where a drill had been deferred due to poor weather or sea conditions, communications with the company",
          "relating to the deferment."
        ],
        "risk": "medium",
        "status": "not_started"
      },
      {
        "id": "5.1.17",
        "number": "5.1.17",
        "chapter": "5",
        "section": "5.1",
        "text": "Were the Master and officers familiar with the shipboard emergency plans regarding LNG bunker operations, and had drills taken place to test the effectiveness of the shipboard emergency response plans in accordance with company procedures?",
        "short_text": "Emergency plans and drills for LNG bunker operations",
        "vessel_types": [
          "Oil",
          "Chemical",
          "LPG"
        ],
        "objective": "To ensure that the crew will respond effectively to an emergency situation involving LNG bunker operations\nin accordance with the vessel’s shipboard emergency response plans.",
        "negative_grounds": [
          "There was no fuel handling manual for LNG bunkers available.",
          "The fuel handling manual did not include emergency procedures.",
          "The emergency procedures were insufficiently ship-specific.",
          "The accompanying officer was unfamiliar with the emergency procedures contained in the fuel handling",
          "manual for LNG bunkers.",
          "The drill records were not maintained in the format defined by the company procedure.",
          "The drill scenario was unrealistic or inadequate to test the shipboard emergency plan.",
          "Drill dates were inconsistent with the vessel activities as recorded within the Bridge Log Book."
        ],
        "evidence": [
          "The vessel’s fuel handling manual for LNG bunkers.",
          "The emergency response plans for LNG bunkers if not contained within the fuel handling manual.",
          "The records for completed LNG bunker related drills.",
          "The vessel’s Bridge Log Book for the previous twelve months."
        ],
        "risk": "medium",
        "status": "not_started"
      },
      {
        "id": "5.1.18",
        "number": "5.1.18",
        "chapter": "5",
        "section": "5.1",
        "text": "Were the Master and officers familiar with the company procedures setting out the actions to be taken in the event of a cargo leak into a double hull tank, and was all required equipment available and in satisfactory condition?",
        "short_text": "Cargo leak into double hull spaces.",
        "vessel_types": [
          "Oil",
          "Chemical"
        ],
        "objective": "To ensure the crew can respond promptly and effectively in the event of a cargo leak into a double hull tank.",
        "negative_grounds": [
          "There were no company procedures setting out the actions to be taken in the event of a cargo leak into a",
          "The accompanying officer was not familiar with the company procedures setting out the actions to be taken",
          "in the event of a cargo leak into a double hull tank.",
          "The accompanying officer was not familiar with the location of the equipment required by company",
          "procedures setting out the actions to be taken in the event of a cargo leak into a double hull tank.",
          "An item of equipment required by the company procedures setting out the actions to be taken in the event of",
          "a cargo leak into a double hull tank was:"
        ],
        "evidence": [
          "Company procedures setting out the actions to be taken in the event of a cargo leak into a double hull tank.",
          "If available, an inventory of the equipment required by these procedures.",
          "Records of tests for electrical continuity of flexible hoses designated for inerting double hull tanks."
        ],
        "risk": "medium",
        "status": "not_started"
      },
      {
        "id": "5.1.19",
        "number": "5.1.19",
        "chapter": "5",
        "section": "5.1",
        "text": "Were the Master and officers familiar with the emergency arrangements to pump out the spaces forward of the collision bulkhead in the event of flooding and were these arrangements prominently marked and in good order?",
        "short_text": "OBO forward space emergency pumping arrangements",
        "vessel_types": [
          "Oil"
        ],
        "objective": "To ensure forward ballast tanks and dry spaces on OBO and Ore-Oil combination carriers can be pumped\nout safely in the event of flooding.",
        "negative_grounds": [
          "There were no company procedures to pump out the spaces forward of the collision bulkhead in the event of",
          "There was no shipboard emergency response plan for forecastle space flooding.",
          "The company procedures to pump out the spaces forward of the collision bulkhead in the event of flooding",
          "were not ship specific.",
          "The accompanying officer was unfamiliar with company procedures to pump out the spaces forward of the",
          "collision bulkhead in the event of flooding."
        ],
        "evidence": [
          "The company procedures to pump out the spaces forward of the collision bulkhead in the event of flooding.",
          "The shipboard emergency response plan for forecastle space flooding."
        ],
        "risk": "high",
        "status": "not_started"
      },
      {
        "id": "5.2.1",
        "number": "5.2.1",
        "chapter": "5",
        "section": "5.2",
        "text": "Were the Master, officers and ratings familiar with the starting procedure for the emergency fire pump, and were records available to demonstrate that the emergency fire pump and its location had been maintained and tested in accordance with company procedures?",
        "short_text": "Emergency fire pump",
        "vessel_types": [
          "Oil",
          "Chemical",
          "LPG",
          "LNG"
        ],
        "objective": "To ensure that crewmembers can respond effectively to a fire situation in accordance with the shipboard\nemergency plan.",
        "negative_grounds": [
          "There was no company procedure for starting and testing the emergency fire pump.",
          "Where the access to the emergency fire pump space was through the machinery space:",
          "One or both air-lock doors were either open or there was evidence that they had been held open.",
          "The second access door was locked or secured to prevent access to the space from the outer",
          "decks in the event of a fire in the machinery space.",
          "There were no ship-specific starting instructions posted adjacent to the emergency fire pump.",
          "The emergency fire pump sea suction or discharge valves were closed when the pump was designed for"
        ],
        "evidence": [
          "The company procedures for the operation and testing of the emergency fire pump.",
          "The ship-specific procedure for starting the emergency fire pump.",
          "Onboard records for the testing of the emergency fire pump and, where driven by a diesel engine, the",
          "engine and the fuel quick closing valve."
        ],
        "risk": "high",
        "status": "not_started"
      },
      {
        "id": "5.2.2",
        "number": "5.2.2",
        "chapter": "5",
        "section": "5.2",
        "text": "Were the Master, officers and crew familiar with the location, purpose, testing and operation of the vessel’s fire dampers, the means of closing the main inlets and outlets of all ventilation systems and the means of stopping the power ventilation systems from outside the space served?",
        "short_text": "Fire dampers & ventilation stops",
        "vessel_types": [
          "Oil",
          "Chemical",
          "LPG",
          "LNG"
        ],
        "objective": "To ensure that crewmembers can respond effectively to a fire situation in accordance with the shipboard\nemergency plan.",
        "negative_grounds": [
          "The Master, officers or crew were not familiar with the location, purpose and operation of the vessel’s fire",
          "dampers, skylights, closing devices or remote fan stops.",
          "Closing devices did not operate freely.",
          "Closing devices were ineffective due to corrosion, worn gaskets, seized dogs etc.",
          "Closing devices were not clearly marked with the spaces they served or their open/shut positions.",
          "Closing devices were not marked with required warning notices e.g. battery lockers.",
          "Closing devices were not marked with the required position when conduction cargo operations.",
          "An interviewed officer or rating was not familiar with the required position of each closing device while"
        ],
        "evidence": [
          "The vessel’s maintenance plan for vessel’s fire protection systems and fire-fighting systems and appliances.",
          "The records of inspections, tests and maintenance carried out on fire dampers, skylights, closing devices",
          "and remote fan stops.",
          "The vessel specific list of closing devices for ventilation inlets or outlets and their required status while",
          "conducting cargo operations."
        ],
        "risk": "high",
        "status": "not_started"
      },
      {
        "id": "5.2.3",
        "number": "5.2.3",
        "chapter": "5",
        "section": "5.2",
        "text": "Were the Master and officers familiar with the location, purpose and operation of the vessel’s fixed fire detection and fire alarm system, and was the equipment in good working order, regularly inspected, tested and maintained?",
        "short_text": "Fixed fire detection and fire alarm system",
        "vessel_types": [
          "Oil",
          "Chemical",
          "LPG",
          "LNG"
        ],
        "objective": "To ensure that crewmembers can respond effectively to a fire situation in accordance with the shipboard\nemergency plan.",
        "negative_grounds": [
          "There was no company procedure which defined the operation and maintenance of the fixed fire detection",
          "and fire alarm system The Master or officers were not familiar with the location, purpose and operation of the vessel’s fixed fire",
          "detection and fire alarm system The responsible officer was not familiar with the maintenance and testing of the fixed fire detection and fire",
          "The vessel was not provided with the fire detector testing equipment appropriate to each type of fire/smoke",
          "detector in accordance with the manufacturer’s instructions.",
          "Information was not displayed on or adjacent to each indicating unit about the spaces covered and the"
        ],
        "evidence": [
          "The company procedure which defined the requirements for operating and testing the fixed fire detection",
          "and fire alarm system The manufacturer’s instruction manual for the fixed fire detection and fire alarm system.",
          "The inspection, calibration and maintenance records for the fixed fire detection and fire alarm system.",
          "The Engine Room Logbook."
        ],
        "risk": "high",
        "status": "not_started"
      },
      {
        "id": "5.2.4",
        "number": "5.2.4",
        "chapter": "5",
        "section": "5.2",
        "text": "Were the Master and officers familiar with the location, purpose and operation of the vessel’s fixed carbon dioxide fire extinguishing system, and was the equipment in good working order and available for immediate use, with the release procedure and operating instructions displayed at the control stations?",
        "short_text": "Machinery space fixed carbon dioxide fire extinguishing system",
        "vessel_types": [
          "Oil",
          "Chemical",
          "LPG",
          "LNG"
        ],
        "objective": "To ensure that crewmembers can respond effectively to a fire situation in accordance with the shipboard\nemergency plan.",
        "negative_grounds": [
          "There were no safety procedures for entering the CO2 space posted at each entrance door.",
          "The accompanying officer was unfamiliar with the safety precautions for entering the CO2 space.",
          "The CO2 space or release cabinets were locked but there were no keys provided.",
          "The machinery space carbon dioxide fire extinguishing system release procedure, operating instructions and",
          "warning notices were not posted at the release station.",
          "There was no maintenance plan for the vessel’s fire protection systems and fire-fighting systems and",
          "appliances available.",
          "The maintenance plan for the vessel’s fire protection systems and fire-fighting systems and appliances did"
        ],
        "evidence": [
          "The vessel’s maintenance plan for the vessel’s fire protection systems and fire-fighting systems and",
          "appliances.",
          "The records of inspections, tests and maintenance for the machinery space fixed carbon dioxide firefighting"
        ],
        "risk": "high",
        "status": "not_started"
      },
      {
        "id": "5.2.5",
        "number": "5.2.5",
        "chapter": "5",
        "section": "5.2",
        "text": "Were the Master and officers familiar with the location, purpose and operation of the vessel’s machinery space fixed high-expansion foam fire extinguishing system, and was the equipment in good working order, available for immediate use, and with operating instructions clearly displayed at the control stations?",
        "short_text": "Machinery space fixed high-expansion foam fire extinguishing system",
        "vessel_types": [
          "Oil",
          "Chemical",
          "LPG",
          "LNG"
        ],
        "objective": "To ensure that crewmembers can respond effectively to a fire situation in accordance with the shipboard\nemergency plan.\nIndustry Guidelines\nOCIMF/ICS: International Safety Guide for Oil Tankers and Terminals. Sixth Edition.\nChapter 5 Fire Protection\n5.3.2.1.1 Categories of foam\nTwo categories of foam concentrate are currently in use.\nProtein foam concentrates are used at 3-6% by volume concentration in water. They include:\n• Protein foam (P) made from hydrolysed protein materials.\n• Fluoroprotei",
        "negative_grounds": [
          "The machinery space fixed high-expansion foam fire extinguishing system release procedure, operating",
          "instructions and warning notices, in the working language of the ship, were not posted at the release station.",
          "The valves and/or system controls were not clearly identified to their purpose and required status during",
          "The foam concentrate test had not been carried out within the required time frame.",
          "The foam concentrate test certificate indicated that the foam was not fit for continued use.",
          "Where the system also provided protection for a cargo pump room, the foam concentrate was incompatible",
          "with the cargo being carried and no alternative arrangement, to the satisfaction of the Flag Administration,"
        ],
        "evidence": [
          "The vessel’s maintenance plan for the vessel’s fire protection systems and fire-fighting systems and",
          "appliances.",
          "The records of inspections, tests and maintenance carried out on the machinery space fixed high-expansion",
          "foam fire extinguishing system, including: o The annual foam concentrate test results.",
          "o The five-yearly test of foam proportioners or other foam mixing devices."
        ],
        "risk": "high",
        "status": "not_started"
      },
      {
        "id": "5.2.6",
        "number": "5.2.6",
        "chapter": "5",
        "section": "5.2",
        "text": "Were the Master and officers familiar with the location, purpose and operation of the vessel’s machinery space fixed pressure water-spraying fire extinguishing system, and was the equipment in good working order and available for immediate use, with operating instructions clearly displayed at the control stations?",
        "short_text": "Machinery space fixed pressure water-spraying fire extinguishing system",
        "vessel_types": [
          "Oil",
          "Chemical",
          "LPG",
          "LNG"
        ],
        "objective": "To ensure that crewmembers can respond effectively to a fire situation in accordance with the shipboard\nemergency plan.\nIndustry guidance\nOCIMF: International Safety Guide for Oil Tankers and Terminals. Sixth Edition\n5.3.1.2 Water mist\nWater mist fire protection systems use a spray mist to absorb heat and displace oxygen. They are effective in\naccommodation spaces and areas within the engine room. These systems consist of a water supply connected to an\natomising distribution system that can deli",
        "negative_grounds": [
          "The machinery space fixed pressure water-spraying fire-extinguishing system or the equivalent water mist",
          "fire-extinguishing system release procedure, operating instructions and warning notices were not posted at",
          "the release stations in the working language of the ship.",
          "The valves and/or system controls were not clearly identified to their purpose and required status during",
          "There was no maintenance plan for the vessel’s fire protection systems and firefighting systems and",
          "appliances available.",
          "The maintenance plan for the vessel’s fire protection systems and firefighting systems and appliances did"
        ],
        "evidence": [
          "The vessel’s maintenance plan for vessel’s fire protection systems and firefighting systems and appliances.",
          "The records of inspections, tests and maintenance carried out on the machinery space fixed pressure water-",
          "spraying fire extinguishing system, including quarterly system water quality assessments."
        ],
        "risk": "high",
        "status": "not_started"
      },
      {
        "id": "5.2.7",
        "number": "5.2.7",
        "chapter": "5",
        "section": "5.2",
        "text": "Were the Master and officers familiar with the location, purpose and operation of the vessel’s fire pumps, fire main, fire main isolating valves and fire hydrants, and was the system and its components in good working order and available for immediate use?",
        "short_text": "Fire pumps, fire main, fire main isolating valves and fire hydrants",
        "vessel_types": [
          "Oil",
          "Chemical",
          "LPG",
          "LNG"
        ],
        "objective": "To ensure that crewmembers can respond effectively to a fire situation in accordance with the shipboard\nemergency plan.",
        "negative_grounds": [
          "The fire pumps could not be started remotely from the navigating bridge or fire control station.",
          "There was no means to verify the delivery pressure on the fire main either on the navigating bridge or at the",
          "fire control station.",
          "Fire hydrant valves or fire main isolating valves did not operate freely.",
          "Fire main isolation valves were found to be closed.",
          "There was hard rust, deterioration or temporary repairs to the fire main pipework.",
          "The fire pump suction or delivery valves were found to be closed The fire hydrant or fire main isolating valves were not clearly marked."
        ],
        "evidence": [
          "The vessel’s maintenance plan for vessel’s fire protection systems and fire-fighting systems and appliances.",
          "The records of inspections, tests and maintenance carried out on the fire mains, fire pumps, isolating valves",
          "and hydrants."
        ],
        "risk": "high",
        "status": "not_started"
      },
      {
        "id": "5.2.8",
        "number": "5.2.8",
        "chapter": "5",
        "section": "5.2",
        "text": "Were the Master, officers and galley staff familiar with the location, purpose and operation of the fixed and portable fire extinguishing systems provided in the galley, were the systems in good working order and available for immediate use, and were galley ranges, exhaust vents, filter cowls free of grease or combustible material?",
        "short_text": "Galley fixed and portable fire extinguishing systems & fire prevention",
        "vessel_types": [
          "Oil",
          "Chemical",
          "LPG",
          "LNG"
        ],
        "objective": "To ensure that the fire protection measures provided in the galley are properly maintained and crewmembers\ncan respond effectively to a fire situation in accordance with the shipboard emergency plan.",
        "negative_grounds": [
          "There were no instructions posted in the galley describing the use of the fixed fire extinguishing systems",
          "The interviewed galley staff were not familiar with the purpose and operation of the fixed or portable fire",
          "extinguishing or fire protection systems in the galley.",
          "Oily or fatty deposits were found on galley ranges, in grease traps, within flue pipes, around fire",
          "extinguishing nozzles, around fire detector heads and in the filter cowls of galley vents.",
          "There was evidence that deep fat frying had been taking place using open pans or a fixed deep fat fryer with",
          "no fixed fire extinguishing system.",
          "Automatic self-closing fire doors or serving hatch shutters were found to be held back or restricted from"
        ],
        "evidence": [
          "The vessel’s maintenance plan for vessel’s fire protection systems and fire-fighting systems and appliances.",
          "The records of inspections, tests and maintenance carried out on the galley fire extinguishing systems."
        ],
        "risk": "high",
        "status": "not_started"
      },
      {
        "id": "5.2.9",
        "number": "5.2.9",
        "chapter": "5",
        "section": "5.2",
        "text": "Were the Master and officers familiar with the location, purpose and operation of the water-spray system for cooling, fire prevention and crew protection on deck, and was the equipment in good working order, regularly inspected, tested and maintained?",
        "short_text": "Water-spray system on deck",
        "vessel_types": [
          "LPG",
          "LNG"
        ],
        "objective": "To ensure that crewmembers can respond effectively to a fire situation in accordance with the shipboard\nemergency plan.",
        "negative_grounds": [
          "The accompanying officer was not familiar with the location, purpose and operation of the vessel’s water-",
          "spray system for cooling, fire prevention and crew protection on deck.",
          "The accompanying officer was unfamiliar with the maintenance plan for the vessel’s fire protection systems",
          "and fire-fighting systems and appliances.",
          "The operating instructions for the water-spray system were not posted at the control station.",
          "Access to the system controls was obstructed.",
          "The system valves and controls were not properly marked or set.",
          "Stop valves or isolating valves did not operate freely."
        ],
        "evidence": [
          "The vessel’s maintenance plan for vessel’s fire protection systems and fire-fighting systems and appliances.",
          "The records of inspections, tests and maintenance carried out on the water-spray system for cooling, fire",
          "prevention and crew protection on deck."
        ],
        "risk": "high",
        "status": "not_started"
      },
      {
        "id": "5.2.10",
        "number": "5.2.10",
        "chapter": "5",
        "section": "5.2",
        "text": "Were the Master and officers familiar with the location, purpose and operation of the fixed fire extinguishing system installed within enclosed spaces containing cargo handling equipment, and was the equipment in good working order and available for immediate use, with the release procedure and operating instructions displayed at the control stations?",
        "short_text": "Cargo handling equipment space(s) fixed fire extinguishing system",
        "vessel_types": [
          "LPG",
          "LNG"
        ],
        "objective": "To ensure that crewmembers can respond effectively to a fire situation in accordance with the shipboard\nemergency plan.",
        "negative_grounds": [
          "There were no company procedures for the operation, inspection and maintenance of the fixed fire",
          "extinguishing system installed within enclosed spaces containing cargo handling equipment that included:",
          "A description of the fixed fire extinguishing system, its components, and its functions.",
          "Instructions for the operation of the fixed fire extinguishing system.",
          "There was no maintenance plan for the vessel’s fire protection systems and fire-fighting systems and",
          "appliances available.",
          "The maintenance plan for the vessel’s fire protection systems and fire-fighting systems and appliances did"
        ],
        "evidence": [
          "The company procedures for the operation, inspection and maintenance of the fixed fire extinguishing",
          "system installed within enclosed spaces containing cargo handling equipment.",
          "Records of inspections, tests and maintenance of the fixed fire extinguishing system installed within",
          "enclosed spaces containing cargo handling equipment."
        ],
        "risk": "high",
        "status": "not_started"
      },
      {
        "id": "5.2.11",
        "number": "5.2.11",
        "chapter": "5",
        "section": "5.2",
        "text": "Were the Master and officers familiar with the location, purpose and operation of the vessel’s fixed dry chemical powder fire extinguishing system, and was the equipment in good working order and readily available for immediate use, with operating instructions clearly displayed at the control stations.",
        "short_text": "Fixed dry chemical powder fire extinguishing system",
        "vessel_types": [
          "LPG",
          "LNG"
        ],
        "objective": "To ensure that crewmembers can respond effectively to a fire situation in accordance with the shipboard\nemergency plan.",
        "negative_grounds": [
          "The cargo area fixed dry chemical powder extinguishing system operating instructions were not posted at",
          "each operating station in the working language of the ship.",
          "The system controls and valves were not clearly marked in accordance with the operating instructions.",
          "There was no maintenance plan for the vessel’s fire protection systems and fire-fighting systems and",
          "appliances available.",
          "The maintenance plan for the vessel’s fire protection systems and fire-fighting systems and appliances did",
          "not include the vessel’s fixed dry chemical powder fire-extinguishing system or all the required inspections,",
          "tests and maintenance."
        ],
        "evidence": [
          "The vessel’s maintenance plan for the vessel’s fire protection systems and fire-fighting systems and",
          "appliances.",
          "The records of inspections, tests and maintenance carried out on the cargo area fixed dry chemical powder",
          "extinguishing system including: o The annual agitation of the dry powder by nitrogen.",
          "o The two-yearly testing of a sample of dry chemical powder for moisture content."
        ],
        "risk": "high",
        "status": "not_started"
      },
      {
        "id": "5.2.12",
        "number": "5.2.12",
        "chapter": "5",
        "section": "5.2",
        "text": "Were the Master and officers familiar with the location, purpose and operation of the fixed fire-extinguishing system in the vessel’s paint locker and any other flammable liquid locker, and was the system in good working order and available for immediate use?",
        "short_text": "Paint locker fixed fire-extinguishing system",
        "vessel_types": [
          "Oil",
          "Chemical",
          "LPG",
          "LNG"
        ],
        "objective": "To ensure that crewmembers can respond effectively to a fire situation in accordance with the shipboard\nemergency plan.",
        "negative_grounds": [
          "There were no instructions posted outside a paint or flammable liquids locker describing the use of the fixed",
          "fire extinguishing system provided.",
          "The accompanying officer was not familiar with the purpose and operation of the fixed fire extinguishing",
          "system in a paint or other flammable liquid locker.",
          "Paints or flammable liquids were found stored in lockers or locations not designed to contain flammable",
          "Paints or flammable liquids were stored in open containers The maintenance plan for the vessel’s fire protection systems and fire-fighting systems and appliances did",
          "not include the fixed fire extinguishing system for paint and flammable liquid lockers or all the required"
        ],
        "evidence": [
          "The vessel’s maintenance plan for vessel’s fire protection systems and fire-fighting systems and appliances.",
          "The records of inspections, tests and maintenance carried out on the paint or flammable liquid locker fixed",
          "fire extinguishing systems."
        ],
        "risk": "high",
        "status": "not_started"
      },
      {
        "id": "5.2.13",
        "number": "5.2.13",
        "chapter": "5",
        "section": "5.2",
        "text": "Were the Master and officers familiar with the location, purpose and operation of the machinery space fixed water-based or equivalent local application fire-fighting system, and was the equipment in good working order and readily available for immediate use, with operating instructions clearly displayed at the control stations?",
        "short_text": "Machinery space fixed water-based or equivalent local application fire-fighting system",
        "vessel_types": [
          "Oil",
          "Chemical",
          "LPG",
          "LNG"
        ],
        "objective": "To ensure that crewmembers can respond effectively to a fire situation in accordance with the shipboard\nemergency plan\nIndustry guidance\nOCIMF: International Safety Guide for Oil Tankers and Terminals. Sixth Edition\n5.3.1.2 Water mist\nWater mist fire protection systems use a spray mist to absorb heat and displace oxygen. They are effective in\naccommodation spaces and areas within the engine room. These systems consist of a water supply connected to an\natomising distribution system that can deliv",
        "negative_grounds": [
          "There was no company procedure which described the use of the automatic release mode of the fixed",
          "water-based local application fire-fighting system where this function was provided.",
          "The accompanying officer was not familiar with the purpose, operation and required operating mode of the",
          "The accompanying officer was unfamiliar with the maintenance plan for the vessel’s fire protection systems",
          "and fire-fighting systems and appliances.",
          "There were no operating instructions in the working language of the ship posted at the system control",
          "The system was not set on automatic release mode when required by the company procedure.",
          "The machinery space was being operated in the unattended mode with the system in manual release mode."
        ],
        "evidence": [
          "The vessel’s maintenance plan for the vessel’s fire protection systems and fire-fighting systems and",
          "appliances.",
          "The records of inspections, tests and maintenance carried out on the fixed water-based local application fire-",
          "fighting system."
        ],
        "risk": "high",
        "status": "not_started"
      },
      {
        "id": "5.2.14",
        "number": "5.2.14",
        "chapter": "5",
        "section": "5.2",
        "text": "Were the Master and officers familiar with the purpose of the cargo, ballast and stripping pump temperature sensing devices, and was there evidence that alarm activation points had been correctly set and tested in accordance with company procedures and manufacturer's instructions?",
        "short_text": "Cargo, ballast and stripping pump temperature sensing devices",
        "vessel_types": [
          "Oil",
          "Chemical"
        ],
        "objective": "To ensure that measures specifically designed to prevent fires in the cargo pump room are effective.",
        "negative_grounds": [
          "There was no company procedure for the operation and maintenance of the cargo, ballast and stripping",
          "pump temperature sensing system.",
          "The accompanying officer was unfamiliar with the operation of the cargo, ballast and stripping pump",
          "temperature sensing system.",
          "The accompanying officer was unfamiliar with the alarm activation settings of the cargo, ballast and stripping",
          "pump temperature sensing system.",
          "There were no records maintained for the temperature of bulkhead shaft glands, bearings and pump casings",
          "for cargo, ballast or stripping pumps in operation."
        ],
        "evidence": [
          "The company procedures for the maintenance and operation of the cargo, ballast and stripping pump",
          "temperature sensing system.",
          "The records of temperature sensing device readings for cargo, ballast and stripping pumps while in",
          "The manufacturer’s instruction manual for the cargo, ballast and stripping pump temperature sensing"
        ],
        "risk": "medium",
        "status": "not_started"
      },
      {
        "id": "5.2.15",
        "number": "5.2.15",
        "chapter": "5",
        "section": "5.2",
        "text": "Were the Master, officers and ratings familiar with the purpose and operation of the vessel’s deck foam system, including portable applicators, and was the system in good working order and available for immediate use, with operating instructions displayed at the control station?",
        "short_text": "Deck foam system, including portable applicators",
        "vessel_types": [
          "Oil",
          "Chemical"
        ],
        "objective": "To ensure that crewmembers can respond effectively to a fire situation in accordance with the shipboard\nemergency plan.",
        "negative_grounds": [
          "The deck foam system operating instructions, in the working language of the ship, were not posted in the",
          "space containing the foam concentrate tank, pumps and control station.",
          "The valves and/or system controls were not clearly identified to their purpose and required status during",
          "The foam storage tank was not filled to the required level.",
          "The foam concentrate test had not been carried out within the required time frame.",
          "The foam concentrate test certificate indicated that the foam was not fit for continued use.",
          "The foam concentrate was incompatible with the cargo being carried but no alternative arrangement, to the"
        ],
        "evidence": [
          "The vessel’s maintenance plan for the vessel’s fire protection systems and fire-fighting systems and",
          "appliances.",
          "The records of inspections, tests and maintenance carried out on the deck foam system, including:",
          "o The annual foam concentrate test results.",
          "o The five-yearly test of foam proportioners or other foam mixing devices.",
          "The system manual showing the quantity of foam concentrate required to be in the storage tank to meet the"
        ],
        "risk": "medium",
        "status": "not_started"
      },
      {
        "id": "5.2.16",
        "number": "5.2.16",
        "chapter": "5",
        "section": "5.2",
        "text": "Were the Master, officers and crew familiar with the location, purpose, testing and operation of the vessel’s fire doors?",
        "short_text": "Fire doors",
        "vessel_types": [
          "Oil",
          "Chemical",
          "LPG",
          "LNG"
        ],
        "objective": "To ensure that crewmembers can respond effectively to a fire situation in accordance with the shipboard\nemergency plan.",
        "negative_grounds": [
          "There was no company procedure which defined the frequency of inspections, tests and maintenance for",
          "The Master, officers or ratings were not familiar with the location, purpose and operation of the vessel’s fire",
          "A replacement fire door did not meet the minimum fire rating as indicated on the Fire Control Plan.",
          "Fire door self-closing devices did not operate properly.",
          "Fire doors and/or their frames, where appropriate, were:",
          "Held back by non-approved methods such as tiebacks, hooks, wedges or other such Corroded or wasted.",
          "Subject to inappropriate cable penetrations."
        ],
        "evidence": [
          "The vessel’s maintenance plan for vessel’s fire protection systems and fire-fighting systems and appliances.",
          "The records of inspections, tests and maintenance carried out on fire doors.",
          "The Fire Control Plan."
        ],
        "risk": "high",
        "status": "not_started"
      },
      {
        "id": "5.3.1",
        "number": "5.3.1",
        "chapter": "5",
        "section": "5.3",
        "text": "Were the Master, officers and ratings familiar with the location and use of the vessel’s firefighter’s outfits including the self-contained breathing apparatus (SCBA), and was the equipment maintained in good condition and ready for immediate use in accordance with company procedures?",
        "short_text": "Firefighter’s outfits including self-contained breathing apparatus (SCBA)",
        "vessel_types": [
          "Oil",
          "Chemical",
          "LPG",
          "LNG"
        ],
        "objective": "To ensure that crewmembers can respond effectively to a fire or enclosed space rescue situation in\naccordance with the shipboard emergency plans.",
        "negative_grounds": [
          "The firefighter’s suits or SCBAs were not stored in the correct location in accordance with the fire plan;",
          "unless they were in position for cargo operations in accordance with company procedures.",
          "The firefighter’s outfits were incomplete or defective in any respect.",
          "The SCBAs and firefighter's outfits were not prepared for immediate use with a fully charged bottle and the",
          "required spare bottle(s).",
          "A SCBA was defective in any respect.",
          "The electric safety lamps were not explosion proof type 1."
        ],
        "evidence": [
          "The vessel’s maintenance plan for vessel’s fire protection systems and firefighting systems and appliances.",
          "The records of inspections, tests and maintenance carried out on: o The firefighter’s outfits.",
          "o The SCBAs.",
          "o The spare SCBA cylinders.",
          "o The breathing air compressor including air quality checks."
        ],
        "risk": "high",
        "status": "not_started"
      },
      {
        "id": "5.3.2",
        "number": "5.3.2",
        "chapter": "5",
        "section": "5.3",
        "text": "Were the Master, officers and crew familiar with the location, purpose and operation of the vessel’s fire hoses, nozzles and international shore connection, and was the equipment in good working order and available for immediate use?",
        "short_text": "Fire hoses, nozzles and international shore connection",
        "vessel_types": [
          "Oil",
          "Chemical",
          "LPG",
          "LNG"
        ],
        "objective": "To ensure that crewmembers can respond effectively to a fire situation in accordance with the shipboard\nemergency plan.",
        "negative_grounds": [
          "Fire hoses, nozzles or international shore connections were missing from the locations shown on the fire",
          "control plan unless laid out for cargo or bunker operations.",
          "Fire hoses, nozzles or international shore connections were not ready for immediate use.",
          "Fire hoses were either less than 10m in length or longer than the maximum permitted for their location.",
          "The required gaskets, nuts, washers or recommended spanners were missing from the international shore",
          "connection(s) storage location.",
          "The accompanying officer was not familiar with the purpose and operation of the fire hoses, nozzles and",
          "international shore connections."
        ],
        "evidence": [
          "The vessel’s maintenance plan for vessel’s fire protection systems and fire-fighting systems and appliances.",
          "The records of inspections, tests and maintenance carried out on the fire hoses, nozzles and international",
          "shore connections."
        ],
        "risk": "high",
        "status": "not_started"
      },
      {
        "id": "5.3.3",
        "number": "5.3.3",
        "chapter": "5",
        "section": "5.3",
        "text": "Were the Master, officers and ratings familiar with the location, purpose and operation of the vessel’s portable fire extinguishers, and were the extinguishers in good order and readily available for immediate use with operating instructions clearly marked?",
        "short_text": "Portable fire extinguishers",
        "vessel_types": [
          "Oil",
          "Chemical",
          "LPG",
          "LNG"
        ],
        "objective": "To ensure that crewmembers can respond effectively to a fire situation in accordance with the shipboard\nemergency plan.",
        "negative_grounds": [
          "Fire extinguisher(s) were missing or not located as shown in the Fire Control Plan.",
          "The fire control plan did not comply with MSC.1/Circ.1275 with regards to the distribution of fire",
          "extinguishers. (for ships constructed before 1 January 2009 make a comment only in the Hardware",
          "Fire extinguisher(s) were not fully charged.",
          "Fire extinguisher(s) were not readily available for immediate use."
        ],
        "evidence": [
          "The Fire Control Plan.",
          "The maintenance plan for fire protection systems and fire-fighting systems and appliances.",
          "Records of inspections, tests and maintenance carried out on portable fire extinguishers required by the",
          "maintenance plan.",
          "Inventory of spare fire extinguisher charges and/or spare fire extinguishers."
        ],
        "risk": "high",
        "status": "not_started"
      },
      {
        "id": "5.3.4",
        "number": "5.3.4",
        "chapter": "5",
        "section": "5.3",
        "text": "Were the Master, officers and ratings familiar with the location and purpose of the Emergency Escape Breathing Devices (EEBDs) carried on board, and were these devices in good order, suitably located and ready for immediate use?",
        "short_text": "Emergency Escape Breathing Devices (EEBDs)",
        "vessel_types": [
          "Oil",
          "Chemical",
          "LPG",
          "LNG"
        ],
        "objective": "To ensure that Emergency Escape Breathing Devices (EEBDs) are readily available to personnel in the event\nof a fire or any other emergency on the vessel.",
        "negative_grounds": [
          "There were no company procedures for the use and maintenance of EEBDs.",
          "The accompanying officer was not familiar with the location, inspection and maintenance of the EEBDs.",
          "The EEBDs were not positioned in accordance with the fire control plan.",
          "There were fewer spare EEBDs onboard than indicated on the fire control plan.",
          "An inspected EEBD was found defective in any respect, including:",
          "The cylinder pressure was outside the normal range.",
          "The unit was passed its expiry date.",
          "The donning instructions could not be read."
        ],
        "evidence": [
          "The company procedure for the use and maintenance of EEBDs The inspection and maintenance records for the EEBDs contained within the onboard maintenance plan."
        ],
        "risk": "high",
        "status": "not_started"
      },
      {
        "id": "5.3.5",
        "number": "5.3.5",
        "chapter": "5",
        "section": "5.3",
        "text": "Were the Master, officers and engine ratings familiar with the purpose and operation of the vessel’s wheeled (mobile) fire extinguishers, and was the equipment in good order and available for immediate use with operating instructions clearly marked?",
        "short_text": "Wheeled (mobile) fire extinguishers",
        "vessel_types": [
          "Oil",
          "Chemical",
          "LPG",
          "LNG"
        ],
        "objective": "To ensure that crewmembers can respond effectively to a fire situation in accordance with the shipboard\nemergency plan.",
        "negative_grounds": [
          "A wheeled fire extinguisher(s) was not:",
          "Readily available for immediate use.",
          "Marked with the required information.",
          "Marked with the date of onboard inspections or servicing.",
          "Included in the maintenance plan for fire protection systems and fire-fighting systems and",
          "A wheeled fire extinguisher(s) was:",
          "Missing or not located as shown in the fire control plan.",
          "Defective in any respect."
        ],
        "evidence": [
          "The fire control plan The maintenance plan for fire protection systems and fire-fighting systems and appliances.",
          "Records of inspections, tests and maintenance carried out on wheeled fire extinguishers required by the",
          "maintenance plan.",
          "Inventory of spare charges."
        ],
        "risk": "high",
        "status": "not_started"
      },
      {
        "id": "5.4.1",
        "number": "5.4.1",
        "chapter": "5",
        "section": "5.4",
        "text": "Were the Master and officers familiar with the operation of the davit-launched lifeboats, release mechanisms and launching appliances, and were they in good order with records available to demonstrate that they had been inspected and tested as required?",
        "short_text": "Davit-launched lifeboats, release mechanisms and launching appliances",
        "vessel_types": [
          "Oil",
          "Chemical",
          "LPG",
          "LNG"
        ],
        "objective": "To ensure the lifeboats, release mechanisms and launching appliances will be ready for immediate use in an\nemergency.",
        "negative_grounds": [
          "There was no procedure to ensure the lifeboats, release mechanisms and launching appliances were",
          "periodically inspected and tested and ready for immediate use in an emergency.",
          "The accompanying officer was unfamiliar with the operation of the lifeboats, release mechanisms and",
          "launching appliances.",
          "The accompanying officer was unfamiliar with the required inspection and testing of the lifeboats, release",
          "mechanisms and launching appliances.",
          "Records of weekly and monthly inspections and routine maintenance of the lifeboats, release mechanisms",
          "and launching appliances were incomplete."
        ],
        "evidence": [
          "The company procedure to ensure lifeboats, release mechanisms and launching appliances were",
          "periodically inspected and tested and ready for immediate use in an emergency.",
          "A copy of the monthly inspection checklist required by SOLAS III/36.",
          "The Bridge Log Book.",
          "Records of periodic inspections and tests of the lifeboats, release mechanisms and launching appliances."
        ],
        "risk": "medium",
        "status": "not_started"
      },
      {
        "id": "5.4.2",
        "number": "5.4.2",
        "chapter": "5",
        "section": "5.4",
        "text": "Were the Master and officers familiar with the operation of the free-fall lifeboat, its release systems and its launching appliance, and was the equipment in satisfactory condition with records available to demonstrate that it had been inspected and tested in accordance with company procedures?",
        "short_text": "Free-fall lifeboat, its release systems and its launching appliance",
        "vessel_types": [
          "Oil",
          "Chemical",
          "LPG",
          "LNG"
        ],
        "objective": "To ensure the free-fall lifeboat, its release system and launching appliance will be ready for immediate use in\nan emergency.",
        "negative_grounds": [
          "There was no company procedure to ensure the free-fall lifeboat, its release systems, launching appliance",
          "and recovery equipment were periodically inspected and tested and ready for immediate use in an",
          "The accompanying officer was unfamiliar with the operation of the free-fall lifeboat, its release systems,",
          "launching appliance and recovery equipment.",
          "The accompanying officer was unfamiliar with the required inspection and testing of the free-fall lifeboat, its",
          "release systems, launching appliance and recovery equipment.",
          "Records of weekly and monthly inspections and routine maintenance of the free-fall lifeboat, its release",
          "systems, launching appliance and recovery equipment were incomplete."
        ],
        "evidence": [
          "The company procedure to ensure the free-fall lifeboat, its release system and launching appliance were",
          "periodically inspected and tested and ready for immediate use in an emergency.",
          "A copy of the monthly inspection checklist required by SOLAS III/36.",
          "The Bridge Log Book.",
          "Records of thorough examination and operational tests of the free-fall lifeboat, its release systems,",
          "launching appliance and recovery equipment."
        ],
        "risk": "high",
        "status": "not_started"
      },
      {
        "id": "5.4.3",
        "number": "5.4.3",
        "chapter": "5",
        "section": "5.4",
        "text": "Were the Master and officers familiar with the operation of the dedicated rescue boat and launching appliance, and were they in good order with records available to demonstrate that they had been inspected and tested as required?",
        "short_text": "Dedicated rescue boat and launching appliance",
        "vessel_types": [
          "Oil",
          "Chemical",
          "LPG",
          "LNG"
        ],
        "objective": "To ensure the rescue boat will be ready for immediate use in an emergency.",
        "negative_grounds": [
          "The accompanying officer was unfamiliar with the operation of the rescue boat and launching appliance.",
          "The accompanying officer was unfamiliar with the required inspection and testing of the rescue boat and",
          "Records of weekly and monthly inspections and routine maintenance of the rescue boat and launching",
          "appliance were incomplete.",
          "Records of annual and five-yearly thorough examinations and tests of the rescue boat and launching",
          "appliance were incomplete.",
          "A full set of maintenance manuals and associated technical documentation for the rescue boat and"
        ],
        "evidence": [
          "The company procedure to ensure the rescue boat and launching appliance were periodically inspected and",
          "tested and ready for immediate use in an emergency.",
          "The Bridge Log Book.",
          "Records of periodic inspections and tests of the rescue boat and launching appliance."
        ],
        "risk": "medium",
        "status": "not_started"
      },
      {
        "id": "5.4.4",
        "number": "5.4.4",
        "chapter": "5",
        "section": "5.4",
        "text": "Were the Master and Officers familiar with the location, purpose and operation of the rocket parachute flares and line throwing appliances and were they in good order, with records available to demonstrate that had they had been inspected as required?",
        "short_text": "Rocket parachute flares and line throwing appliances",
        "vessel_types": [
          "Oil",
          "Chemical",
          "LPG",
          "LNG"
        ],
        "objective": "To ensure the rocket parachute flares and line throwing appliances will function correctly in an emergency.",
        "negative_grounds": [
          "There was no company procedure to ensure that rocket parachute flares and line throwing appliances were",
          "periodically inspected and ready for immediate use in an emergency.",
          "The accompanying officer was unfamiliar with the purpose and operation of the rocket parachute flares and",
          "line throwing appliances.",
          "The accompanying officer was unfamiliar with the required inspection of the rocket parachute flares and line",
          "There were insufficient rocket parachute flares or line throwing appliances on board.",
          "The stowage location(s) of rocket parachute flares and line throwing appliances were not clearly marked"
        ],
        "evidence": [
          "The company procedure to ensure that rocket parachute flares and line throwing appliances were",
          "periodically inspected and ready for immediate use in an emergency.",
          "Records of periodic inspections of the rocket parachute flares and line throwing appliances."
        ],
        "risk": "medium",
        "status": "not_started"
      },
      {
        "id": "5.4.5",
        "number": "5.4.5",
        "chapter": "5",
        "section": "5.4",
        "text": "Were the Master and officers familiar with the operation of the liferafts, hydrostatic releases and liferaft launching appliances, where provided, and were they in good order with records available to demonstrate that they had been serviced, inspected and tested as required?",
        "short_text": "Liferafts, hydrostatic releases and liferaft launching appliances",
        "vessel_types": [
          "Oil",
          "Chemical",
          "LPG",
          "LNG"
        ],
        "objective": "To ensure that liferafts, hydrostatic releases and, liferaft launching appliances, where fitted, will function\ncorrectly in an emergency.",
        "negative_grounds": [
          "The accompanying officer was unfamiliar with the operation of the liferafts, hydrostatic releases and, liferaft",
          "launching appliances, where provided.",
          "The accompanying officer was unfamiliar with the required servicing, inspection and testing of the liferafts,",
          "hydrostatic releases and, liferaft launching appliances, where provided.",
          "There was insufficient liferaft capacity for the number of people on board.",
          "A liferaft was not in a state of continuous readiness in any respect except where the liferafts had been",
          "removed for shore servicing after arrival in port and would be replaced before departure.",
          "A liferaft, other than a remotely located survival craft, was not capable of floating free from the ship."
        ],
        "evidence": [
          "The company procedure to ensure liferafts, and launching appliances if fitted, were periodically inspected",
          "and tested and ready for immediate use in an emergency.",
          "The Bridge Log Book.",
          "Records of periodic servicing, inspection and tests of the liferafts, hydrostatic releases and, launching",
          "appliances, where provided."
        ],
        "risk": "medium",
        "status": "not_started"
      },
      {
        "id": "5.4.6",
        "number": "5.4.6",
        "chapter": "5",
        "section": "5.4",
        "text": "Were the lifebuoys, and associated lights, smoke floats and lifelines, in good order, clearly marked and correctly distributed around the ship?",
        "short_text": "Lifebuoys, and associated lights, smoke floats and lifelines",
        "vessel_types": [
          "Oil",
          "Chemical",
          "LPG",
          "LNG"
        ],
        "objective": "To ensure that all life-saving appliances are in working order and ready for immediate use.",
        "negative_grounds": [
          "Less than the required number of lifebuoys.",
          "An insufficient number of lifebuoys with lights A lifebuoy fitted with both light and lifeline.",
          "No lifebuoy on either side with a buoyant lifeline of the required length.",
          "Lifebuoys were not readily available on both sides of the ship, on each open deck or in the vicinity of the",
          "Lifebuoy stowage locations were not clearly marked with the approved symbols.",
          "Not marked with retro-reflective tape.",
          "Not clearly marked with ship’s name and port of registry."
        ],
        "evidence": [
          "The company procedure to ensure that lifebuoys, and associated lights, smoke floats and lifelines, were in",
          "good order, clearly marked and correctly distributed around the ship.",
          "The checklist and log for records of monthly inspections and maintenance of the lifebuoys."
        ],
        "risk": "medium",
        "status": "not_started"
      },
      {
        "id": "5.4.7",
        "number": "5.4.7",
        "chapter": "5",
        "section": "5.4",
        "text": "Were the Master, officers and ratings familiar with the immersion suits, and were the immersion suits in good order, readily accessible and their location(s) clearly indicated?",
        "short_text": "Immersion suits",
        "vessel_types": [
          "Oil",
          "Chemical",
          "LPG",
          "LNG"
        ],
        "objective": "To ensure that all life-saving appliances are in working order and ready for immediate use.",
        "negative_grounds": [
          "There was no company procedure which defined the actions to be taken to ensure that immersion suits are",
          "in good order, readily accessible and their location(s) clearly indicated.",
          "The accompanying officer was unfamiliar with the required inspection and tests required to be carried out for",
          "the immersion suits in accordance with the company procedures.",
          "An interviewed officer or rating was not familiar with the instructions for donning an immersion suit.",
          "An immersion suit of an appropriate size was not provided for each person on board."
        ],
        "evidence": [
          "The company procedures to ensure that immersion suits are in good order, readily accessible and their",
          "location(s) clearly indicated.",
          "Records of monthly inspections and periodic air-pressure tests of the ship’s immersion suits."
        ],
        "risk": "medium",
        "status": "not_started"
      },
      {
        "id": "5.4.8",
        "number": "5.4.8",
        "chapter": "5",
        "section": "5.4",
        "text": "Were the Master, officers and ratings familiar with the lifejackets and personal flotation devices (PFDs) provided on board, and was the equipment in good condition, and properly maintained?",
        "short_text": "Lifejackets and personal flotation devices (PFDs)",
        "vessel_types": [
          "Oil",
          "Chemical",
          "LPG",
          "LNG"
        ],
        "objective": "To ensure that all life-saving appliances are in working order and ready for immediate use.",
        "negative_grounds": [],
        "evidence": [],
        "risk": "low",
        "status": "not_started"
      },
      {
        "id": "5.4.9",
        "number": "5.4.9",
        "chapter": "5",
        "section": "5.4",
        "text": "Were the Master and officers familiar with the company procedures for the periodic testing and maintenance of the emergency lighting system, was there evidence of periodic testing, and was the system in proper operating condition?",
        "short_text": "Emergency lighting.",
        "vessel_types": [
          "Oil",
          "Chemical",
          "LPG",
          "LNG"
        ],
        "objective": "To ensure that the emergency lighting system will operate correctly in the event of a loss of primary power\nand lighting.",
        "negative_grounds": [
          "There were no company procedures for the inspection and testing of the emergency lighting system.",
          "Company procedures did not require the emergency lighting to be inspected and tested at least once per",
          "The responsible officer was not familiar with company procedures for the inspection and testing of the",
          "emergency lighting system.",
          "The accompanying officer was not familiar with the location of the switches to turn on the emergency source",
          "Records indicated that emergency lighting had not been inspected and tested in compliance with company",
          "There were no records of the inspection and testing of the emergency lighting system.",
          "One or more emergency lights were:"
        ],
        "evidence": [
          "Company procedures for the inspection and testing of the emergency lighting system.",
          "Records of inspection and testing of the emergency lighting system."
        ],
        "risk": "medium",
        "status": "not_started"
      },
      {
        "id": "5.5.1",
        "number": "5.5.1",
        "chapter": "5",
        "section": "5.5",
        "text": "Were the Master, officers and ratings familiar with the company enclosed space entry procedures, and was evidence available to demonstrate that all enclosed space entries had been made in strict compliance with the procedures?",
        "short_text": "Enclosed space entry procedures",
        "vessel_types": [
          "Oil",
          "Chemical",
          "LPG",
          "LNG"
        ],
        "objective": "To ensure that enclosed space entry is always strictly controlled and conducted in accordance with industry\nbest practice.",
        "negative_grounds": [
          "There were no company enclosed space entry procedures.",
          "The company enclosed space entry procedures had not identified all spaces that were considered to be",
          "enclosed spaces along with corresponding precautions for entering each type of identified enclosed space.",
          "There was no evidence that documented risk assessments were completed and/or reviewed before each",
          "enclosed space entry.",
          "The company enclosed entry procedure did not give clear guidance on the requirement to clean cargo,",
          "bunker and ballast tanks prior to entry based on the previous content.",
          "Company procedures did not require the completion of an enclosed space entry permit when entering a"
        ],
        "evidence": [
          "The company procedures which defined the enclosed space entry requirements for the identified enclosed",
          "spaces found onboard.",
          "The enclosed space entry permits for the previous six months for: o Spaces under the control of the engineering department.",
          "o Spaces under the control of the deck department.",
          "The cargo pumproom, cargo compressor room, nitrogen generator room, inert gas plant room and/or ballast"
        ],
        "risk": "medium",
        "status": "not_started"
      },
      {
        "id": "5.5.2",
        "number": "5.5.2",
        "chapter": "5",
        "section": "5.5",
        "text": "Were the Master, officers and, where directly involved, ratings familiar with the company hot work procedure, and was evidence available to demonstrate that hot work had been conducted in accordance with the procedure?",
        "short_text": "Hot work procedure",
        "vessel_types": [
          "Oil",
          "Chemical",
          "LPG",
          "LNG"
        ],
        "objective": "To ensure that hot work is always carried out in a controlled manner.",
        "negative_grounds": [
          "There were no company hot work procedures.",
          "The company hot work procedures were not in alignment with the guidance provided by ISGOTT Chapter 9.",
          "Evidence was available that hot work had been conducted anywhere outside of the designated space",
          "without the issue of a hot work permit.",
          "Hot work permits had been issued without:",
          "A risk assessment being prepared for the specific hot work task.",
          "A work plan being prepared for the specific hot work task.",
          "A work planning meeting taking place."
        ],
        "evidence": [
          "The company hot work procedures.",
          "The hot work permits issued onboard the vessel during the previous six months, supplemented by:",
          "o The risk assessment relating to the specific hot work task.",
          "o The work plan relating to the specific hot work task.",
          "o Evidence that a work planning meeting had been held.",
          "o Documented approval for the hot work from shore management, where required."
        ],
        "risk": "medium",
        "status": "not_started"
      },
      {
        "id": "5.5.3",
        "number": "5.5.3",
        "chapter": "5",
        "section": "5.5",
        "text": "Were the Master, officers and ratings familiar with the company procedure for working at height, and was there evidence that risk control measures such as permits to work or documented risk assessments were consistently used whenever work was undertaken at height?",
        "short_text": "Working at height",
        "vessel_types": [
          "Oil",
          "Chemical",
          "LPG",
          "LNG"
        ],
        "objective": "To ensure that work at height is always conducted in a controlled manner with procedures to manage and\nmitigate risk to workers.",
        "negative_grounds": [
          "There was no company safe working procedure which included working at height."
        ],
        "evidence": [
          "The company safe work procedures for working at height.",
          "The working at height permits or risk assessments for the previous two months.",
          "Records of the periodic checks of working at height PPE and specialist equipment."
        ],
        "risk": "low",
        "status": "not_started"
      },
      {
        "id": "5.5.4",
        "number": "5.5.4",
        "chapter": "5",
        "section": "5.5",
        "text": "Were the Master, officers and ratings familiar with the company procedures for working over the side, and was there evidence that risk control measures such as standard work procedures, permits to work or documented risk assessments were consistently used whenever work was undertaken over the side?",
        "short_text": "Working over the side",
        "vessel_types": [
          "Oil",
          "Chemical",
          "LPG",
          "LNG"
        ],
        "objective": "To ensure that work over the side is always conducted in a controlled manner with procedures to manage\nand mitigate risk to workers.",
        "negative_grounds": [
          "There was no company safe working procedure which included working over the side.",
          "There was no requirement to complete a permit or risk assessment when working over the side unless the",
          "company procedures provided specific exclusions.",
          "The accompanying officer was unfamiliar with the company working over the side safe work procedure.",
          "The accompanying officer was unfamiliar with the requirement to conduct periodic checks on specialist",
          "working at height and over the side PPE and equipment.",
          "There was evidence that work over the side had been undertaken that required either a work over the side",
          "permit or a documented risk assessment, but where neither was available for review."
        ],
        "evidence": [
          "The company safe work procedures for working over the side.",
          "Standard work procedures for work over the side that did not require a permit or risk assessment to be",
          "prepared on each occasion.",
          "The work over the side permits or risk assessments for the previous six months.",
          "Records of the periodic checks of specialist working at height and over the side PPE and equipment."
        ],
        "risk": "medium",
        "status": "not_started"
      },
      {
        "id": "5.5.5",
        "number": "5.5.5",
        "chapter": "5",
        "section": "5.5",
        "text": "Were the Master and officers familiar with the company procedures for working on electrical equipment and systems, and was there evidence that risk control measures such as permits to work and/or documented risk assessments were consistently used whenever work was undertaken on electrical equipment and systems?",
        "short_text": "Working on electrical equipment and systems",
        "vessel_types": [
          "Oil",
          "Chemical",
          "LPG",
          "LNG"
        ],
        "objective": "To ensure that work on electrical equipment and systems is always conducted in a controlled manner with\nprocedures to manage and mitigate risk to workers.",
        "negative_grounds": [
          "There was no company safe working procedure which included working on electrical equipment or systems.",
          "There was no requirement to complete a permit and/or risk assessment when working on electrical",
          "equipment or systems.",
          "The accompanying officer was unfamiliar with the company safe work procedure for working on electrical",
          "equipment or systems.",
          "An interviewed electrician or engineer officer was unfamiliar with The company safe working procedure for working on electrical equipment or systems and either the",
          "related permit and/or risk assessment development, review and approval process."
        ],
        "evidence": [
          "The company safe work procedure for working on electrical equipment or systems.",
          "The work on electrical equipment or systems permits and/or risk assessments for the previous two months.",
          "Access to the planned maintenance system.",
          "Access the daily work planning meeting records."
        ],
        "risk": "medium",
        "status": "not_started"
      },
      {
        "id": "5.5.6",
        "number": "5.5.6",
        "chapter": "5",
        "section": "5.5",
        "text": "Were the Master and officers familiar with the company procedures for the control of hazardous energy, and was evidence available, through documented risk assessment or permits, that hazardous energy sources were routinely identified and isolated before working on, or in, machinery, systems or spaces where hazardous energy could be present?",
        "short_text": "Control of hazardous energy",
        "vessel_types": [
          "Oil",
          "Chemical",
          "LPG",
          "LNG"
        ],
        "objective": "To ensure that hazardous energy sources are always identified and effectively isolated before work starts on,\nor in, machinery, systems or spaces where hazardous energy sources could be present.",
        "negative_grounds": [
          "There were no company control of hazardous energy procedures.",
          "There was no specialist LO/TO equipment available onboard.",
          "There was no inventory of specialist LO/TO equipment.",
          "Work had been completed that required either a permit, risk assessment or other documented work",
          "procedure to identify and control hazardous energy sources according to the company procedure, but none",
          "An interviewed deck or engineer officer was unfamiliar with the company control of hazardous energy",
          "An interviewed deck or engineer officer was unfamiliar with the process to identify and document the"
        ],
        "evidence": [
          "The company control of hazardous energy procedures.",
          "Permits, Safety Critical Task Assessments, risk assessments or other documented work processes that had",
          "been used to identify and control hazardous energy sources for the previous three months.",
          "The daily work planning records.",
          "The Bridge Log Book.",
          "The Engine Room Logbook."
        ],
        "risk": "medium",
        "status": "not_started"
      },
      {
        "id": "5.6.1",
        "number": "5.6.1",
        "chapter": "5",
        "section": "5.6",
        "text": "Were the Master and officers familiar with the purpose, operation, testing, maintenance and calibration of the vessel’s portable and personal gas measurement instruments, and was the equipment on board sufficient, in good working order, regularly tested and periodically calibrated?",
        "short_text": "Portable and personal gas measurement instruments",
        "vessel_types": [
          "Oil",
          "Chemical",
          "LPG",
          "LNG"
        ],
        "objective": "To ensure sufficient calibrated portable and personal gas measurement instruments are always available on\nboard to enable safe enclosed space entry and cargo operations.",
        "negative_grounds": [
          "There were no company procedures for the operation, testing, maintenance and calibration of the portable",
          "and personal gas measurement instruments.",
          "The accompanying officer was unable to explain or demonstrate:",
          "The type and number of portable and personal gas measurement instruments required to be",
          "The toxic gases or vapours for which tubes, chips or other consumables required to be carried",
          "The purpose(s) and function(s) of each instrument, including the sensor technology utilised and",
          "whether the instrument can be used in an inert atmosphere and/or at above atmospheric pressure."
        ],
        "evidence": [
          "The company procedures for the operation, testing, maintenance and calibration of the vessel’s portable and",
          "personal gas measurement instruments.",
          "The inventory of portable and personal gas measurement instruments, spare parts, test gases and tubes,",
          "chips or other consumables for measuring toxic gases.",
          "Instruction manuals for the portable and personal gas measurement instruments.",
          "Test and calibration records for the portable and personal gas measurement instruments."
        ],
        "risk": "medium",
        "status": "not_started"
      },
      {
        "id": "5.6.2",
        "number": "5.6.2",
        "chapter": "5",
        "section": "5.6",
        "text": "Were the Master and deck officers familiar with the company procedures for testing the atmosphere in double-hull and double bottom spaces for flammable gas, and were records available to confirm that appropriate measurements had been taken using the equipment fitted to, or provided on, the vessel?",
        "short_text": "Testing the atmosphere in double-hull and double bottom spaces for flammable gas",
        "vessel_types": [
          "Oil",
          "Chemical"
        ],
        "objective": "To ensure that structural failures between cargo tanks adjacent to ballast tanks and void spaces of double-\nhull and double-bottom spaces are promptly detected.",
        "negative_grounds": [
          "There was no company procedure which defined the process and frequency for testing double-hull, double-",
          "bottom and void spaces. for hydrocarbon gas accumulation.",
          "The accompanying deck officer was unfamiliar with the company procedure for monitoring double-hull,",
          "double-bottom and void spaces for hydrocarbon gas accumulation.",
          "Records, or absence of records, indicated that gas measurements had not been taken and recorded in",
          "accordance with company procedures.",
          "Records, or absence of records, indicated that fixed gas detector tank sensors had been isolated without",
          "appropriate manual gas measurements being taken in accordance with company procedures."
        ],
        "evidence": [
          "The company procedures for detecting and monitoring flammable gas concentrations in double-hull, double-",
          "bottom and void spaces.",
          "Records to demonstrate that hydrocarbon gas measurements had been undertaken in accordance with the",
          "company procedure.",
          "Records to demonstrate that the fixed gas detecting system, where fitted, had been in continuous operation",
          "and where individual tank sensors, or groups of sensors, had been isolated, the times of isolation and"
        ],
        "risk": "medium",
        "status": "not_started"
      },
      {
        "id": "5.6.3",
        "number": "5.6.3",
        "chapter": "5",
        "section": "5.6",
        "text": "Were the Master and officers familiar with the location, purpose and operation of the vessel’s fixed gas detection systems required by the IGC Code, and was the equipment in good working order, regularly maintained and calibrated?",
        "short_text": "Fixed gas detection systems required by the IGC Code",
        "vessel_types": [
          "LPG",
          "LNG"
        ],
        "objective": "To ensure that the vessel staff can detect unintentional releases or leaks from the cargo system.",
        "negative_grounds": [
          "There was no company procedure for the operation and maintenance of the fixed gas detecting systems",
          "required by the IGC code.",
          "The fixed gas detection systems required by the IGC code were:",
          "Not monitoring all sensors provided by the systems."
        ],
        "evidence": [
          "The company procedures for the operation and maintenance of the fixed gas detecting systems required",
          "under the IGC code.",
          "Inspection, calibration and maintenance records for the fixed gas detection systems.",
          "The list of fixed gas detector sensors and the corresponding alarm (and where appropriate, automatic",
          "shutdown) set points.",
          "The manufacturer's calibration instructions for the fixed gas detecting systems and sensors."
        ],
        "risk": "medium",
        "status": "not_started"
      },
      {
        "id": "5.6.4",
        "number": "5.6.4",
        "chapter": "5",
        "section": "5.6",
        "text": "Were the Master and officers familiar with the location, purpose and operation of the vessel’s fixed gas detection system required by the IGF Code, and was the equipment in good working order, regularly maintained and calibrated in accordance with company procedures and manufacturer’s instructions?",
        "short_text": "Fixed gas detection system required by the IGF Code",
        "vessel_types": [
          "Oil",
          "Chemical",
          "LPG"
        ],
        "objective": "To ensure that the vessel is protected from the consequences of unintentional releases or leaks from the gas\nor other low-flashpoint fuel system.",
        "negative_grounds": [
          "There was no company procedure which defined the requirements for operating and testing the fixed gas",
          "detecting system required under the IGF Code.",
          "The vessel’s maintenance plan did not include the fixed gas detecting system required under the IGF Code.",
          "The maintenance plan did not define the frequency of sensor calibration and automated gas safety system",
          "The accompanying officer was not familiar with the company procedure for the operation and maintenance",
          "f the fixed gas detection system.",
          "The accompanying officer was not familiar with the maintenance plan tasks for fixed gas detector sensor"
        ],
        "evidence": [
          "The company procedure which defined the requirements for operating and testing the fixed gas detecting",
          "system required under the IGF Code.",
          "The manufacturer’s instruction manual for the fixed gas detecting system.",
          "The Inspection, calibration and maintenance records for the fixed gas detection system."
        ],
        "risk": "medium",
        "status": "not_started"
      },
      {
        "id": "5.6.5",
        "number": "5.6.5",
        "chapter": "5",
        "section": "5.6",
        "text": "Were the Master and officers familiar with the operation and maintenance of the cargo pump room fixed gas detection system, and was the equipment fully operational with sensors calibrated and alarm activation points set in accordance with company procedures and manufacturer's instructions?",
        "short_text": "Cargo pump room fixed gas detection system",
        "vessel_types": [
          "Oil",
          "Chemical"
        ],
        "objective": "To ensure that measures specifically designed to prevent fire in the pumproom are effective.",
        "negative_grounds": [
          "There was no company procedure for the maintenance and operation of the pumproom gas detection",
          "The accompanying officer was unfamiliar with the operation and maintenance of the pumproom gas",
          "The alarm activation point of one or more hydrocarbon gas sensors was more than 10% LFL.",
          "The gas detection sensors had not been calibrated in accordance with manufacturer’s instructions at the",
          "frequency defined by the company.",
          "The audible and visual alarms in the cargo control room, pumproom and on the bridge had not been tested",
          "at the frequency defined by the company."
        ],
        "evidence": [
          "The company procedures for the maintenance and operation of the cargo pumproom gas detection system.",
          "The manufacturer’s instruction manual for the pumproom fixed gas detection system.",
          "The maintenance and calibration records for the cargo pumproom gas detection system.",
          "Where the fixed gas detection system was out of service, records of manual atmosphere measurements."
        ],
        "risk": "medium",
        "status": "not_started"
      },
      {
        "id": "5.6.6",
        "number": "5.6.6",
        "chapter": "5",
        "section": "5.6",
        "text": "Were the Master and officers familiar with the operation and maintenance of the oxygen sensors and associated alarms fitted in the space, or spaces, containing the inert gas system, and was the equipment fully operational with sensors calibrated and alarm activation points set in accordance with company procedures and manufacturer's instructions?",
        "short_text": "Oxygen sensors in inert gas system spaces.",
        "vessel_types": [
          "Oil",
          "Chemical"
        ],
        "objective": "To ensure that entry into the space, or spaces, containing the inert gas plant is always made safely.",
        "negative_grounds": [
          "There was no company procedure describing the maintenance and operation of the oxygen sensors and",
          "associated alarms fitted in the space, or spaces, containing the inert gas system.",
          "The accompanying officer was unfamiliar with the operation and maintenance of the oxygen sensors and",
          "associated alarms fitted in the space, or spaces, containing the inert gas system.",
          "The oxygen sensors had not been calibrated in accordance with manufacturer’s instructions at the frequency",
          "defined by the company.",
          "The audible and visual alarms had not been tested at the frequency defined by the company.",
          "The calibration gas used for calibration of the oxygen sensors was out of date or not appropriate for use with"
        ],
        "evidence": [
          "The company procedures for the maintenance and operation of the oxygen sensors and associated alarms",
          "fitted in the space or spaces containing the inert gas system.",
          "The manufacturer’s instruction manual for the oxygen sensors and associated alarms fitted in the space, or",
          "spaces, containing the inert gas system.",
          "The maintenance and calibration records for the oxygen sensors fitted in the space, or spaces, containing",
          "the inert gas system."
        ],
        "risk": "medium",
        "status": "not_started"
      },
      {
        "id": "5.7.1",
        "number": "5.7.1",
        "chapter": "5",
        "section": "5.7",
        "text": "Had all onboard incidents been reported and investigated in accordance with company procedures, and was an incident investigation report or a summarised lessons learned bulletin available for each incident at or above a defined threshold?",
        "short_text": "Incident investigation reports for defined incidents",
        "vessel_types": [
          "Oil",
          "Chemical",
          "LPG",
          "LNG"
        ],
        "objective": "To ensure that seafarers can learn from incidents which occurred onboard their vessel to improve safety and\npollution prevention standards.",
        "negative_grounds": [
          "There was no incident investigation report or lessons learned bulletin available onboard for one or more of",
          "the incidents reported through the HVPQ or PIQ, unless the vessel operator had declared that the incident",
          "investigation was ongoing."
        ],
        "evidence": [
          "The company procedures that required incidents and near-misses were promptly reported and investigated.",
          "The system for tracking incident and near-miss reports to closure.",
          "Incident investigation reports or lessons learned for any of the incident types listed in the guidance notes",
          "which had occurred during the 12 months prior to the inspection."
        ],
        "risk": "medium",
        "status": "not_started"
      },
      {
        "id": "5.7.2",
        "number": "5.7.2",
        "chapter": "5",
        "section": "5.7",
        "text": "Were the Master, officers and ratings familiar with the company incident and near- miss reporting procedure and was evidence available to demonstrate that incidents and near-misses had been investigated and closed out in accordance with the company procedure?",
        "short_text": "Incident and near-miss reporting procedure",
        "vessel_types": [
          "Oil",
          "Chemical",
          "LPG",
          "LNG"
        ],
        "objective": "To ensure that seafarers can learn from incidents and near-misses onboard their vessel to improve safety\nand pollution prevention.",
        "negative_grounds": [
          "There was no company procedure that required incidents and near-misses were promptly reported by all",
          "ranks and investigated.",
          "The Master or accompanying officer was unfamiliar with the process to:",
          "Track each incident and near-miss through to closure.",
          "Document onboard incidents and near-misses.",
          "Report incidents or near-misses to shore-based management.",
          "Investigate incidents and near-misses assigned to vessel staff.",
          "Implement and document corrective and preventative actions."
        ],
        "evidence": [
          "The company procedure that required incidents and near-misses were promptly reported by all ranks and",
          "investigated.",
          "The system for tracking incident and near-miss reports to closure.",
          "Shore-based management acknowledgement of incident and near-miss reports.",
          "Incident and near-miss reports generated by the vessel during the previous three months.",
          "Incident and near-miss investigation reports where these were a separate document from the initial report."
        ],
        "risk": "medium",
        "status": "not_started"
      },
      {
        "id": "5.7.3",
        "number": "5.7.3",
        "chapter": "5",
        "section": "5.7",
        "text": "Were the Master, officers and ratings familiar with the company procedure for holding and documenting shipboard safety meetings and was evidence available that safety concerns raised at the meetings were acknowledged and addressed by shore management?",
        "short_text": "Shipboard safety meetings",
        "vessel_types": [
          "Oil",
          "Chemical",
          "LPG",
          "LNG"
        ],
        "objective": "To ensure that there is an effective two-way dialogue between the vessel staff and shore-based management\nin matters relating to safety and pollution prevention at both the fleet and individual vessel level.\nUK MCA: Code of Safe Working Practices for Merchant Seafarers\n1.2.2 Effective communication and workforce involvement is crucial in ensuring a safe living and working\nenvironment. Communication is a two-way process. There is a need to be able to gain information and knowledge\nthat can be act",
        "negative_grounds": [
          "There were no company procedures which defined the process for holding shipboard safety meetings,",
          "recording the minutes and shore management review of the minutes of each meeting.",
          "Shipboard safety meetings had not been held at the frequency defined by the company procedure or at",
          "approximately monthly intervals.",
          "Extraordinary safety meetings had not been held after a serious incident onboard or during a shore",
          "management visit, where practical.",
          "The minutes of shipboard safety meetings had not been documented in accordance with the required",
          "The minutes of shipboard safety meetings had not been submitted for shore management review."
        ],
        "evidence": [
          "The company procedures relating to shipboard safety meetings.",
          "The safety committee meeting minutes for all meetings conducted during the previous six months.",
          "The shore management response to all safety committee meetings conducted during the previous six",
          "months except for minutes submitted within one week of the inspection."
        ],
        "risk": "high",
        "status": "not_started"
      },
      {
        "id": "5.7.4",
        "number": "5.7.4",
        "chapter": "5",
        "section": "5.7",
        "text": "Were the Master, officers and ratings familiar with the company work planning procedures and were records available to demonstrate that onboard work planning meetings had been conducted and documented in accordance with the procedures?",
        "short_text": "Work planning procedure",
        "vessel_types": [
          "Oil",
          "Chemical",
          "LPG",
          "LNG"
        ],
        "objective": "To ensure that all onboard work activities are planned to agree the scope of work and specific safety\nrequirements applicable to each task, and to avoid operational, departmental or rest hour conflicts.",
        "negative_grounds": [
          "There was no company procedure which defined the requirements for documented work planning meetings.",
          "Work planning meetings were not being held at the frequency defined by the company procedure.",
          "Work planning meeting records had not been approved onboard in accordance with the company",
          "The outcome from work planning meetings was not being recorded in the format defined by the company",
          "The detail included in the work planning meeting records was not enough to understand what a job entailed.",
          "Work planning meeting tasks required permits, risk assessments or detailed work plans to be used but these",
          "Reviewed work planning records did not reflect the actual activities of the vessel during the period of review."
        ],
        "evidence": [
          "The company procedure which defined the requirements for documented work planning meetings.",
          "The work planning meeting records for the previous month.",
          "Permits, risk assessments and detailed work plans referenced by work planning meeting records.",
          "The Bridge Log Book."
        ],
        "risk": "medium",
        "status": "not_started"
      },
      {
        "id": "5.7.5",
        "number": "5.7.5",
        "chapter": "5",
        "section": "5.7",
        "text": "Were the Master, officers and ratings familiar with the purpose and implementation of the company Stop Work Authority policy and procedure?",
        "short_text": "Stop Work Authority",
        "vessel_types": [
          "Oil",
          "Chemical",
          "LPG",
          "LNG"
        ],
        "objective": "To ensure that vessel staff are aware of their responsibility and authority to stop unsafe work.",
        "negative_grounds": [
          "There was no company Stop Work Authority policy and procedure.",
          "There was no evidence that Stop Work Authority was included and discussed in work planning processes",
          "such as tool-box talks, risk assessments, daily work planning meetings or safety meetings.",
          "More than one crewmember was unfamiliar with the company Stop Work Authority policy and/or procedure."
        ],
        "evidence": [
          "The company Stop Work Authority policy and procedure.",
          "Any onboard work planning tools such as tool-box talks, risk assessments, daily work planning meetings or",
          "safety meetings which highlight the use of Stop Work Authority."
        ],
        "risk": "medium",
        "status": "not_started"
      },
      {
        "id": "5.7.6",
        "number": "5.7.6",
        "chapter": "5",
        "section": "5.7",
        "text": "Were the Master, officers and ratings familiar with the company procedures for risk assessment, as appropriate to their duties, and was there evidence of the development and review of risk assessments in accordance with the procedures?",
        "short_text": "Risk assessments for new, non-routine, unplanned or specified tasks",
        "vessel_types": [
          "Oil",
          "Chemical",
          "LPG",
          "LNG"
        ],
        "objective": "To ensure that new, non-routine or unplanned tasks, not covered by existing procedures, are subject to risk\nassessment before work starts, and that risk assessments are reviewed before work starts on other specified\ntasks such as enclosed space entry or hot-work.",
        "negative_grounds": [
          "There was no company procedure describing the risk assessment development and review processes.",
          "The company risk assessment procedure did not define:",
          "The circumstances in which a risk assessment must be developed or reviewed.",
          "The process for developing a risk assessment.",
          "The process for recording the results of a risk assessment.",
          "The process for reviewing an available risk assessment.",
          "Who is responsible for completing a risk assessment.",
          "Who should be involved in the development of a risk assessment."
        ],
        "evidence": [
          "The company procedure describing the risk assessment development and review processes.",
          "The risk assessments used onboard during the previous three months."
        ],
        "risk": "medium",
        "status": "not_started"
      },
      {
        "id": "5.7.7",
        "number": "5.7.7",
        "chapter": "5",
        "section": "5.7",
        "text": "Were Safety Data Sheets (SDS) available on board for all cargo, bunkers, chemicals, paints and other products being handled, and were crew members familiar with their use?",
        "short_text": "Safety Data Sheets.",
        "vessel_types": [
          "Oil",
          "Chemical",
          "LPG",
          "LNG"
        ],
        "objective": "To ensure crew members are provided with clear, accurate information on the health and environmental\neffects of all hazardous and toxic substances carried on board, including guidance on their safe handling.",
        "negative_grounds": [
          "There were no company procedures to ensure that up to date Safety Data Sheets are readily available for all",
          "hazardous or toxic substances carried on board and to give guidance on the handling and stowage of these",
          "substances, including PPE requirements.",
          "The accompanying officer was not familiar with the purpose and content of the relevant SDSs.",
          "There was no SDS available for a cargo or fuel oil on board at the time of the inspection.",
          "The (M)SDS for an Annex I cargo or fuel oil on board at the time of the inspection was not in compliance",
          "with the requirements of IMO: Resolution MSC.286(86).",
          "The (M)SDS for a cargo containing benzene was not in compliance with the requirements of IMO:"
        ],
        "evidence": [
          "Company procedures to ensure that up to date Safety Data Sheets are readily available for all hazardous or",
          "toxic substances carried on board and to give guidance on the handling and stowage of these substances.",
          "SDSs for, where carried: o All oil, chemical and/or gas cargoes.",
          "o All grades of bunkers.",
          "o Hydraulic oils."
        ],
        "risk": "medium",
        "status": "not_started"
      },
      {
        "id": "5.7.8",
        "number": "5.7.8",
        "chapter": "5",
        "section": "5.7",
        "text": "Were the Master, officers and ratings familiar with the company Simultaneous Operations (SIMOPS) procedure and was there evidence that SIMOPS were considered during work planning and the required controls implemented for the duration of such operations?",
        "short_text": "Simultaneous Operations (SIMOPS) procedure",
        "vessel_types": [
          "Oil",
          "Chemical",
          "LPG",
          "LNG"
        ],
        "objective": "To ensure that the impact of Simultaneous Operations (SIMOPS) is understood and managed effectively.",
        "negative_grounds": [
          "There was no company procedure which gave guidance and instruction on Simultaneous Operations",
          "The accompanying officer was unfamiliar with the company SIMOPS procedure."
        ],
        "evidence": [
          "The company procedure which provided guidance and instruction on Simultaneous Operations (SIMOPS).",
          "The SIMOPS decision matrix, if provided as part of the SIMOPS procedure.",
          "The SIMOPS matrix of permitted operations, if provided as part of the SIMOPS procedure.",
          "The daily work planning meeting records.",
          "Risk assessments dealing with SIMOPS for the previous three months.",
          "SIMOPS plan/interface documents."
        ],
        "risk": "medium",
        "status": "not_started"
      },
      {
        "id": "5.8.1",
        "number": "5.8.1",
        "chapter": "5",
        "section": "5.8",
        "text": "Were the Master and officers familiar with the company procedure for safety inspections of the main deck areas, and had inspections been effective in identifying hazards to health, safety and the environment?",
        "short_text": "Safety inspection of the main deck and mooring areas.",
        "vessel_types": [
          "Oil",
          "Chemical",
          "LPG",
          "LNG"
        ],
        "objective": "To ensure that the main deck areas are always maintained in a safe condition.",
        "negative_grounds": [
          "There was no company procedure which required that safety inspections of the main deck areas were",
          "conducted at appropriate intervals by the designated Safety Officer to identify hazards and potential hazards",
          "to health, safety and the environment.",
          "Records of safety inspections of the main deck areas were missing or incomplete.",
          "There was no checklist provided to facilitate the safety inspections of the main deck areas.",
          "The accompanying officer was unfamiliar with the company procedure which required that safety inspections",
          "f the main deck areas were conducted at appropriate intervals by the designated Safety Officer.",
          "The accompanying officer was unfamiliar with any of the checks required to be conducted in accordance"
        ],
        "evidence": [
          "The company procedure which requires that safety inspections of the main deck areas are conducted at",
          "appropriate intervals by the designated Safety Officer to identify hazards and potential hazards to health,",
          "safety and the environment.",
          "Records of safety inspections of the main deck areas including associated checklists."
        ],
        "risk": "high",
        "status": "not_started"
      },
      {
        "id": "5.8.2",
        "number": "5.8.2",
        "chapter": "5",
        "section": "5.8",
        "text": "Were the Master and officers familiar with the company procedure for safety inspections of the machinery spaces, and had inspections been effective in identifying hazards to health, safety and the environment?",
        "short_text": "Safety inspection of the machinery space.",
        "vessel_types": [
          "Oil",
          "Chemical",
          "LPG",
          "LNG"
        ],
        "objective": "To ensure that the machinery spaces are always maintained in a safe condition.",
        "negative_grounds": [
          "There was no company procedure which required that safety inspections of the machinery spaces were",
          "conducted at appropriate intervals by the designated Safety Officer to identify hazards and potential hazards",
          "to health, safety and the environment.",
          "Records of safety inspections of the machinery spaces were missing or incomplete.",
          "There was no checklist provided to facilitate the safety inspections of the machinery spaces.",
          "The accompanying officer was unfamiliar with the company procedure which required that safety inspections",
          "f the machinery spaces were conducted at appropriate intervals by the designated Safety Officer.",
          "The accompanying officer was unfamiliar with any of the checks required to be conducted in accordance"
        ],
        "evidence": [
          "The company procedure which required that safety inspections of the machinery spaces were conducted at",
          "appropriate intervals by the designated Safety Officer to identify hazards and potential hazards to health,",
          "safety and the environment.",
          "Records of safety inspections of the machinery spaces including associated checklists."
        ],
        "risk": "high",
        "status": "not_started"
      },
      {
        "id": "5.8.3",
        "number": "5.8.3",
        "chapter": "5",
        "section": "5.8",
        "text": "Were the Master and officers familiar with the company procedure for safety inspections of the cargo pumproom, and had inspections been effective in identifying hazards to health, safety and the environment?",
        "short_text": "Safety inspections of the cargo pumproom",
        "vessel_types": [
          "Oil",
          "Chemical"
        ],
        "objective": "To ensure that the cargo pump room is always maintained in a safe condition.",
        "negative_grounds": [
          "There was no company procedure which required that safety inspections of the cargo pumproom be",
          "conducted at appropriate intervals by the designated Safety Officer to identify hazards and potential hazards",
          "to health, safety and the environment.",
          "Records of safety inspections of the cargo pumproom were missing or incomplete.",
          "There was no checklist provided to facilitate the safety inspections of the cargo pumproom.",
          "The accompanying officer was unfamiliar with the company procedure which required that safety inspections",
          "f the cargo pumproom were conducted at appropriate intervals by the designated Safety Officer."
        ],
        "evidence": [
          "The company procedure which required that safety inspections of the cargo pumproom were conducted at",
          "appropriate intervals by the designated Safety Officer to identify hazards and potential hazards to health,",
          "safety and the environment.",
          "Records of safety inspections of the cargo pumproom including associated checklists."
        ],
        "risk": "medium",
        "status": "not_started"
      },
      {
        "id": "5.8.4",
        "number": "5.8.4",
        "chapter": "5",
        "section": "5.8",
        "text": "Were the Master and officers familiar with the procedure for safety inspections of the cargo machinery rooms, and had inspections been effective in identifying hazards to health, safety and the environment?",
        "short_text": "Cargo machinery rooms safety inspections",
        "vessel_types": [
          "LPG",
          "LNG"
        ],
        "objective": "To ensure that cargo machinery rooms are always maintained in a safe condition.",
        "negative_grounds": [],
        "evidence": [],
        "risk": "low",
        "status": "not_started"
      },
      {
        "id": "5.8.5",
        "number": "5.8.5",
        "chapter": "5",
        "section": "5.8",
        "text": "Were the Master and officers familiar with the company procedure for safety inspections of the forecastle, and had inspections been effective in identifying hazards to health, safety and the environment?",
        "short_text": "Safety inspection of the forecastle spaces",
        "vessel_types": [
          "Oil",
          "Chemical",
          "LPG",
          "LNG"
        ],
        "objective": "To ensure that the forecastle is always maintained in a safe condition.",
        "negative_grounds": [
          "There was no company procedure which required that safety inspections of the forecastle were conducted at",
          "appropriate intervals by the designated Safety Officer to identify hazards and potential hazards to health,",
          "safety and the environment.",
          "Records of safety inspections of the forecastle were missing or incomplete.",
          "There was no checklist provided to facilitate the safety inspections of the forecastle.",
          "The accompanying officer was unfamiliar with the company procedure which required that safety inspections",
          "f the forecastle were conducted at appropriate intervals by the designated Safety Officer.",
          "The accompanying officer was unfamiliar with any of the checks required to be conducted in accordance"
        ],
        "evidence": [
          "The company procedure which required that safety inspections of the forecastle were conducted at",
          "appropriate intervals by the designated Safety Officer to identify hazards and potential hazards to health,",
          "safety and the environment.",
          "Records of safety inspections of the forecastle including associated checklists."
        ],
        "risk": "medium",
        "status": "not_started"
      },
      {
        "id": "5.8.6",
        "number": "5.8.6",
        "chapter": "5",
        "section": "5.8",
        "text": "Were the Master and officers familiar with the company procedure for safety inspections of the accommodation, and had inspections been effective in identifying hazards to health, safety and the environment?",
        "short_text": "Safety inspections of the accommodation spaces",
        "vessel_types": [
          "Oil",
          "Chemical",
          "LPG",
          "LNG"
        ],
        "objective": "To ensure that the accommodation is always maintained in a safe condition.",
        "negative_grounds": [
          "There was no company procedure which required that safety inspections of the accommodation were",
          "conducted at appropriate intervals by the designated Safety Officer to identify hazards and potential hazards",
          "to health, safety and the environment.",
          "Records of safety inspections of the accommodation were missing or incomplete.",
          "There was no checklist provided to facilitate the safety inspections of the accommodation.",
          "The accompanying officer was unfamiliar with the company procedure which required that safety inspections",
          "f the accommodation were conducted at appropriate intervals by the designated Safety Officer.",
          "The accompanying officer was unfamiliar with any of the checks required to be conducted in accordance"
        ],
        "evidence": [
          "The company procedure which required that safety inspections of the accommodation were conducted at",
          "appropriate intervals by the designated Safety Officer to identify hazards and potential hazards to health,",
          "safety and the environment.",
          "Records of safety inspections of the accommodation including associated checklists.",
          "Records of regular testing of the refrigerated room alarm."
        ],
        "risk": "high",
        "status": "not_started"
      },
      {
        "id": "5.8.7",
        "number": "5.8.7",
        "chapter": "5",
        "section": "5.8",
        "text": "Were the Master and officers familiar with the company procedure for safety inspections of the ballast and/or bunker pumproom, and had inspections been effective in identifying hazards to health, safety and the environment?",
        "short_text": "Ballast and/or bunker pumproom safety inspection",
        "vessel_types": [
          "Oil",
          "Chemical",
          "LPG",
          "LNG"
        ],
        "objective": "To ensure that the ballast and/or bunker pump room is always maintained in a safe condition.",
        "negative_grounds": [
          "There was no company procedure which required that safety inspections of the ballast and/or bunker",
          "pumproom be conducted at appropriate intervals by the designated Safety Officer to identify hazards and",
          "potential hazards to health, safety and the environment.",
          "Records of safety inspections of the ballast and/or bunker pumproom were missing or incomplete.",
          "There was no checklist provided to facilitate the safety inspections of the ballast and/or bunker pumproom.",
          "The accompanying officer was unfamiliar with the company procedure which required that safety inspections",
          "f the ballast and/or bunker pumproom were conducted at appropriate intervals by the designated Safety",
          "The accompanying officer was unfamiliar with any of the checks required to be conducted in accordance"
        ],
        "evidence": [
          "The company procedure which required that safety inspections of the ballast and/or bunker pumproom were",
          "conducted at appropriate intervals by the designated Safety Officer to identify hazards and potential hazards",
          "to health, safety and the environment.",
          "Records of safety inspections of the ballast and/or bunker pumproom including associated checklists."
        ],
        "risk": "high",
        "status": "not_started"
      },
      {
        "id": "5.9.1",
        "number": "5.9.1",
        "chapter": "5",
        "section": "5.9",
        "text": "Were the Master, officers and ratings familiar with the company lifting and rigging procedures, and was evidence available to demonstrate that each item of lifting and rigging equipment had been maintained, inspected and tested in accordance with the procedure?",
        "short_text": "Lifting and rigging equipment procedures, maintenance and inspection",
        "vessel_types": [
          "Oil",
          "Chemical",
          "LPG",
          "LNG"
        ],
        "objective": "To ensure that all lifting and rigging equipment has been thoroughly inspected at least annually and is\nalways fit for purpose when used.",
        "negative_grounds": [
          "There was no company procedure for the management of lifting and rigging equipment.",
          "The accompanying officer was unfamiliar with the company procedure for the management of lifting and",
          "Certification for lifting equipment and loose gear covered by a Classification Society programme had not",
          "been maintained in accordance with the Classification Society requirements:",
          "An item of lifting equipment and loose gear covered by a Classification Society programme was out of",
          "An item of lifting equipment or loose gear covered by a Classification Society programme was found to be",
          "defective in any respect."
        ],
        "evidence": [
          "The company procedure for the management of lifting and rigging equipment.",
          "The certificates for each item of lifting equipment covered by a Classification Society programme.",
          "The records of periodic inspections by a competent person required to be maintained for each item of lifting",
          "equipment and loose gear covered by a Classification Society programme.",
          "The inventory of lifting and rigging equipment not covered by a Classification Society programme.",
          "The manufacturer’s certificates for all lifting equipment wire falls and topping lift wires."
        ],
        "risk": "medium",
        "status": "not_started"
      },
      {
        "id": "5.9.2",
        "number": "5.9.2",
        "chapter": "5",
        "section": "5.9",
        "text": "Where the vessel was fitted with a single cargo hose handling crane, was a risk assessment available which identified the minimum spare parts that must be carried onboard to ensure continued operation in the event of a single component failure, and were the identified spare parts available onboard?",
        "short_text": "Spare parts for a single cargo hose handling crane.",
        "vessel_types": [
          "Oil",
          "Chemical",
          "LPG",
          "LNG"
        ],
        "objective": "To ensure that a hose crane is always available to connect and disconnect cargo hoses.",
        "negative_grounds": [
          "There was no risk assessment available which identified the minimum spare parts that must be carried for a",
          "single hose handling crane.",
          "There was not at least one spare hydraulic hose suitable to replace any hydraulic hose fitted to the hose",
          "Any other spare parts identified by the risk assessment as being essential for the continued use of the hose",
          "handling crane were not available onboard."
        ],
        "evidence": [
          "The risk assessment for the continued operation of a single hose crane.",
          "The inventory of spare parts for the hose crane including hydraulic hoses, with details of length, diameter",
          "and hose end fittings.",
          "The hose crane operations and maintenance manual which included the full list of hydraulic hoses, including",
          "diameter and length, fitted to the hose handling crane."
        ],
        "risk": "medium",
        "status": "not_started"
      },
      {
        "id": "5.10.1",
        "number": "5.10.1",
        "chapter": "5",
        "section": "5.10",
        "text": "Were the Master, deck officers and deck ratings familiar with the company procedures for rigging the pilot boarding arrangements, and was the equipment provided in satisfactory condition and used in accordance with industry best practice?",
        "short_text": "Pilot boarding arrangements",
        "vessel_types": [
          "Oil",
          "Chemical",
          "LPG",
          "LNG"
        ],
        "objective": "To ensure pilot boarding arrangements are always correctly rigged under the supervision of a responsible\nofficer.",
        "negative_grounds": [
          "There was no company procedure for the safe rigging of the pilot boarding arrangements.",
          "An inspected pilot ladder was found:",
          "Without any identification to connect it to its manufacturer’s certificate or maintenance records.",
          "With defects or arrangements which were specifically identified as unacceptable on BPG Checklist",
          "Constructed with materials or in a manner that did not comply with BPG Checklist A4.",
          "Without manufacturer’s certificates or maintenance records.",
          "To have been repaired in a manner which did not conform to the manufacturer’s instructions.",
          "The pilot access arrangements did not conform to the requirements of BPG Checklist A4."
        ],
        "evidence": [
          "The company procedure for the safe rigging of the pilot boarding arrangements.",
          "The manufacturer’s certificates for each pilot ladder.",
          "The manufacturer’s repair instructions, where provided.",
          "The maintenance records for each pilot ladder which included the date the ladder was put in service."
        ],
        "risk": "medium",
        "status": "not_started"
      },
      {
        "id": "5.10.2",
        "number": "5.10.2",
        "chapter": "5",
        "section": "5.10",
        "text": "Were the Master, deck officers and deck ratings familiar with the company procedures for rigging the accommodation ladders, and were the accommodation ladders in good order and used in accordance with the company procedure and manufacturer’s instructions?",
        "short_text": "Accommodation ladders",
        "vessel_types": [
          "Oil",
          "Chemical",
          "LPG",
          "LNG"
        ],
        "objective": "To ensure accommodation ladders are always correctly rigged under the supervision of a responsible\nperson or officer.",
        "negative_grounds": [
          "There was no company procedure that described the safe rigging of an accommodation ladder.",
          "The maintenance records for the accommodation ladders were missing or incomplete.",
          "The certificate(s) for the five-yearly load test of an accommodation ladder was not available or the test had",
          "not been completed within the required time frame.",
          "There was no evidence that the accommodation ladder fall wires had been replaced within the previous five",
          "years or, the manufacturer’s certificate was not available for a fall wire in service.",
          "The fall wire was not long enough to permit the accommodation ladder to be deployed at the maximum",
          "freeboard whilst leaving sufficient turns on the winch drum."
        ],
        "evidence": [
          "The company procedure for the safe rigging of the accommodation ladders.",
          "The manufacturer’s instructions and/or design drawings for the accommodation ladders.",
          "The maintenance records for each accommodation ladder.",
          "The certificate and date of installation for each accommodation ladder fall wire.",
          "The certificate for the five-yearly load test for each accommodation ladder.",
          "Evidence of thorough examination of the portable gangway during annual surveys."
        ],
        "risk": "medium",
        "status": "not_started"
      },
      {
        "id": "5.10.3",
        "number": "5.10.3",
        "chapter": "5",
        "section": "5.10",
        "text": "Were the Master, officers and ratings familiar with the company procedure for providing safe access to the vessel while alongside a terminal/berth, and was safe access provided by the ship’s portable gangway, the vessel’s accommodation ladder or a shore gangway?",
        "short_text": "Safe access to the vessel while alongside a terminal/berth",
        "vessel_types": [
          "Oil",
          "Chemical",
          "LPG",
          "LNG"
        ],
        "objective": "To ensure safe access is always provided between the ship and a berth, whether by a ship’s portable\ngangway, accommodation ladder or a gangway provided by the terminal.",
        "negative_grounds": [
          "There was no company procedure which described the requirements for providing safe access to the vessel",
          "while alongside a terminal/berth.",
          "The maintenance records for the portable gangway, where provided, were missing or incomplete.",
          "Where a portable gangway was provided:",
          "The certificate for the five-yearly load test of the portable gangway was not available or the test had",
          "not been completed within the required time frame.",
          "The portable gangway was found:",
          " Without plates or markings showing the restrictions on the safe operation and loading,"
        ],
        "evidence": [
          "The company procedure which described the requirements for providing safe access to the vessel while",
          "alongside a terminal/berth.",
          "Where a portable gangway was provided: o The manufacturer’s instructions and/or design drawings for the portable gangway.",
          "o The maintenance records for the portable gangway.",
          "o The certificate for the five-yearly load test for the portable gangway."
        ],
        "risk": "medium",
        "status": "not_started"
      },
      {
        "id": "5.10.4",
        "number": "5.10.4",
        "chapter": "5",
        "section": "5.10",
        "text": "Were the Master and officers familiar with the company personnel transfer by crane procedure, and where a personnel transfer basket (PTB) and accessories were provided, were these in satisfactory condition and used in accordance with company procedures and manufacturer’s recommendations?",
        "short_text": "Personnel transfer by crane",
        "vessel_types": [
          "Oil",
          "Chemical",
          "LPG",
          "LNG"
        ],
        "objective": "To ensure personnel transfer by crane is always conducted in accordance with industry best practice\nguidance.",
        "negative_grounds": [
          "There was no company procedure describing the requirements for transfer of personnel by crane.",
          "The accompanying officer was not familiar with:",
          "The company procedure describing the requirements for transfer of personnel by crane.",
          "The use of the PTB or accessories for personnel transfer by crane.",
          "The checks on the PTB and accessories required to be carried out before personnel transfer by",
          "The risk assessment and personnel transfer by crane plan development process.",
          "The contingency plan for crane failure during personnel transfer by crane."
        ],
        "evidence": [
          "The company procedure describing personnel transfer by crane.",
          "The manufacturer’s test certificates for the PTB and accessories.",
          "The crane certification for personnel transfer use, where HVPQ question 13.1.7 had been declared as",
          "affirmative.",
          "The training records for the personnel designated for personnel transfer by crane operations.",
          "The onboard maintenance and inspection records for the crane, PTB and accessories."
        ],
        "risk": "medium",
        "status": "not_started"
      },
      {
        "id": "5.10.5",
        "number": "5.10.5",
        "chapter": "5",
        "section": "5.10",
        "text": "Were the Master and officers familiar with the company procedures for helicopter/ship operations, and had these procedures been complied with?",
        "short_text": "Helicopter operations",
        "vessel_types": [
          "Oil",
          "Chemical",
          "LPG",
          "LNG"
        ],
        "objective": "To ensure helicopter/ship operations are performed safely and in a controlled manner.",
        "negative_grounds": [
          "There were no procedures providing guidance on helicopter/ship operations including:",
          "Helicopter operations risk assessment."
        ],
        "evidence": [
          "Company procedures providing guidance on helicopter/ship operations.",
          "Helicopter operations risk assessment and evidence of last review.",
          "ICS Guide to Helicopter/Ship Operations.",
          "Records of training and emergency drills in helicopter/ship operations.",
          "Completed ICS Shipboard Safety Checklists for Helicopter Operations (or equivalent).",
          "Inventory of helicopter tools and equipment required for routine and emergency operations."
        ],
        "risk": "medium",
        "status": "not_started"
      },
      {
        "id": "5.10.6",
        "number": "5.10.6",
        "chapter": "5",
        "section": "5.10",
        "text": "Were the Master and officers familiar with the company procedures for helicopter/ship operations, and had the crew involved received appropriate training?",
        "short_text": "Helicopter facilities",
        "vessel_types": [
          "Oil"
        ],
        "objective": "To ensure helicopter/ship operations on vessels equipped with helicopter facilities are performed safely and\nin a controlled manner.",
        "negative_grounds": [
          "There were no procedures providing guidance on helicopter/ship operations including:",
          "Helicopter operations risk assessment.",
          "Identification of job roles and responsibilities for all personnel involved.",
          "Training requirements of all personnel involved.",
          "Emergency drill requirements.",
          "Use of the ICS Shipboard Safety Checklist for Helicopter Operations (or equivalent).",
          "Emergency tools and equipment requirements.",
          "Restrictions on cargo operations during helicopter/ship operations."
        ],
        "evidence": [
          "Company procedures providing guidance on helicopter/ship operations.",
          "Helicopter operations risk assessment and evidence of last review.",
          "Helicopter Landing Area Certificate (HLAC) if available.",
          "If no HLAC is available, records of appropriate formal accredited training courses such as Offshore",
          "Helicopter Landing Officer (HLO) and Offshore Helideck Assistant (HDA) followed by ship-specific",
          "familiarisation of the helicopter facilities and operations."
        ],
        "risk": "medium",
        "status": "not_started"
      },
      {
        "id": "5.10.7",
        "number": "5.10.7",
        "chapter": "5",
        "section": "5.10",
        "text": "Were the Master, officers and crew familiar with the escape routes from the machinery spaces, pump rooms, compressor rooms, accommodation spaces and, when in port, from the vessel, and were these routes clearly marked, unobstructed and well illuminated?",
        "short_text": "Escape routes",
        "vessel_types": [
          "Oil",
          "Chemical",
          "LPG",
          "LNG"
        ],
        "objective": "To ensure that there are marked escape routes available to ship and shore personnel in the event of an\nemergency on the vessel.",
        "negative_grounds": [
          "There was no company procedure which defined the requirements for identifying and marking escape",
          "The escape routes from within the accommodation spaces, machinery spaces, pump rooms, compressor",
          "rooms, thruster rooms or any other spaces where a person could become disorientated in an emergency",
          "were not marked with signs in accordance with IMO guidance.",
          "The accompanying officer could not direct the inspector to the escape route from any location within the",
          "vessel where there was potential to take a route to a dead end or space with no exit to an outside deck.",
          "External doors forming part of an escape route were locked or bolted with no means of rapid opening from",
          "An officer or rating was unable to demonstrate the opening of an external door which formed part of an"
        ],
        "evidence": [
          "The company procedure defining the requirements for identifying and marking emergency escape routes."
        ],
        "risk": "high",
        "status": "not_started"
      },
      {
        "id": "5.11.1",
        "number": "5.11.1",
        "chapter": "5",
        "section": "5.11",
        "text": "Were the Master and officers familiar with the company procedures addressing the management of samples of bunker fuel oil and Annex I and/or Annex II cargoes as applicable, and were samples being properly stored and eventually disposed of?",
        "short_text": "Cargo and bunker sample management.",
        "vessel_types": [
          "Oil",
          "Chemical",
          "LPG",
          "LNG"
        ],
        "objective": "To ensure cargo and bunker samples are safely stored on board and properly disposed of in a timely\nmanner.",
        "negative_grounds": [
          "There were no company procedures addressing the management of bunker fuel oil and Annex I and/or",
          "Annex II cargo samples as applicable, including:",
          "Marking/labelling of samples.",
          "Storage arrangements.",
          "The responsible officer was not familiar with the company procedures addressing the management of",
          "bunker fuel oil or Annex I and/or Annex II cargo samples, as appropriate.",
          "The designated storage space(s) for samples was:"
        ],
        "evidence": [
          "Company procedures addressing the management of samples of bunker fuel oil and Annex I and/or Annex II",
          "cargoes as applicable.",
          "Records of bunker fuel oil and cargo samples.",
          "Oil Record Book Part II or Cargo Record Book as applicable."
        ],
        "risk": "high",
        "status": "not_started"
      },
      {
        "id": "5.12.1",
        "number": "5.12.1",
        "chapter": "5",
        "section": "5.12",
        "text": "Were the Master, officers and ratings familiar with the company procedures that addressed the use of respiratory protective equipment during cargo operations, and did the procedures prohibit the use of filter type respirators for this purpose?",
        "short_text": "Respiratory protective equipment",
        "vessel_types": [
          "Oil",
          "Chemical",
          "LPG",
          "LNG"
        ],
        "objective": "To ensure the correct respiratory protective equipment is worn during cargo operations.",
        "negative_grounds": [
          "There were no company procedures for the use of respiratory protective equipment during cargo operations.",
          "The company procedures for the use of respiratory protective equipment during cargo operations did not",
          "prohibit the use of filter type respirators during cargo operations.",
          "The accompanying officer was not familiar with the company procedures for the use of respiratory protective",
          "equipment during cargo operations.",
          "Filter type respirators were observed being used by crew members involved in cargo operations."
        ],
        "evidence": [
          "Company procedures for the use of respiratory protective equipment during cargo operations."
        ],
        "risk": "medium",
        "status": "not_started"
      },
      {
        "id": "5.12.2",
        "number": "5.12.2",
        "chapter": "5",
        "section": "5.12",
        "text": "Were the Master, officers and ratings familiar with the location and operation of the decontamination showers and eyewash stations on deck, and were these facilities suitably marked, easily accessible and ready for use?",
        "short_text": "Decontamination showers and eyewash stations.",
        "vessel_types": [
          "Chemical",
          "LPG"
        ],
        "objective": "To ensure the decontamination showers and eyewash stations provided on deck are always ready to use in\nan emergency.",
        "negative_grounds": [
          "There was no company procedure which ensures that decontamination showers and eye wash stations on",
          "deck were ready for use."
        ],
        "evidence": [
          "Company procedure which ensures that decontamination showers and eye wash stations on deck were",
          "ready for use.",
          "Records of inspection and testing of the decontamination showers and eye wash stations on deck."
        ],
        "risk": "medium",
        "status": "not_started"
      },
      {
        "id": "5.6.1",
        "number": "5.6.1",
        "chapter": "5",
        "section": "5.6",
        "text": "",
        "short_text": "",
        "vessel_types": [],
        "objective": "",
        "negative_grounds": [
          "There were no ship-specific company procedures for carrying out emergency discharge operations using an",
          "emergency cargo pump or via pressurisation as applicable.",
          "The accompanying officer was not familiar with the company procedures for carrying out emergency",
          "discharge operations.",
          "Where emergency discharge procedures involved an emergency cargo pump, the pump was:",
          "Defective in any respect.",
          "Not stored in the required ‘dry’ atmosphere.",
          "Where carried, there were no records of the inspection and testing of the emergency cargo pump."
        ],
        "evidence": [
          "Company procedures for carrying out emergency discharge operations.",
          "Where carried, the inspection and testing records for the emergency cargo pump."
        ],
        "risk": "medium",
        "status": "not_started"
      },
      {
        "id": "5.12.4",
        "number": "5.12.4",
        "chapter": "5",
        "section": "5.12",
        "text": "",
        "short_text": "",
        "vessel_types": [],
        "objective": "",
        "negative_grounds": [
          "There were no company procedures for the regular inspection and maintenance of cargo and vapour",
          "pipeline insulation and expansion arrangements.",
          "Inspection and maintenance of cargo and vapour pipeline insulation and expansion arrangements had not",
          "been carried out in accordance with the company procedures.",
          "A section of cargo or vapour pipeline insulation had been removed and not replaced.",
          "Cargo or vapour pipeline insulation was cracked or otherwise damaged (give details).",
          "Icing on pipework insulation indicated a local failure of the insulation.",
          "There was evidence of corrosion on the pipework underneath the insulation."
        ],
        "evidence": [
          "The company procedures for the regular inspection and maintenance of cargo and vapour pipeline insulation",
          "and expansion arrangements.",
          "Records of the regular inspection and maintenance of cargo and vapour pipeline insulation and expansion",
          "arrangements."
        ],
        "risk": "medium",
        "status": "not_started"
      }
    ]
  },
  {
    "id": "C6",
    "title": "Pollution Prevention",
    "roles": [
      "Master",
      "CE",
      "Officers"
    ],
    "questions": [
      {
        "id": "6.1.1",
        "number": "6.1.1",
        "chapter": "6",
        "section": "6.1",
        "text": "Were the Master and officers familiar with the company procedure for maintaining the Cargo Record Book, and did the entries contained in the Cargo Record Book accurately record the cargo related operations required to be documented by MARPOL Annex II?",
        "short_text": "Cargo Record Book",
        "vessel_types": [
          "Chemical",
          "LPG"
        ],
        "objective": "To ensure that all cargo operations are conducted in compliance with the Procedures and Arrangements\nManual and recorded in accordance with MARPOL Annex II.",
        "negative_grounds": [
          "There was no company procedure for maintaining the Cargo Record Book in accordance with MARPOL",
          "Annex II and any Flag Administration instructions.",
          "The accompanying officer was not familiar with company procedures for maintaining the CRB in accordance",
          "with MARPOL Annex II and any Flag Administration instructions.",
          "Where the vessel was using an electronic record book, there were no instructions available for the use of the",
          "electronic record book system.",
          "Where the vessel was using an electronic record book, there was no Declaration from flag/class authorising",
          "There was no facility for automatic backup and recovery of data if the electronic record book system were to"
        ],
        "evidence": [
          "The company procedures for maintaining the Cargo Record Book, either in paper or electronic format, in",
          "accordance with MARPOL Annex II and any Flag Administration instructions.",
          "Cargo Record Books for the previous six months.",
          "Cargo records for the previous six months.",
          "The Bridge Log Book for the previous six months.",
          "Where an electronic record book is in use, the Declaration from flag/class."
        ],
        "risk": "medium",
        "status": "not_started"
      },
      {
        "id": "6.1.2",
        "number": "6.1.2",
        "chapter": "6",
        "section": "6.1",
        "text": "Were the Master and officers familiar with the company procedure for maintaining the Oil Record Book Part II, and did the entries contained in the Oil Record Book Part II accurately record the cargo related operations required to be documented by MARPOL Annex I?",
        "short_text": "Oil Record Book Part II",
        "vessel_types": [
          "Oil",
          "Chemical"
        ],
        "objective": "To ensure that all cargo operations are conducted and recorded in compliance with MARPOL Annex I.",
        "negative_grounds": [
          "There was no company procedure for maintaining the Oil Record Book Part II (ORB II) in accordance with",
          "MARPOL Annex I and any Flag Administration instructions.",
          "The accompanying officer was not familiar with company procedure for maintaining the ORB II in",
          "accordance with MARPOL Annex I and any Flag Administration instructions.",
          "Where the vessel was using an electronic record book, there were no instructions available for the use of the",
          "electronic record book system.",
          "Where the vessel was using an electronic record book, there was no Declaration from flag/class authorising",
          "There was no facility for automatic backup and recovery of data if the electronic record book system were to"
        ],
        "evidence": [
          "The company procedures for maintaining the Oil Record Book Part II in accordance with MARPOL Annex I",
          "and any Flag Administration instructions.",
          "Oil Record Book Part II for the previous six months.",
          "Cargo records for the previous six months.",
          "The Bridge Log Book for the previous six months.",
          "Where an electronic record book is in use, the Declaration from flag/class."
        ],
        "risk": "medium",
        "status": "not_started"
      },
      {
        "id": "6.1.3",
        "number": "6.1.3",
        "chapter": "6",
        "section": "6.1",
        "text": "Were the Master and engineer officers familiar with the company procedure for maintaining the Oil Record Book Part I, and did the entries contained in the Oil Record Book Part I accurately record the machinery space operations required to be documented by MARPOL Annex I?",
        "short_text": "Oil Record Book Part I",
        "vessel_types": [
          "Oil",
          "Chemical",
          "LPG",
          "LNG"
        ],
        "objective": "To ensure that all machinery space operations are conducted and recorded in compliance with MARPOL\nAnnex I.",
        "negative_grounds": [
          "There was no company procedure for maintaining the Oil Record Book Part I in accordance with MARPOL",
          "Annex I and any Flag Administration instructions.",
          "Where the vessel was using an electronic record book, there were no instructions available for the use of the",
          "electronic record book system.",
          "Where the vessel was using an electronic record book, there was no Declaration from flag/class authorising",
          "There was no facility for automatic backup and recovery of data if the electronic record book system were to",
          "fail or not be available from the ship’s network.",
          "The accompanying officer was not familiar with company procedure for maintaining the Oil Record Book"
        ],
        "evidence": [
          "The company procedures for maintaining the Oil Record Book Part I in accordance with MARPOL Annex I",
          "and any Flag Administration instructions.",
          "Oil Record Book Part I for the previous six months.",
          "The Engine Room Log Book for the previous six months.",
          "A copy of the supplement to the IOPP certificate (Form B) Where an electronic record book is in use, the Declaration from flag/class."
        ],
        "risk": "medium",
        "status": "not_started"
      },
      {
        "id": "6.1.4",
        "number": "6.1.4",
        "chapter": "6",
        "section": "6.1",
        "text": "Were the Master and officers familiar with the company procedures for maintaining the Garbage Record Book in accordance with the Garbage Management Plan, and did the entries contained in the Garbage Record Book accurately record the garbage management activities required to be documented by MARPOL Annex V?",
        "short_text": "Garbage Record Book",
        "vessel_types": [
          "Oil",
          "Chemical",
          "LPG",
          "LNG"
        ],
        "objective": "To ensure that all garbage management activities are conducted and recorded in compliance with MARPOL\nAnnex V.",
        "negative_grounds": [
          "There was no company procedure for maintaining the Garbage Record Book, either in paper or electronic",
          "format, in accordance with MARPOL Annex V and any Flag Administration instructions.",
          "Where the vessel was using an electronic record book, there were no instructions available for the use of the",
          "electronic record book system.",
          "Where the vessel was using an electronic record book, there was no Declaration from flag/class authorising",
          "There was no facility for automatic backup and recovery of data if the electronic record book system were to",
          "fail or not be available from the ship’s network.",
          "The was no Garbage Management Plan available onboard."
        ],
        "evidence": [
          "The company procedures for developing a Garbage Management Plan and maintaining the Garbage Record",
          "Book (GRB), either in paper or electronic format, in accordance with MARPOL Annex V and any Flag",
          "Administration guidance.",
          "The Garbage Management Plan.",
          "Garbage Record Book for the previous six months.",
          "The Bridge Log Book for the previous six months."
        ],
        "risk": "medium",
        "status": "not_started"
      },
      {
        "id": "6.1.5",
        "number": "6.1.5",
        "chapter": "6",
        "section": "6.1",
        "text": "Were the Master and engineer officers familiar with the company procedure for maintaining the Ozone-depleting Substances Record Book, and did the entries contained in the Ozone-depleting Substances Record Book accurately record the operations and emissions required to be documented by MARPOL Annex VI?",
        "short_text": "Ozone Depleting Substances Record Book",
        "vessel_types": [
          "Oil",
          "Chemical",
          "LPG",
          "LNG"
        ],
        "objective": "To ensure all operations involving ozone-depleting substances, including any deliberate and non-deliberate\nemissions, are recorded in compliance with MARPOL Annex VI.",
        "negative_grounds": [
          "There was no company procedure that described the requirements for maintaining the Ozone-depleting",
          "Substances Record Book, either in paper or electronic format, in accordance with MARPOL Annex VI and",
          "any Flag Administration guidance.",
          "The accompanying officer was not familiar with the company procedures that described the requirements for",
          "maintaining the Ozone-depleting Substances Record Book, either in paper or electronic format, in",
          "accordance with MARPOL Annex VI and any Flag Administration guidance.",
          "Where the vessel was using an electronic record book, there were no instructions available for the use of the",
          "electronic record book system."
        ],
        "evidence": [
          "The company procedures that described the requirements for maintaining the Ozone-depleting Substances",
          "Record Book, either in paper or electronic format, in accordance with MARPOL Annex VI and any Flag",
          "Administration guidance.",
          "The Ozone-depleting Substances Record Book for the previous six months.",
          "The maintenance records for the equipment on board containing ozone-depleting substances for the",
          "previous six months."
        ],
        "risk": "medium",
        "status": "not_started"
      },
      {
        "id": "6.1.6",
        "number": "6.1.6",
        "chapter": "6",
        "section": "6.1",
        "text": "Were the documents and records required by MARPOL Annex VI Regulation 13 for the control of NOx and associated emissions in good order?",
        "short_text": "MARPOL Annex VI NOx Compliance and Record Keeping.",
        "vessel_types": [
          "Oil",
          "Chemical",
          "LPG",
          "LNG"
        ],
        "objective": "To ensure the documents and records required by MARPOL Annex VI for the control of NOx and associated\nemissions are maintained as required.",
        "negative_grounds": [],
        "evidence": [],
        "risk": "low",
        "status": "not_started"
      },
      {
        "id": "6.2.1",
        "number": "6.2.1",
        "chapter": "6",
        "section": "6.2",
        "text": "Were the Master and officers familiar with the arrangements to drain the cargo pumproom bilges in the event of flooding or accidental leakage, and were these arrangements in good order?",
        "short_text": "Flooding or accidental leakage of cargo pumproom bilges",
        "vessel_types": [
          "Oil",
          "Chemical"
        ],
        "objective": "To ensure that the cargo pumproom bilge pump could be operated when the pumproom was flooded.",
        "negative_grounds": [
          "There was no company procedure for draining the pumproom bilges.",
          "There was no shipboard emergency response plan for pumproom flooding.",
          "The company procedures did not provide guidance on:",
          "Transferring bilge contents to cargo/slop tanks or other containment tanks without risk of pollution."
        ],
        "evidence": [
          "The company procedures for draining the pumproom bilges.",
          "The shipboard emergency response plan for pumproom flooding.",
          "The Oil Record Book Part II.",
          "Records of tests of the arrangements for draining the pumproom bilges."
        ],
        "risk": "medium",
        "status": "not_started"
      },
      {
        "id": "6.2.2",
        "number": "6.2.2",
        "chapter": "6",
        "section": "6.2",
        "text": "Were cargo system overboard and sea suction valves checked and verified as closed and secured prior to commencement of cargo transfer, and where provided, were sea valve-testing arrangements in order and regularly monitored for leakage?",
        "short_text": "Cargo system overboard and sea suction valves",
        "vessel_types": [
          "Oil",
          "Chemical"
        ],
        "objective": "To ensure all precautions are taken to prevent cargo spillages through cargo system overboard and sea\nsuction valves.",
        "negative_grounds": [
          "There were no company procedures to prevent cargo spillages through cargo system overboard and sea",
          "suction valves that included detailed guidance on:",
          "Taking ballast into cargo tanks via sea-valves.",
          "Line displacement with sea water.",
          "And precautionary measures including:",
          "Checking cargo system overboard and sea suction valves are closed and secured prior to",
          "commencement of cargo transfer.",
          "Checking cargo system overboard and sea suction valves for leakage, where arrangements are"
        ],
        "evidence": [
          "Company procedures to prevent cargo spillages through cargo system overboard and sea suction valves.",
          "Records of o Checks that cargo system overboard and sea suction valves are closed and secured prior to",
          "commencement of cargo transfer in the bridge or cargo logbook.",
          "o Checks of cargo system overboard and sea suction valves for leakage.",
          "o Tests of cargo system overboard and sea suction valves for integrity between dry-docks."
        ],
        "risk": "medium",
        "status": "not_started"
      },
      {
        "id": "6.2.3",
        "number": "6.2.3",
        "chapter": "6",
        "section": "6.2",
        "text": "Were the Master and officers familiar with the company procedures for inspections and pressure tests of the bunker oil (HFO and MDO) pipeline system, and had the tests been performed and the results suitably recorded?",
        "short_text": "Bunker pipeline system pressure testing",
        "vessel_types": [
          "Oil",
          "Chemical",
          "LPG",
          "LNG"
        ],
        "objective": "To ensure the bunker pipeline system is regularly inspected and tested.",
        "negative_grounds": [
          "There were no company procedures for the inspection and pressure testing of the bunker pipeline system",
          "including guidance on the:",
          "Equipment to be inspected/tested.",
          "Inspection and test frequency."
        ],
        "evidence": [
          "Company procedures for the inspection and pressure testing of the bunker pipeline system.",
          "Records of inspection and testing of the bunker pipeline system.",
          "Records of testing the bunker system relief valve, where fitted.",
          "Records of testing tank level alarms, where fitted.",
          "Records of the disposal of the liquid used to test the pipeline system."
        ],
        "risk": "medium",
        "status": "not_started"
      },
      {
        "id": "6.3.1",
        "number": "6.3.1",
        "chapter": "6",
        "section": "6.3",
        "text": "Were the Master and officers familiar with the company procedures for the safe operation of the ballast water management system (BWMS), and was the equipment in satisfactory condition and used in accordance with the company procedures and manufacturer’s instructions?",
        "short_text": "Ballast water management system (BWMS)",
        "vessel_types": [
          "Oil",
          "Chemical",
          "LPG",
          "LNG"
        ],
        "objective": "To ensure that ballast is always handled safely in accordance with company procedures and manufacturer’s\ninstructions.",
        "negative_grounds": [
          "There were no company procedures for the operation, inspection and maintenance of the ballast water",
          "management system (BWMS), including guidance on:",
          "Who is responsible for supervising the use of the BWMS.",
          "Who is permitted to use the BWMS.",
          "Identification of hazards to the crew presented by the operation of the BWMS.",
          "Mitigation measures for hazards presented by the operation of the BWMS.",
          "Use, handling and storage of any active substances, such as chemicals, used by the system for",
          "disinfection or neutralisation."
        ],
        "evidence": [
          "Company procedures for the operation, inspection and maintenance of the ballast water management",
          "system (BWMS).",
          "The operation and safety manual for the BWMS.",
          "Inspection and maintenance records of the BWMS.",
          "Records of the operation of the BWMS."
        ],
        "risk": "medium",
        "status": "not_started"
      },
      {
        "id": "6.4.1",
        "number": "6.4.1",
        "chapter": "6",
        "section": "6.4",
        "text": "Were the Master, officers and ratings familiar with the company procedures for the removal of small quantities of oil or chemical spilled and contained on deck, and was suitable response equipment available, in satisfactory condition and effectively deployed?",
        "short_text": "Main deck oil or chemical spill clean up equipment.",
        "vessel_types": [
          "Oil",
          "Chemical",
          "LPG",
          "LNG"
        ],
        "objective": "To ensure any oil or chemical spills contained on deck are promptly and safely cleaned up.",
        "negative_grounds": [
          "There were no company procedures for the removal of oil or chemical spilled and contained on deck.",
          "There was no inventory of spill clean-up equipment on board.",
          "The records of periodic inspections of the inventory of spill clean-up equipment were missing or incomplete.",
          "There were no instructions available for the safe use of the spill clean-up equipment, including PPE",
          "Company procedures did not contain:",
          "A provision that no chemical agent should be used in response to pollution on the sea without",
          "authorization of the appropriate coastal State and that such authorization should also be requested,",
          "when required, for use of containment or recovery equipment."
        ],
        "evidence": [
          "The SOPEP or SMPEP Company procedures for the removal of oil or chemical spilled and contained on deck.",
          "The inventory of spill clean-up equipment and records of periodic inspections."
        ],
        "risk": "medium",
        "status": "not_started"
      },
      {
        "id": "6.4.2",
        "number": "6.4.2",
        "chapter": "6",
        "section": "6.4",
        "text": "Were the Master and officers familiar with the company procedures for the disposal of accumulations of water contaminated with oil and/or marine pollutants in the forecastle and other internal spaces, and had the procedures been implemented?",
        "short_text": "Disposal of oily water in the forecastle and other internal spaces",
        "vessel_types": [
          "Oil",
          "Chemical",
          "LPG",
          "LNG"
        ],
        "objective": "To ensure any water contaminated with oil or marine pollutants generated in the forecastle and other internal\nspaces is disposed of properly.",
        "negative_grounds": [
          "There were no company procedures to ensure proper disposal of oily waste or other marine pollutants",
          "accumulated in internal space bilge wells including:",
          "Identification of relevant spaces.",
          "Measures to minimise oily waste generation.",
          "Monitoring of bilge levels, by inspection or sensor/alarm.",
          "Arrangements for proper disposal of any oily and/or marine pollutant waste generated.",
          "The accompanying officer was not familiar with the company procedures to ensure proper disposal of oily",
          "waste or other marine pollutants accumulated in internal space bilge wells."
        ],
        "evidence": [
          "Company procedures to ensure proper disposal of oily waste or other marine pollutants accumulated in",
          "internal space bilge wells.",
          "Records of the disposal of oily waste or other marine pollutants accumulated in internal space bilge wells."
        ],
        "risk": "medium",
        "status": "not_started"
      },
      {
        "id": "6.5.1",
        "number": "6.5.1",
        "chapter": "6",
        "section": "6.5",
        "text": "Were the Master and officers familiar with the emergency arrangements to pump out the machinery space bilges in the event of flooding, and were these arrangements prominently marked and in good order?",
        "short_text": "Emergency arrangements to pump out the machinery space bilges",
        "vessel_types": [
          "Oil",
          "Chemical",
          "LPG",
          "LNG"
        ],
        "objective": "To ensure that the machinery space bilges could be pumped out promptly in the event of a flooding\nsituation.",
        "negative_grounds": [],
        "evidence": [],
        "risk": "low",
        "status": "not_started"
      },
      {
        "id": "6.5.2",
        "number": "6.5.2",
        "chapter": "6",
        "section": "6.5",
        "text": "Were the engineer officers familiar with the company procedure for the safe use of the incinerator, and was the incinerator in satisfactory condition and used in accordance with the company procedure and in compliance with MARPOL?",
        "short_text": "Incinerator operation.",
        "vessel_types": [
          "Oil",
          "Chemical",
          "LPG",
          "LNG"
        ],
        "objective": "To ensure that the disposal of garbage and sludge using the incinerator is always carried out safely and in\naccordance with the requirements of MARPOL.",
        "negative_grounds": [
          "There was no company procedure which described the safe use of the incinerator.",
          "There was no risk assessment available for the safe operation of the incinerator.",
          "The accompanying officer was unfamiliar with the company procedure or risk assessment for the safe",
          "peration of the incinerator.",
          "An interviewed engineer officer was unfamiliar with:",
          "The company procedures or risk assessment for the safe operation of the incinerator.",
          "The PPE that must be worn when loading garbage into the incinerator.",
          "The process to safely load garbage into the incinerator."
        ],
        "evidence": [
          "The company procedures which described the safe use of the incinerator.",
          "The risk assessment for the safe operation of the incinerator.",
          "The incinerator operation and maintenance manual."
        ],
        "risk": "medium",
        "status": "not_started"
      },
      {
        "id": "6.6.1",
        "number": "6.6.1",
        "chapter": "6",
        "section": "6.6",
        "text": "Were the Master and engineer officers familiar with the company procedures for the use of the oil filtering equipment, and was the oil filtering equipment in satisfactory condition and used in accordance with the company procedure, manufacturer’s instructions and MARPOL Annex I?",
        "short_text": "Oil filtering equipment.",
        "vessel_types": [
          "Oil",
          "Chemical",
          "LPG",
          "LNG"
        ],
        "objective": "To ensure that bilge discharges from machinery spaces are always within the limits permitted by MARPOL\nAnnex I.",
        "negative_grounds": [
          "There was no company procedure which described the use of the oil filtering equipment provided.",
          "The 15 ppm bilge alarm sensor had not been calibrated within the previous five years or within the time",
          "frame specified by the manufacturer’s operation and maintenance manual, where this was less than five",
          "The oil filtering equipment overboard valve was not closed and/or was not secured and sealed to prevent",
          "There was no warning sign posted at the overboard valve indicating that the valve was only to be operated",
          "with the authority of the Chief Engineer or the Master.",
          "There was evidence that the oil filtering equipment or its system pipework had been tampered with."
        ],
        "evidence": [
          "The company procedures which described the use of the oil filtering equipment provided.",
          "The calibration certificate for the 15 ppm bilge alarm fitted to the oil filtering equipment.",
          "The manufacturer’s maintenance and operation manuals for the oil filtering equipment.",
          "Records of inspection and maintenance of the oil filtering equipment in the vessel’s maintenance plan.",
          "The Oil Record Book Part I."
        ],
        "risk": "medium",
        "status": "not_started"
      },
      {
        "id": "6.6.2",
        "number": "6.6.2",
        "chapter": "6",
        "section": "6.6",
        "text": "Were the Master and officers familiar with the company procedures for the use of the oil discharge monitoring and control system, and was the oil discharge monitoring and control system in satisfactory condition and used in accordance with the company procedures, manufacturer’s instructions and MARPOL Annex I?",
        "short_text": "Oil discharge monitoring and control system (ODME)",
        "vessel_types": [
          "Oil",
          "Chemical"
        ],
        "objective": "To ensure that discharges from cargo and ballast spaces are always within the limits permitted by MARPOL\nAnnex I.",
        "negative_grounds": [
          "There was no company procedure which described the use of the oil discharge monitoring and control",
          "The oil discharge monitoring and control system was defective in any respect."
        ],
        "evidence": [
          "The company procedures which described the use of the oil discharge monitoring and control system",
          "The manufacturer’s maintenance and operation manuals for the oil discharge monitoring and control system.",
          "The maintenance and inspection records for the oil discharge monitoring and control system.",
          "Print-outs of ODME data or data displayed from memory.",
          "The Oil Record Book Part II."
        ],
        "risk": "medium",
        "status": "not_started"
      }
    ]
  },
  {
    "id": "C7",
    "title": "Maritime Security",
    "roles": [
      "Master",
      "SSO",
      "Officers"
    ],
    "questions": [
      {
        "id": "7.1.1",
        "number": "7.1.1",
        "chapter": "7",
        "section": "7.1",
        "text": "Was security threat and risk assessment an integral part of voyage planning, and did the passage plan contain security related information for each leg of the voyage?",
        "short_text": "Security threat and risk assessment during passage planning.",
        "vessel_types": [
          "Oil",
          "Chemical",
          "LPG",
          "LNG"
        ],
        "objective": "To ensure voyage planning always addresses security considerations.",
        "negative_grounds": [
          "The vessel did not have the appropriate security information available such as:",
          "Relevant security charts.",
          "Industry best management practice guidance (BMP) publications.",
          "Regional Security Guidance (e.g., ReCAAP Guidance) Company specific guidance.",
          "No security risk assessment had been performed for a recent voyage.",
          "Completed voyage security risk assessments did not identify ship protection measures where required.",
          "No company specific guidance regarding recommended routeing had been provided for a recent voyage"
        ],
        "evidence": [
          "UKHO or equivalent security charts.",
          "Industry best management practice guidance (BMP) publications.",
          "Regional Security Guidance (e.g., ReCAAP Guidance) Company passage plan appraisal form checklist for a recently completed voyage.",
          "Passage plan for the same recently completed voyage.",
          "Security risk assessment for the same recently completed voyage."
        ],
        "risk": "medium",
        "status": "not_started"
      },
      {
        "id": "7.2.1",
        "number": "7.2.1",
        "chapter": "7",
        "section": "7.2",
        "text": "Were the Master and officers familiar with the company procedures for hardening the vessel when entering areas of increased security risk, and was there a Vessel Hardening Plan (VHP) available?",
        "short_text": "Vessel hardening.",
        "vessel_types": [
          "Oil",
          "Chemical",
          "LPG",
          "LNG"
        ],
        "objective": "To ensure the vessel can be hardened effectively if scheduled to enter an area of increased security risk.",
        "negative_grounds": [
          "There were no company procedures for hardening the vessel when entering areas of increased security risk.",
          "The Ship Security Officer was not familiar with the company procedures for hardening the vessel when",
          "entering areas of increased security risk.",
          "There was no Vessel Hardening Plan (VHP) available.",
          "The Vessel Hardening Plan was not ship-specific.",
          "The VHP did not include a list of materials needed to implement the VHP and the required quantities.",
          "There was no inventory of the hardening materials currently on board.",
          "There were no records of inspection and maintenance of security equipment such as water cannons, CCTV,"
        ],
        "evidence": [
          "Company procedures for hardening the vessel.",
          "Vessel Hardening plan (VHP).",
          "Inventory of hardening materials.",
          "Inspection and maintenance records for security equipment such as water cannons, CCTV, infrared",
          "detection cameras, etc.",
          "Bridge Log Book."
        ],
        "risk": "medium",
        "status": "not_started"
      },
      {
        "id": "7.2.2",
        "number": "7.2.2",
        "chapter": "7",
        "section": "7.2",
        "text": "Were the Master, officers and ratings familiar with the company procedures to control access to the vessel in port and to ensure the safety of visitors, and were these procedures effectively implemented?",
        "short_text": "Controlling access to the vessel",
        "vessel_types": [
          "Oil",
          "Chemical",
          "LPG",
          "LNG"
        ],
        "objective": "To ensure access to the vessel is controlled at all times, and that all visitors are provided with an overview of\nthe hazards present and the safety precautions to observe while they are on board.",
        "negative_grounds": [
          "There were no company procedures to control access to the vessel in port and to ensure the safety of",
          "The gangway watchman was unfamiliar with the company procedures to control access to the vessel in port",
          "and to ensure the safety of visitors.",
          "The Master had not provided the terminal with a list of approved visitors, including Agents, Surveyors,",
          "Loading Masters and the SIRE inspector.",
          "A continuous gangway watch was not maintained.",
          "There were no regular patrols of the deck to monitor potential unauthorised access points e.g. hawse pipes,"
        ],
        "evidence": [
          "Company procedures to control access to the vessel in port, and to ensure the safety of visitors, if available",
          "outside of the Ship Security Plan.",
          "Visitor Log.",
          "Visitor Information Card, if provided."
        ],
        "risk": "medium",
        "status": "not_started"
      },
      {
        "id": "7.3.1",
        "number": "7.3.1",
        "chapter": "7",
        "section": "7.3",
        "text": "Were the Master and officers familiar with regional maritime security reporting requirements and operation of the ship security alert system (SSAS) and had this equipment been regularly tested?",
        "short_text": "Ship security reporting and communications",
        "vessel_types": [
          "Oil",
          "Chemical",
          "LPG",
          "LNG"
        ],
        "objective": "To ensure that the vessel staff have knowledge of regional maritime security reporting and that the SSAS\nworks.",
        "negative_grounds": [
          "The accompanying officer was not familiar with the 24-hour contact details of the company security officer",
          "The 24-hour contact details of the CSO were not posted appropriately.",
          "The Master and/or SSO were not familiar with the company procedures for voluntary security reporting in"
        ],
        "evidence": [
          "Contact details of the CSO.",
          "Records of participation in voluntary security reporting."
        ],
        "risk": "medium",
        "status": "not_started"
      },
      {
        "id": "7.4.1",
        "number": "7.4.1",
        "chapter": "7",
        "section": "7.4",
        "text": "Did the Ship Security Officer (SSO) have a valid Certificate of Proficiency and a full understanding of their role, and were ship security records of port calls being maintained as required by SOLAS?",
        "short_text": "Ship Security Officer (SSO).",
        "vessel_types": [
          "Oil",
          "Chemical",
          "LPG",
          "LNG"
        ],
        "objective": "To ensure the SSO is trained and qualified and required security records are maintained.",
        "negative_grounds": [
          "The SMS did not clearly designate who should be SSO.",
          "The SMS did not contain a description of the role of the SSO, and a list of their duties.",
          "The SSO did not have a valid Certificate of Proficiency.",
          "The designated SSO was not a member of the crew.",
          "The SSO did not have a full understanding of their role, responsibilities, and duties. For example, they were",
          "not familiar with one or more of the following:",
          "Purpose of the Ship Security Plan (SSP).",
          "Operation, testing and maintenance of security equipment on board"
        ],
        "evidence": [
          "SSO’s Certificate of Proficiency.",
          "Sections of the SMS relating to ship security.",
          "Evidence of regular security inspections of the vessel by the SSO.",
          "Ship security records as required by SOLAS."
        ],
        "risk": "medium",
        "status": "not_started"
      },
      {
        "id": "7.5.1",
        "number": "7.5.1",
        "chapter": "7",
        "section": "7.5",
        "text": "Were the Master and officers familiar with the company procedures for cyber security risk management, and had these procedures been fully implemented?",
        "short_text": "Cyber security risk management.",
        "vessel_types": [
          "Oil",
          "Chemical",
          "LPG",
          "LNG"
        ],
        "objective": "To ensure the vessel has in place effective technical and procedural measures to protect against a cyber\nincident and ensure continuity of operations.",
        "negative_grounds": [
          "There were no company procedures for cyber risk management that:",
          "Identified the roles and responsibilities of users, key personnel, and management both ashore and",
          "Identified the IT and OT systems at risk on board.",
          "Described technical protection measures to protect against a cyber incident.",
          "Described procedural protection measures to protect against a cyber incident.",
          "The accompanying officer was not familiar with the company procedures for cyber risk management.",
          "A space containing sensitive IT or OT control equipment was not securely locked.",
          "There was no inventory/register of sensitive IT/OT systems fitted on board."
        ],
        "evidence": [
          "Company procedures for cyber risk management.",
          "The inventory/register of sensitive IT/OT systems fitted onboard.",
          "Records of approval for external local or remote access to sensitive IT/OT systems.",
          "Cyber contingency plans in hard copy.",
          "Contact details for technical support from the operator’s IT department or external IT contractors.",
          "Records of cyber security training."
        ],
        "risk": "medium",
        "status": "not_started"
      },
      {
        "id": "7.1.1",
        "number": "7.1.1",
        "chapter": "7",
        "section": "7.1",
        "text": "",
        "short_text": "",
        "vessel_types": [],
        "objective": "",
        "negative_grounds": [],
        "evidence": [],
        "risk": "low",
        "status": "not_started"
      },
      {
        "id": "7.1.6",
        "number": "7.1.6",
        "chapter": "7",
        "section": "7.1",
        "text": "",
        "short_text": "",
        "vessel_types": [],
        "objective": "",
        "negative_grounds": [
          "There were no company procedures describing the operation, testing and maintenance of the cargo heating",
          "The accompanying officer was not familiar with the company procedures describing the operation, testing",
          "and maintenance of the cargo heating system including any cargo temperature limits.",
          "The cargo heating system had not been operated and/or tested in compliance with company procedures.",
          "There were no records of the cargo heating system testing.",
          "There were no records of cargo heating operations.",
          "The cargo heating system had not been isolated where required in compliance with company procedures.",
          "There were no records of the regular monitoring of the cargo heating system return to detect leakage."
        ],
        "evidence": [
          "The company procedures describing the operation, testing and maintenance of the cargo heating system.",
          "The vessel’s operation manuals, where provided.",
          "The records of cargo heating system usage.",
          "The daily temperature records for heated cargo.",
          "Records of the inspection and testing of the cargo heating system."
        ],
        "risk": "medium",
        "status": "not_started"
      }
    ]
  },
  {
    "id": "C8",
    "title": "Cargo and Ballast Systems",
    "roles": [
      "Master",
      "CE",
      "Cargo Officers"
    ],
    "questions": [
      {
        "id": "8.12.1",
        "number": "8.12.1",
        "chapter": "8",
        "section": "8.12",
        "text": "",
        "short_text": "",
        "vessel_types": [],
        "objective": "",
        "negative_grounds": [
          "There were no company procedures to ensure that the lifejackets required by SOLAS were in good order,",
          "readily accessible and their location(s) clearly indicated."
        ],
        "evidence": [
          "The company procedures to ensure that the lifejackets required by SOLAS were in good order, readily",
          "accessible and their location(s) clearly indicated.",
          "The company procedures providing guidance on the use of “working lifejackets”, including the servicing of",
          "inflatable lifejackets, if carried.",
          "Records of monthly inspections of all lifejackets.",
          "Records of annual servicing of inflatable lifejackets, if carried."
        ],
        "risk": "medium",
        "status": "not_started"
      },
      {
        "id": "8.1.1",
        "number": "8.1.1",
        "chapter": "8",
        "section": "8.1",
        "text": "Were the Master and officers familiar with the company procedures for the use of the inert gas system, and had the inert gas system been used in accordance with ISGOTT guidance, with cargo tanks maintained in an inert condition at all times, except when it was necessary to be gas-free for entry?",
        "short_text": "Inert gas system usage on oil tankers.",
        "vessel_types": [
          "Oil"
        ],
        "objective": "To ensure the inert gas system is used in accordance with ISGOTT guidance, and cargo tanks are always\nmaintained in an inert condition, except when it is necessary to be gas-free for entry.",
        "negative_grounds": [
          "There were no company procedures for the operation of the vessel’s inert gas system which included:",
          "Inerting empty cargo tanks.",
          "Operation during discharge, de-ballasting, COW and tank cleaning."
        ],
        "evidence": [
          "The company procedures for the operation of the vessel’s inert gas system.",
          "The detailed instruction manuals for the inert gas system.",
          "Cargo and inert gas records for the previous three months or three voyages whichever was greater."
        ],
        "risk": "medium",
        "status": "not_started"
      },
      {
        "id": "8.1.2",
        "number": "8.1.2",
        "chapter": "8",
        "section": "8.1",
        "text": "Were the Master and officers familiar with the company procedures and international regulations for the planning, preparation, conduct and documentation of crude oil washing operations (COW), and was the COW system in satisfactory condition and used in accordance with the company procedures for each COW operation?",
        "short_text": "Crude Oil Washing operations (COW)",
        "vessel_types": [
          "Oil"
        ],
        "objective": "To ensure crude oil washing operations are always planned, prepared, conducted and documented in\naccordance with international regulation and industry best practice.",
        "negative_grounds": [
          "There were no company procedures for the planning, preparation, conduct and documentation of crude oil",
          "washing which included the:",
          "Roles, responsibilities and qualifications of those involved in COW operations.",
          "Requirement for crude oil washing of cargo tanks for:",
          " Sludge control purposes.",
          " Preparation for the carriage of ballast in a cargo tank or tanks.",
          "Suitability of crude oils for crude oil washing.",
          "Use of dry crude oil for washing."
        ],
        "evidence": [
          "The company procedures for the planning, preparation, conduct and documentation of crude oil washing.",
          "The COW manual.",
          "The records and checklists for the current and previous COW operations.",
          "Ship Shore Safety Check Lists (SSSCL).",
          "The COW plan for the current operation.",
          "The Bridge and/or Cargo Log Book."
        ],
        "risk": "medium",
        "status": "not_started"
      },
      {
        "id": "8.1.3",
        "number": "8.1.3",
        "chapter": "8",
        "section": "8.1",
        "text": "Were the Master and officers familiar with the company procedures for the isolation of individual cargo tanks from the common venting system in accordance with SOLAS, and were these procedures being followed?",
        "short_text": "Cargo tank isolation from venting system.",
        "vessel_types": [
          "Oil"
        ],
        "objective": "To ensure there are no incidences of cargo tank over or under pressurisation as a result of the mishandling\nor failure of vapour or inert gas isolating valves.",
        "negative_grounds": [
          "There were no company procedures for the isolation of individual cargo tanks from the common venting",
          "system which included:",
          "Maintenance and pre-operational testing of isolating valves.",
          "Checking the operational status of isolating valves prior to commencing operations.",
          "Locking arrangements for isolating valves, under the control of the responsible officer.",
          "Guidance on personnel authorised to operate the isolating valves.",
          "Provision of clear visual indication of the operational status of the valves or other acceptable means",
          "A method of recording the current position of the valves/means of isolation at the cargo control"
        ],
        "evidence": [
          "The company procedures for the isolation of individual cargo tanks from the common venting system.",
          "The record or display of the current operational status of the isolating valves Cargo operation logbooks",
          "Records of checks, tests and maintenance of the isolating valves."
        ],
        "risk": "medium",
        "status": "not_started"
      },
      {
        "id": "8.1.4",
        "number": "8.1.4",
        "chapter": "8",
        "section": "8.1",
        "text": "Were the Master and deck officers familiar with the company procedures for planning and documenting cargo tank cleaning operations after the carriage of volatile products, and had these procedures been followed?",
        "short_text": "Oil cargo tank cleaning procedures.",
        "vessel_types": [
          "Oil"
        ],
        "objective": "To ensure that tank cleaning and gas freeing operations after the carriage of volatile products are always\ncarefully planned, conducted and documented.",
        "negative_grounds": [
          "There were no company procedures for planning and documenting cargo tank cleaning operations after the",
          "carriage of volatile products that addressed:",
          "Tank washing and gas freeing plans."
        ],
        "evidence": [
          "Company procedures for planning and documenting cargo tank cleaning and gas freeing operations after",
          "the carriage of volatile products.",
          "Completed plans, risk assessments, log books and records for previous tank cleaning operations."
        ],
        "risk": "medium",
        "status": "not_started"
      },
      {
        "id": "8.2.1",
        "number": "8.2.1",
        "chapter": "8",
        "section": "8.2",
        "text": "Were the Master and officers familiar with the company procedures for the operation of the inert gas system, and had the inert gas system been used in accordance with these procedures, industry guidance, and SOLAS and IBC regulations?",
        "short_text": "Chemical tanker inert gas system usage.",
        "vessel_types": [
          "Chemical"
        ],
        "objective": "To ensure the inert gas system is always used in accordance with industry guidance, SOLAS and IBC\nregulations and company procedures to prevent fire and explosion.",
        "negative_grounds": [
          "There were no company procedures for the operation of the vessel’s inert gas system which included:",
          "Inerting empty cargo tanks.",
          "Inerting tanks before commencement of unloading.",
          "Operation during discharge and tank cleaning.",
          "Purging tanks before gas freeing.",
          "Topping up the pressure in the cargo tanks when necessary during other stages of the voyage.",
          "Actions to be taken in the event of a failure of the inert gas system.",
          "The accompanying officer was not familiar with the company procedures for the operation of the vessel’s"
        ],
        "evidence": [
          "The company procedures for the operation of the vessel’s inert gas system.",
          "The detailed instruction manuals for the inert gas system.",
          "Cargo and inert gas records for the previous three months or three voyages whichever was greater."
        ],
        "risk": "medium",
        "status": "not_started"
      },
      {
        "id": "8.2.2",
        "number": "8.2.2",
        "chapter": "8",
        "section": "8.2",
        "text": "Were the Master and officers familiar with the company procedures that addressed the carriage of inhibited cargoes, and had these procedures been followed?",
        "short_text": "Carriage of inhibited chemical cargoes.",
        "vessel_types": [
          "Chemical"
        ],
        "objective": "To ensure that inhibited cargoes are carried safely and in compliance with company procedures and the IBC\nCode.",
        "negative_grounds": [
          "There were no company procedures that addressed the carriage of inhibited cargoes and included guidance",
          "Inhibited cargo certificates of protection.",
          "Temperature monitoring of inhibited cargoes and adjacent spaces.",
          "Inerting of inhibited cargoes and monitoring of the oxygen level in the vapour space.",
          "Preventing a build-up of solid polymers in the venting system.",
          "The use of compressed nitrogen to clear arms/hoses after loading.",
          "The addition of extra inhibitor when provided on board.",
          "Contingency planning for uncontrolled polymerisation."
        ],
        "evidence": [
          "Company procedures that address the carriage of inhibited cargoes.",
          "Inhibited cargo certificates of protection.",
          "Inert gas logs relevant to the carriage of inhibited cargoes.",
          "Bridge and Cargo Log Books.",
          "Cargo tank temperature records relevant to the carriage of inhibited cargoes.",
          "Cargo load and discharge plans relevant to the carriage of inhibited cargoes."
        ],
        "risk": "medium",
        "status": "not_started"
      },
      {
        "id": "8.2.3",
        "number": "8.2.3",
        "chapter": "8",
        "section": "8.2",
        "text": "Were the Master and officers familiar with the information contained in the Procedures and Arrangements Manual, Certificate of Fitness for the Carriage of Noxious Liquid Substances in Bulk, the IBC Code and the latest MEPC.2/Circular, and was this information readily available to the officers engaged in cargo planning and operations?",
        "short_text": "Procedures and Arrangements Manual.",
        "vessel_types": [
          "Chemical",
          "LPG"
        ],
        "objective": "To ensure the Master and officers have the necessary information readily available to them to plan and\nperform safe cargo operations.",
        "negative_grounds": [
          "The officer responsible for cargo planning and operations was not familiar with the information contained in",
          "the P&A Manual, Certificate of Fitness for the Carriage of Noxious Liquid Substances in Bulk, the IBC Code",
          "and/or the latest MEPC.2/Circular.",
          "The officer responsible for cargo planning and operations was not familiar with the “stripping quantities” for",
          "The accompanying officer was not familiar with the information contained in the P&A Manual, as it related to",
          "The P&A Manual was not readily available.",
          "On a ship engaged in international voyages, the P&A Manual was not available in either English, French or"
        ],
        "evidence": [
          "Procedures and Arrangements Manual.",
          "List of permitted cargoes.",
          "Latest edition available of the MEPC.2/Circular."
        ],
        "risk": "medium",
        "status": "not_started"
      },
      {
        "id": "8.2.4",
        "number": "8.2.4",
        "chapter": "8",
        "section": "8.2",
        "text": "Were the Master and deck officers familiar with the company procedures for planning and documenting cargo tank cleaning operations after the carriage of volatile and/or toxic products, and had these procedures been followed?",
        "short_text": "Chemical tank cleaning procedures.",
        "vessel_types": [
          "Chemical"
        ],
        "objective": "To ensure that tank cleaning and gas freeing operations after the carriage of volatile and/or toxic products\nare always carefully planned, conducted and documented.",
        "negative_grounds": [
          "There were no company procedures for planning and documenting cargo tank cleaning operations after the",
          "carriage of volatile and/or toxic products that addressed:",
          "Tank cleaning guidelines for all expected cargoes.",
          "Written tank washing and gas freeing plans.",
          "Tank washing procedures and arrangements.",
          "The required atmosphere for tank washing.",
          "Manufacturer’s coating guidelines."
        ],
        "evidence": [
          "Company procedures for planning and documenting cargo tank cleaning operations after the carriage of",
          "volatile and/or toxic products.",
          "P&A Manual Completed written tank cleaning plans, risk assessments, log books and records for previous tank cleaning",
          "operations.",
          "Tank cleaning guidelines for all expected cargoes."
        ],
        "risk": "medium",
        "status": "not_started"
      },
      {
        "id": "8.2.5",
        "number": "8.2.5",
        "chapter": "8",
        "section": "8.2",
        "text": "Were the Master and deck officers familiar with the company procedures for identifying and segregating incompatible cargoes during cargo stowage planning, and had these procedures been followed?",
        "short_text": "Chemical cargo compatibility charts.",
        "vessel_types": [
          "Chemical"
        ],
        "objective": "To ensure cargo stowage is carefully planned to avoid the possibility of co-mingling of incompatible cargoes\nor their vapours.",
        "negative_grounds": [
          "There were no company procedures for cargo stowage planning that included:",
          "Identification of incompatible cargoes using recognised compatibility charts.",
          "Means of segregation of incompatible cargoes, including ship specific arrangements.",
          "The officer responsible for cargo stowage planning was not familiar with company procedures for identifying",
          "and segregating incompatible cargoes.",
          "The officer responsible for cargo stowage planning was not familiar with the contents and use of the",
          "compatibility charts provided on board.",
          "There were no compatibility charts issued by a recognised authority available on board."
        ],
        "evidence": [
          "Company procedures for identifying and segregating incompatible cargoes during cargo stowage planning.",
          "Current and previous cargo stowage plans.",
          "Compatibility charts and appendices.",
          "P&A Manual.",
          "Relevant ship’s drawings showing acceptable segregation arrangements."
        ],
        "risk": "medium",
        "status": "not_started"
      },
      {
        "id": "8.2.6",
        "number": "8.2.6",
        "chapter": "8",
        "section": "8.2",
        "text": "Were there sufficient escape sets as required by the IBC Code for everyone on board, and did the sets provide suitable respiratory and eye protection?",
        "short_text": "Escape sets required by IBC Code.",
        "vessel_types": [
          "Chemical"
        ],
        "objective": "To ensure that everyone on board is provided with a suitable emergency escape set to exit a hazardous\natmosphere in case of an emergency.",
        "negative_grounds": [
          "The escape sets provided:",
          "Did not have a design duration of at least 15 minutes.",
          "Were not included in the company procedures for the use and maintenance of EEBDs and the",
          "nboard maintenance plan.",
          "Used filter-type respiratory protection.",
          "Did not provide suitable eye protection.",
          "Were not suitably marked as not to be used for fire-fighting or cargo-handling purposes.",
          "Were not in addition to the EEBDs required by SOLAS to be located in the accommodation and"
        ],
        "evidence": [
          "The inspection and maintenance records for the EEBDs contained within the onboard maintenance plan"
        ],
        "risk": "high",
        "status": "not_started"
      },
      {
        "id": "8.2.7",
        "number": "8.2.7",
        "chapter": "8",
        "section": "8.2",
        "text": "Were the Master and officers familiar with the company procedures relating to the safety equipment required by the IBC Code, including SCBAs, and was the equipment in satisfactory condition ready for immediate use?",
        "short_text": "Safety equipment required by the IBC Code.",
        "vessel_types": [
          "Chemical"
        ],
        "objective": "To ensure the safety equipment required by the IBC Code is always ready for immediate use in the event of\nan emergency.",
        "negative_grounds": [
          "There were no company procedures relating to the safety equipment, including SCBAs, required by the IBC",
          "Code, giving guidance on:",
          "Stowage and maintaining readiness of the equipment.",
          "Inspection and testing of the SCBAs.",
          "Non-emergency use of the SCBAs, including maximum individual daily use and required rest",
          "The accompanying officer was not familiar with the company procedures relating to the safety equipment,",
          "including SCBAs, required by the IBC Code."
        ],
        "evidence": [
          "Company procedures for the use of the safety equipment, including SCBAs, required by the IBC Code.",
          "Records of inspection and testing of the SCBAs forming part of the safety equipment required by the IBC.",
          "Evidence that the protective suits were suitable for: o All chemicals listed on the certificate of fitness identified under column ‘o’ in the table of chapter 17",
          "of the IBC code.",
          "o Use in a flammable atmosphere."
        ],
        "risk": "medium",
        "status": "not_started"
      },
      {
        "id": "8.2.8",
        "number": "8.2.8",
        "chapter": "8",
        "section": "8.2",
        "text": "Were the Master and officers familiar with the company procedures addressing the protective equipment required by the IBC Code, and was this equipment in satisfactory condition and suitable for the products being handled?",
        "short_text": "Protective equipment required by the IBC Code.",
        "vessel_types": [
          "Chemical"
        ],
        "objective": "To ensure crew members are protected from exposure to hazardous conditions when engaged in cargo\noperations.",
        "negative_grounds": [
          "There were no company procedures addressing the protective equipment required by the IBC that included:",
          "A list of protective equipment to be available on board based upon risk assessment and",
          "considering the products to be carried.",
          "What protective equipment was required to be worn for the different types of operations on board,",
          "and products handled, preferably in the form of a cargo-specific PPE matrix.",
          "Crew training in the correct use of the protective equipment.",
          "Checks to be made that protective equipment is being correctly worn prior to entering a working",
          "Assessment of a user’s fitness to wear particular protective equipment in given climatic conditions."
        ],
        "evidence": [
          "Company procedures, including the cargo-specific PPE matrix where provided, addressing the protective",
          "equipment required by the IBC Code.",
          "Records of inspections of the protective equipment.",
          "An inventory or the protective equipment available onboard required by the IBC Code",
          "SDS for the products being handled.",
          "Chemical resistance list available for the protective suits provided on board."
        ],
        "risk": "medium",
        "status": "not_started"
      },
      {
        "id": "8.3.1",
        "number": "8.3.1",
        "chapter": "8",
        "section": "8.3",
        "text": "Were the Master and officers familiar with the purpose, operation and testing of the inert gas generator, and had the system been operated and maintained in accordance with the manufacturer’s instructions and company procedures?",
        "short_text": "Inert gas generator",
        "vessel_types": [
          "Oil",
          "Chemical"
        ],
        "objective": "To ensure the inert gas generator always delivers inert gas in accordance with its design criteria.",
        "negative_grounds": [
          "There were no company procedures for the operation, inspection, testing and maintenance of the vessel’s",
          "inert gas system which included the:",
          "Inert gas generator Gas regulating valve The accompanying officer was not familiar with the procedures for the operation, inspection, maintenance",
          "and testing of the vessel’s inert gas system.",
          "Where the inert gas plant was contained in an enclosed room or space, there were no safe entry procedures",
          "posted at each entrance to the room."
        ],
        "evidence": [
          "The company procedures for the operation, inspection, maintenance and testing of the inert gas system and",
          "inert gas generator.",
          "The manufacturer's instruction and maintenance manual for the inert gas generator and inert gas system.",
          "The records of inspection, testing and maintenance of the inert gas generator and inert gas system."
        ],
        "risk": "medium",
        "status": "not_started"
      },
      {
        "id": "8.3.2",
        "number": "8.3.2",
        "chapter": "8",
        "section": "8.3",
        "text": "Were the Master and officers familiar with the purpose, operation and testing of the nitrogen generator inert gas system, and had the system been operated and maintained in accordance with the manufacturer’s instructions and company procedures?",
        "short_text": "Nitrogen generator inert gas system",
        "vessel_types": [
          "Oil",
          "Chemical"
        ],
        "objective": "To ensure the nitrogen generator inert gas system always delivers inert gas in accordance with its design\ncriteria.",
        "negative_grounds": [
          "There were no company procedures for the operation, inspection, testing and maintenance of the vessel’s",
          "inert gas system which included the nitrogen generator and its associated equipment.",
          "The accompanying officer was not familiar with the procedures for the operation, inspection, maintenance",
          "and testing of the vessel’s inert gas system including the nitrogen generator.",
          "The accompanying officer was not familiar with the dangers from:",
          "An oxygen deficient atmosphere as a result of nitrogen leakage.",
          "The oxygen-enriched exhaust from the nitrogen generator.",
          "The record of inspection and maintenance of the inert gas plant, including defects and their rectification, was"
        ],
        "evidence": [
          "The company procedures for the operation, inspection, maintenance and testing of the inert gas system.",
          "The manufacturer’s instruction and maintenance manual for the nitrogen generator inert gas system.",
          "The records of inspection, testing and maintenance of the inert gas system."
        ],
        "risk": "medium",
        "status": "not_started"
      },
      {
        "id": "8.3.3",
        "number": "8.3.3",
        "chapter": "8",
        "section": "8.3",
        "text": "Were the Master and officers familiar with the purpose, operation and testing of the flue gas inert gas system, and had the system been operated and maintained in accordance with the manufacturer’s instructions and company procedures?",
        "short_text": "Flue gas inert gas system",
        "vessel_types": [
          "Oil",
          "Chemical"
        ],
        "objective": "To ensure the flue gas inert gas system always delivers inert gas in accordance with its design criteria.",
        "negative_grounds": [
          "There were no company procedures for the operation, inspection, testing and maintenance of the vessel’s",
          "inert gas system which included the:",
          "Boiler uptake valves.",
          "Gas regulating valve.",
          "The accompanying officer was not familiar with the procedures for the operation, inspection, maintenance",
          "and testing of the vessel’s inert gas system.",
          "Where the inert gas plant was contained in an enclosed room or space, there were no safe entry procedures",
          "posted at each entrance to the room."
        ],
        "evidence": [
          "The company procedures for the operation, inspection, maintenance and testing of the inert gas system.",
          "The manufacturer's instruction and maintenance manual for the flue gas inert gas system.",
          "The records of inspection, testing and maintenance of the inert gas system."
        ],
        "risk": "medium",
        "status": "not_started"
      },
      {
        "id": "8.3.4",
        "number": "8.3.4",
        "chapter": "8",
        "section": "8.3",
        "text": "Were the Master and officers familiar with the company procedures for the maintenance, testing and setting of the cargo tank high-level and high-high-level alarms, and were these alarm systems fully operational and properly set?",
        "short_text": "Cargo tank high level and overfill alarms.",
        "vessel_types": [
          "Oil",
          "Chemical"
        ],
        "objective": "To ensure that cargo tank high-level and high-high-level alarms are always fully operational, properly set and\nused during all cargo loading, discharging and transfer operations.",
        "negative_grounds": [
          "There were no company procedures for the maintenance, testing and setting of the cargo tank high-level",
          "and high-high-level alarm systems.",
          "The accompanying officer was not familiar with:",
          "The company procedures for the maintenance, testing and setting of the cargo tank high-level and",
          "high-high-level alarm systems.",
          "The circumstances under which the cargo tank high-level and high-high-level alarm systems or",
          "individual cargo tank alarms may be isolated and the safeguards to ensure they were always in",
          "peration during cargo transfer operations."
        ],
        "evidence": [
          "The company procedures for the maintenance, setting and testing of the cargo tank high-level and high-",
          "high-level alarm systems.",
          "Records of the maintenance, testing and setting of the cargo tank high-level and high-high-level alarm"
        ],
        "risk": "medium",
        "status": "not_started"
      },
      {
        "id": "8.3.5",
        "number": "8.3.5",
        "chapter": "8",
        "section": "8.3",
        "text": "Were the Master, deck officers and deck ratings familiar with the company procedures for dipping, ullaging and sampling flammable static accumulator cargoes in non-inerted tanks, and were these procedures being followed?",
        "short_text": "Gauging and sampling static accumulator cargo in non-inerted tanks.",
        "vessel_types": [
          "Oil",
          "Chemical"
        ],
        "objective": "To ensure that the required additional precautions are taken when dipping, ullaging and sampling flammable\nstatic accumulator cargoes in non-inerted tanks.",
        "negative_grounds": [
          "There were no company procedures for dipping, ullaging and sampling flammable static accumulator",
          "cargoes in non-inerted tanks that described the additional precautions to be taken against static electricity",
          "A description of the dipping, ullaging and sampling equipment to be used.",
          "Bonding/earthing/cleaning procedures for this equipment.",
          "Settling time after completion of operations.",
          "Additional precautions if the vessel is not fitted with properly designed and installed full length",
          "Actions to be taken in the event of a failure of the fixed tank gauging system, if fitted.",
          "The officer in charge of cargo operations was not familiar with the company procedures for dipping, ullaging"
        ],
        "evidence": [
          "Company procedures for dipping, ullaging and sampling flammable static accumulator cargoes in non-",
          "inerted tanks.",
          "Cargo log books and records.",
          "Drawings/plans relating to cargo tank sounding pipes."
        ],
        "risk": "medium",
        "status": "not_started"
      },
      {
        "id": "8.3.6",
        "number": "8.3.6",
        "chapter": "8",
        "section": "8.3",
        "text": "Were the Master and deck officers familiar with the company procedures for loading flammable static accumulator cargoes into non-inerted tanks, and were these procedures being followed?",
        "short_text": "Loading static accumulator cargo into non-inerted tanks.",
        "vessel_types": [
          "Oil",
          "Chemical"
        ],
        "objective": "To ensure suitable precautions are always taken when flammable static accumulator cargoes are loaded into\nnon-inerted tanks.",
        "negative_grounds": [
          "There were no company procedures for loading flammable static accumulator cargoes into non-inerted tanks",
          "The identification of flammable static accumulator cargoes.",
          "The precautions to be taken against hazards from static electricity when loading these cargoes.",
          "The officer in charge of cargo operations was not familiar with the company procedures for loading",
          "flammable static accumulator cargoes into non-inerted tanks.",
          "A flammable static accumulator cargo was loaded into a non-inert tank with:",
          "An initial rate of more than 1 m/sec at the individual tank inlets."
        ],
        "evidence": [
          "Company procedures for loading flammable static accumulator cargoes into non-inerted tanks.",
          "Cargo log books and records."
        ],
        "risk": "medium",
        "status": "not_started"
      },
      {
        "id": "8.3.7",
        "number": "8.3.7",
        "chapter": "8",
        "section": "8.3",
        "text": "Were the Master and officers familiar with the purpose, operation and calibration of the inert gas system fixed oxygen analyser, and had the equipment been operated, maintained and calibrated in accordance with the manufacturer’s instructions and company procedures?",
        "short_text": "IGS oxygen analyser",
        "vessel_types": [
          "Oil",
          "Chemical"
        ],
        "objective": "To ensure the inert gas system always delivers inert gas with an oxygen content of not more than 5% by\nvolume to the cargo tanks at any rate of flow.",
        "negative_grounds": [
          "There were no company procedures for the operation, inspection, testing and maintenance of the vessel’s",
          "inert gas system which included the fixed oxygen analyser.",
          "The accompanying officer was not familiar with the purpose, operation, inspection, testing and maintenance",
          "f the fixed oxygen analyser including the:",
          "Method and frequency of calibration.",
          "Actions to be taken in the event of a failure of the fixed analyser.",
          "The records of inspection and maintenance of the inert gas plant were missing or incomplete.",
          "The fixed oxygen analyser had not been:"
        ],
        "evidence": [
          "The company procedures for the operation, inspection, maintenance and testing of the inert gas system.",
          "The records of inspection, testing and maintenance of the inert gas system.",
          "The manufacturer’s instruction and maintenance manual for the fixed oxygen analyser",
          "The calibration records for the fixed oxygen analyser."
        ],
        "risk": "medium",
        "status": "not_started"
      },
      {
        "id": "8.3.8",
        "number": "8.3.8",
        "chapter": "8",
        "section": "8.3",
        "text": "Were the Master, officers and ratings familiar with the cargo system Emergency Shutdown (ESD) system, where fitted, and/or the cargo pump emergency stop controls, and was there evidence that the systems and equipment had been tested in accordance with company procedures?",
        "short_text": "Oil and Chemical Tanker ESD and/or cargo pump emergency stop controls.",
        "vessel_types": [
          "Oil",
          "Chemical"
        ],
        "objective": "To ensure that the cargo handling system or individual cargo pumps will be brought to a safe, static\ncondition, either automatically or manually, in abnormal circumstances.",
        "negative_grounds": [
          "There was no company procedure which described the testing and operation of cargo system:",
          "Emergency shutdown systems.",
          "Automated cargo pump shutdown systems and associated sensors.",
          "Cargo pump emergency stop controls.",
          "The testing of the ESD, automated shutdown or cargo pump emergency stop controls and systems had not",
          "been tested in accordance with the company procedure.",
          "The ESD system, automated cargo pump shutdown or cargo pump emergency stop controls or systems",
          "were defective in any respect."
        ],
        "evidence": [
          "The company procedures which described the operation and testing of the ESD, where fitted, the cargo",
          "pump automated shutdown, the cargo pump emergency stop controls and the cargo pump emergency stop",
          "The testing records for the ESD, where fitted, the cargo pump automated shutdown, the cargo pump",
          "emergency stop controls and the cargo pump emergency stop system."
        ],
        "risk": "medium",
        "status": "not_started"
      },
      {
        "id": "8.3.9",
        "number": "8.3.9",
        "chapter": "8",
        "section": "8.3",
        "text": "Were the Master and officers familiar with the company procedures for the inspection and testing of cargo, vapour and inert gas pipelines, and were records available for these activities?",
        "short_text": "Pressure testing and inspection of cargo, inert gas and vapour pipelines.",
        "vessel_types": [
          "Oil",
          "Chemical"
        ],
        "objective": "To ensure cargo, vapour and inert gas pipelines are regularly examined, and pressure tested when required,\nto verify their condition.",
        "negative_grounds": [
          "There were no company procedures for the inspection and testing of cargo, vapour and inert gas pipelines",
          "The frequency of visual external examinations The frequency of hydrostatic pressure testing of cargo transfer systems.",
          "The requirement to hydrostatically pressure test a cargo transfer system after repairs, modifications",
          "r sectional replacement.",
          "Records to be maintained of inspections and tests.",
          "The accompanying officer was not familiar with the company procedures for the inspection and testing of",
          "cargo, vapour and inert gas pipelines."
        ],
        "evidence": [
          "The company procedures for the inspection and testing of cargo, vapour and inert gas pipelines.",
          "The determination of the MAWP of the cargo pipeline system.",
          "Records of the inspection and testing of cargo, vapour and inert gas pipelines."
        ],
        "risk": "medium",
        "status": "not_started"
      },
      {
        "id": "8.3.10",
        "number": "8.3.10",
        "chapter": "8",
        "section": "8.3",
        "text": "Were the Master and officers familiar with the company procedures for the inspection, testing and operation of the vapour collection system, and was this equipment in satisfactory condition?",
        "short_text": "Vapour collection system.",
        "vessel_types": [
          "Oil",
          "Chemical"
        ],
        "objective": "To ensure that the vapour collection system is in satisfactory condition and operated correctly when\nrequired.",
        "negative_grounds": [
          "There were no company procedures for the inspection, testing and operation of the vapour collection system",
          "A line diagram of the tanker’s vapour collection piping indicating the locations and purpose of all",
          "control and safety devices.",
          "The initial transfer rate The maximum allowable transfer rate as limited by the venting capacity of the pressure or vacuum",
          "relief valves, or any other factor which would limit the transfer rate.",
          "The maximum pressure drop in the vessel’s vapour collection system for various transfer rates.",
          "The relief settings of each pressure and vacuum valve."
        ],
        "evidence": [
          "The company procedures for the inspection, testing and operation of the vapour collection system.",
          "The vapour collection system manual.",
          "Cargo operations records and checklists relating to the last occasion the vapour collection system was used.",
          "The maintenance and testing records for any vapour hoses provided on chemical tankers in accordance with",
          "IMO MSC/Circ.585 2.2.1."
        ],
        "risk": "medium",
        "status": "not_started"
      },
      {
        "id": "8.3.11",
        "number": "8.3.11",
        "chapter": "8",
        "section": "8.3",
        "text": "Were the Master, deck officers and deck ratings familiar with the company procedures for cargo tank washing after the carriage of volatile products in a non-inert atmosphere, and had these procedures been followed?",
        "short_text": "Oil and chemical tank cleaning in non-inert tanks.",
        "vessel_types": [
          "Oil",
          "Chemical"
        ],
        "objective": "To ensure that tank washing operations after the carriage of volatile products in a non-inert atmosphere are\nalways conducted safely, and in accordance with the recommendations of ISGOTT6.",
        "negative_grounds": [
          "There were no company procedures for cargo tank washing after the carriage of volatile products in a non-",
          "inert atmosphere that included,  Control the fuel in the tank atmosphere.",
          " Control the sources of ignition in the tank.",
          "Bonding of portable tank washing machines and hoses.",
          "Testing tank cleaning hoses.",
          "Avoiding the free-fall or spraying of water into a tank.",
          "Prohibition of steaming."
        ],
        "evidence": [
          "Company procedures for cargo tank washing after the carriage of volatile products in a non-inert",
          "atmosphere.",
          "Completed plans, risk assessments, log books and records for previous tank cleaning operations.",
          "Records of electrical continuity testing of portable tank cleaning hoses and portable hydrant/hose/machine",
          "connections, where applicable."
        ],
        "risk": "medium",
        "status": "not_started"
      },
      {
        "id": "8.3.12",
        "number": "8.3.12",
        "chapter": "8",
        "section": "8.3",
        "text": "Were the Master and officers familiar with the company procedures for the use of portable cargo ullage/temperature/interface (UTI) measurement and sampling equipment, and was the equipment in satisfactory condition and used in accordance with the company procedures?",
        "short_text": "Portable ullage/temperature/interface (UTI) measurement and sampling equipment.",
        "vessel_types": [
          "Oil",
          "Chemical"
        ],
        "objective": "To ensure that portable UTI and sampling equipment is always used in accordance with international\nregulations and industry best practice.",
        "negative_grounds": [
          "There were no company procedures describing the use, operation, testing, calibration and servicing of the of",
          "portable cargo ullage/temperature/interface (UTI) measurement and sampling equipment.",
          "The accompanying officer was not familiar with the company procedures describing the use, operation,",
          "testing and maintenance of the UTI measurement and sampling equipment.",
          "The accompanying officer was not familiar with:",
          "The service rating of the portable UTI measurement and sampling equipment provided onboard.",
          "The service and calibration requirements.",
          "The pre-operational checks of portable UTI measurement and sampling equipment."
        ],
        "evidence": [
          "The company procedures describing the use, operation, testing, calibration and servicing of the of portable",
          "cargo ullage/temperature/interface (UTI) measurement and sampling equipment.",
          "The manufacturer’s manuals and instructions for the portable cargo UTI measurement and sampling",
          "equipment provided.",
          "The records of pre-operational checks of the portable cargo UTI measurement and sampling equipment.",
          "The service and calibration records for the portable cargo UTI measurement units."
        ],
        "risk": "medium",
        "status": "not_started"
      },
      {
        "id": "8.3.13",
        "number": "8.3.13",
        "chapter": "8",
        "section": "8.3",
        "text": "Were the Master and officers familiar with the company procedures for the operation of the primary and secondary cargo tank venting systems in accordance with SOLAS, and were these systems correctly set?",
        "short_text": "Secondary venting systems.",
        "vessel_types": [
          "Oil",
          "Chemical"
        ],
        "objective": "To ensure cargo tanks are always protected from over or under pressurisation in the event of inappropriate\nuse of the ventilation system or a failure of a primary protection device.",
        "negative_grounds": [
          "There were no company procedures for the operation of the primary and secondary cargo tank venting",
          "systems in accordance with SOLAS which described:",
          "The primary and secondary system for each anticipated cargo tank/group configuration.",
          "The associated settings of the pressure/vacuum sensor alarms, where fitted.",
          "Maintenance, test and calibration procedures for the cargo tank pressure/vacuum monitoring",
          "system per the manufacturer’s instructions.",
          "The accompanying officer was not familiar with the company procedures for the operation of the primary and",
          "secondary cargo tank venting systems in accordance with SOLAS."
        ],
        "evidence": [
          "Company procedures for the operation of the primary and secondary cargo tank venting systems.",
          "Ship’s drawings of the cargo tank venting arrangements.",
          "Cargo handling manual(s).",
          "Records of tests and calibration of the pressure sensors, where fitted."
        ],
        "risk": "medium",
        "status": "not_started"
      },
      {
        "id": "8.3.14",
        "number": "8.3.14",
        "chapter": "8",
        "section": "8.3",
        "text": "Were the Master and officers familiar with the company procedures for the operation, inspection, testing and maintenance of the cargo tank venting systems, and were the systems in satisfactory condition?",
        "short_text": "Cargo tank venting systems.",
        "vessel_types": [
          "Oil",
          "Chemical"
        ],
        "objective": "To ensure that cargo tank venting systems are maintained in satisfactory condition and operated correctly.",
        "negative_grounds": [
          "The accompanying officer was not familiar with the company procedures for the operation, inspection,",
          "testing and maintenance of the cargo tank venting systems.",
          "There were no records of inspection, testing and maintenance of the cargo tank venting systems.",
          "P/V valves and/or high velocity vents had not been checked for free movement prior to the commencement",
          "f each cargo operation as required by the Ship Shore Safety Check List – Part 1A. Tanker checks pre-",
          "No information was available regarding the maximum permissible loading rate for each cargo tank and in the",
          "case of combined venting systems, for each group of cargo tanks."
        ],
        "evidence": [
          "Company procedures for the operation, inspection, testing and maintenance of the cargo tank venting",
          "Records of inspection and maintenance of P/V valves and/or high velocity vents, which may be contained in",
          "the planned maintenance system.",
          "Ship Shore Safety Check Lists Information regarding the maximum permissible loading rate for each cargo tank and in the case of"
        ],
        "risk": "medium",
        "status": "not_started"
      },
      {
        "id": "8.3.15",
        "number": "8.3.15",
        "chapter": "8",
        "section": "8.3",
        "text": "Were the Master and officers familiar with the company procedures for monitoring leakage into the cofferdams of deepwell pumps, and had regular purging of the cofferdams taken place to identify any excessive leakage?",
        "short_text": "Deepwell pump cofferdam purging.",
        "vessel_types": [
          "Oil",
          "Chemical"
        ],
        "objective": "To ensure the vessel’s deep well pumps are always in full operational condition.",
        "negative_grounds": [
          "There were no company procedures for monitoring leakage into the cofferdams of deepwell pumps.",
          "The accompanying officer was not familiar with:",
          "The company procedure for monitoring leakage into the cofferdams of deepwell pumps.",
          "The connections, controls and indicators used during the purging process."
        ],
        "evidence": [
          "The company procedures for monitoring leakage into the cofferdams of deepwell pumps.",
          "Manufacturer’s instruction manual(s) for the deepwell pumps.",
          "Records of purging of the deepwell pump cofferdams."
        ],
        "risk": "medium",
        "status": "not_started"
      },
      {
        "id": "8.3.16",
        "number": "8.3.16",
        "chapter": "8",
        "section": "8.3",
        "text": "Were the Master and officers familiar with the purpose, operation, testing and maintenance of the non-return devices installed in the inert gas system, and were these devices in satisfactory condition?",
        "short_text": "Inert gas system non-return devices",
        "vessel_types": [
          "Oil",
          "Chemical"
        ],
        "objective": "To ensure the devices installed in the inert gas system to prevent the return of vapour and liquid to the inert\ngas plant, or to any gas-safe spaces, function correctly.",
        "negative_grounds": [
          "There were no company procedures for the operation, inspection, testing and maintenance of the inert gas",
          "system that included the:",
          "deck seal or double block and bleed arrangement non-return valve The accompanying officer was not familiar with the company procedures for the operation, inspection,",
          "testing and maintenance of the inert gas system that included the:",
          "deck seal or double block and bleed arrangement non-return valve"
        ],
        "evidence": [
          "The company procedures for the operation, inspection, testing and maintenance of the vessel’s inert gas",
          "The records of inspection, testing and maintenance of the non-return devices installed in the inert gas"
        ],
        "risk": "medium",
        "status": "not_started"
      },
      {
        "id": "8.3.17",
        "number": "8.3.17",
        "chapter": "8",
        "section": "8.3",
        "text": "Were the Master and officers familiar with the company procedures for the use, inspection and testing of manifold reducers, spool pieces and other portable pipework, and were these items in satisfactory condition and properly fitted when in use?",
        "short_text": "Manifold reducers and spool pieces.",
        "vessel_types": [
          "Oil",
          "Chemical"
        ],
        "objective": "To ensure manifold reducers, spool pieces and other items of portable pipework meet the required pressure\nrating for the cargo transfer system and will not leak at the flange face when used.",
        "negative_grounds": [
          "There were no company procedures for the use, inspection and testing of manifold reducers, spool pieces",
          "and other portable pipework that included guidance on:",
          "The correct use of manifold reducers, spool pieces and other portable pipework.",
          "Provision of test certification.",
          "Suitable storage arrangements, including the protection of flange faces.",
          "Pressure testing at least annually.",
          "Records to be maintained of inspections and tests."
        ],
        "evidence": [
          "The company procedures for the use, inspection and testing of manifold reducers, spool pieces and other",
          "portable pipework.",
          "The inventory of manifold reducers, spool pieces and other portable pipework.",
          "Records of the inspection and pressure testing of manifold reducers, spool pieces and other portable"
        ],
        "risk": "medium",
        "status": "not_started"
      },
      {
        "id": "8.3.18",
        "number": "8.3.18",
        "chapter": "8",
        "section": "8.3",
        "text": "Were the Master and officers familiar with the purpose, operation, testing and maintenance of the pressure/vacuum-breaking (P/V) device(s) installed in the inert gas main, and was this device(s) in satisfactory condition?",
        "short_text": "Inert gas system pressure/vacuum-breaking (P/V) device(s)",
        "vessel_types": [
          "Oil",
          "Chemical"
        ],
        "objective": "To ensure cargo tanks are not subject to excessive pressure or vacuum should the inert gas system fail or\nwhere the venting system is used inappropriately.",
        "negative_grounds": [
          "There were no company procedures for the operation, inspection, testing and maintenance of the inert gas",
          "system that included the pressure/vacuum-breaking devices.",
          "The accompanying officer was not familiar with the company procedures for the operation, inspection,",
          "testing and maintenance of the inert gas system that included the pressure/vacuum-breaking devices.",
          "The fabric condition of a P/V breaker was unsatisfactory.",
          "P/V breaker flame screens were damaged, missing, fitted with gaps, or had been repaired with mesh which",
          "did not conform to the required mesh gauge specification.",
          "The liquid level in a P/V breaker indicated that the device was not filled to the design settings."
        ],
        "evidence": [
          "The company procedures for the operation, inspection, testing and maintenance of the vessel’s inert gas",
          "The records of inspection, testing and maintenance of the pressure/vacuum breaking device(s) installed in",
          "the inert gas system."
        ],
        "risk": "medium",
        "status": "not_started"
      },
      {
        "id": "8.3.19",
        "number": "8.3.19",
        "chapter": "8",
        "section": "8.3",
        "text": "Were the Master and officers familiar with the purpose, operation and testing of the indicators and alarms in the inert gas system, and had the equipment been operated, maintained and calibrated in accordance with the manufacturer’s instructions and company procedures?",
        "short_text": "Indicators and alarms for the inert gas system",
        "vessel_types": [
          "Oil",
          "Chemical"
        ],
        "objective": "To ensure the inert gas system always delivers inert gas in accordance with its design criteria.",
        "negative_grounds": [],
        "evidence": [],
        "risk": "low",
        "status": "not_started"
      },
      {
        "id": "8.3.20",
        "number": "8.3.20",
        "chapter": "8",
        "section": "8.3",
        "text": "Were the Master and officers familiar with the purpose and operation of the connections and interconnections to the inert gas system for routine and emergency inert gas operations, and were these arrangements in satisfactory condition and clearly identified as to their purpose?",
        "short_text": "Connections and interconnections to/with the inert gas system piping",
        "vessel_types": [
          "Oil",
          "Chemical"
        ],
        "objective": "To ensure the Master and officers are familiar with the location and use of connections to, and\ninterconnections with, the inert gas system, which may include:\n• Connections for the emergency supply of inert gas from an external source.\n• Connections for portable arrangements to introduce inert gas to the double hull spaces.\n• Fixed interconnections with the ballast system piping to introduce inert gas to the double hull\nspaces.\n• Fixed interconnections with the cargo system piping to introduce ",
        "negative_grounds": [
          "There were no company procedures for the operation, inspection and maintenance of the vessel’s inert gas",
          "system which included the arrangements for the:",
          "Supply of inert gas to the double-hull spaces in an emergency.",
          "External supply of inert gas in the event of a failure of the vessel’s inert gas system.",
          "Connection of the inert gas supply main to the cargo piping system for inerting, purging and gas-",
          "The accompanying officer was not familiar with the arrangements for the:",
          "Supply of inert gas to the double-hull spaces in an emergency, including the forepeak."
        ],
        "evidence": [
          "The company procedures for the operation, inspection and maintenance of the vessel’s inert gas system.",
          "The detailed instruction manuals for the inert gas system.",
          "Cargo and inert gas operation log books.",
          "The records of inspection, testing and maintenance of the arrangements for connection to the inert gas"
        ],
        "risk": "medium",
        "status": "not_started"
      },
      {
        "id": "8.3.21",
        "number": "8.3.21",
        "chapter": "8",
        "section": "8.3",
        "text": "Were the Master and officers familiar with the company procedure for cargo heating, and was the cargo heating system in satisfactory condition and tested and used in accordance with the company procedure?",
        "short_text": "Cargo heating system",
        "vessel_types": [
          "Oil",
          "Chemical"
        ],
        "objective": "To ensure cargo heating is always conducted in accordance with international regulations, industry\nguidance and within the design criteria of the vessel and its fittings.",
        "negative_grounds": [],
        "evidence": [],
        "risk": "low",
        "status": "not_started"
      },
      {
        "id": "8.3.22",
        "number": "8.3.22",
        "chapter": "8",
        "section": "8.3",
        "text": "Were the Master and officers familiar with the company procedures for managing on-board doping operations, and had these procedures been complied with?",
        "short_text": "Cargo doping and additives.",
        "vessel_types": [
          "Oil",
          "Chemical"
        ],
        "objective": "To ensure on-board doping operations are properly planned, risk assessed and performed safely.",
        "negative_grounds": [
          "There were no company procedures for managing on-board doping operations that included:",
          "Reviewing the supplier’s/contractor’s doping plan.",
          "Performing a risk assessment of the proposed operation.",
          "Supervising the doping operation.",
          "The officer responsible for cargo operations was not familiar with the company procedures for managing on-",
          "board doping operations.",
          "The vessel had not been provided with the supplier’s/contractor’s plan for an on-board doping operation.",
          "A risk assessment had not been performed based upon the supplier’s/contractor’s plan for an on-board"
        ],
        "evidence": [
          "Company procedures for managing on-board doping operations.",
          "Doping plans.",
          "Associated risk assessments.",
          "Safety Data Sheets for additives used.",
          "Cargo operation log books."
        ],
        "risk": "medium",
        "status": "not_started"
      },
      {
        "id": "8.3.23",
        "number": "8.3.23",
        "chapter": "8",
        "section": "8.3",
        "text": "Were the Master and officers familiar with the company procedures for the maintenance, testing and calibration of the cargo temperature monitoring equipment, and was the equipment in satisfactory condition?",
        "short_text": "Cargo tank temperature monitoring systems.",
        "vessel_types": [
          "Oil",
          "Chemical"
        ],
        "objective": "To ensure the cargo temperature monitoring equipment is maintained in full operational condition.",
        "negative_grounds": [
          "There were no company procedures for the maintenance, testing and calibration of the cargo temperature",
          "monitoring equipment in accordance with manufacturer’s instructions.",
          "The accompanying officer was not familiar with the company procedures for the maintenance, testing and",
          "calibration of the cargo temperature monitoring equipment.",
          "The accompanying officer was unable to demonstrate the operation of the fixed cargo temperature",
          "monitoring equipment, including alarms.",
          "There were no records of checks, tests or calibration of the cargo temperature monitoring equipment.",
          "The fixed cargo temperature monitoring equipment had not been tested and calibrated in accordance with"
        ],
        "evidence": [
          "Company procedures for the maintenance, testing and calibration of the cargo temperature monitoring",
          "Manufacturer’s manuals and instructions for the fixed cargo temperature monitoring equipment.",
          "Records of checks, tests and calibration of the cargo temperature monitoring equipment."
        ],
        "risk": "medium",
        "status": "not_started"
      },
      {
        "id": "8.3.24",
        "number": "8.3.24",
        "chapter": "8",
        "section": "8.3",
        "text": "Were the Master and officers familiar with the company procedures for managing cargo and vapour connections at the cargo manifolds, and were the manifold arrangements in satisfactory condition?",
        "short_text": "Cargo manifold arrangements.",
        "vessel_types": [
          "Oil",
          "Chemical"
        ],
        "objective": "To ensure that cargo and vapour manifolds are always properly connected and monitored throughout cargo\ntransfer operations.",
        "negative_grounds": [
          "There were no company procedures which described the management of cargo and vapour connections at",
          "the cargo manifolds to prevent and detect leakages.",
          "The accompanying officer was not familiar with the company procedures which described the management",
          "f cargo and vapour connections at the cargo manifolds to prevent and detect leakages.",
          "A manifold connection was:",
          "Secured with damaged bolts or bolts of an inappropriate diameter, length or material.",
          "Not fully bolted, i.e. without a bolt in every hole in the flange.",
          "Made using improvised arrangements such as a G-clamp or similar device."
        ],
        "evidence": [
          "The company procedures which described the management of cargo and vapour connections at the cargo",
          "manifolds to prevent and detect leakages.",
          "Documentation supporting the pressure rating of manifold blanks, where appropriate."
        ],
        "risk": "medium",
        "status": "not_started"
      },
      {
        "id": "8.3.25",
        "number": "8.3.25",
        "chapter": "8",
        "section": "8.3",
        "text": "Were the Master and deck officers familiar with the company procedures for receiving nitrogen from shore for operations such as inerting, purging or padding cargo tank, or for clearing cargo lines?",
        "short_text": "Receiving nitrogen from shore",
        "vessel_types": [
          "Oil",
          "Chemical"
        ],
        "objective": "To ensure cargo tanks are not over pressurised, possibly resulting in serious deformation or catastrophic\nfailure of the tank structure.",
        "negative_grounds": [
          "There was no company procedure which described the processes for receiving nitrogen from the shore for",
          "perations such as for operations such as, inerting, purging or padding cargo tanks or for clearing cargo",
          "Company procedures did not describe the actions to be taken to avoid over pressurisation of cargo tanks",
          "when nitrogen is received from shore, including the:",
          "Requirement to carry out a risk assessment prior to operations.",
          "Choice of connection and piping system for receiving the nitrogen.",
          "Methods of controlling the incoming flow of nitrogen.",
          "The accompanying officer was not familiar with the company procedures which described the procedure for"
        ],
        "evidence": [
          "The company procedure which described the procedure for receiving nitrogen from the shore for operations",
          "such as inerting or purging tanks, for padding cargo tanks or to clear lines.",
          "Records and completed risk assessments for operations where nitrogen had been received from shore",
          "within the last six months."
        ],
        "risk": "medium",
        "status": "not_started"
      },
      {
        "id": "8.4.1",
        "number": "8.4.1",
        "chapter": "8",
        "section": "8.4",
        "text": "Were the Master and officers familiar with the company procedures that addressed the carriage of inhibited cargoes, and had these procedures been followed?",
        "short_text": "Carriage of inhibited cargoes.",
        "vessel_types": [
          "LPG"
        ],
        "objective": "To ensure that inhibited cargoes are carried safely and in compliance with company procedures and the IGC\nCode.",
        "negative_grounds": [
          "There were no company procedures that addressed the carriage of inhibited cargoes and included guidance",
          "Inhibited cargo certificates.",
          "Temperature monitoring of inhibited cargoes.",
          "Inerting of inhibited cargoes.",
          "Draining/purging of the reliquefaction system after shut-down.",
          "The use of anti-freeze with inhibited cargoes.",
          "The exclusion of water from the cargo system.",
          "Recirculation of cargo to ensure a uniform concentration of inhibitor."
        ],
        "evidence": [
          "Company procedures that address the carriage of inhibited cargoes.",
          "Inhibited cargo certificates.",
          "Inert gas logs.",
          "Bridge and cargo log books.",
          "Cargo tank temperature records relating to inhibited cargoes.",
          "Cargo load and discharge plans relating to inhibited cargoes."
        ],
        "risk": "medium",
        "status": "not_started"
      },
      {
        "id": "8.4.2",
        "number": "8.4.2",
        "chapter": "8",
        "section": "8.4",
        "text": "Were the Master and officers familiar with the company procedures for carrying out cargo sampling operations?",
        "short_text": "Cargo sampling",
        "vessel_types": [
          "LPG"
        ],
        "objective": "To ensure LPG cargo sampling operations are performed safely.",
        "negative_grounds": [
          "There were no company procedures for performing cargo sampling operations for all cargoes included on",
          "the vessel’s Certificate of Fitness which required that:",
          "Sampling must be authorised and directly supervised by a responsible officer and carried out in a",
          "safe manner, regardless of who is actually performing the sampling operation.",
          "Only fully compatible sampling equipment, connected properly, is used for the task.",
          "Venting to atmosphere is minimised during sampling.",
          "Purging, venting or ullaging of sample containers must be carried out in a safe location.",
          "Only ‘closed loop’ equipment is used when toxic products are being sampled."
        ],
        "evidence": [
          "Company procedures for performing cargo sampling operations."
        ],
        "risk": "medium",
        "status": "not_started"
      },
      {
        "id": "8.4.3",
        "number": "8.4.3",
        "chapter": "8",
        "section": "8.4",
        "text": "Were the Master and officers familiar with the company procedures for identifying and segregating incompatible cargoes and refrigerants during cargo stowage planning, and had these procedures been followed?",
        "short_text": "Segregating incompatible cargoes and refrigerants",
        "vessel_types": [
          "LPG"
        ],
        "objective": "To ensure cargo stowage is carefully planned to avoid the co-mingling of incompatible cargoes and\nrefrigerants.",
        "negative_grounds": [
          "There were no company procedures for cargo stowage planning that included the:",
          "Identification of incompatible cargoes and refrigerants using all available data.",
          "Means of identifying and documenting locations and processes where segregation is necessary.",
          "Means of segregation of incompatible cargoes and refrigerants.",
          "The officer responsible for cargo stowage planning was not familiar with company procedures for identifying",
          "and segregating incompatible cargoes and refrigerants.",
          "The officer responsible for cargo stowage planning was not familiar with the use of the compatibility chart"
        ],
        "evidence": [
          "Company procedures for identifying and segregating incompatible cargoes and refrigerants during cargo",
          "stowage planning.",
          "Current and previous cargo stowage plans.",
          "Cargo log book.",
          "Risk assessments or checklists that identify systems and processes that require segregation.",
          "Compatibility charts."
        ],
        "risk": "medium",
        "status": "not_started"
      },
      {
        "id": "8.4.4",
        "number": "8.4.4",
        "chapter": "8",
        "section": "8.4",
        "text": "Were the Master and officers familiar with the company procedures for the safe carriage of propylene oxide (PO), ethylene oxide (EO) and PO-EO mixtures?",
        "short_text": "Carriage of propylene oxide (PO) and/or ethylene oxide (EO)",
        "vessel_types": [
          "LPG"
        ],
        "objective": "To ensure the safe carriage of propylene oxide (PO), ethylene oxide (EO) and PO-EO mixtures.",
        "negative_grounds": [
          "There were no company procedures for the safe carriage of propylene oxide (PO), ethylene oxide (EO) and",
          "The officer in charge of cargo operations was not familiar with the company procedures for the safe carriage",
          "f propylene oxide (PO), ethylene oxide (EO) and PO-EO mixtures including:",
          "Tank preparation and inspection, including compatibility with previous cargoes.",
          "Separation of pipeline systems and compressors, including sealing and certification.",
          "Pressure relief valve (PRV) settings.",
          "Nitrogen purging and padding requirements.",
          "Cargo discharge methods."
        ],
        "evidence": [
          "The company procedures for the safe carriage of propylene oxide (PO), ethylene oxide (EO) and PO-EO",
          "Approved cargo handling plans.",
          "P&A Manual.",
          "The Cargo System Operation Manual, where provided.",
          "Segregation certification issued by the appropriate shore authority prior to loading."
        ],
        "risk": "medium",
        "status": "not_started"
      },
      {
        "id": "8.4.5",
        "number": "8.4.5",
        "chapter": "8",
        "section": "8.4",
        "text": "Were there sufficient escape sets as required by the IGC Code for everyone on board, and did the sets provide suitable respiratory and eye protection?",
        "short_text": "Escape sets as required by the IGC Code",
        "vessel_types": [
          "LPG"
        ],
        "objective": "To ensure that everyone on board is provided with a suitable emergency escape set to exit a hazardous\natmosphere in case of an emergency.",
        "negative_grounds": [
          "The escape sets provided:",
          "Did not have a design duration of at least 15 minutes.",
          "Were not included in the company procedures for the use and maintenance of EEBDs and the",
          "nboard maintenance plan.",
          "Used filter-type respiratory protection.",
          "Did not provide suitable eye protection.",
          "Were not suitably marked as not to be used for fire-fighting or cargo-handling purposes.",
          "Were not in addition to the EEBDs required by SOLAS to be located in the accommodation and"
        ],
        "evidence": [
          "The inspection and maintenance records for the EEBDs contained within the onboard maintenance plan."
        ],
        "risk": "high",
        "status": "not_started"
      },
      {
        "id": "8.4.6",
        "number": "8.4.6",
        "chapter": "8",
        "section": "8.4",
        "text": "Were the Master and officers familiar with the company procedures for the inspection and maintenance of the cargo tank insulation, and was the insulation reported to be in good condition?",
        "short_text": "Cargo tank insulation",
        "vessel_types": [
          "LPG"
        ],
        "objective": "To ensure the cargo tank insulation is properly inspected and maintained.",
        "negative_grounds": [
          "There were no company procedures for the inspection and maintenance of the cargo tank insulation which",
          "included guidance on:",
          "Scope and frequency of inspections.",
          "Maintenance procedures.",
          "Records to be kept of inspections and maintenance."
        ],
        "evidence": [
          "Company procedures for the inspection and maintenance of the cargo tank insulation.",
          "Records of inspection of the cargo tank insulation.",
          "Records of maintenance and repair of the cargo tank insulation.",
          "Open defect reports for any defects to the cargo tank insulation.",
          "The enclosed space entry records and permits for recent cargo tank insulation inspections."
        ],
        "risk": "medium",
        "status": "not_started"
      },
      {
        "id": "8.4.7",
        "number": "8.4.7",
        "chapter": "8",
        "section": "8.4",
        "text": "Were the vent outlets from the cargo containment system fitted with the correct protection screen or flame screen required for the cargo being carried, and were the screens in satisfactory condition?",
        "short_text": "Vent outlet protection screens or flame screens",
        "vessel_types": [
          "LPG"
        ],
        "objective": "To ensure that the correct protection or flame screens are fitted to vent outlets in accordance with the cargo\nbeing carried, and that these screens are in satisfactory condition.",
        "negative_grounds": [
          "A vent outlet connected to the cargo containment system was not fitted with the required flame screen (or",
          "safety head) or protection screen for the cargo being carried.",
          "A flame screen or protection screen fitted to a vent outlet connected to the cargo containment system was",
          "not in satisfactory condition e.g., blocked or clogged, painted over or damaged.",
          "Flame screens not currently in use were not stored properly in order to prevent damage and/or marked",
          "clearly so that they could be located readily when required.",
          "A vessel issued with an International Pollution Prevention Certificate for the Carriage of Noxious Liquid",
          "Substances in Bulk (NLS) did not have the required flame screens (or safety heads) available on board to fit"
        ],
        "evidence": [
          "Cargo plans and/or maintenance records that demonstrated vent outlets from the cargo containment system",
          "were fitted with the correct flame screen or protection screen for the cargo being carried.",
          "Maintenance plans that demonstrated flame screens or protection screens had been inspected and",
          "maintained in a satisfactory condition."
        ],
        "risk": "medium",
        "status": "not_started"
      },
      {
        "id": "8.5.1",
        "number": "8.5.1",
        "chapter": "8",
        "section": "8.5",
        "text": "Were the Master and officers familiar with the company procedures for the operation, testing and calibration of the custody transfer measurement system (CTMS), and was the system in satisfactory condition?",
        "short_text": "Custody transfer measurement system (CTMS)",
        "vessel_types": [
          "LNG"
        ],
        "objective": "To ensure the vessel is able to measure the quantity of energy loaded from production facilities, unloaded to\na receiving terminal, or transferred to another LNG carrier during ship-to-ship operations.",
        "negative_grounds": [
          "There were no company procedures for the operation, testing and calibration of the custody transfer",
          "measurement system (CTMS).",
          "The accompanying officer was not familiar with the company procedures for the operation, testing and",
          "calibration of the custody transfer measurement system (CTMS).",
          "The CTMS had not been calibrated as required by company procedures.",
          "There was no current certificate of calibration for the CTMS available on board.",
          "There were no records of pre-operational tests of the CTMS.",
          "The CTMS had not been tested prior to the current loading/discharging operations."
        ],
        "evidence": [
          "Company procedures for the operation, testing and calibration of the CTMS.",
          "Manufacturer’s manuals and instructions for the CTMS.",
          "Records of pre-operational tests of the CTMS.",
          "Service and calibration records for the CTMS"
        ],
        "risk": "medium",
        "status": "not_started"
      },
      {
        "id": "8.5.2",
        "number": "8.5.2",
        "chapter": "8",
        "section": "8.5",
        "text": "Were the Master and officers familiar with the company procedures for the operation, inspection, maintenance and testing of the Gas Combustion Unit (GCU)?",
        "short_text": "Gas Combustion Unit (GCU)",
        "vessel_types": [
          "LNG"
        ],
        "objective": "To ensure the Gas Combustion Unit is properly operated, inspected, maintained, and tested.",
        "negative_grounds": [
          "There were no company procedures for the operation, inspection, maintenance and testing of the GCU.",
          "The accompanying officer was not familiar with:",
          "Actions to be taken in the event of the failure of the GCU in automatic mode and procedures for",
          "manual operation if required.",
          "Provision to manually isolate the gas fuel supply to the GCU from a safely accessible position.",
          "Company procedures for testing GCU alarms which may include:",
          " Loss of combustion air supply."
        ],
        "evidence": [
          "The company procedures for the operation, inspection, testing and maintenance of the GCU.",
          "Records of inspection, maintenance and testing of the GCU."
        ],
        "risk": "medium",
        "status": "not_started"
      },
      {
        "id": "8.5.3",
        "number": "8.5.3",
        "chapter": "8",
        "section": "8.5",
        "text": "Were the Master and officers familiar with the company procedures for the inspection, maintenance and testing of the safety arrangements for the LNG gas fuel supply system, and were these arrangements in satisfactory condition?",
        "short_text": "LNG gas fuel supply system",
        "vessel_types": [
          "LNG"
        ],
        "objective": "To ensure the safe supply of boil-off gas (BOG) to consumers in the engine-room such as boilers, inert gas\ngenerators, internal combustion engines, gas combustion unit and gas turbines.",
        "negative_grounds": [
          "There were no company procedures for the inspection, maintenance and testing of the safety arrangements",
          "for the LNG gas fuel supply system to consumers in the engine-room such as boilers, inert gas generators,",
          "internal combustion engines, gas combustion unit and gas turbines.",
          "The accompanying officer was not familiar with the company procedures for the inspection, testing and",
          "maintenance of the safety arrangements for the LNG gas fuel supply system including:",
          "The inerting or ventilation systems for the annular space of double-wall fuel pipes.",
          "Leak detection systems.",
          "Ventilation systems in spaces containing BOG consumers."
        ],
        "evidence": [
          "The company procedures for the inspection, testing and maintenance of the safety arrangements for the",
          "LNG gas fuel supply system to consumers in the engine-room such as boilers, inert gas generators, internal",
          "combustion engines, gas combustion unit and gas turbines.",
          "Records of inspection, maintenance and testing of the safety arrangements for the LNG gas fuel supply"
        ],
        "risk": "medium",
        "status": "not_started"
      },
      {
        "id": "8.5.4",
        "number": "8.5.4",
        "chapter": "8",
        "section": "8.5",
        "text": "Were the Master and officers familiar with the company procedures for protecting the hull structure from low temperature exposure, and was temperature monitoring and cofferdam heating equipment, where fitted, in satisfactory condition?",
        "short_text": "Cold spots and cofferdam temperature monitoring and heating equipment.",
        "vessel_types": [
          "LNG"
        ],
        "objective": "To ensure the hull is protected against the risk of brittle fracture in the event of a failure of the cargo\ncontainment or insulation.",
        "negative_grounds": [
          "There were no company procedures for monitoring the integrity of the containment system and protecting",
          "the hull structure from low temperature exposure that included:",
          "Roles and responsibilities.",
          "Guidance on the detection of cold spots by the inner hull temperature measurement system, and/or",
          "by visual inspection.",
          "Operation, alarm settings and maintenance of the inner hull temperature monitoring equipment.",
          "Operation and maintenance of the cofferdam heating equipment, where fitted.",
          "Actions to be taken if:"
        ],
        "evidence": [
          "Company procedures for monitoring the integrity of the containment system and protecting the hull structure",
          "from low temperature exposure.",
          "Records of: o Inner hull temperature readings o Visual inspections of the inner hull structure for cold spots.",
          "o Cold spots identified and actions taken."
        ],
        "risk": "medium",
        "status": "not_started"
      },
      {
        "id": "8.6.1",
        "number": "8.6.1",
        "chapter": "8",
        "section": "8.6",
        "text": "Were the Master and officers familiar with the company procedures for the maintenance, testing and setting of the independent cargo tank high-level and overfill alarms, and were these alarm systems fully operational and properly set?",
        "short_text": "Cargo tank overfill alarms",
        "vessel_types": [
          "LPG",
          "LNG"
        ],
        "objective": "To ensure that independent cargo tank high-level and overfill alarms are always fully operational, properly\nset and used during all cargo loading, discharging and transfer operations.",
        "negative_grounds": [
          "There were no company procedures for the maintenance, testing and setting of the cargo tank high-level",
          "and overfill alarm systems.",
          "The company procedures for the maintenance, testing and setting of the cargo tank high-level and overfill",
          "alarm systems did not include:",
          "The mandatory use of the alarms during all loading, discharging and transfer operations.",
          "Set points for all alarms.",
          "Testing procedures and frequency.",
          "Records of testing and maintenance to be kept."
        ],
        "evidence": [
          "The company procedures for the maintenance, setting and testing of the cargo tank high-level and overfill",
          "alarm systems.",
          "Records of the maintenance, testing and setting of the cargo tank high-level and overfill alarm systems.",
          "The document specifying the maximum allowable loading limits for each cargo tank and product, at each",
          "applicable loading temperature and maximum reference temperature."
        ],
        "risk": "medium",
        "status": "not_started"
      },
      {
        "id": "8.6.2",
        "number": "8.6.2",
        "chapter": "8",
        "section": "8.6",
        "text": "Were the Master, officers, and ratings involved with cargo operations, familiar with the functions of the vessel’s cargo transfer Emergency Shut Down (ESD) systems, and was the equipment in good working order, regularly inspected, tested and maintained?",
        "short_text": "Cargo transfer Emergency Shut Down (ESD)",
        "vessel_types": [
          "LPG",
          "LNG"
        ],
        "objective": "To ensure that crewmembers can respond effectively to an emergency situation during cargo transfer\noperations in accordance with the shipboard emergency plan.",
        "negative_grounds": [
          "There were no company procedures for the operation, inspection, maintenance and testing of the vessel’s",
          "The Master, officers and ratings involved in cargo operations were not familiar with the vessel’s ESD",
          "systems at a depth relevant to their seniority."
        ],
        "evidence": [
          "The company procedures for the operation, inspection, maintenance and testing of the vessel’s ESD",
          "The checklist used to conduct the pre-arrival tests on the ESD system prior to the previous cargo transfer",
          "The checklist used to verify the timing and sequencing of the ESD system functions.",
          "Records of the inspection, maintenance and testing of the vessel’s ESD systems."
        ],
        "risk": "medium",
        "status": "not_started"
      },
      {
        "id": "8.6.3",
        "number": "8.6.3",
        "chapter": "8",
        "section": "8.6",
        "text": "Were the Master and officers familiar with the company procedures for the inspection, maintenance, testing and setting of the cargo tank relief valves?",
        "short_text": "Cargo tank relief valves",
        "vessel_types": [
          "LPG",
          "LNG"
        ],
        "objective": "To ensure cargo tank relief valves are properly inspected, maintained, tested, and set.",
        "negative_grounds": [
          "There were no company procedures for the inspection, maintenance, testing and setting of the cargo tank",
          "The accompanying officer was not familiar with the company procedures for:",
          "Changing the set pressure of the cargo tank relief valves and the corresponding resetting of",
          "alarms, including record keeping.",
          "Inspection, maintenance and testing of the cargo tank relief valves.",
          "Actions to take in the event of a cargo rank relief valve malfunction including emergency isolation.",
          "The accompanying officer was not familiar with the company procedures for the operation of the automated",
          "cargo tank venting system."
        ],
        "evidence": [
          "The company procedures for the inspection, maintenance, testing and setting of the cargo tank relief valves.",
          "Records of inspection, maintenance, testing and setting of the cargo tank relief valves.",
          "Records for any change of settings of cargo tank relief valves.",
          "Evidence of training for the officer responsible for the maintenance and operation of the cargo tank relief"
        ],
        "risk": "medium",
        "status": "not_started"
      },
      {
        "id": "8.6.4",
        "number": "8.6.4",
        "chapter": "8",
        "section": "8.6",
        "text": "Was a ship specific Cargo System Operation Manual provided on board, and were the Master and officers familiar with its content?",
        "short_text": "Cargo System Operation Manual",
        "vessel_types": [
          "LPG",
          "LNG"
        ],
        "objective": "To ensure that all ship staff involved in cargo operations have sufficient information about cargo properties\nand operating the cargo system so that they can conduct cargo operations safely. (IMO: IGC Code Ch.18\nGoal)",
        "negative_grounds": [
          "There was no Cargo System Operation Manual available on board.",
          "The Cargo System Operation Manual available on board was not ship specific.",
          "The Cargo System Operation Manual available on board did not address the hazards and properties of all",
          "the liquified gas cargoes that the vessel was permitted to carry.",
          "The Cargo System Operation Manual available on board did not document the overall operation cycle of the",
          "ship from dry-dock to dry-dock and/or describe the cargo equipment and systems fitted.",
          "The Cargo System Operation Manual available on board did not include information on maximum loading",
          "The Cargo System Operation Manual was not approved by the flag administration or a recognised"
        ],
        "evidence": [
          "Cargo System Operation Manual(s)"
        ],
        "risk": "medium",
        "status": "not_started"
      },
      {
        "id": "8.6.5",
        "number": "8.6.5",
        "chapter": "8",
        "section": "8.6",
        "text": "Were the Master and officers familiar with the company procedures for monitoring the integrity of the containment system and maintaining the atmosphere in the interbarrier spaces and/or hold spaces in a safe condition, and had records been maintained?",
        "short_text": "Maintaining the atmosphere in the interbarrier spaces and/or hold spaces",
        "vessel_types": [
          "LPG",
          "LNG"
        ],
        "objective": "To ensure that the integrity of the containment system is monitored and that the atmosphere within the\nsystem and hold spaces are always maintained in a safe condition.",
        "negative_grounds": [
          "There were no company procedures for monitoring the integrity of the containment system and maintaining",
          "the atmosphere in the interbarrier spaces and/or hold spaces in a safe condition that included:"
        ],
        "evidence": [
          "The company procedures for monitoring the integrity of the containment system and maintaining the",
          "atmosphere in the interbarrier spaces and/or hold spaces in a safe condition.",
          "Records of the parameters monitored.",
          "Records of actions taken to maintain the atmosphere in the required condition.",
          "Records of nitrogen consumption and, where fitted, running hours of the nitrogen generator."
        ],
        "risk": "medium",
        "status": "not_started"
      },
      {
        "id": "8.6.6",
        "number": "8.6.6",
        "chapter": "8",
        "section": "8.6",
        "text": "Were the Master and officers familiar with the company procedures for the management and operation of the cargo alarm systems, and had these procedures been followed?",
        "short_text": "Cargo system alarm management",
        "vessel_types": [
          "LPG",
          "LNG"
        ],
        "objective": "To ensure that there is an effective alarm management system in place.",
        "negative_grounds": [
          "There were no company procedures for the management and operation of the cargo alarm systems that",
          "included, as applicable:",
          "Roles and responsibilities, including the identities of the personnel responsible for managing",
          "changes to the system, keeping proper records, and carrying out maintenance.",
          "Authorisation required before changing a set point or overriding an alarm.",
          "Requirements for risk assessment before changing a set point or overriding an alarm.",
          "Actions to be taken when an alarm is temporarily out in service.",
          "Records to be kept, including any changes made to alarm systems and/or settings, and when"
        ],
        "evidence": [
          "The company procedures for the management and operation of the cargo alarm systems.",
          "Records of any changes made to alarm systems and/or settings, and when alarms have been overridden."
        ],
        "risk": "medium",
        "status": "not_started"
      },
      {
        "id": "8.6.7",
        "number": "8.6.7",
        "chapter": "8",
        "section": "8.6",
        "text": "Were the Master and officers familiar with the company procedures for the operation, inspection, testing and maintenance of the vessel’s inert gas system and its associated equipment, and was the equipment in satisfactory condition?",
        "short_text": "Inert gas system",
        "vessel_types": [
          "LPG",
          "LNG"
        ],
        "objective": "To ensure the inert gas system always delivers inert gas in accordance with the requirements for the cargo\ncarried.",
        "negative_grounds": [],
        "evidence": [],
        "risk": "low",
        "status": "not_started"
      },
      {
        "id": "8.6.8",
        "number": "8.6.8",
        "chapter": "8",
        "section": "8.6",
        "text": "Were the Master and officers familiar with the company procedures for managing cargo and vapour connections at the cargo manifolds, and were the manifold arrangements in satisfactory condition?",
        "short_text": "Gas vessel cargo manifolds",
        "vessel_types": [
          "LPG",
          "LNG"
        ],
        "objective": "To ensure that cargo and vapour manifolds are always safely connected, disconnected, and monitored\nthroughout cargo transfer operations.",
        "negative_grounds": [
          "There were no company procedures which described the management of cargo and vapour connections at",
          "the cargo manifolds to prevent and detect leakages.",
          "On an LNG carrier, there were no detailed disconnection procedures.",
          "On an LNG carrier, the meter used to verify that target conditions (flammable gas concentration) for",
          "disconnection had been achieved was not calibrated for measuring methane in nitrogen.",
          "The accompanying officer was not familiar with the company procedures which described the management",
          "f cargo and vapour connections at the cargo manifolds.",
          "On an LNG carrier, the accompanying officer was not familiar with the:"
        ],
        "evidence": [
          "Company procedures for managing cargo and vapour connections at the cargo manifolds.",
          "Information on the allowable loads for the manifold supports and pressure rating of flanges, reducers, and",
          "spool pieces, certified by the vessel’s Class Society."
        ],
        "risk": "medium",
        "status": "not_started"
      },
      {
        "id": "8.6.9",
        "number": "8.6.9",
        "chapter": "8",
        "section": "8.6",
        "text": "Were the Master and officers familiar with the company procedures for the use, inspection and testing of manifold reducers, spool pieces and other portable pipework, and were these items in satisfactory condition and properly fitted when in use?",
        "short_text": "Manifold reducers, spool pieces and other portable pipework",
        "vessel_types": [
          "LPG",
          "LNG"
        ],
        "objective": "To ensure manifold reducers, spool pieces and other items of portable pipework meet the required pressure\nrating for the cargo transfer system and will not leak at the flange face when used.",
        "negative_grounds": [
          "There were no company procedures for the use, inspection and testing of manifold reducers, spool pieces",
          "and other portable pipework that included guidance on:",
          "The correct use of manifold reducers, spool pieces and other portable pipework.",
          "Provision of test certification.",
          "Suitable storage arrangements, including the protection of flange faces.",
          "Records to be maintained of inspections.",
          "There was no inventory of manifold reducers, spool pieces and other portable pipework."
        ],
        "evidence": [
          "The company procedures for the use and inspection of manifold reducers, spool pieces and other portable",
          "The inventory of manifold reducers, spool pieces and other portable pipework.",
          "Records of the inspection of manifold reducers, spool pieces and other portable pipework."
        ],
        "risk": "medium",
        "status": "not_started"
      },
      {
        "id": "8.6.10",
        "number": "8.6.10",
        "chapter": "8",
        "section": "8.6",
        "text": "Were the Master and officers familiar with the company procedures for carrying out emergency discharge operations, and was any required additional equipment in satisfactory condition?",
        "short_text": "Emergency discharge operations",
        "vessel_types": [
          "LPG",
          "LNG"
        ],
        "objective": "To ensure the vessel will be able to discharge the cargo safely in the event of equipment failure.",
        "negative_grounds": [],
        "evidence": [],
        "risk": "low",
        "status": "not_started"
      },
      {
        "id": "8.6.11",
        "number": "8.6.11",
        "chapter": "8",
        "section": "8.6",
        "text": "Were the Master and officers familiar with the company procedures for the regular inspection and maintenance of cargo and vapour pipeline insulation and expansion arrangements, and were these arrangements in satisfactory condition?",
        "short_text": "Cargo and vapour pipeline insulation and expansion arrangements",
        "vessel_types": [
          "LPG",
          "LNG"
        ],
        "objective": "To ensure cargo and vapour line insulation and expansion arrangements are regularly inspected and\nproperly maintained.",
        "negative_grounds": [],
        "evidence": [],
        "risk": "low",
        "status": "not_started"
      },
      {
        "id": "8.6.12",
        "number": "8.6.12",
        "chapter": "8",
        "section": "8.6",
        "text": "Were the Master and officers familiar with the company procedures relating to the safety, rescue and recovery equipment, including SCBAs, required by the IGC Code, and was the equipment ready for immediate use?",
        "short_text": "IGC safety, rescue and recovery equipment",
        "vessel_types": [
          "LPG",
          "LNG"
        ],
        "objective": "To ensure the safety, rescue and recovery equipment required by the IGC Code is always ready for\nimmediate use in the event of an emergency.",
        "negative_grounds": [
          "There were no company procedures relating to the safety equipment, including SCBAs, required by the IGC",
          "Code, giving guidance on:",
          "Stowage and maintaining readiness of the equipment.",
          "Inspection and testing of the SCBAs.",
          "Non-emergency use of the SCBAs, including maximum individual daily use and required rest",
          "Use of the oxygen resuscitation equipment.",
          "The accompanying officer was not familiar with the company procedures relating to the safety equipment,",
          "including SCBAs and/or oxygen resuscitation equipment, required by the IGC Code."
        ],
        "evidence": [
          "Company procedures for the use of the safety equipment, including SCBAs, required by the IGC Code.",
          "Records of inspection and testing of the SCBAs forming part of the safety equipment required by the IGC.",
          "Evidence that the protective suits were suitable for: o All the cargoes listed on the International Certificate of Fitness for the Carriage of Liquified Gases",
          "o Use in a flammable atmosphere."
        ],
        "risk": "high",
        "status": "not_started"
      },
      {
        "id": "8.6.13",
        "number": "8.6.13",
        "chapter": "8",
        "section": "8.6",
        "text": "Were the Master and officers familiar with the company procedures addressing the protective equipment required by the IGC Code, and was this equipment in satisfactory condition and suitable for the products being handled?",
        "short_text": "Protective equipment required by the IGC Code",
        "vessel_types": [
          "LPG",
          "LNG"
        ],
        "objective": "To ensure crew members are protected from exposure to hazardous conditions when engaged in cargo\noperations.",
        "negative_grounds": [
          "There were no company procedures addressing the protective equipment required by the IGC that included:",
          "A list of protective equipment to be available on board based upon risk assessment and",
          "considering the products to be carried.",
          "What protective equipment was required to be worn for the different types of operations on board,",
          "and products handled, preferably in the form of a PPE matrix.",
          "Crew training in the correct use of the protective equipment.",
          "Checks to be made that protective equipment is being correctly worn prior to entering a working",
          "Assessment of a user’s fitness to wear particular protective equipment in given climatic conditions."
        ],
        "evidence": [
          "Company procedures, including PPE matrix where provided, addressing the protective equipment required",
          "by the IGC Code.",
          "Records of inspections of the protective equipment.",
          "An inventory of the protective equipment available onboard required by the IGC Code.",
          "SDS for the products being handled.",
          "Chemical resistance list available for the protective suits provided on board."
        ],
        "risk": "medium",
        "status": "not_started"
      },
      {
        "id": "8.6.14",
        "number": "8.6.14",
        "chapter": "8",
        "section": "8.6",
        "text": "Were the Master and officers familiar with the company procedures for the safe operation and maintenance of the reliquefaction plant, and was the equipment in satisfactory condition?",
        "short_text": "Reliquefaction plant",
        "vessel_types": [
          "LPG",
          "LNG"
        ],
        "objective": "To ensure the safe operation of the reliquefaction plant.",
        "negative_grounds": [
          "There were no company procedures for the operation, testing and maintenance of the reliquefaction plant,",
          "machinery, instrumentation, control and shutdown equipment that included, as applicable:",
          "Roles and responsibilities for operation, testing and maintenance.",
          "Description of the reliquefaction system, its components and its functions.",
          "Procedures for start-up and shut-down of the system.",
          "Regular checks including:",
          " compressor lubrication oil levels,  suction filters"
        ],
        "evidence": [
          "The company procedures for the operation, testing and maintenance of the reliquefaction plant, machinery,",
          "instrumentation, control and shutdown equipment.",
          "Record of inspection, maintenance and testing of the reliquefaction system.",
          "Test records for safety relief valves fitted to reliquefaction system.",
          "Records of regular checks of reliquefaction plant liquid level during operation."
        ],
        "risk": "medium",
        "status": "not_started"
      },
      {
        "id": "8.6.15",
        "number": "8.6.15",
        "chapter": "8",
        "section": "8.6",
        "text": "Were the Master and officers familiar with the company procedures for the safe operation and maintenance of the cargo heaters, vaporisers and condensers, and was the equipment in satisfactory condition?",
        "short_text": "Cargo heaters, vaporisers and condensers",
        "vessel_types": [
          "LPG",
          "LNG"
        ],
        "objective": "To ensure the safe operation of the cargo heaters, vaporisers and condensers.",
        "negative_grounds": [
          "There were no company procedures for the operation, testing and maintenance of the cargo heaters,",
          "vaporisers and condensers that included, as applicable:",
          "Roles and responsibilities for operation, testing and maintenance.",
          "Descriptions of the cargo heaters, vaporisers, condensers, their components and functions.",
          "Procedures for start-up and shut-down of the system, including tests of both cargo and water sides",
          "for leakage and test water flow shutdowns.",
          "Ensuring the equipment in use is compatible with the cargo being handled."
        ],
        "evidence": [
          "The company procedures for the operation, testing and maintenance of the cargo heaters, vaporisers and",
          "condensers.",
          "Records of inspection, testing and maintenance of the cargo heaters, vaporisers, condensers.",
          "Test records for safety relief valves fitted to cargo heaters, vaporisers, condensers.",
          "Records of checks of the cargo heaters, vaporisers, condensers prior, during and after operation."
        ],
        "risk": "medium",
        "status": "not_started"
      },
      {
        "id": "8.6.16",
        "number": "8.6.16",
        "chapter": "8",
        "section": "8.6",
        "text": "Were the Master and officers familiar with the filling limits (FL) and loading limits (LL) for the cargo tanks, and was this information readily available in the cargo control room or position?",
        "short_text": "Filling Limits (FL) and Loading Limits (LL)",
        "vessel_types": [
          "LPG",
          "LNG"
        ],
        "objective": "To ensure cargo tanks are never over-filled.",
        "negative_grounds": [
          "There was no document available specifying the maximum allowable loading limits for each cargo tank and",
          "product, at each applicable loading temperature and maximum reference temperature.",
          "The document specifying the maximum allowable loading limits for each cargo tank and product, at each",
          "applicable loading temperature and maximum reference temperature had not been approved by the flag",
          "administration or the vessel’s class society on its behalf.",
          "The officer responsible for cargo planning was not familiar with filling limits (FL), loading limits (LL) and/or",
          "reference temperatures, and their application when planning cargo stowage.",
          "A cargo tank(s) had been loaded above the specified loading limit (LL)."
        ],
        "evidence": [
          "The approved document specifying the maximum allowable loading limits for each cargo tank and product,",
          "at each applicable loading temperature and maximum reference temperature.",
          "Loading plans for the current and previous cargo."
        ],
        "risk": "medium",
        "status": "not_started"
      },
      {
        "id": "8.6.17",
        "number": "8.6.17",
        "chapter": "8",
        "section": "8.6",
        "text": "Were the Master and officers familiar with the company procedures for the operation, inspection, testing and maintenance of the vent mast fire suppression system, and was the system in satisfactory condition?",
        "short_text": "Vent mast fire suppression system",
        "vessel_types": [
          "LPG",
          "LNG"
        ],
        "objective": "To ensure that crewmembers can respond effectively to a fire situation in accordance with the shipboard\nemergency plan.",
        "negative_grounds": [
          "There were no company procedures for the operation, inspection, testing and maintenance of the vent mast",
          "fire suppression system that included:",
          "Roles and responsibilities for inspection, testing and maintenance."
        ],
        "evidence": [
          "The company procedures for the operation, inspection, testing and maintenance of the vent mast fire",
          "suppression system.",
          "Record of inspection, testing and maintenance of the vent mast fire suppression system.",
          "The Cargo System Operation Manual and/or FFA manual."
        ],
        "risk": "high",
        "status": "not_started"
      },
      {
        "id": "8.6.18",
        "number": "8.6.18",
        "chapter": "8",
        "section": "8.6",
        "text": "Were the Master and officers familiar with the company procedures for detecting water leakage into hold or insulation spaces and for dealing with any water or liquid cargo that may have accumulated in these spaces?",
        "short_text": "Water or liquid cargo leakage into a hold or insulation space",
        "vessel_types": [
          "LPG",
          "LNG"
        ],
        "objective": "To ensure any water or cargo liquid leakage into hold or insulation spaces is safely removed.",
        "negative_grounds": [],
        "evidence": [],
        "risk": "low",
        "status": "not_started"
      },
      {
        "id": "8.6.19",
        "number": "8.6.19",
        "chapter": "8",
        "section": "8.6",
        "text": "Were the Master and officers familiar with the company procedures for the operation of the submerged motor electric cargo pumps and the testing of their associated safety devices and alarms, and had these procedures been followed?",
        "short_text": "Submerged motor electric cargo pumps",
        "vessel_types": [
          "LPG",
          "LNG"
        ],
        "objective": "To ensure the submerged motor electric cargo pumps are always operated safely.",
        "negative_grounds": [
          "There were no company procedures for the operation of the submerged motor electric cargo pumps and the",
          "testing of their associated safety devices and alarms that included guidance on:",
          "Arrangements for isolating the pumps from the electrical supply and the occasions when this must",
          "be done e.g., during gas-freeing operations.",
          "Settings and periodic tests of the associated safety devices such as:",
          " Low pump discharge pressure alarm.",
          " Low motor current alarm."
        ],
        "evidence": [
          "Company procedures for the operation of the submerged motor electric cargo pumps and the testing of their",
          "associated safety devices and alarms.",
          "Records of tests of the safety devices and alarms.",
          "Records of visual inspection of the junction boxes of the submerged motor electric cargo pumps prior to",
          "each discharge."
        ],
        "risk": "medium",
        "status": "not_started"
      },
      {
        "id": "8.6.20",
        "number": "8.6.20",
        "chapter": "8",
        "section": "8.6",
        "text": "Were the Master and officers familiar with the company procedures for the inspection, maintenance, testing and setting of the liquid line, hold, insulation and inter- barrier space relief valves?",
        "short_text": "Liquid line, hold, insulation and inter-barrier space relief valves",
        "vessel_types": [
          "LPG",
          "LNG"
        ],
        "objective": "To ensure liquid line, hold, and insulation and inter-barrier space relief valves are properly inspected,\nmaintained, tested, and set.",
        "negative_grounds": [
          "There were no company procedures for the inspection, maintenance, testing and setting of the liquid line,",
          "hold, insulation and inter-barrier space relief valves.",
          "The accompanying officer was not familiar with:",
          "The company procedures for the inspection, maintenance, testing and setting of the liquid line,",
          "hold, insulation and inter-barrier space relief valves.",
          "The actions to take in the event of a relief valve malfunction.",
          "There were no records available of inspections, tests and maintenance carried out on the relief valves",
          "Checks prior each loading."
        ],
        "evidence": [
          "The company procedures for the inspection, maintenance, testing and setting of the liquid line, hold,",
          "insulation and inter-barrier space relief valves Records of inspection, maintenance, testing and setting of the liquid line, hold, insulation and inter-barrier",
          "space relief valves Evidence of training for the officer responsible for the maintenance and operation of the relief valves."
        ],
        "risk": "medium",
        "status": "not_started"
      },
      {
        "id": "8.6.21",
        "number": "8.6.21",
        "chapter": "8",
        "section": "8.6",
        "text": "Were the Master and officers familiar with the company procedures that gave guidance on cargo tank environmental control during inerting, gas freeing and gassing up operations, thermal load hazards during tank cool-down, and the minimum cargo temperature?",
        "short_text": "Inerting, gas freeing and gassing up operations",
        "vessel_types": [
          "LPG",
          "LNG"
        ],
        "objective": "To ensure inerting, gas freeing, gassing up and tank cool-down operations are carried out in a safe manner.",
        "negative_grounds": [
          "There were no company procedures that gave guidance on cargo tank environmental control during inerting,",
          "gas freeing and gassing up operations, thermal load hazards during tank cool-down, and the minimum cargo",
          "temperature, and included as applicable:",
          "Guidance on parameters to be monitored, which may include:",
          " Pressure in interbarrier spaces during cool-down.",
          " Nitrogen consumption/flow.",
          " Flammable gas levels at different levels in the tank."
        ],
        "evidence": [
          "The company procedures that give guidance on cargo tank environmental control during inerting, gas",
          "freeing and gassing up operations, thermal load hazards during tank cool-down, and the minimum cargo",
          "temperature.",
          "Records of inerting, gassing up and cooling down operations including: o Parameters monitored.",
          "o Evidence that gas concentration monitoring was carried out at different tank levels during inerting"
        ],
        "risk": "medium",
        "status": "not_started"
      },
      {
        "id": "8.7.1",
        "number": "8.7.1",
        "chapter": "8",
        "section": "8.7",
        "text": "Were the Master and officers familiar with the purpose and operation of the vessel’s Emergency Shut Down (ESD) systems, and was the equipment in good working order, regularly inspected, tested and maintained?",
        "short_text": "BLS Emergency Shut Down (ESD) systems",
        "vessel_types": [
          "Oil"
        ],
        "objective": "To ensure the vessel is able to execute a controlled ESD 1 or ESD 2 operation.",
        "negative_grounds": [
          "There were no company procedures that defined the operation, inspection, maintenance and testing of the",
          "There were no checklists available for preparation/testing of the ESD systems.",
          "The ESD systems had not been tested as required by company procedures.",
          "The vessel’s planned maintenance system did not include the ESD systems or the required inspections,",
          "maintenance and tests.",
          "Records of inspections, maintenance and tests carried out were incomplete.",
          "The accompanying officer was not familiar with the purpose, operation and testing of the ESD systems.",
          "The responsible officer was unfamiliar with the maintenance plan for the ESD system."
        ],
        "evidence": [
          "The company procedures for operation, inspection, maintenance and testing of the ESD systems.",
          "Completed checklists for the preparation/testing of the ESD systems.",
          "The inspection, maintenance and test records for the ESD systems."
        ],
        "risk": "medium",
        "status": "not_started"
      },
      {
        "id": "8.7.2",
        "number": "8.7.2",
        "chapter": "8",
        "section": "8.7",
        "text": "Were the Master and officers familiar with the company procedures, including appropriate arrival checklists, detailing the necessary checks and actions to be carried out when approaching an offshore terminal prior to DP and/or bow loading operations, and had these procedures been complied with?",
        "short_text": "Checks when approaching an offshore terminal.",
        "vessel_types": [
          "Oil"
        ],
        "objective": "To ensure DP and bow loading shuttle tankers carry out all necessary checks and actions when approaching\noffshore terminals.",
        "negative_grounds": [
          "There were no company procedures detailing the necessary checks and actions to be carried out when",
          "approaching an offshore terminal prior to DP and /or bow loading operations.",
          "The company procedures detailing the necessary checks and actions to be carried out when approaching an",
          "ffshore terminal prior to DP and /or bow loading operations did not include appropriate arrival checklists.",
          "The accompanying officer was not familiar with the company procedures detailing the necessary checks and",
          "actions to be carried out when approaching an offshore terminal prior to DP and /or bow loading operations.",
          "The accompanying officer was unfamiliar with the company checklists used when approaching an offshore",
          "The accompanying officer was unfamiliar with any actions they were responsible for completing or verifying"
        ],
        "evidence": [
          "Company procedures, including appropriate arrival checklists, detailing the necessary checks and actions to",
          "be carried out when approaching an offshore terminal prior to DP and /or bow loading operations.",
          "Completed arrival checklists."
        ],
        "risk": "medium",
        "status": "not_started"
      },
      {
        "id": "8.7.3",
        "number": "8.7.3",
        "chapter": "8",
        "section": "8.7",
        "text": "Were the Master and officers familiar with the equipment for control and monitoring of the Bow Loading System (BLS), and was the equipment in good working order, regularly inspected, tested and maintained?",
        "short_text": "Control and monitoring of the Bow Loading System (BLS)",
        "vessel_types": [
          "Oil"
        ],
        "objective": "To ensure that the vessel’s telemetry and green line systems will safely start, control and stop cargo transfer\noperations.",
        "negative_grounds": [
          "There were no company procedures for the operation, inspection, maintenance and testing of the equipment",
          "for control and monitoring of the BLS which set out:",
          "Guidance on the use of the telemetry and green line systems to ensure safe start, control and",
          "stopping of cargo transfer offshore.",
          "The actions to take in the event of a green line failure (GLF).",
          "The frequency and method of inspection, maintenance and testing of the telemetry and green line",
          "systems, including sensors e.g., tension monitoring load cells, and where fitted, the cargo flow",
          "The accompanying officer was unfamiliar with the:"
        ],
        "evidence": [
          "The company procedures for operation, inspection, maintenance and testing of the equipment for control",
          "and monitoring of the BLS.",
          "FMEA report for the cargo loading system and BLS.",
          "The inspection, maintenance and test records for the equipment for control and monitoring of the BLS.",
          "Completed checklists for the regular testing/preparation of the BLS including the telemetry system and green",
          "line system."
        ],
        "risk": "medium",
        "status": "not_started"
      },
      {
        "id": "8.7.4",
        "number": "8.7.4",
        "chapter": "8",
        "section": "8.7",
        "text": "Were the Master and officers familiar with the company procedures for the operation, inspection, testing and maintenance of the Bow Loading System (BLS), including alarms and indicators, and was the BLS area well maintained and free from oil.",
        "short_text": "Bow Loading System (BLS) operation, inspection, testing and maintenance.",
        "vessel_types": [
          "Oil"
        ],
        "objective": "To ensure the BLS is operated safely and regularly inspected, tested, and maintained.",
        "negative_grounds": [
          "There were no company procedures for the operation, inspection, testing and maintenance of the Bow",
          "Loading System (BLS), including:",
          "BLS coupler valve tightness tests.",
          "Coupler and inboard valve closing-time checks.",
          "BLS operator console alarm and indicators tests.",
          "Other test requirements.",
          "Arrangements for flushing and gas-freeing the bow cargo piping.",
          "The accompanying officer was not familiar with the company procedures for the operation, inspection,"
        ],
        "evidence": [
          "The company procedures for the operation, inspection, testing and maintenance of the Bow Loading System",
          "Records of inspection, testing and maintenance of the BLS including: o BLS coupler valve tightness tests.",
          "o Coupler and inboard valve closing-time checks.",
          "o BLS operator console alarm and indicators tests."
        ],
        "risk": "medium",
        "status": "not_started"
      },
      {
        "id": "8.7.5",
        "number": "8.7.5",
        "chapter": "8",
        "section": "8.7",
        "text": "Were the Master and officers familiar with the location, purpose and operation of the deluge system in the bow loading system (BLS) area, and was the equipment in good working order, regularly inspected, tested and maintained?",
        "short_text": "Deluge system in the bow loading system (BLS) area",
        "vessel_types": [
          "Oil"
        ],
        "objective": "To ensure that those measures specifically designed to prevent or extinguish fires in the BLS area of shuttle\ntankers are effective.",
        "negative_grounds": [
          "There was no company procedure for the testing, maintenance and operations of the BLS deluge system.",
          "Operating instructions for the BLS deluge system were not posted close to the operator panels.",
          "There was no maintenance plan for the vessel’s fire protection systems and fire-fighting systems and",
          "appliances available.",
          "The maintenance plan for the vessel’s fire protection systems and fire-fighting systems and appliances did",
          "not include the BLS deluge system or the required inspections, tests and maintenance.",
          "Records of inspections, tests and maintenance carried out on the BLS deluge system were incomplete.",
          "The accompanying officer was not familiar with the purpose and operation of the BLS deluge system."
        ],
        "evidence": [
          "The company procedures for the testing, maintenance and operation of the BLS deluge system.",
          "The manufacturer’s instruction manuals for the BLS deluge system.",
          "The maintenance and test records for the BLS deluge system."
        ],
        "risk": "high",
        "status": "not_started"
      },
      {
        "id": "8.7.6",
        "number": "8.7.6",
        "chapter": "8",
        "section": "8.7",
        "text": "Were the Master and officers familiar with the location, purpose and operation of the fixed foam fire extinguishing system in the bow loading system (BLS) area, and was the equipment in good working order and regularly inspected, tested and maintained?",
        "short_text": "Fixed foam fire extinguishing system in the bow loading system (BLS) area",
        "vessel_types": [
          "Oil"
        ],
        "objective": "To ensure that those measures specifically designed to prevent or extinguish fires in the BLS area of shuttle\ntankers are effective.",
        "negative_grounds": [
          "There was no company procedure for the operation, inspection and maintenance of the BLS fixed foam fire",
          "extinguishing system.",
          "The BLS fixed foam fire extinguishing system operating instructions were not posted near the control panel",
          "and in the space(s) containing the BLS foam system foam concentrate tanks(s) and pump(s).",
          "The valves and/or system controls were not clearly identified to their purpose and required status during",
          "The foam storage tank was not filled to the required level.",
          "The foam concentrate test had not been carried out within the required time frame."
        ],
        "evidence": [
          "The company procedures for the operation, inspection and maintenance of the BLS fixed foam fire",
          "extinguishing system.",
          "The vessel’s maintenance plan for the vessel’s fire protection systems and fire-fighting systems and",
          "appliances.",
          "The records of inspections, tests and maintenance carried out on the BLS fixed foam fire extinguishing",
          "system, including annual foam concentrate test results."
        ],
        "risk": "high",
        "status": "not_started"
      },
      {
        "id": "8.7.7",
        "number": "8.7.7",
        "chapter": "8",
        "section": "8.7",
        "text": "Are all items of DP equipment in satisfactory condition and are they included in the Planned Maintenance System (PMS)?",
        "short_text": "DP equipment condition and maintenance",
        "vessel_types": [
          "Oil"
        ],
        "objective": "To ensure all DP systems and sub-systems are maintained in good working order.",
        "negative_grounds": [
          "An item of DP equipment was defective in any respect.",
          "An item of DP equipment (give details) was not included in the Planned Maintenance System.",
          "A necessary task (give details) was not included in the Planned Maintenance System, e.g., calibration of",
          "thrusters, routine rebooting of computer systems.",
          "Necessary data (give details) was not included in the Planned Maintenance System, e.g., battery expiry",
          "Maintenance tasks associated with DP equipment were overdue or deferred without shore authorisation."
        ],
        "evidence": [
          "Planned Maintenance System.",
          "DP log book.",
          "DP data log.",
          "Shore maintenance reports."
        ],
        "risk": "medium",
        "status": "not_started"
      },
      {
        "id": "8.7.8",
        "number": "8.7.8",
        "chapter": "8",
        "section": "8.7",
        "text": "Were the Master and officers familiar with the vessel’s DP FMEA, was the latest version available on board, and were any modifications to the DP system included?",
        "short_text": "DP FMEA",
        "vessel_types": [
          "Oil"
        ],
        "objective": "To ensure that the FMEA is properly managed and that the appropriate vessel personnel are familiar with its\ncontents.",
        "negative_grounds": [
          "There were no company procedures to ensure that the:",
          "FMEA is reviewed and updated as required due to changes in operating procedures or",
          "modifications to DP hardware and/or software.",
          "Latest copy of the FMEA is available on board.",
          "Master, DPOs and engineers are familiar with the content of the FMEA.",
          "The FMEA was not identified as a controlled document within the vessels quality management system or",
          "include a revision history.",
          "The FMEA was not written in the working language of the ship."
        ],
        "evidence": [
          "The latest FMEA document, and associated documents.",
          "The Planned Maintenance System (PMS)."
        ],
        "risk": "medium",
        "status": "not_started"
      },
      {
        "id": "8.7.9",
        "number": "8.7.9",
        "chapter": "8",
        "section": "8.7",
        "text": "Were the Master and officers familiar with the location, purpose and operation of the gas and fire detection systems in the bow loading system (BLS) area, and was the equipment in good working order, regularly tested, maintained and calibrated?",
        "short_text": "Gas and fire detection systems in the bow loading system (BLS) area",
        "vessel_types": [
          "Oil"
        ],
        "objective": "To ensure that those measures specifically designed to prevent or extinguish fires in the Bow Loading\nSystem (BLS) area of shuttle tankers are effective.",
        "negative_grounds": [
          "There were no company procedures for the operation, inspection and maintenance of the fire and",
          "hydrocarbon gas detection and alarm systems fitted in the BLS area."
        ],
        "evidence": [
          "The company procedures for the operation, inspection and maintenance of the fire and hydrocarbon gas",
          "detection and alarm systems fitted in the BLS area.",
          "The manufacturer’s instruction manuals for the fire and hydrocarbon gas detection and alarm systems fitted",
          "in the BLS area.",
          "The maintenance, calibration and test records for the fire and hydrocarbon gas detection and alarm systems",
          "fitted in the BLS area."
        ],
        "risk": "high",
        "status": "not_started"
      },
      {
        "id": "8.8.1",
        "number": "8.8.1",
        "chapter": "8",
        "section": "8.8",
        "text": "Were the Master and officers familiar with the company procedures for the operation, inspection, maintenance and testing of the cargo hold hatch-covers, and were the hatch covers in satisfactory condition?",
        "short_text": "Cargo hold hatch covers",
        "vessel_types": [
          "Oil"
        ],
        "objective": "To ensure the cargo hold hatch-covers of combination carriers are properly maintained and gas tight.",
        "negative_grounds": [
          "There were no company procedures for the operation, inspection, maintenance, and testing of the cargo",
          "The accompanying officer was not familiar with the company procedures for the operation, inspection,",
          "maintenance, and testing of the cargo hold hatch-covers.",
          "The accompanying officer was not aware of the optimum tank atmosphere pressure range to maintain an",
          "effective hatch seal.",
          "The sealing arrangements of the hatch-covers were not of the dual-seal type.",
          "The hatch-covers were not included in the vessel’s maintenance plan."
        ],
        "evidence": [
          "Company procedures for the operation, inspection, maintenance, and testing of the cargo hold hatch-covers.",
          "Records of inspection, maintenance and testing of the cargo hold hatch-covers.",
          "Risk assessments pertaining to any gas or liquid leaks from the hatch-covers."
        ],
        "risk": "medium",
        "status": "not_started"
      },
      {
        "id": "8.8.2",
        "number": "8.8.2",
        "chapter": "8",
        "section": "8.8",
        "text": "Were the Master and officers familiar with the company procedures for changing cargo modes, including ship-specific checklists, and were there records to show that these procedures had been followed?",
        "short_text": "Changing between wet and dry cargoes",
        "vessel_types": [
          "Oil"
        ],
        "objective": "To ensure the changeover from wet to dry and vice versa in combination carriers is carried out safely and\nthat all the necessary actions are completed.",
        "negative_grounds": [
          "There were no company procedures for changing cargo mode from wet to dry and vice versa.",
          "The procedures for changing cargo mode from wet to dry and vice versa did not include ship-specific",
          "checklists to facilitate the changeover.",
          "The ship-specific cargo mode changeover checklists had not been completed as required by company",
          "There were no records available of previous cargo mode changeovers.",
          "Records showed that the company procedures had not been followed during a previous cargo mode",
          "There were no records of hold inspections and corrective actions taken prior to cargo mode changeover.",
          "The accompanying officer was not familiar with the company procedures for changing cargo mode from wet"
        ],
        "evidence": [
          "Company procedures for changing cargo mode from wet to dry and vice versa.",
          "Records of cargo mode changeovers, including completed checklists.",
          "Records of hold inspections prior to changeover."
        ],
        "risk": "medium",
        "status": "not_started"
      },
      {
        "id": "8.99.1",
        "number": "8.99.1",
        "chapter": "8",
        "section": "8.99",
        "text": "Were the Master and all officers directly involved in cargo transfer operations familiar with the company procedure for planning cargo and ballast transfers, and were records available to demonstrate that cargo operations had been planned in accordance with the company procedure and conducted in accordance with the agreed plan?",
        "short_text": "Cargo and ballast transfer planning and execution.",
        "vessel_types": [
          "Oil",
          "Chemical",
          "LPG",
          "LNG"
        ],
        "objective": "To ensure cargo and ballast transfer operations are planned and conducted in accordance with company\nprocedures and industry best practice guidance.",
        "negative_grounds": [
          "There was no company procedure:",
          "That required cargo and ballast transfer plans to be prepared with defined content applicable to the",
          "vessel type and the equipment and systems fitted.",
          "Which defined the record-keeping requirements for cargo and ballast transfer operations.",
          "The accompanying officer was unfamiliar with the:",
          "Company procedures for cargo and ballast transfer planning.",
          "Company requirements for maintaining records of cargo and ballast operations.",
          "The reviewed cargo and ballast transfer plan was:"
        ],
        "evidence": [
          "The company procedures for planning cargo and ballast transfers.",
          "The company procedures for cargo and ballast operation record keeping.",
          "The plans for recent cargo and ballast transfer operations.",
          "The records for recent cargo and ballast transfer operations."
        ],
        "risk": "medium",
        "status": "not_started"
      },
      {
        "id": "8.99.2",
        "number": "8.99.2",
        "chapter": "8",
        "section": "8.99",
        "text": "Were the Master and all officers with a direct responsibility for cargo, tank cleaning or ballast operations familiar with the requirements of the ISGOTT Ship/Shore Safety Checklist (SSSCL) and, were appropriate sections of the SSSCL in use with all applicable provisions and agreements maintained throughout?",
        "short_text": "Ship/Shore Safety Checklist (SSSCL)",
        "vessel_types": [
          "Oil",
          "Chemical",
          "LPG",
          "LNG"
        ],
        "objective": "To verify that there are good communications between the tanker and terminal, from pre-arrival to post\ndeparture, to ensure compliance with agreed safe operational procedures.\nOCIMF/ICS: International Safety Guide for Oil Tankers and Terminals. Sixth Edition.\nChapter 25 The Ship/Shore Safety Checklist\nThe responsibility for the safe conduct of operations while a tanker is at a terminal is shared between the tanker’s\nMaster and the Terminal Representative. Before cargo or ballast operations start",
        "negative_grounds": [
          "There was no company procedure which required the relevant sections of a SSSCL in accordance with",
          "ISGOTT Sixth Edition to be completed during every cargo, tank cleaning or ballast operation at a terminal or",
          "during defined ship to ship transfer operations.",
          "The relevant sections of the SSSCL in use were not in alignment with the guidance provided in ISGOTT",
          "The sections of the SSSCL relevant to the operation being undertaken or reviewed had not been completed",
          "There were open defect reports for equipment or systems relevant to the SSSCL which had not been",
          "brought to the attention of the Terminal Representative through a documented remark in the relevant"
        ],
        "evidence": [
          "The company procedure which required the relevant sections of a SSSCL in accordance with ISGOTT Sixth",
          "Edition to be completed during every cargo, tank cleaning or ballast operation at a terminal or during defined",
          "ship to ship transfer operations.",
          "The SSSCL for the ongoing operations and for at least two previous operations.",
          "Cargo operational records for the ongoing operation and at least two previous operations.",
          "The Bridge Log Book."
        ],
        "risk": "medium",
        "status": "not_started"
      },
      {
        "id": "8.99.3",
        "number": "8.99.3",
        "chapter": "8",
        "section": "8.99",
        "text": "Were the Master and officers familiar with the company procedures which provided guidance on the level of supervision and support for cargo / port operations, and were operations supervised and supported by an appropriate team in accordance with the company procedures?",
        "short_text": "Cargo operations team composition.",
        "vessel_types": [
          "Oil",
          "Chemical",
          "LPG",
          "LNG"
        ],
        "objective": "To ensure that there are always enough properly supervised personnel on duty for the management of cargo\noperations, means of access, moorings and any other planned operations while in port or at a terminal.",
        "negative_grounds": [
          "There were no company procedures that provided guidance on the supervision and support levels required",
          "during cargo / port operations.",
          "The accompanying officer was not familiar with the company procedures that provided guidance on the",
          "supervision and support levels required during cargo / port operations.",
          "The cargo / port planning documentation did not include the level of supervision and support required during",
          "the various stages of cargo / port operations.",
          "The cargo / port planning documentation was not developed in alignment with the company procedures that",
          "provided guidance on the supervision and support levels required during cargo / port operations."
        ],
        "evidence": [
          "The company procedures that provided guidance on the supervision and support levels required during",
          "cargo / port operations.",
          "The cargo / port planning documentation for the current operations and the previous three months or six",
          "cargo / port operations whichever is the lesser.",
          "The Bridge Log Book."
        ],
        "risk": "medium",
        "status": "not_started"
      },
      {
        "id": "8.99.4",
        "number": "8.99.4",
        "chapter": "8",
        "section": "8.99",
        "text": "Were the Master and officers familiar with the company procedures for checking and testing cargo and ballast system valves, and were the valves and the remote control system in satisfactory condition?",
        "short_text": "Cargo and ballast valve testing.",
        "vessel_types": [
          "Oil",
          "Chemical",
          "LPG",
          "LNG"
        ],
        "objective": "To ensure that cargo and ballast system valves always operate as designed.",
        "negative_grounds": [
          "There were no company procedures for the regular checking and testing of cargo and ballast system valves",
          "Frequency of checks and tests of cargo and ballast system valves.",
          "Records to be kept of checks and tests of cargo and ballast system valves.",
          "Procedure for checking of the time taken for power operated valves to move from open to closed,",
          "and from closed to open, and the optimum times.",
          "Verification of the accuracy of local and remote valve indicators."
        ],
        "evidence": [
          "The company procedures for the regular checking and testing of cargo and ballast system valves.",
          "The manufacturer's operation and maintenance manual for the power operated valves fitted in the cargo and",
          "ballast systems.",
          "The ship's drawings which identified the design opening and closing times for each size, type and service of",
          "power operated valve fitted in the cargo and ballast systems.",
          "Records of checks and tests of cargo and ballast system valves."
        ],
        "risk": "medium",
        "status": "not_started"
      },
      {
        "id": "8.99.5",
        "number": "8.99.5",
        "chapter": "8",
        "section": "8.99",
        "text": "Were the Master and officers familiar with the company procedures for the operation, maintenance, testing, calibration and comparison of the fixed cargo tank level gauging system, and was the system in satisfactory condition and fully operational?",
        "short_text": "Fixed cargo tank level gauging system.",
        "vessel_types": [
          "Oil",
          "Chemical",
          "LPG",
          "LNG"
        ],
        "objective": "To ensure the fixed tank level gauging system is always fully operational, reliable and accurate.",
        "negative_grounds": [
          "There were no company procedures for the operation, maintenance, testing, calibration and comparison",
          "checks of the fixed tank level gauging system based on the manufacturer’s instructions.",
          "The accompanying officer was not familiar with:"
        ],
        "evidence": [
          "The company procedures for the operation, maintenance, testing, calibration and comparison checks of the",
          "fixed tank level gauging system.",
          "The manufacturer’s instruction manual for the fixed tank level gauging system.",
          "Records of maintenance, testing, calibration, and comparison checks of the fixed tank level gauge system."
        ],
        "risk": "medium",
        "status": "not_started"
      },
      {
        "id": "8.99.6",
        "number": "8.99.6",
        "chapter": "8",
        "section": "8.99",
        "text": "Were the Master and deck officers familiar with the company procedure and manufacturer’s instructions for the periodic testing of the stability and loading instrument(s), and were records maintained to confirm that tests had been completed in accordance with the procedure?",
        "short_text": "Stability and loading instrument(s)",
        "vessel_types": [
          "Oil",
          "Chemical",
          "LPG",
          "LNG"
        ],
        "objective": "To ensure that the vessel’s stability and loading instrument(s) provides accurate stress and stability\ncalculations.",
        "negative_grounds": [
          "There was no company procedure requiring the periodic testing of the vessel’s loading instrument.",
          "The accompanying officer was unfamiliar with the company procedures or the manufacturer’s instructions for",
          "testing the loading instrument.",
          "The accompanying officer was unfamiliar with the damage stability functions of the loading instrument.",
          "The vessel had not completed the periodic verification of the loading instrument accuracy in accordance with",
          "the company procedures or the manufacturer’s instructions.",
          "Records were not available for the periodic verification of the loading instrument accuracy.",
          "Records were not available for the verification of the loading instrument accuracy at Special Survey in the"
        ],
        "evidence": [
          "The company procedures for the management and testing of the stability and loading instrument.",
          "The stability and loading instrument instruction manual.",
          "The records for the regular tests of the stability and loading instrument accuracy by vessel staff.",
          "The records for the annual tests of the stability and loading instrument at the time of annual survey.",
          "The records for the tests in the presence of a class surveyor at the time of special survey.",
          "Where a vessel was exempt from carrying a stability and/or loading instrument under IMO regulations or"
        ],
        "risk": "medium",
        "status": "not_started"
      },
      {
        "id": "8.99.7",
        "number": "8.99.7",
        "chapter": "8",
        "section": "8.99",
        "text": "Where the vessel was subject to loading restrictions and/or intact stability concerns at any phase of a voyage or cargo operation, had the company developed procedures to manage these restrictions and/or concerns, and were the Master and cargo officers familiar with the company procedures?",
        "short_text": "Loading limitations",
        "vessel_types": [
          "Oil",
          "Chemical",
          "LPG",
          "LNG"
        ],
        "objective": "To ensure that the vessel is never loaded in such a manner that any structural limitations are exceeded due\nto tank filling level, or intact stability is compromised by unmanaged free surface effect.",
        "negative_grounds": [
          "The vessel operator had not correctly declared any loading limitations or stability concerns applicable to the",
          "vessel through the pre-inspection questionnaire.",
          "The vessel was subject to loading limitations or stability concerns, but the vessel operator had not",
          "developed procedures to manage the issues onboard the vessel.",
          "The vessel was subject to loading limitations or stability concerns, but there were no warning signs posted to",
          "notify the officers with cargo related responsibilities of the issues onboard the vessel.",
          "The accompanying officer was unfamiliar with the loading limitations or stability concerns applicable to the",
          "vessel, where they existed."
        ],
        "evidence": [
          "The vessel’s loading and stability manual.",
          "The company procedures that addressed any loading limitations or stability concerns.",
          "Recent cargo plans and records to demonstrate that the company procedures to address any loading",
          "limitations or stability concerns had been complied with.",
          "Evidence that the impact of any equipment installations or structural modifications had been assessed and",
          "the loading instrument and stability manual updated as appropriate."
        ],
        "risk": "medium",
        "status": "not_started"
      },
      {
        "id": "8.99.8",
        "number": "8.99.8",
        "chapter": "8",
        "section": "8.99",
        "text": "Were the Master and officers familiar with the company procedures for the selection, inspection, testing and storage of cargo transfer hoses, and were the hoses in satisfactory condition?",
        "short_text": "Cargo transfer hoses.",
        "vessel_types": [
          "Oil",
          "Chemical",
          "LPG",
          "LNG"
        ],
        "objective": "To ensure ship supplied cargo transfer hoses are always fit for purpose.",
        "negative_grounds": [
          "There were no company procedures for the selection, inspection, testing, storage, and retirement of cargo",
          "The accompanying officer was not familiar with the company procedures for the selection, inspection,",
          "testing, storage, and retirement of cargo transfer hoses.",
          "A ship supplied cargo transfer hose:",
          "Was not clearly marked with the required information.",
          "Had not been inspected within the last 12 months to confirm suitability for continued use.",
          "Had not been pressure tested within the last 12 months to confirm suitability for continued use.",
          "Had not been retired in accordance with the company set criteria."
        ],
        "evidence": [
          "The company procedures for the selection, inspection, testing, storage, and retirement of cargo transfer",
          "Cargo transfer hose certificates and compatibility data.",
          "Inspection records.",
          "Hydrostatic, elongation and electrical continuity test records.",
          "Cargo transfer hose usage history."
        ],
        "risk": "medium",
        "status": "not_started"
      },
      {
        "id": "8.99.9",
        "number": "8.99.9",
        "chapter": "8",
        "section": "8.99",
        "text": "Were the Master and officers familiar with the company procedures for periodically verifying the accuracy of cargo and ballast system controls and indicators, and were legible and up-to-date pipeline and/or mimic diagrams available at the cargo control location(s) and in the pumproom(s) as applicable?",
        "short_text": "Cargo and ballast system controls, indicators, mimics and displays.",
        "vessel_types": [
          "Oil",
          "Chemical",
          "LPG",
          "LNG"
        ],
        "objective": "To ensure accurate information and data is available to the officer in charge of cargo operations.",
        "negative_grounds": [
          "Legible and up to date pipeline and/or mimic diagrams were not available in the pumproom(s) and/or at the",
          "cargo control location(s).",
          "Pipeline and/or mimic diagrams had not been updated to reflect modifications or additions to the pipeline",
          "Pipeline systems were not marked/identified consistently with the cargo systems mimic diagram or display.",
          "There was no company procedure which ensured that:",
          "All cargo and ballast system pressure, temperature and level sensors are periodically verified for",
          "Cargo information displays and mimics are checked periodically to verify that information is being",
          "transferred and displayed correctly."
        ],
        "evidence": [
          "The company procedures which ensured that: o All cargo and ballast system pressure, temperature and level sensors are periodically verified for",
          "o Cargo information displays and mimics are checked periodically to verify that information is being",
          "transferred and displayed correctly.",
          "o Cargo and ballast system controls incorporated into cargo information displays and mimics are"
        ],
        "risk": "medium",
        "status": "not_started"
      },
      {
        "id": "8.99.10",
        "number": "8.99.10",
        "chapter": "8",
        "section": "8.99",
        "text": "Were the Master and officers a familiar with the company procedures for the inspection and maintenance of the bonding arrangements for independent cargo tanks, process plant and cargo pipelines and, were these arrangements in satisfactory condition?",
        "short_text": "Cargo system bonding arrangements.",
        "vessel_types": [
          "Oil",
          "Chemical",
          "LPG",
          "LNG"
        ],
        "objective": "To ensure the earthing and bonding arrangements for the cargo tanks, process plant and piping systems on\nboard are maintained as required by class rules and international regulations.",
        "negative_grounds": [
          "There were no company procedures for the inspection and maintenance of the bonding arrangements for",
          "independent cargo tanks, process plant and cargo pipelines.",
          "The accompanying officer was not familiar with the company procedures for the inspection and maintenance",
          "f the bonding arrangements for independent cargo tanks, process plant and cargo pipelines or the",
          "particular arrangements on board the vessel.",
          "Bonding straps or other bonding arrangements, where required by the original vessel design, were:",
          "Mechanically damaged Functionally compromised by high resistivity contamination e.g. corrosive products or paint."
        ],
        "evidence": [
          "The company procedures for the inspection and maintenance of the bonding arrangements for independent",
          "cargo tanks, process plant and cargo pipelines.",
          "The ship’s drawings or instruction books showing bonding arrangements as fitted.",
          "Records of inspections and maintenance of the bonding arrangements."
        ],
        "risk": "medium",
        "status": "not_started"
      },
      {
        "id": "8.99.11",
        "number": "8.99.11",
        "chapter": "8",
        "section": "8.99",
        "text": "Was there a procedure in place to complete an independent check of the entire cargo liquid, vapour and venting pipeline system prior to commencement of cargo operations to ensure that valves, vacuum breakers, sampling connections, drains and unused connections or interconnections were correctly set, and blanked or capped, where appropriate?",
        "short_text": "Independent verification of cargo piping systems line up.",
        "vessel_types": [
          "Oil",
          "Chemical",
          "LPG",
          "LNG"
        ],
        "objective": "To ensure that the entire cargo system integrity and line up is independently verified by a second person\nbefore every cargo operation.",
        "negative_grounds": [
          "There were no company procedures to ensure that that the entire cargo liquid, vapour and venting pipeline",
          "system is independently cross-checked by a second person under the control of the responsible officer prior",
          "to commencement of cargo operations.",
          "The accompanying officer was not familiar with the company procedures to ensure that that the entire cargo",
          "liquid, vapour and venting pipeline system is independently cross-checked by a second person under the",
          "control of the responsible officer prior to commencement of cargo operations.",
          "There was no documentary evidence that the independent cargo system pipeline cross-checks had been",
          "completed before commencing cargo operations."
        ],
        "evidence": [
          "The company procedures to ensure that that entire cargo liquid, vapour and venting pipeline system is",
          "independently cross-checked by a second person under the control of the responsible officer prior to",
          "commencement of cargo operations.",
          "Cargo records which demonstrated that the independent cross-checks of cargo system pipelines had been",
          "completed and documented before cargo operations commenced."
        ],
        "risk": "medium",
        "status": "not_started"
      }
    ]
  },
  {
    "id": "C9",
    "title": "Mooring and Anchoring",
    "roles": [
      "Master",
      "Officers",
      "Bosun"
    ],
    "questions": [
      {
        "id": "9.1.3",
        "number": "9.1.3",
        "chapter": "9",
        "section": "9.1",
        "text": "",
        "short_text": "",
        "vessel_types": [],
        "objective": "",
        "negative_grounds": [
          "The designated working language of the vessel had not been determined by the vessel operator.",
          "The designated working language in use during the inspection was not the same as declared through the",
          "HVPQ and/or entered in the logbook.",
          "An officer or rating was observed to be unable to communicate verbally in the designated working language",
          "An officer or rating was observed to be unable to read a safety sign or instruction in any of the language(s)",
          "in which it was displayed.",
          "Where the common working language was not an official language of the Flag State, plans and notices",
          "required to be posted did not include a translation into the designated working language."
        ],
        "evidence": [
          "The deck log book (or ship’s log book where different) which recorded the designated working language of",
          "the vessel.",
          "The Safety Management System documentation, checklists etc."
        ],
        "risk": "medium",
        "status": "not_started"
      },
      {
        "id": "9.4.2",
        "number": "9.4.2",
        "chapter": "9",
        "section": "9.4",
        "text": "",
        "short_text": "",
        "vessel_types": [],
        "objective": "",
        "negative_grounds": [],
        "evidence": [],
        "risk": "low",
        "status": "not_started"
      },
      {
        "id": "9.4.3",
        "number": "9.4.3",
        "chapter": "9",
        "section": "9.4",
        "text": "",
        "short_text": "",
        "vessel_types": [],
        "objective": "",
        "negative_grounds": [],
        "evidence": [],
        "risk": "low",
        "status": "not_started"
      },
      {
        "id": "9.4.6",
        "number": "9.4.6",
        "chapter": "9",
        "section": "9.4",
        "text": "",
        "short_text": "",
        "vessel_types": [],
        "objective": "",
        "negative_grounds": [
          "There were no company procedures for the operation, inspection, testing and maintenance of the inert gas",
          "system that included, as applicable:",
          "Roles and responsibilities for operation, testing and maintenance.",
          "Description of the inert gas system fitted on board.",
          "Procedures to ensure that instruments and equipment used in the system are maintained in good",
          "condition and calibrated in accordance with the recommendations of original equipment",
          "Arrangements to prevent the backflow of cargo vapour into the inert gas system.",
          "Guidance on the maximum percentage of carbon dioxide that is acceptable to avoid ‘dry ice’"
        ],
        "evidence": [
          "The company procedures for the operation, inspection, testing and maintenance of the inert gas system.",
          "Records of inspection, testing and maintenance of the inert gas system.",
          "Records of checks of the inert gas system, before, during and after operation.",
          "Records of checks to confirm that the oxygen concentration did not exceed the specified level and that the",
          "pressure was above atmospheric when inert gas was used in the cargo system, including tanks, holds or",
          "interbarrier spaces."
        ],
        "risk": "medium",
        "status": "not_started"
      },
      {
        "id": "9.1.1",
        "number": "9.1.1",
        "chapter": "9",
        "section": "9.1",
        "text": "Were the Master and deck officers familiar with the company procedures for the testing and correct operation of the mooring winch brakes, and were records available to demonstrate that brakes had been tested periodically, after maintenance or when there was evidence of premature brake slippage?",
        "short_text": "Testing and correct operation of the mooring winch brakes",
        "vessel_types": [
          "Oil",
          "Chemical",
          "LPG",
          "LNG"
        ],
        "objective": "To ensure that mooring winches function as designed, shedding excess load at a defined value in\naccordance with the Ship Design MBL.",
        "negative_grounds": [
          "There was no company procedure which provided instructions for the use and testing of the mooring",
          "winches brakes fitted to the vessel.",
          "The vessel was not provided with a Mooring System Management Plan (MSMP) which was in alignment",
          "The accompanying deck officer was not familiar with the company procedures for the operation, setting and",
          "testing of the mooring winch brakes.",
          "The accompanying deck officer or observed crew were not familiar with the operation and setting of the",
          "mooring winch brakes.",
          "The brake testing equipment was not maintained in good condition, or the hydraulic jack pressure gauge"
        ],
        "evidence": [
          "The company mooring procedures which included the use and testing of mooring winches fitted to the",
          "The Mooring System Management Plan, where provided.",
          "The Line Management Plan.",
          "The mooring winch brake testing records.",
          "The calibration test certificate for the brake testing equipment pressure gauge where testing equipment"
        ],
        "risk": "medium",
        "status": "not_started"
      },
      {
        "id": "9.1.2",
        "number": "9.1.2",
        "chapter": "9",
        "section": "9.1",
        "text": "Was the vessel satisfactorily moored in accordance with both the terminal mooring plan and the mooring configurations permitted by the vessel’s Mooring System Management Plan?",
        "short_text": "Was the vessel satisfactorily moored",
        "vessel_types": [
          "Oil",
          "Chemical",
          "LPG",
          "LNG"
        ],
        "objective": "To ensure that the vessel is always moored safely in accordance with a terminal’s published mooring plan\nand the acceptable mooring line configurations identified within the vessel’s Mooring System Management\nPlan.",
        "negative_grounds": [
          "The vessel was not provided with a Mooring System Management Plan (MSMP) which was in alignment",
          "The Mooring System Management Plan was not developed to include the permissible mooring",
          "configurations for optimal, sub-optimal and alternative mooring arrangements for conventional tanker berths",
          "and, where used, conventional buoy moorings.",
          "The Mooring System Management Plan was not developed to show the maximum permitted deviation from",
          "the horizontal angles of lines to the perpendicular of the ships fore and aft axis and vertical angles of lines.",
          "The accompanying deck officer was unfamiliar with the process for comparing the published or proposed",
          "terminal mooring plan with the mooring configurations permitted within the Mooring System Management"
        ],
        "evidence": [
          "The Mooring System Management Plan.",
          "The terminal mooring plan, showing the positioning of a similar sized vessel in relationship to the terminal",
          "mooring fittings, published in either the terminal handbook or an industry standard publication.",
          "The passage plan, pilot card, cargo plan or risk assessment which showed the specific mooring layout that",
          "was used at the terminal or berth.",
          "Where the vessel was required to be subject to a terminal compatibility assessment prior to berthing, the"
        ],
        "risk": "medium",
        "status": "not_started"
      },
      {
        "id": "9.1.3",
        "number": "9.1.3",
        "chapter": "9",
        "section": "9.1",
        "text": "Were the Master, deck officers, and ratings involved with mooring operations, familiar with the content of the Line Management Plan and was the plan maintained in accordance with company instructions with mooring line, mooring tail and joining shackle certificates available for each item included within the Line Management Plan?",
        "short_text": "Line Management Plan (LMP) implementation.",
        "vessel_types": [
          "Oil",
          "Chemical",
          "LPG",
          "LNG"
        ],
        "objective": "To ensure that mooring lines, mooring tails and joining shackles are always in serviceable condition and\nmanaged to avoid failure in service.",
        "negative_grounds": [
          "The vessel was not provided with a Line Management Plan (LMP).",
          "The vessel had not retained manufacturer’s product certificates for all mooring lines, mooring tails and",
          "joining shackles onboard referenced against each item’s location.",
          "The LMP was not developed in alignment with the sections and subsections of MEG4 table 5.2, as a",
          "The accompanying officer was unfamiliar with the content of the LMP and how the information was to be",
          "recorded and managed within it.",
          "An interviewed rating who was involved with mooring operations was unfamiliar with the existence of the",
          "LMP or content relevant to their role onboard."
        ],
        "evidence": [
          "The Line Management Plan.",
          "The manufacturer’s product certificates for all mooring lines, mooring tails and joining shackles onboard.",
          "The SMS procedures that were referenced in the general section of the Line Management Plan.",
          "Incident investigation reports for any in service mooring line, mooring tail or joining shackle failures."
        ],
        "risk": "medium",
        "status": "not_started"
      },
      {
        "id": "9.1.4",
        "number": "9.1.4",
        "chapter": "9",
        "section": "9.1",
        "text": "Did all mooring lines, mooring tails and joining shackles, including those carried as spares, meet industry guidelines?",
        "short_text": "Mooring lines, tails and mooring shackles.",
        "vessel_types": [
          "Oil",
          "Chemical",
          "LPG",
          "LNG"
        ],
        "objective": "To ensure that mooring lines, mooring tails and joining shackles are fit for the intended purpose to prevent\nline failure in service.",
        "negative_grounds": [
          "The vessel was not provided with a Mooring Systems Management Plan (MSMP).",
          "The vessel did not have a file containing the manufacturer’s product certificates for all mooring lines,",
          "mooring tails and joining shackles carried onboard.",
          "One or more mooring lines onboard, in service mounted on a winch, or loose or carried as a spare, had a",
          "Line Design Break Force (LDBF) that was lower than 100% of the Ship Design MBL.",
          "One or more mooring tails carried onboard, either in service or carried as a spare, had a Tail Design Break",
          "Force (TDBF) that was lower than 125% of the Ship Design MBL.",
          "One or more of the mooring joining shackles carried onboard, either in use or carried as a spare, had a Safe"
        ],
        "evidence": [
          "The Mooring System Management Plan.",
          "The list of loose equipment (mooring lines, mooring tails and joining shackles) The file of manufacturer product certificates for all mooring lines, mooring tails and joining shackles."
        ],
        "risk": "medium",
        "status": "not_started"
      },
      {
        "id": "9.2.1",
        "number": "9.2.1",
        "chapter": "9",
        "section": "9.2",
        "text": "Were the Master and all officers familiar with the vessel specific emergency towing procedure, and was the emergency towing equipment, where fitted, in satisfactory condition and ready for immediate use?",
        "short_text": "Emergency towing procedure and equipment",
        "vessel_types": [
          "Oil",
          "Chemical",
          "LPG",
          "LNG"
        ],
        "objective": "To ensure that the vessel crew are familiar with the emergency towing procedure, and that the emergency\ntowing equipment, where required to be fitted, is ready for immediate use.",
        "negative_grounds": [
          "The emergency towing procedure (ETB) was not based on the existing arrangements and equipment fitted",
          "The accompanying officer was unfamiliar with the vessel specific emergency towing procedure (ETB).",
          "The accompanying officer was unfamiliar with the emergency towing equipment fitted to the vessel.",
          "The accompanying officer was unfamiliar with the process of deploying the emergency towing equipment",
          "fitted to the vessel.",
          "The emergency towing procedure (ETB) was not available on the bridge, in the ship’s office or cargo control",
          "room and in the forecastle space.",
          "The emergency towing arrangements were defective in any respect."
        ],
        "evidence": [
          "Vessel specific emergency towing procedure (Emergency Towing Booklet - ETB)."
        ],
        "risk": "medium",
        "status": "not_started"
      },
      {
        "id": "9.3.1",
        "number": "9.3.1",
        "chapter": "9",
        "section": "9.3",
        "text": "Were the Master and deck officers familiar with the company procedures for anchoring operations, and were records available to confirm that recent anchoring operations had been conducted in compliance with company expectations?",
        "short_text": "Anchoring operations",
        "vessel_types": [
          "Oil",
          "Chemical",
          "LPG",
          "LNG"
        ],
        "objective": "To ensure that anchoring operations are conducted within the limitations of the equipment fitted to the\nvessel",
        "negative_grounds": [
          "There were no company procedures with supporting checklists which covered the process of anchoring and",
          "The selection of an anchorage taking into account the proximity and density of other vessels at",
          "anchor, the quality of the seabed and the proximity of navigational dangers.",
          "The maximum depth of water permitted for normal anchoring operations.",
          "The required level of supervision of the anchoring party.",
          "The minimum composition of the anchoring party.",
          "The maximum environmental conditions permitted for anchoring.",
          "The environmental conditions at which the vessel would be expected to have departed an"
        ],
        "evidence": [
          "The company procedures for anchoring operations.",
          "Records and checklists for recent anchoring operations.",
          "Recent checklist and/or maintenance record to demonstrate that the windlass brake setting had been",
          "Bridge Log Book and bell book."
        ],
        "risk": "medium",
        "status": "not_started"
      },
      {
        "id": "9.4.1",
        "number": "9.4.1",
        "chapter": "9",
        "section": "9.4",
        "text": "Were the Master, deck officers and deck ratings familiar with the company procedure that defined mooring team supervision and composition for the various mooring and anchoring operations likely to be undertaken, and was evidence available that each mooring work space had been supervised and manned in accordance with company expectations?",
        "short_text": "Mooring team supervision and composition",
        "vessel_types": [
          "Oil",
          "Chemical",
          "LPG",
          "LNG"
        ],
        "objective": "To ensure that mooring and anchoring operations are always properly supervised with enough personnel\nassigned to conduct the operations safely and efficiently at each mooring or anchoring workspace.",
        "negative_grounds": [
          "MSMP sections, relating to Manning and Training and Mooring Operations Plans and Procedures, had not",
          "been developed to specify the mooring or anchoring team composition or identified the required level of",
          "supervision at each mooring workspace.",
          "The accompanying deck officer was unable to identify the company procedure defining who should",
          "supervise each mooring and anchoring workspace and the minimum workspace composition when",
          "An interviewed deck officer or rating involved in mooring operations was unfamiliar with the company",
          "expectations with regards to mooring or anchoring team composition or workspace supervision."
        ],
        "evidence": [
          "The company procedure which defined the mooring and anchoring team composition and workspace",
          "supervision expectations.",
          "The hours of rest records for the previous full month.",
          "The vessel’s Mooring System Management Plan sections: o Manning and Training – Safe manning levels required by the ship’s SMS,",
          "o Mooring Operations Plans and Procedures - Requirements for operations supervision at each"
        ],
        "risk": "medium",
        "status": "not_started"
      },
      {
        "id": "9.4.2",
        "number": "9.4.2",
        "chapter": "9",
        "section": "9.4",
        "text": "Were the deck officers and ratings involved with mooring operations familiar with the safe operation of the mooring winches and the dangers of working with and around mooring lines during mooring operations and while under tension?",
        "short_text": "Dangers of working with and around mooring lines",
        "vessel_types": [
          "Oil",
          "Chemical",
          "LPG",
          "LNG"
        ],
        "objective": "To ensure that vessel personnel are aware of the dangers of working with mooring equipment and near lines\nunder tension.",
        "negative_grounds": [
          "There was no company procedure which included the considerations for operational safety during mooring",
          "perations or in areas where mooring lines were under tension.",
          "A deck officer or rating involved in mooring operations was unfamiliar with the company mooring procedure",
          "which defined the considerations for operational safety during mooring operations and in areas where there",
          "were mooring lines under tension.",
          "A deck officer or rating involved in mooring operations was unfamiliar with the danger of snap-back and how",
          "this was communicated onboard the vessel prior to and after mooring operations."
        ],
        "evidence": [
          "The company mooring procedure which defined operational safety during mooring operations or in areas",
          "where mooring lines were under tension."
        ],
        "risk": "medium",
        "status": "not_started"
      },
      {
        "id": "9.5.1",
        "number": "9.5.1",
        "chapter": "9",
        "section": "9.5",
        "text": "Were the appropriate industry checklists used during STS operations, and were comprehensive records of these operations maintained?",
        "short_text": "STS operations checklists",
        "vessel_types": [
          "Oil",
          "Chemical",
          "LPG",
          "LNG"
        ],
        "objective": "To ensure that all stages of an STS operation are conducted in accordance with industry best practice\nguidance.",
        "negative_grounds": [
          "There was no company procedure which required the vessel to use the checklists identified by the OCIMF*",
          "There was no company procedure which required that comprehensive STS records were maintained",
          "The accompanying deck officer was not familiar with the company procedure for the use of checklists during",
          "The accompanying officer was not familiar with the company procedure for the retention of records relating",
          "Review of checklists in use at the time of the inspection or from past STS operations indicated that the",
          "wrong STS checklists were used i.e. “at sea” checklists were used for “in port” operations or vice-versa."
        ],
        "evidence": [
          "The company procedure which required the vessel to use the checklists identified by the OCIMF* STS",
          "Transfer Guide.",
          "The company procedure which required the retention of STS checklists and records.",
          "Where the vessel was undertaking an STS operation at the time of the inspection, the STS checklists,",
          "standard pre-transfer checklist and, vapour balancing checklist where this was taking place.",
          "The records for STS operations completed during the previous twelve months or, where numerous"
        ],
        "risk": "medium",
        "status": "not_started"
      },
      {
        "id": "9.5.2",
        "number": "9.5.2",
        "chapter": "9",
        "section": "9.5",
        "text": "Where the vessel was involved in an “at sea” STS operation, was an accurate Joint Plan of Operation available onboard, were the Master and deck officers familiar with its content, and were operations being conducted in accordance with its requirements?",
        "short_text": "STS Joint Plan of Operation (JPO)",
        "vessel_types": [
          "Oil",
          "Chemical",
          "LPG",
          "LNG"
        ],
        "objective": "To ensure that each “at sea” ship to ship (STS) operations is planned and executed taking into consideration\nthe operational and environmental requirements for the specific transfer location, vessels and cargo transfer\noperations involved.",
        "negative_grounds": [
          "There was no procedure which required that a Joint Plan of Operation (JPO) was developed for every STS",
          "The vessel did not have onboard a JPO which reflected the specific STS operation being undertaken.",
          "The JPO did not include all information required by the OCIMF* STS Guide relevant to the operation being",
          "The accompanying deck officer was unfamiliar with the company procedure which required a JPO to be",
          "developed for every STS operation.",
          "The accompanying deck officer was unfamiliar with the content of the JPO.",
          "An interviewed deck officer or deck rating had not been briefed regarding the content of the JPO prior to the",
          "commencement of the STS operation."
        ],
        "evidence": [
          "The company procedures which required the development of a Joint Plan of Operation for every STS",
          "The vessel’s STS Operations Plan.",
          "The Joint Plan of Operation for the STS operation, developed by the STS service provider, the STS",
          "organiser, the STS Superintendent or the Person in overall advisory control (POAC) depending on the",
          "circumstances of the operation."
        ],
        "risk": "medium",
        "status": "not_started"
      },
      {
        "id": "9.5.3",
        "number": "9.5.3",
        "chapter": "9",
        "section": "9.5",
        "text": "Were the Master, officers and deck ratings familiar with the vessel’s STS Operations Plan?",
        "short_text": "STS Operations Plan",
        "vessel_types": [
          "Oil",
          "Chemical",
          "LPG",
          "LNG"
        ],
        "objective": "To ensure that ship to ship (STS) mooring & cargo operations are always planned and conducted in a\nconsistent manner.",
        "negative_grounds": [
          "The vessel did not have an STS Operations Plan. (irrespective of whether the vessel had been involved in",
          "STS operations.) Where the vessel had been involved in the STS transfer of Annex 1 cargo the STS plan had not been",
          "approved by the vessel’s Administration. (except where specifically exempted by MARPOL Annex 1",
          "Where the vessel was not involved in the carriage of Annex 1 cargo, the content of the STS Operations Plan",
          "was not in alignment with Annex A of the OCIMF Ship to Ship Transfer Guide.",
          "The onboard STS Operations Plan were found to be outdated or incomplete.",
          "One or more copies of the STS Operations Plan was missing from the following locations; bridge, cargo"
        ],
        "evidence": [
          "The vessel’s STS Operations Plan."
        ],
        "risk": "medium",
        "status": "not_started"
      },
      {
        "id": "9.6.1",
        "number": "9.6.1",
        "chapter": "9",
        "section": "9.6",
        "text": "Were the vapour collection system manifold arrangements suitable for hose handling at buoy moorings?",
        "short_text": "Vapour hose securing arrangement for buoy moorings.",
        "vessel_types": [
          "Oil"
        ],
        "objective": "To ensure that vapour collection system manifolds are suitably designed and equipped to facilitate hose\nhandling at buoy moorings.",
        "negative_grounds": [
          "For a vapour return system manifold (VRSM) which was designed for use at single buoy moorings:",
          "The vapour manifolds were not supported to the same strength as the cargo manifolds.",
          "Hose rails did not extend beyond the vapour manifolds.",
          "Hose rails serving the vapour manifolds were not:",
          "Of the same strength and construction throughout their length.",
          "Fitted with stopper plates at both the forward and aft ends of the hose rails.",
          "The vapour manifolds were not fitted with the necessary:"
        ],
        "evidence": [
          "The vessel’s mooring arrangement plan."
        ],
        "risk": "medium",
        "status": "not_started"
      },
      {
        "id": "9.6.2",
        "number": "9.6.2",
        "chapter": "9",
        "section": "9.6",
        "text": "Were the Master and officers familiar with the company procedures for mooring at an SPM or F(P)SO and were the fittings required accurately described in the HVPQ?",
        "short_text": "SPM mooring arrangements.",
        "vessel_types": [
          "Oil",
          "Chemical",
          "LPG",
          "LNG"
        ],
        "objective": "To ensure the vessel is appropriately equipped and will be able to safely moor to an SPM or F(P)SO terminal.",
        "negative_grounds": [
          "There were no company procedures for mooring at SPM or F(P)SO terminals that included:",
          "Guidance on preparations for mooring at SPM or F(P)SO terminals.",
          "Instructions for safe mooring at SPM or F(P)SO terminals.",
          "Inspection and maintenance instructions for the bow stopper(s).",
          "The accompanying officer was not familiar with the company procedures for mooring at SPM or F(P)SO",
          "terminals, as they related to their duties.",
          "The actual physical arrangements for mooring at an SPM or F(P)SO terminal were not as described in the",
          "HVPQ - provide details."
        ],
        "evidence": [
          "The company procedures for mooring at SPM or F(P)SO terminals.",
          "Mooring arrangement plan(s).",
          "Certificates, issued by an independent authority, such as a Classification Society, for the:",
          "o Bow stopper(s) and/or foundations and supporting structure.",
          "o Closed bow fairlead(s) and/or foundations and supporting structure.",
          "Records of inspection and maintenance of the bow stoppers, which may form part of the maintenance plan."
        ],
        "risk": "medium",
        "status": "not_started"
      },
      {
        "id": "9.7.1",
        "number": "9.7.1",
        "chapter": "9",
        "section": "9.7",
        "text": "Were the Master and officers familiar with the company procedures for the operation, inspection, testing and maintenance of the bow mooring system for offshore terminals, and was the equipment in satisfactory condition?",
        "short_text": "Shuttle tanker bow mooring system",
        "vessel_types": [
          "Oil"
        ],
        "objective": "To ensure the bow mooring system is regularly inspected, tested, and maintained, and operated safely.",
        "negative_grounds": [
          "There were no company procedures for the operation, inspection, testing and maintenance of the bow",
          "mooring system for offshore terminals.",
          "The accompanying officer was not familiar with the company procedures for the operation, inspection,",
          "testing and maintenance of the bow mooring system for offshore terminals including:",
          "Measures to prevent accidental release of the chafe chain from the bow stopper.",
          "Use of the traction winch manual brake release in the event of a power failure.",
          "Use of the messenger line cutter device designed to enable cutting the line if sucked into the",
          "thruster(s) / propeller(s)."
        ],
        "evidence": [
          "The company procedures for the operation, inspection, testing and maintenance of the bow mooring system",
          "for offshore terminals.",
          "Records of inspection, testing and maintenance of the bow mooring system for offshore terminals."
        ],
        "risk": "medium",
        "status": "not_started"
      }
    ]
  },
  {
    "id": "C10",
    "title": "Machinery",
    "roles": [
      "CE",
      "Engineers"
    ],
    "questions": [
      {
        "id": "10.1.1",
        "number": "10.1.1",
        "chapter": "10",
        "section": "10.1",
        "text": "Had the Chief Engineer prepared Standing Orders, supplemented by Daily Orders, which emphasised and reinforced the company expectations with regards to engine room management and, if so, had all engineer officers signed to acknowledge their understanding of the same?",
        "short_text": "Chief Engineer's standing and daily orders",
        "vessel_types": [
          "Oil",
          "Chemical",
          "LPG",
          "LNG"
        ],
        "objective": "To ensure that all engineer officers are aware of the key expectations of both the company and the Chief\nEngineer with respect to the management of the vessel’s machinery spaces.",
        "negative_grounds": [
          "There was no company procedure defining the requirement for the Chief Engineer to prepare Standing and",
          "The accompanying engineer officer was unfamiliar with the content of the Chief Engineer’s Standing or Daily",
          "The Chief Engineer had not prepared their own Standing Orders which were signed and dated at the time of",
          "taking over the responsibilities as Chief Engineer.",
          "The engineer officers onboard at the time of the inspection had not signed the Standing Orders, (unless they",
          "had only joined that day).",
          "The content of the Standing Orders was in contradiction to the company procedures for managing the",
          "machinery space or any machinery or equipment."
        ],
        "evidence": [
          "The company procedures for developing the Chief Engineer’s Standing Orders and for writing Daily Orders.",
          "The current Chief Engineer’s Standing Orders signed by the Chief Engineer and all engineer officers.",
          "The Daily Order Book with each dated and timed entry signed by the Chief Engineer, and subsequently,",
          "each watchkeeping officer before taking over their watch or period of duty.",
          "The Engine Room Log Book and other records to support the changes of machinery space operating mode",
          "and the status of machinery."
        ],
        "risk": "medium",
        "status": "not_started"
      },
      {
        "id": "10.1.2",
        "number": "10.1.2",
        "chapter": "10",
        "section": "10.1",
        "text": "Were the Chief Engineer and engineer officers familiar with the company procedures for testing main propulsion, steering gear, thrusters and power generation plant prior to use and at critical points during a voyage or operation, and were checklists and log book entries completed as required?",
        "short_text": "Testing main propulsion, steering gear, thrusters & power generation plant",
        "vessel_types": [
          "Oil",
          "Chemical",
          "LPG",
          "LNG"
        ],
        "objective": "To ensure that all machinery required for safe navigation is tested to verify full functionality and availability\nat key stages of a voyage or operation.",
        "negative_grounds": [
          "There was no documented procedure for testing and checking equipment and machinery at defined points in",
          "The accompanying engineer officer was unfamiliar with the machinery testing process or any test or check",
          "that was required to be carried out by the vessel specific checklist.",
          "The accompanying engineer officer was unfamiliar with the local operation of the steering gear.",
          "Checklists did not reflect the equipment fitted to the vessel or the tests and/or checks required to be carried",
          "ut at defined points prior to and within the voyage.",
          "Machinery and equipment tests and/or checks required by the company procedures had not been completed",
          "Defects detected during the equipment and machinery testing process had not been recorded as either"
        ],
        "evidence": [
          "The company procedures which defined the pre-arrival, pre-departure and/or pre-transit machinery testing",
          "requirements.",
          "Completed pre-arrival, pre-departure and pre-operational machinery checklists or the required wipe-clean",
          "checklist along with the supporting logbook entries to verify satisfactory completion of the required tests.",
          "Evidence that machinery and equipment defects detected during the testing program had been noted and",
          "either immediately repaired by onboard staff or that the defect had been communicated to the bridge and"
        ],
        "risk": "medium",
        "status": "not_started"
      },
      {
        "id": "10.1.3",
        "number": "10.1.3",
        "chapter": "10",
        "section": "10.1",
        "text": "Were the Chief Engineer and engineer officers familiar with company procedures for periodic rounds and monitoring of the machinery space, and were log book entries and checklists available to confirm that the rounds had been completed as required?",
        "short_text": "Periodic rounds of machinery space for non-UMS vessels",
        "vessel_types": [
          "Oil",
          "Chemical",
          "LPG",
          "LNG"
        ],
        "objective": "To ensure that the machinery spaces had been effectively monitored to manage machinery in operation and\non standby.",
        "negative_grounds": [
          "There was no procedure that required periodic machinery space rounds.",
          "The accompanying engineer officer was unfamiliar with the company procedures for monitoring the",
          "The accompanying engineer officer was unfamiliar with any of the checks required to be conducted during",
          "the machinery space rounds and included on the checklists.",
          "There were no vessel specific checklists for periodic rounds of the machinery space.",
          "The periodic rounds of the machinery spaces had not been carried out in accordance with the company"
        ],
        "evidence": [
          "The company procedures which defined the requirement for routine monitoring of machinery spaces.",
          "Checklists for machinery space rounds.",
          "Engine room operational records for recent voyages."
        ],
        "risk": "medium",
        "status": "not_started"
      },
      {
        "id": "10.1.4",
        "number": "10.1.4",
        "chapter": "10",
        "section": "10.1",
        "text": "Were the Chief Engineer and engineer officers familiar with company procedures for periodic machinery space rounds and monitoring of the machinery space during both manned and unmanned (UMS) periods, and were log book entries and checklists available to confirm that the inspections had been completed as required?",
        "short_text": "Periodic machinery space rounds during both manned and unmanned (UMS) periods",
        "vessel_types": [
          "Oil",
          "Chemical",
          "LPG",
          "LNG"
        ],
        "objective": "To ensure that the machinery spaces had been monitored to effectively manage machinery in operation and\non standby while in both manned and unmanned modes.",
        "negative_grounds": [
          "There was no procedure that required periodic machinery space rounds during manned periods and prior to",
          "The accompanying engineer officer was unfamiliar with the company procedures for monitoring the",
          "machinery spaces during manned and unmanned operation.",
          "There were no vessel specific checklists for periodic inspections of the machinery space during manned",
          "periods and prior to unmanned operation.",
          "The accompanying engineer officer was unfamiliar with any of the checks required to be conducted during",
          "the machinery space rounds and included on the checklists."
        ],
        "evidence": [
          "The company procedures which defined the requirement for routine monitoring of machinery during manned",
          "operation and, prior to and during unmanned machinery space periods.",
          "Checklists for machinery space rounds during manned operation and prior to unmanned machinery space",
          "Machinery space operational records for recent voyages.",
          "Machinery space alarm records for recent voyages."
        ],
        "risk": "medium",
        "status": "not_started"
      },
      {
        "id": "10.1.5",
        "number": "10.1.5",
        "chapter": "10",
        "section": "10.1",
        "text": "Were the Chief Engineer and engineer officers familiar with the operation, inspection and testing of the means provided to control propulsion machinery and related auxiliary systems locally in the event of failure of a remote-control system?",
        "short_text": "Local control of propulsion machinery",
        "vessel_types": [
          "Oil",
          "Chemical",
          "LPG",
          "LNG"
        ],
        "objective": "To ensure the engineer officers can respond promptly and effectively in the event of a failure of the remote\ncontrol of propulsion machinery or a related auxiliary system.",
        "negative_grounds": [
          "There were no company procedures for the operation, inspection and testing of the means provided to",
          "control the propulsion machinery and related auxiliary systems locally.",
          "The accompanying engineer officer was not familiar with the purpose, operation and testing of the",
          "propulsion local control systems.",
          "Ship specific operating instructions for the local control systems were not posted close to the control",
          "The planned maintenance system did not include the means provided to control the propulsion machinery",
          "locally or the required inspections and tests Records of inspections and tests carried out were incomplete."
        ],
        "evidence": [
          "The company procedures for the operation, inspection and testing of the means provided to control the",
          "propulsion machinery and related auxiliary systems locally.",
          "The inspection and test records for the local control systems."
        ],
        "risk": "medium",
        "status": "not_started"
      },
      {
        "id": "10.2.1",
        "number": "10.2.1",
        "chapter": "10",
        "section": "10.2",
        "text": "Were the officers familiar with the starting procedure for the emergency generator and were records available to demonstrate that the emergency generator had been tested according to company procedures?",
        "short_text": "Emergency generator",
        "vessel_types": [
          "Oil",
          "Chemical",
          "LPG",
          "LNG"
        ],
        "objective": "To ensure the emergency generator will supply alternative power when needed.",
        "negative_grounds": [
          "There was no company procedure for operating, testing and maintaining the emergency generator.",
          "The emergency generator was not set up to start and supply power to the emergency switchboard",
          "automatically in the event of a power interruption.",
          "Ship specific starting instructions were not posted adjacent to the equipment.",
          "Posted starting instructions were unclear or inadequate.",
          "Officers were not familiar with the ship specific starting procedure for the emergency generator and",
          "connecting it to the emergency switchboard.",
          "The emergency generator would not start within three attempts by either the primary or secondary means."
        ],
        "evidence": [
          "The company procedures for the operation and testing of the emergency generator.",
          "The ship specific procedure for starting the emergency generator and connecting it to the emergency",
          "switchboard.",
          "Onboard records for the testing of the emergency generator, fuel quick closing valve and spare starter",
          "motor, where provided."
        ],
        "risk": "high",
        "status": "not_started"
      },
      {
        "id": "10.2.2",
        "number": "10.2.2",
        "chapter": "10",
        "section": "10.2",
        "text": "Were the Chief Engineer and engineer officers familiar with the company procedures for the regular inspection, maintenance and testing of the ship’s emergency batteries, and were the batteries fully charged and in satisfactory condition?",
        "short_text": "Battery emergency source of power.",
        "vessel_types": [
          "Oil",
          "Chemical",
          "LPG",
          "LNG"
        ],
        "objective": "To ensure that the emergency source of electrical power is always ready in all respects.",
        "negative_grounds": [
          "There were no company procedures for the regular inspection, maintenance and testing of the emergency",
          "battery source of electrical power, including:",
          "Inspection of the batteries.",
          "Assessment of the condition of the batteries.",
          "Periodic testing of the complete emergency battery system.",
          "The battery retirement criteria based on either the maximum service life and/or functional condition.",
          "The accompanying officer was not familiar with the company procedures for the regular inspection,",
          "maintenance and testing of the emergency battery source of electrical power."
        ],
        "evidence": [
          "Company procedures for the regular inspection, maintenance and testing of the emergency battery source",
          "of electrical power.",
          "Records of: o Inspection of the batteries.",
          "o Assessment of the condition of the batteries.",
          "o Periodic testing of the complete emergency battery system."
        ],
        "risk": "medium",
        "status": "not_started"
      },
      {
        "id": "10.2.3",
        "number": "10.2.3",
        "chapter": "10",
        "section": "10.2",
        "text": "Were the Chief Engineer and engineer officers familiar with the company procedures for the operation, calibration and maintenance of the exhaust gas cleaning system (EGCS), and were required safety and regulatory measures being complied with?",
        "short_text": "Exhaust gas cleaning system (EGCS)",
        "vessel_types": [
          "Oil",
          "Chemical",
          "LPG",
          "LNG"
        ],
        "objective": "To ensure the EGCS is operated safely in accordance with company procedures and applicable regulations\nand local/national limitations.",
        "negative_grounds": [
          "There were no company procedures for the operation, calibration and maintenance of the exhaust gas",
          "cleaning system (EGCS) that included:",
          "The identification of associated hazards.",
          "Crew training requirements.",
          "PPE and signage requirements."
        ],
        "evidence": [
          "Company procedures for the operation, calibration and maintenance of the EGCS.",
          "Any checklists provided for the routine operation of the EGCS.",
          "The planned maintenance records for the EGCS.",
          "Risk assessments for the operation, calibration and maintenance of the EGCS.",
          "Records of crew training or familiarisation in the operation, calibration and maintenance of the EGCS.",
          "Sox Emissions Compliance Plan."
        ],
        "risk": "medium",
        "status": "not_started"
      },
      {
        "id": "10.2.4",
        "number": "10.2.4",
        "chapter": "10",
        "section": "10.2",
        "text": "Were seawater pipelines, sea chests and seawater pumps in satisfactory condition and free of temporary repairs?",
        "short_text": "Seawater pipelines",
        "vessel_types": [
          "Oil",
          "Chemical",
          "LPG",
          "LNG"
        ],
        "objective": "To ensure there are no weak points in seawater systems that might lead to failure and machinery space\nflooding.",
        "negative_grounds": [
          "A seawater pipeline, sea chest, storm valve, hull penetration or seawater pump was corroded with pitting or",
          "hard rust/scale (give details and location).",
          "A seawater pipeline, sea chest, storm valve, hull penetration or seawater pump was leaking (give details and",
          "Fixed expansion joints (bellows) in a seawater pipeline were deformed.",
          "A pipeline was worn/thinned in way of a clip or support.",
          "A series of pipe clips and/or supports in a single pipe length were heavily corroded or missing.",
          "There was a temporary repair on a seawater pipeline e.g. a clamp or bandage (give details and location).",
          "There was an unacceptable ‘permanent’ repair on a seawater pipeline e.g. a doubler plate or coupling (give"
        ],
        "evidence": [
          "Machinery space pipeline drawings and specifications."
        ],
        "risk": "medium",
        "status": "not_started"
      },
      {
        "id": "10.2.5",
        "number": "10.2.5",
        "chapter": "10",
        "section": "10.2",
        "text": "Were the officers familiar with the company procedure for testing the bilge monitoring devices within their area of responsibility, and were records available to demonstrate that the bilge monitoring devices and associated alarms had been tested in accordance with the company procedure?",
        "short_text": "Bilge monitoring devices",
        "vessel_types": [
          "Oil",
          "Chemical",
          "LPG",
          "LNG"
        ],
        "objective": "To ensure that the flooding detection systems fitted on board are always fully operational.",
        "negative_grounds": [
          "There was no company procedure which required that all bilge level monitoring devices and water level",
          "detectors were periodically tested.",
          "The accompanying deck or engineer officer was not familiar with company procedure for the testing of the",
          "bilge level monitoring devices and water level detectors within their area of responsibility.",
          "There were no records available to demonstrate that the periodic testing of all bilge level monitoring devices",
          "and water level detectors and their associated alarms, including any activation delay, had been completed in",
          "accordance with company procedures.",
          "A bilge level monitoring device and / or water level detector and/or its associated alarm was defective in any"
        ],
        "evidence": [
          "The company procedure that required all bilge level monitoring devices and water level detectors and their",
          "associated alarms and indicators were identified and periodically tested.",
          "The vessel records to demonstrate that each bilge level monitoring device, its activation delay and its",
          "associated alarm had been tested in accordance with company procedures."
        ],
        "risk": "high",
        "status": "not_started"
      },
      {
        "id": "10.2.6",
        "number": "10.2.6",
        "chapter": "10",
        "section": "10.2",
        "text": "Were the Chief Engineer and engineer officers familiar with the company procedures for the operation, inspection and testing of the emergency air compressor and emergency air reservoir, and was the equipment in satisfactory condition?",
        "short_text": "Emergency compressed air machinery starting system.",
        "vessel_types": [
          "Oil",
          "Chemical",
          "LPG",
          "LNG"
        ],
        "objective": "To ensure the emergency compressed air machinery starting system is always ready in all respects.",
        "negative_grounds": [
          "There were no company procedures for:",
          "The operation, inspection and testing of the emergency air compressor and emergency air",
          "The use of the emergency air compressor and emergency air reservoir for bringing machinery into",
          "peration from the dead ship condition.",
          "The accompanying officer was not familiar with:",
          "The company procedures for the operation, inspection and testing of the emergency air",
          "compressor and emergency air reservoir.",
          "The actions necessary to use the emergency air compressor and/or emergency air reservoir to"
        ],
        "evidence": [
          "Company procedures for: o The operation, inspection and testing of the emergency air compressor and emergency air",
          "o The use of the emergency air compressor and emergency air reservoir for bringing machinery into",
          "operation from the dead ship condition.",
          "Records of regular inspection and testing of the emergency air compressor and emergency air reservoir."
        ],
        "risk": "medium",
        "status": "not_started"
      },
      {
        "id": "10.3.1",
        "number": "10.3.1",
        "chapter": "10",
        "section": "10.3",
        "text": "Was suitable deck insulation provided to the front and rear of electrical switchboards, and was it in good order?",
        "short_text": "Switchboard deck insulation.",
        "vessel_types": [
          "Oil",
          "Chemical",
          "LPG",
          "LNG"
        ],
        "objective": "To ensure that people are protected from injury when working on or around switchboards.",
        "negative_grounds": [
          "Switchboards were not provided with deck insulation to the front and/or rear.",
          "The deck insulation matting or composite insulating deck covering was incomplete or damaged.",
          "The deck insulation matting or composite insulating deck covering provided was not suitable for the specific",
          "voltage of the switchboard.",
          "There was no certification, marking or other documentary evidence of the rating of the deck insulation",
          "If the insulation matting presented a trip hazard this should be recorded as an observation under question 5.8.2"
        ],
        "evidence": [
          "Certification, marking or other documentary evidence of the safe working voltage rating for the deck",
          "insulation in use."
        ],
        "risk": "medium",
        "status": "not_started"
      },
      {
        "id": "10.3.2",
        "number": "10.3.2",
        "chapter": "10",
        "section": "10.3",
        "text": "Were the engineer officers familiar with the purpose and setting of the insulation monitoring devices provided on the primary and secondary distribution systems, and were the distribution switchboards free of significant earth faults?",
        "short_text": "Electrical distribution system switchboard earth monitoring.",
        "vessel_types": [
          "Oil",
          "Chemical",
          "LPG",
          "LNG"
        ],
        "objective": "To ensure that any significant earth faults are promptly addressed to prevent injury to personnel from\nelectrical shock.",
        "negative_grounds": [
          "There was no company procedure which:",
          "Provided guidance for the setting values for the IMDs for 110v, 220v, 440v and any other voltages",
          "used for the primary or secondary distribution systems.",
          "Where a vessel was only provided with earth insulation lamps as the IMD, provided guidance on",
          "interpreting the indications for low insulation faults.",
          "Required that the causes of earth faults are investigated and corrected with the aim to maintain the",
          "insulation values as close to infinity as possible.",
          "The accompanying officer was not familiar with the company procedure which provided guidance for the"
        ],
        "evidence": [
          "The company procedure which: o Provided guidance for the setting values for the IMDs for 110v, 220v, 440v and any other voltages",
          "used for the primary or secondary distribution systems.",
          "o Where a vessel was only provided with earth insulation lamps as the IMD, provided guidance on",
          "interpreting the indications for low insulation faults.",
          "o Required that the causes of earth faults are investigated and corrected with the aim to maintain the"
        ],
        "risk": "medium",
        "status": "not_started"
      },
      {
        "id": "10.3.3",
        "number": "10.3.3",
        "chapter": "10",
        "section": "10.3",
        "text": "Were the Chief Engineer and engineer officers familiar with the company procedures for safe entry into the machinery space(s) during UMS operation, including the operation and testing of the dead man alarm, if fitted?",
        "short_text": "Entry into the machinery space during UMS.",
        "vessel_types": [
          "Oil",
          "Chemical",
          "LPG",
          "LNG"
        ],
        "objective": "To ensure safe entry into the machinery space(s) during UMS operation.",
        "negative_grounds": [
          "There were no company procedures for safe entry into the machinery space(s) during UMS operation",
          "During unattended periods, no-one enters the machinery spaces alone, for example to carry out",
          "final evening checks, without first informing the bridge.",
          "During unattended periods, contact should be maintained with the bridge at frequent predetermined",
          "periods during any entry, unless a dead man alarm is fitted.",
          "A rating should not be assigned any duty which involved them attending the engine room alone",
          "during unattended periods.",
          "Where a single engineer maintains a watch, contact is maintained with the bridge or cargo control"
        ],
        "evidence": [
          "Company procedures for safe entry into the machinery space(s) during UMS operation.",
          "Records of testing of the dead man alarm (where fitted).",
          "Engine Room Log Book.",
          "Bridge Log Book."
        ],
        "risk": "medium",
        "status": "not_started"
      },
      {
        "id": "10.3.4",
        "number": "10.3.4",
        "chapter": "10",
        "section": "10.3",
        "text": "Were the Chief Engineer and engineer officers familiar with the operation of the engineers’ alarm, and was the alarm in good order, tested regularly and the results recorded?",
        "short_text": "Engineers' alarm.",
        "vessel_types": [
          "Oil",
          "Chemical",
          "LPG",
          "LNG"
        ],
        "objective": "To ensure the engineers’ alarm is in good order and regularly tested.",
        "negative_grounds": [
          "There were no company procedures for the operation and testing of the engineers’ alarm that included:",
          "A description of its operation.",
          "Requirements for regularly testing the alarm and recording the results.",
          "The accompanying officer was not familiar with the company procedures for the operation and testing of the",
          "The accompanying officer could not identify the locations of the engineers’ alarm activation points within the",
          "There were no records of the regular testing of the engineers’ alarm."
        ],
        "evidence": [
          "Company procedures for the operation and testing of the engineers’ alarm.",
          "Records of regular testing of the engineers’ alarm."
        ],
        "risk": "medium",
        "status": "not_started"
      },
      {
        "id": "10.3.5",
        "number": "10.3.5",
        "chapter": "10",
        "section": "10.3",
        "text": "Were the Chief Engineer and engineer officers familiar with the operation of the machinery alarm, and was the alarm in good order, tested regularly and the results recorded?",
        "short_text": "Machinery alarm",
        "vessel_types": [
          "Oil",
          "Chemical",
          "LPG",
          "LNG"
        ],
        "objective": "To ensure the machinery alarm is in good order and regularly tested.",
        "negative_grounds": [
          "There were no company procedures for the operation and testing of the machinery alarm that included:",
          "A description of its operation.",
          "Requirements for regularly testing the alarm and recording the results.",
          "The accompanying officer was not familiar with the company procedures for the operation and testing of the",
          "The accompanying engineer officer was not familiar with the separate functions of the machinery alarm",
          "panel in the engine room.",
          "A navigation officer was not familiar with the separate functions of the machinery alarm panel on the bridge."
        ],
        "evidence": [
          "Company procedures for the operation and testing of the machinery alarm.",
          "Records of regular testing of the machinery alarm."
        ],
        "risk": "medium",
        "status": "not_started"
      },
      {
        "id": "10.3.6",
        "number": "10.3.6",
        "chapter": "10",
        "section": "10.3",
        "text": "Were the Master and officers familiar with the company procedures for the operation, inspection and regular testing of watertight doors, and were the watertight doors in satisfactory condition?",
        "short_text": "Watertight doors.",
        "vessel_types": [
          "Oil",
          "Chemical",
          "LPG",
          "LNG"
        ],
        "objective": "To ensure watertight doors are regularly tested and ready to operate in an emergency.",
        "negative_grounds": [
          "There were no company procedures for the operation, inspection and regular testing of watertight doors.",
          "The accompanying officer was not familiar with the company procedures for the operation, inspection and",
          "regular testing of watertight doors.",
          "An interviewed rating was unable to describe or demonstrate the local operation of a watertight door.",
          "The rubber gasket on a sliding watertight door was damaged, in poor condition or missing.",
          "There was hydraulic oil leakage from the operating mechanism of a sliding watertight door.",
          "A sliding watertight door could not be closed from the bridge.",
          "The local audible alarm and/or light for a sliding watertight door was inoperative when the door was remotely"
        ],
        "evidence": [
          "Company procedures for the operation, inspection and regular testing of watertight doors.",
          "Records of the inspection and testing of watertight doors."
        ],
        "risk": "high",
        "status": "not_started"
      },
      {
        "id": "10.3.7",
        "number": "10.3.7",
        "chapter": "10",
        "section": "10.3",
        "text": "Was gas welding and cutting equipment in good order, and spare oxygen and acetylene cylinders stored apart in a well-ventilated location outside of the accommodation and engine room?",
        "short_text": "Gas welding and cutting equipment.",
        "vessel_types": [
          "Oil",
          "Chemical",
          "LPG",
          "LNG"
        ],
        "objective": "To ensure gas welding and cutting equipment is properly installed and in satisfactory condition.",
        "negative_grounds": [
          "Gas cylinders were not properly secured in their location.",
          "Gas cylinders were not secured such that they could be easily released in the case of fire.",
          "Protective caps were not screwed in place on cylinders not in use or being moved.",
          "The valve on an empty cylinder was open.",
          "A supply valve on a gas cylinder had been left open after completion of work.",
          "Oxygen and acetylene cylinders were stored together.",
          "Empty cylinders were not kept separate from full ones.",
          "Cylinders were stored with the valve end down."
        ],
        "evidence": [
          "Records of periodic inspection and replacement of flashback arrestors and regulators in the gas cutting and",
          "welding equipment."
        ],
        "risk": "high",
        "status": "not_started"
      },
      {
        "id": "10.3.8",
        "number": "10.3.8",
        "chapter": "10",
        "section": "10.3",
        "text": "Were engineer officers and ratings familiar with the safety precautions for the use of electric welding equipment, were these safety precautions posted, and was the equipment in satisfactory condition?",
        "short_text": "Electric welding equipment.",
        "vessel_types": [
          "Oil",
          "Chemical",
          "LPG",
          "LNG"
        ],
        "objective": "To ensure that electric welding equipment is always used safely.",
        "negative_grounds": [
          "The accompanying officer was not familiar with the safety precautions for electric welding.",
          "An interviewed rating was not familiar with the safety precautions for electric welding.",
          "Safety precautions for electric welding were not posted in the engine room workshop or other appropriate",
          "Equipment, such as welding curtains or screens, required by the safety precautions for electric welding were",
          "missing or in unsatisfactory condition.",
          "The supply wiring was not adequate to carry the electrical current demand without overloading.",
          "There was evidence that the ship's structure had been used as the earth return.",
          "In the case of a welding work station, the earthing connection was not next to the work site with the cable"
        ],
        "evidence": [
          "Safety precautions for electric welding.",
          "Equipment nameplate or documentation confirming the output voltage of the electric welding equipment."
        ],
        "risk": "medium",
        "status": "not_started"
      },
      {
        "id": "10.4.1",
        "number": "10.4.1",
        "chapter": "10",
        "section": "10.4",
        "text": "Were the responsible vessel staff familiar with the company procedure for managing and using the planned maintenance system, and was the system updated with an accurate record of onboard maintenance and spare parts in accordance with the procedure?",
        "short_text": "Planned maintenance system (PMS)",
        "vessel_types": [
          "Oil",
          "Chemical",
          "LPG",
          "LNG"
        ],
        "objective": "To ensure that vessel structure, machinery and equipment is maintained in accordance with class\nrequirements, manufacturer’s recommendations and company instructions.",
        "negative_grounds": [
          "There was no company procedure for managing the planned maintenance system.",
          "The accompanying responsible officer was unfamiliar with the company procedure for managing the planned",
          "The accompanying responsible officer was unfamiliar with the operation of the planned maintenance",
          "An interviewed deck officer or junior engineer was unfamiliar with the process of completing and recording",
          "tasks assigned to them within the planned maintenance system Defects to structure, machinery or equipment were recorded in the planned maintenance system but were",
          "not transferred to the defect reporting system, if not a combined system."
        ],
        "evidence": [
          "The company procedure for managing the planned maintenance system provided onboard.",
          "The planned maintenance system.",
          "The manufacturer’s instructions for operating the planned maintenance system provided onboard. (where",
          "the system was computer based) The spare parts inventory with critical equipment and spare parts identified, if not contained within the",
          "planned maintenance system."
        ],
        "risk": "medium",
        "status": "not_started"
      },
      {
        "id": "10.4.2",
        "number": "10.4.2",
        "chapter": "10",
        "section": "10.4",
        "text": "Did the vessel operator subscribe to a lube oil and hydraulic oil analysis program and was a procedure in place to act on the results and trends identified by the analysis?",
        "short_text": "Lube oil and hydraulic oil analysis program",
        "vessel_types": [
          "Oil",
          "Chemical",
          "LPG",
          "LNG"
        ],
        "objective": "To ensure that the quality of lube oils and hydraulic oils is monitored, and action taken when necessary to\navoid machinery damage.\nIACS: UR_Z21 Surveys of Propeller Shafts and Tube Shafts.\n1.2.14 Lubricating oil analysis\nLubricating oil analysis is to be carried out at regular intervals not exceeding six (6) months taking into account IACS\nRec. 36.\nThe documentation on lubricating oil analysis is to be available on board. Oil samples, to be submitted for the\nanalysis, should be taken under serv",
        "negative_grounds": [
          "The vessel did not have a programme for the routine sampling and analysis of lubricating and hydraulic oils.",
          "The accompanying officer was unfamiliar with the company procedure for managing the lubricating and",
          "hydraulic oil analysis programme.",
          "One or more oils required to be sampled and analysed had not been landed for analysis in alignment with",
          "the programme, unless the analysis due date was during the previous voyage or there was objective",
          "evidence of vessel had not been able to land the samples in previous ports / regions.",
          "One or more oils analysed during the previous two cycles of oil analysis had resulted in a “critical” (red)",
          "There was no evidence that the recommended or instructed actions to correct the condition of an oil"
        ],
        "evidence": [
          "The lubricating and hydraulic oil analysis programme information documenting the oils subject to analysis.",
          "The lubricating and hydraulic oil analysis records for the previous two cycles of analysis.",
          "Where analysis had resulted in a “critical” (red) or “warning” (amber) status, any follow up communications",
          "from shore-based management.",
          "Maintenance records to demonstrate that the recommended or instructed actions had been taken to correct",
          "any “critical” or “warning” status."
        ],
        "risk": "medium",
        "status": "not_started"
      },
      {
        "id": "10.5.1",
        "number": "10.5.1",
        "chapter": "10",
        "section": "10.5",
        "text": "Were the Master, Chief Engineer, officers, and ratings involved in bunkering operations, familiar with the company bunkering procedures, and were records available to demonstrate that bunker operations had been planned and conducted in accordance with the company procedure?",
        "short_text": "Conventional bunkering operations",
        "vessel_types": [
          "Oil",
          "Chemical",
          "LPG",
          "LNG"
        ],
        "objective": "To ensure that bunkering operations are planned and conducted in accordance with Industry best practice\nguidance.",
        "negative_grounds": [
          "There was no company procedure that required bunker transfer plans to be prepared with defined content in",
          "alignment with ISGOTT Chapter 24 and TMSA KPI 6.2.5.",
          "There were no supporting checklists for pre-arrival, checks after mooring, pre-transfer conference, pre-",
          "bunkering, repetitive checks or post-bunkering.",
          "There was no company procedure which defined the record-keeping requirements for bunkering operations.",
          "The accompanying officer was unfamiliar with the company procedures for bunker transfer planning.",
          "The accompanying officer was unfamiliar with the company requirement for maintaining records of",
          "bunkering operations."
        ],
        "evidence": [
          "The company procedure for developing bunker transfer plans.",
          "The company procedure for bunker operation record keeping.",
          "The plans for recent bunker transfer operations.",
          "The records for recent bunker transfer operations."
        ],
        "risk": "medium",
        "status": "not_started"
      },
      {
        "id": "10.5.2",
        "number": "10.5.2",
        "chapter": "10",
        "section": "10.5",
        "text": "Were the Chief Engineer and engineer officers familiar with the company procedures for bunker fuel oil sampling and analysis, and were records available to demonstrate that samples had been taken and retained or analysed in accordance with the procedure?",
        "short_text": "Bunker fuel oil sampling and analysis",
        "vessel_types": [
          "Oil",
          "Chemical",
          "LPG",
          "LNG"
        ],
        "objective": "To ensure that marine distillate and residual fuel oils meet the defined quality and environmental standards\nfor use onboard in propulsion and power generating machinery.",
        "negative_grounds": [
          "There was no company procedure for managing fuel oil samples, arranging fuel oil analysis and the",
          "remedial actions to be taken where fuel oil quality raised a concern.",
          "The accompanying engineer officer was not familiar with the company procedures for fuel oil sampling,",
          "sample retention or fuel oil analysis.",
          "Bunker delivery notes were not available for each delivery of marine distillate and residual fuel oil.",
          "Bunker samples had not been retained for each delivery of marine distillate and residual fuel oil.",
          "There was no company requirement to arrange for fuel oil analysis on every occasion marine residual fuel oil",
          "was loaded for consumption onboard."
        ],
        "evidence": [
          "The company procedures for managing fuel oil samples, arranging fuel oil analysis and remedial actions to",
          "be taken where fuel oil quality raises a concern.",
          "Bunker delivery notes for the previous twelve months.",
          "Bunker analysis reports for the previous twelve months.",
          "Oil Record Book Part 1 covering all fuel oil bunkering operations for the previous six months and the last",
          "bunkering if more than six months previously."
        ],
        "risk": "medium",
        "status": "not_started"
      },
      {
        "id": "10.5.3",
        "number": "10.5.3",
        "chapter": "10",
        "section": "10.5",
        "text": "Were the Chief Engineer and senior engineer officers familiar with the company and vessel specific fuel changeover procedures, and were records available to demonstrate that fuel grade changeovers had been completed in compliance with the procedures and MARPOL regulations?",
        "short_text": "Fuel change over procedures",
        "vessel_types": [
          "Oil",
          "Chemical",
          "LPG",
          "LNG"
        ],
        "objective": "To ensure that fuel grade changeovers are conducted in accordance with regulations while maintaining the\nsafe and continuous availability of propulsion and electrical power.",
        "negative_grounds": [
          "There was no company procedure describing the changeover of fuel grades onboard.",
          "There were no ship specific fuel grade changeover procedures.",
          "The accompanying engineer officer was unfamiliar with the company procedures describing the changeover",
          "f fuel grades onboard .",
          "The accompanying engineer officer was unfamiliar with the vessel specific fuel grade changeover",
          "Records for changing of fuel grades were either missing or inaccurate.",
          "Entries had not been made in the appropriate Log Book to record the volume of low sulphur fuel oils in each",
          "tank as well as the date, time and position of the ship on:"
        ],
        "evidence": [
          "The company procedures describing the changeover of fuel grades onboard .",
          "The vessel specific procedures for changing of fuel grades for main engines, generators and boilers.",
          "Onboard records demonstrating that fuel changes had been completed in accordance with MARPOL Annex",
          "VI regulations, company procedures and vessel specific instructions, including: o Engine Room Log Book",
          "o Any other Log Book used to record fuel changeovers as required by MARPOL Annex VI,"
        ],
        "risk": "medium",
        "status": "not_started"
      },
      {
        "id": "10.6.1",
        "number": "10.6.1",
        "chapter": "10",
        "section": "10.6",
        "text": "Were the Master and officers familiar with the location, purpose and operation of the LNG fuel tank water-spray system for cooling and fire prevention on deck, and was the equipment in good working order, regularly inspected, tested and maintained?",
        "short_text": "LNG fuel tank water-spray system",
        "vessel_types": [
          "Oil",
          "Chemical",
          "LPG"
        ],
        "objective": "To ensure that crewmembers can respond effectively to a fire situation in accordance with the shipboard\nemergency plan.",
        "negative_grounds": [],
        "evidence": [],
        "risk": "low",
        "status": "not_started"
      },
      {
        "id": "10.6.2",
        "number": "10.6.2",
        "chapter": "10",
        "section": "10.6",
        "text": "Were the Chief Engineer, and those officers and ratings, involved in LNG bunkering operations, familiar with the functions of the vessel’s LNG (or other low- flashpoint fuel) bunkering Emergency Shut Down (ESD) systems, and was the equipment in good working order, regularly inspected, tested and maintained?",
        "short_text": "LNG gas fuel bunkering ESD system",
        "vessel_types": [
          "Oil",
          "Chemical",
          "LPG"
        ],
        "objective": "To ensure that crewmembers can respond effectively to an emergency while bunkering LNG (or other low-\nflashpoint fuel) in accordance with the shipboard emergency plan.",
        "negative_grounds": [
          "The Chief Engineer and officers directly involved in bunker operations were not familiar with the vessel’s",
          "bunkering ESD systems.",
          "Instrumentation and controls at the bunker control station were not fully operative.",
          "A fuel system schematic/piping and instrumentation diagram was not posted at the bunker station or at the",
          "remote bunker control station.",
          "There was no fuel handling manual available.",
          "The fuel handling manual did not describe the bunkering ESD system.",
          "There was no record of checks and tests of the bunkering ESD systems before bunkering operations began."
        ],
        "evidence": [
          "The company procedures for the operation, inspection, maintenance and testing of the vessel’s bunkering",
          "ESD systems.",
          "The completed checklist used to conduct the pre-arrival tests on the bunker ESD system prior to the",
          "previous LNG bunker transfer operation.",
          "Records of the inspection, maintenance and testing of the vessel’s bunkering ESD systems.",
          "The fuel handling manual."
        ],
        "risk": "medium",
        "status": "not_started"
      },
      {
        "id": "10.6.3",
        "number": "10.6.3",
        "chapter": "10",
        "section": "10.6",
        "text": "Were the Chief Engineer, and those officers and ratings involved in LNG bunkering operations, familiar with the company LNG (or other low-flashpoint fuel) bunkering procedures, and were records available to demonstrate that bunker operations had been planned and conducted in accordance with the company procedures?",
        "short_text": "LNG (or other low-flashpoint fuel) bunkering procedures.",
        "vessel_types": [
          "Oil",
          "Chemical",
          "LPG"
        ],
        "objective": "To ensure that LNG (or other low-flashpoint fuel) bunkering operations are planned and conducted in\naccordance with industry best practice guidance.",
        "negative_grounds": [
          "There were no company procedures that included:",
          "The preparation of a detailed bunker transfer plan for each operation.",
          "Roles and responsibilities of the personnel involved in the bunkering operation.",
          "Description of the bunkering system, including emergency shutdown (ESD) and emergency release",
          "systems (ERS), where fitted.",
          "Hazards when connecting/disconnecting hoses or hard arms.",
          "Pre-bunkering verification of:",
          " All communication methods, including ship shore link (SSL), if fitted."
        ],
        "evidence": [
          "Company procedures for bunkering operations of LNG (or other low-flashpoint fuel).",
          "Fuel Handling Manual required by the IGF Code.",
          "Plans for recent bunker transfer operations.",
          "Records for recent bunker transfer operations, including completed checklists."
        ],
        "risk": "high",
        "status": "not_started"
      },
      {
        "id": "10.6.4",
        "number": "10.6.4",
        "chapter": "10",
        "section": "10.6",
        "text": "Were the safety measures at the bunkering control station and bunkering manifold area in satisfactory condition?",
        "short_text": "LNG fuel bunkering control station and manifold.",
        "vessel_types": [
          "Oil",
          "Chemical",
          "LPG"
        ],
        "objective": "To ensure safety measures at the bunker control station and in the bunker manifold area are in satisfactory\ncondition.",
        "negative_grounds": [
          "The bunkering control location was not in a safe area.",
          "The bunkering control location was not equipped with one or more of the following, or one or more of the",
          "controls or instruments was not operational:",
          "Controls for the remote operated shutdown valve at the manifold.",
          "Controls for the remote operated valves in the water spray system.",
          "Indicators for fuel tank pressure, temperature and tank level.",
          "Overfill and automatic shutdown alarm.",
          "Audible and visual alarms for ventilation failure and gas detection in the ducting around the bunker"
        ],
        "evidence": [],
        "risk": "high",
        "status": "not_started"
      },
      {
        "id": "10.7.1",
        "number": "10.7.1",
        "chapter": "10",
        "section": "10.7",
        "text": "Were the Master and officers familiar with the location, purpose, testing and operation of the vessel’s remote controls for fuel and lube oil valves, emergency fuel and lube oil pump shut-offs and oil tank quick closing valves, and were the systems in good working order?",
        "short_text": "Remote controls for fuel and lube oil system valves",
        "vessel_types": [
          "Oil",
          "Chemical",
          "LPG",
          "LNG"
        ],
        "objective": "To ensure that crewmembers can respond effectively to a fire situation in accordance with the shipboard\nemergency plan.",
        "negative_grounds": [
          "There was no company procedure for the inspection, testing and maintenance of the remote controls for fuel",
          "and lube oil valves and emergency fuel and lube oil pump shut-offs and oil tank quick closing valves.",
          "The remote controls for fuel and lube oil valves and emergency fuel and lube oil pump shut-offs were not",
          "clearly marked and identified.",
          "The access to remote controls for fuel and lube oil valves and emergency fuel and lube oil pump shut-offs"
        ],
        "evidence": [
          "The company procedures for the inspection, testing and maintenance of the remote controls for fuel and",
          "lube oil valves and emergency fuel and lube oil pump shut-offs and oil tank quick closing valves.",
          "The vessel’s maintenance plan for vessel’s fire protection systems and fire-fighting systems and appliances.",
          "The records of inspections, tests and maintenance carried out on the remote controls for fuel and lube oil",
          "valves and emergency fuel and lube oil pump shut-offs and oil tank quick closing valves."
        ],
        "risk": "medium",
        "status": "not_started"
      },
      {
        "id": "10.7.2",
        "number": "10.7.2",
        "chapter": "10",
        "section": "10.7",
        "text": "Were the Master and officers familiar with the measures to prevent fire in the machinery spaces caused by flammable liquid spraying onto a hot surface and, were the protective measures provided regularly inspected and properly maintained?",
        "short_text": "Fire prevention in machinery spaces - hot surfaces and oil spray",
        "vessel_types": [
          "Oil",
          "Chemical",
          "LPG",
          "LNG"
        ],
        "objective": "To ensure fire prevention measures relating to hot surfaces and flammable liquids in the machinery space\nare understood and properly maintained.",
        "negative_grounds": [
          "There was no company procedure that set out the actions to be taken to ensure the integrity of the",
          "measures in place to prevent fires in the machinery spaces caused by a flammable liquid spraying onto a",
          "The records of periodic inspections verifying that fire prevention measures in the machinery spaces relating",
          "to hot surfaces and flammable liquids were missing or incomplete."
        ],
        "evidence": [
          "The company procedures that set out the actions to be taken to ensure the integrity of measures in place to",
          "prevent fires in the machinery spaces caused by a flammable liquid spraying onto a hot surface.",
          "The records of periodic inspections of the fire prevention measures relating to hot surfaces and flammable",
          "liquids in the machinery spaces.",
          "The ship-specific checklist to facilitate the inspection of the fire prevention measures, which included the",
          "measures relating to hot surfaces and flammable liquids, in the machinery spaces."
        ],
        "risk": "high",
        "status": "not_started"
      },
      {
        "id": "10.7.3",
        "number": "10.7.3",
        "chapter": "10",
        "section": "10.7",
        "text": "Were the main engine crankcase oil mist detectors, engine bearing temperature monitors or equivalent devices and associated alarms in good order?",
        "short_text": "Main engine crank case monitoring.",
        "vessel_types": [
          "Oil",
          "Chemical",
          "LPG",
          "LNG"
        ],
        "objective": "To ensure the monitoring arrangements to warn of potential crankcase explosion are always effective.",
        "negative_grounds": [
          "There was no company procedure for the crankcase oil mist detectors, engine bearing temperature monitors",
          "r equivalent devices which described:",
          "Actions to be taken in the event of an alarm.",
          "Testing procedures and frequency.",
          "The accompanying officer was not familiar with the action to be taken in the event of an alarm from the",
          "crankcase oil mist detector, engine bearing temperature monitor or equivalent device.",
          "The accompanying officer was unable to demonstrate a test of the oil mist detector or equivalent device"
        ],
        "evidence": [
          "Company procedures for the operation of the crankcase oil mist detectors or engine bearing temperature",
          "monitors or equivalent devices.",
          "Manufacturer’s instructions for the operation and maintenance of the oil mist detectors, engine bearing",
          "temperature monitors or equivalent devices.",
          "Records for the testing and servicing of the oil mist detectors, engine bearing temperature monitors or",
          "equivalent devices."
        ],
        "risk": "medium",
        "status": "not_started"
      },
      {
        "id": "10.7.4",
        "number": "10.7.4",
        "chapter": "10",
        "section": "10.7",
        "text": "Where hydraulic power packs were located within the main engine compartment, were fire protection measures provided, and if so, where they in satisfactory condition?",
        "short_text": "Hydraulic power packs fire protection measures.",
        "vessel_types": [
          "Oil",
          "Chemical",
          "LPG",
          "LNG"
        ],
        "objective": "To ensure the machinery space is protected from a fire or explosion resulting from a hydraulic oil mist\ncaused by high pressure leakage.",
        "negative_grounds": [
          "Hydraulic power packs of more than 50 kW with a working pressure more than 100 bar were not installed in",
          "specially dedicated spaces with a separate ventilation system.",
          "The hydraulic power packs were located within the main machinery space, not in a specially dedicated",
          "space, but there was either:",
          "No oil mist detector fitted, or No encapsulation of the pumps and high pressure piping protected by a leak detection device.",
          "The accompanying officer was not familiar with the fire protection measures associated with the hydraulic",
          "If fitted, the oil mist detector had not been regularly tested in accordance with manufacturers’"
        ],
        "evidence": [
          "If fitted, records of regular testing of the oil mist detector.",
          "If fitted, records of regular testing of the level alarm or other means of leak detection."
        ],
        "risk": "high",
        "status": "not_started"
      }
    ]
  },
  {
    "id": "C11",
    "title": "General Appearance and Condition – Photograph Comparison",
    "roles": [
      "Master",
      "CE",
      "Officers"
    ],
    "questions": [
      {
        "id": "11.4.2",
        "number": "11.4.2",
        "chapter": "11",
        "section": "11.4",
        "text": "",
        "short_text": "",
        "vessel_types": [],
        "objective": "",
        "negative_grounds": [
          "The operating instructions for the system were not posted at the control station.",
          "The accompanying officer was not familiar with the location, purpose and operation of the vessel’s water-",
          "spray system for cooling and fire prevention on deck.",
          "Access to the system controls was obstructed.",
          "The system valves and controls were not properly marked or set.",
          "Stop valves or isolating valves did not operate freely.",
          "The stop valves or isolating valves were not clearly marked.",
          "There was evidence of clogged or overpainted water spray nozzles."
        ],
        "evidence": [
          "The vessel’s maintenance plan for vessel’s fire protection systems and fire-fighting systems and appliances.",
          "The records of inspections, tests and maintenance carried out on the water-spray system for cooling and fire",
          "prevention on deck"
        ],
        "risk": "high",
        "status": "not_started"
      },
      {
        "id": "11.1.1",
        "number": "11.1.1",
        "chapter": "11",
        "section": "11.1",
        "text": "Was photograph no.1, bow area from dead ahead, representative of the condition as seen onboard at the time of the inspection and, if so, was it free of any areas for concern?",
        "short_text": "Bow area from dead ahead",
        "vessel_types": [
          "Oil",
          "Chemical",
          "LPG",
          "LNG"
        ],
        "objective": "To ensure that the condition of the vessel is accurately reflected in the SIRE 2.0 vessel inspection report.\nTMSA KPI 12.1.2 requires that an inspection plan covers all vessels in the fleet, with at least two inspections of each\nvessel a year.\nThe inspection process provides company management with a comprehensive overview of the condition of the fleet\nat specified intervals.",
        "negative_grounds": [
          "The photograph uploaded for a specified location did not represent the actual condition of the vessel as it",
          "existed at the time of the inspection.",
          "Where the photograph uploaded for a specified location was representative of the actual condition of the",
          "vessel as it existed at the time of the inspection, but the condition of an item pictured was considered to",
          "warrant further review by the user of the report:",
          "Select photo representative - item to be highlighted.",
          "Add additional photographs as considered necessary.",
          "Add a comment to identify the areas that are considered to merit further review."
        ],
        "evidence": [
          "The appropriate photograph will be inserted in the inspection editor for review.",
          "Where no photograph was uploaded to the OCIMF SIRE 2.0 database the question will be automatically",
          "entered as Not Seen in the final report"
        ],
        "risk": "medium",
        "status": "not_started"
      },
      {
        "id": "11.1.2",
        "number": "11.1.2",
        "chapter": "11",
        "section": "11.1",
        "text": "Was photograph no.2, hull forward end starboard side, representative of the condition as seen onboard at the time of the inspection and, if so, was it free of any areas for concern?",
        "short_text": "Hull forward end starboard side",
        "vessel_types": [
          "Oil",
          "Chemical",
          "LPG",
          "LNG"
        ],
        "objective": "",
        "negative_grounds": [],
        "evidence": [],
        "risk": "low",
        "status": "not_started"
      },
      {
        "id": "11.1.3",
        "number": "11.1.3",
        "chapter": "11",
        "section": "11.1",
        "text": "Was photograph no.3, hull forward end port side representative, of the condition as seen onboard at the time of the inspection and, if so, was it free of any areas for concern?",
        "short_text": "Hull forward end port side",
        "vessel_types": [
          "Oil",
          "Chemical",
          "LPG",
          "LNG"
        ],
        "objective": "",
        "negative_grounds": [],
        "evidence": [],
        "risk": "low",
        "status": "not_started"
      },
      {
        "id": "11.1.4",
        "number": "11.1.4",
        "chapter": "11",
        "section": "11.1",
        "text": "Was photograph no.4, hull aft end starboard side, representative of the condition as seen onboard at the time of the inspection and, if so, was it free of any areas for concern?",
        "short_text": "Hull aft end starboard side",
        "vessel_types": [
          "Oil",
          "Chemical",
          "LPG",
          "LNG"
        ],
        "objective": "",
        "negative_grounds": [],
        "evidence": [],
        "risk": "low",
        "status": "not_started"
      },
      {
        "id": "11.1.5",
        "number": "11.1.5",
        "chapter": "11",
        "section": "11.1",
        "text": "Was photograph no.5, hull aft end port side, representative of the condition as seen onboard at the time of the inspection and, if so, was it free of any areas for concern?",
        "short_text": "Hull aft end port side",
        "vessel_types": [
          "Oil",
          "Chemical",
          "LPG",
          "LNG"
        ],
        "objective": "",
        "negative_grounds": [],
        "evidence": [],
        "risk": "low",
        "status": "not_started"
      },
      {
        "id": "11.1.6",
        "number": "11.1.6",
        "chapter": "11",
        "section": "11.1",
        "text": "Was photograph no.6, transom from right astern, representative of the condition as seen onboard at the time of the inspection and, if so, was it free of any areas for concern?",
        "short_text": "Transom from right astern",
        "vessel_types": [
          "Oil",
          "Chemical",
          "LPG",
          "LNG"
        ],
        "objective": "",
        "negative_grounds": [],
        "evidence": [],
        "risk": "low",
        "status": "not_started"
      },
      {
        "id": "11.1.7",
        "number": "11.1.7",
        "chapter": "11",
        "section": "11.1",
        "text": "Was photograph no.7, forecastle port side looking towards fairleads, representative of the condition as seen onboard at the time of the inspection and, if so, was it free of any areas for concern?",
        "short_text": "Forecastle port side looking towards fairleads",
        "vessel_types": [
          "Oil",
          "Chemical",
          "LPG",
          "LNG"
        ],
        "objective": "",
        "negative_grounds": [],
        "evidence": [],
        "risk": "low",
        "status": "not_started"
      },
      {
        "id": "11.1.8",
        "number": "11.1.8",
        "chapter": "11",
        "section": "11.1",
        "text": "Was photograph no.8, forecastle starboard side looking towards fairleads, representative of the condition as seen onboard at the time of the inspection and, if so, was it free of any areas for concern?",
        "short_text": "Forecastle starboard side looking towards fairleads",
        "vessel_types": [
          "Oil",
          "Chemical",
          "LPG",
          "LNG"
        ],
        "objective": "",
        "negative_grounds": [],
        "evidence": [],
        "risk": "low",
        "status": "not_started"
      },
      {
        "id": "11.1.9",
        "number": "11.1.9",
        "chapter": "11",
        "section": "11.1",
        "text": "Was photograph no.9, port or starboard windlass, representative of the condition as seen onboard at the time of the inspection and, if so, was it free of any areas for concern?",
        "short_text": "Port or starboard windlass",
        "vessel_types": [
          "Oil",
          "Chemical",
          "LPG",
          "LNG"
        ],
        "objective": "",
        "negative_grounds": [],
        "evidence": [],
        "risk": "low",
        "status": "not_started"
      },
      {
        "id": "11.1.10",
        "number": "11.1.10",
        "chapter": "11",
        "section": "11.1",
        "text": "Was photograph no.10, forward main deck showing condition of deck (and external framing), representative of the condition as seen onboard at the time of the inspection and, if so, was it free of any areas for concern?",
        "short_text": "Forward main deck showing condition of deck (and external framing)",
        "vessel_types": [
          "Oil",
          "Chemical",
          "LPG",
          "LNG"
        ],
        "objective": "",
        "negative_grounds": [],
        "evidence": [],
        "risk": "low",
        "status": "not_started"
      },
      {
        "id": "11.1.11",
        "number": "11.1.11",
        "chapter": "11",
        "section": "11.1",
        "text": "Was photograph no.11, Forward main deck showing condition of piperack, representative of the condition as seen onboard at the time of the inspection and, if so, was it free of any areas for concern?",
        "short_text": "Forward main deck showing condition of Piperack",
        "vessel_types": [
          "Oil",
          "Chemical",
          "LPG",
          "LNG"
        ],
        "objective": "",
        "negative_grounds": [],
        "evidence": [],
        "risk": "low",
        "status": "not_started"
      },
      {
        "id": "11.1.12",
        "number": "11.1.12",
        "chapter": "11",
        "section": "11.1",
        "text": "Was photograph no.12, one mooring winch including the brake setting arrangement, representative of the condition as seen onboard at the time of the inspection and, if so, was it free of any areas for concern?",
        "short_text": "One mooring winch including the brake setting arrangement",
        "vessel_types": [
          "Oil",
          "Chemical",
          "LPG",
          "LNG"
        ],
        "objective": "",
        "negative_grounds": [],
        "evidence": [],
        "risk": "low",
        "status": "not_started"
      },
      {
        "id": "11.1.13",
        "number": "11.1.13",
        "chapter": "11",
        "section": "11.1",
        "text": "Was photograph no.13, one hose crane with an overall view, representative of the condition as seen onboard at the time of the inspection and, if so, was it free of any areas for concern?",
        "short_text": "One hose crane with an overall view",
        "vessel_types": [
          "Oil",
          "Chemical",
          "LPG",
          "LNG"
        ],
        "objective": "",
        "negative_grounds": [],
        "evidence": [],
        "risk": "low",
        "status": "not_started"
      },
      {
        "id": "11.1.14",
        "number": "11.1.14",
        "chapter": "11",
        "section": "11.1",
        "text": "Was photograph no.14, one hose crane hoisting winch, stowed wire and limit switches, representative of the condition as seen onboard at the time of the inspection and, if so, was it free of any areas for concern?",
        "short_text": "One hose crane hoisting winch, stowed wire and limit switches",
        "vessel_types": [
          "Oil",
          "Chemical",
          "LPG",
          "LNG"
        ],
        "objective": "",
        "negative_grounds": [],
        "evidence": [],
        "risk": "low",
        "status": "not_started"
      },
      {
        "id": "11.1.15",
        "number": "11.1.15",
        "chapter": "11",
        "section": "11.1",
        "text": "Was photograph no.15, starboard manifold looking from aft to forward, representative of the condition as seen onboard at the time of the inspection and, if so, was it free of any areas for concern?",
        "short_text": "Starboard manifold looking from aft to forward",
        "vessel_types": [
          "Oil",
          "Chemical",
          "LPG",
          "LNG"
        ],
        "objective": "",
        "negative_grounds": [],
        "evidence": [],
        "risk": "low",
        "status": "not_started"
      },
      {
        "id": "11.1.16",
        "number": "11.1.16",
        "chapter": "11",
        "section": "11.1",
        "text": "Was photograph no.16, starboard manifold looking forward to aft representative of the condition as seen onboard at the time of the inspection and, if so, was it free of any areas for concern?",
        "short_text": "Starboard manifold looking forward to aft",
        "vessel_types": [
          "Oil",
          "Chemical",
          "LPG",
          "LNG"
        ],
        "objective": "",
        "negative_grounds": [],
        "evidence": [],
        "risk": "low",
        "status": "not_started"
      },
      {
        "id": "11.1.17",
        "number": "11.1.17",
        "chapter": "11",
        "section": "11.1",
        "text": "Was photograph no.17, aft main deck showing condition of deck (and external framing), representative of the condition as seen onboard at the time of the inspection and, if so, was it free of any areas for concern?",
        "short_text": "Aft main deck showing condition of deck (and external framing)",
        "vessel_types": [
          "Oil",
          "Chemical",
          "LPG",
          "LNG"
        ],
        "objective": "",
        "negative_grounds": [],
        "evidence": [],
        "risk": "low",
        "status": "not_started"
      },
      {
        "id": "11.1.18",
        "number": "11.1.18",
        "chapter": "11",
        "section": "11.1",
        "text": "Was photograph no.18, aft main deck showing condition of Piperack, representative of the condition as seen onboard at the time of the inspection and, if so, was it free of any areas for concern?",
        "short_text": "Aft main deck showing condition of Piperack",
        "vessel_types": [
          "Oil",
          "Chemical",
          "LPG",
          "LNG"
        ],
        "objective": "",
        "negative_grounds": [],
        "evidence": [],
        "risk": "low",
        "status": "not_started"
      },
      {
        "id": "11.1.19",
        "number": "11.1.19",
        "chapter": "11",
        "section": "11.1",
        "text": "Was photograph no.19, poop deck looking from midships to starboard including fairleads, representative of the condition as seen onboard at the time of the inspection and, if so, was it free of any areas for concern?",
        "short_text": "Poop deck looking from midships to starboard including fairleads",
        "vessel_types": [
          "Oil",
          "Chemical",
          "LPG",
          "LNG"
        ],
        "objective": "",
        "negative_grounds": [],
        "evidence": [],
        "risk": "low",
        "status": "not_started"
      },
      {
        "id": "11.1.20",
        "number": "11.1.20",
        "chapter": "11",
        "section": "11.1",
        "text": "Was photograph no.20, aft emergency towing equipment storage arrangement, representative of the condition as seen onboard at the time of the inspection and, if so, was it free of any areas for concern?",
        "short_text": "Aft emergency towing equipment storage arrangement",
        "vessel_types": [
          "Oil",
          "Chemical",
          "LPG",
          "LNG"
        ],
        "objective": "",
        "negative_grounds": [],
        "evidence": [],
        "risk": "low",
        "status": "not_started"
      },
      {
        "id": "11.1.21",
        "number": "11.1.21",
        "chapter": "11",
        "section": "11.1",
        "text": "Was photograph no.21, aft emergency towing equipment deployment system, representative of the condition as seen onboard at the time of the inspection and, if so, was it free of any areas for concern?",
        "short_text": "Aft emergency towing equipment deployment system",
        "vessel_types": [
          "Oil",
          "Chemical",
          "LPG",
          "LNG"
        ],
        "objective": "",
        "negative_grounds": [],
        "evidence": [],
        "risk": "low",
        "status": "not_started"
      },
      {
        "id": "11.1.22",
        "number": "11.1.22",
        "chapter": "11",
        "section": "11.1",
        "text": "Was photograph no.22, lifeboat and davit, representative of the condition as seen onboard at the time of the inspection and, if so, was it free of any areas for concern?",
        "short_text": "Lifeboat and davit",
        "vessel_types": [
          "Oil",
          "Chemical",
          "LPG",
          "LNG"
        ],
        "objective": "",
        "negative_grounds": [],
        "evidence": [],
        "risk": "low",
        "status": "not_started"
      },
      {
        "id": "11.1.23",
        "number": "11.1.23",
        "chapter": "11",
        "section": "11.1",
        "text": "Was photograph no.23, the emergency generator or accumulator batteries, representative of the condition as seen onboard at the time of the inspection and, if so, was it free of any areas for concern?",
        "short_text": "The emergency generator or accumulator batteries",
        "vessel_types": [
          "Oil",
          "Chemical",
          "LPG",
          "LNG"
        ],
        "objective": "",
        "negative_grounds": [],
        "evidence": [],
        "risk": "low",
        "status": "not_started"
      },
      {
        "id": "11.1.24",
        "number": "11.1.24",
        "chapter": "11",
        "section": "11.1",
        "text": "Was photograph no.24, engine room general view showing top of main engine, representative of the condition as seen onboard at the time of the inspection and, if so, was it free of any areas for concern?",
        "short_text": "Engine room general view showing top of main engine",
        "vessel_types": [
          "Oil",
          "Chemical",
          "LPG",
          "LNG"
        ],
        "objective": "",
        "negative_grounds": [],
        "evidence": [],
        "risk": "low",
        "status": "not_started"
      },
      {
        "id": "11.1.25",
        "number": "11.1.25",
        "chapter": "11",
        "section": "11.1",
        "text": "Was photograph no.25, one generator engine, representative of the condition as seen onboard at the time of the inspection and, if so, was it free of any areas for concern?",
        "short_text": "One generator engine",
        "vessel_types": [
          "Oil",
          "Chemical",
          "LPG",
          "LNG"
        ],
        "objective": "",
        "negative_grounds": [],
        "evidence": [],
        "risk": "low",
        "status": "not_started"
      },
      {
        "id": "11.1.26",
        "number": "11.1.26",
        "chapter": "11",
        "section": "11.1",
        "text": "Was photograph no.26, the oil filtering equipment, representative of the condition as seen onboard at the time of the inspection and, if so, was it free of any areas for concern?",
        "short_text": "The oil filtering equipment",
        "vessel_types": [
          "Oil",
          "Chemical",
          "LPG",
          "LNG"
        ],
        "objective": "",
        "negative_grounds": [],
        "evidence": [],
        "risk": "low",
        "status": "not_started"
      },
      {
        "id": "11.1.27",
        "number": "11.1.27",
        "chapter": "11",
        "section": "11.1",
        "text": "Was photograph no.27, the incinerator, representative of the condition as seen onboard at the time of the inspection and, if so, was it free of any areas for concern?",
        "short_text": "The incinerator",
        "vessel_types": [
          "Oil",
          "Chemical",
          "LPG",
          "LNG"
        ],
        "objective": "",
        "negative_grounds": [],
        "evidence": [],
        "risk": "low",
        "status": "not_started"
      },
      {
        "id": "11.1.28",
        "number": "11.1.28",
        "chapter": "11",
        "section": "11.1",
        "text": "Was photograph no.28, one boiler from the front, representative of the condition as seen onboard at the time of the inspection and, if so, was it free of any areas for concern?",
        "short_text": "One boiler from the front",
        "vessel_types": [
          "Oil",
          "Chemical",
          "LPG",
          "LNG"
        ],
        "objective": "",
        "negative_grounds": [],
        "evidence": [],
        "risk": "low",
        "status": "not_started"
      },
      {
        "id": "11.1.29",
        "number": "11.1.29",
        "chapter": "11",
        "section": "11.1",
        "text": "Was photograph no.29, one boiler from the top showing control equipment, representative of the condition as seen onboard at the time of the inspection and, if so, was it free of any areas for concern?",
        "short_text": "One boiler from the top showing control equipment",
        "vessel_types": [
          "Oil",
          "Chemical",
          "LPG",
          "LNG"
        ],
        "objective": "",
        "negative_grounds": [],
        "evidence": [],
        "risk": "low",
        "status": "not_started"
      },
      {
        "id": "11.1.30",
        "number": "11.1.30",
        "chapter": "11",
        "section": "11.1",
        "text": "Was photograph no.30, purifier room general view, representative of the condition as seen onboard at the time of the inspection and, if so, was it free of any areas for concern?",
        "short_text": "Purifier room general view",
        "vessel_types": [
          "Oil",
          "Chemical",
          "LPG",
          "LNG"
        ],
        "objective": "",
        "negative_grounds": [],
        "evidence": [],
        "risk": "low",
        "status": "not_started"
      },
      {
        "id": "11.1.31",
        "number": "11.1.31",
        "chapter": "11",
        "section": "11.1",
        "text": "Was photograph no.31, main engine side showing local control station, representative of the condition as seen onboard at the time of the inspection and, if so, was it free of any areas for concern?",
        "short_text": "Main engine side showing local control station",
        "vessel_types": [
          "Oil",
          "Chemical",
          "LPG",
          "LNG"
        ],
        "objective": "",
        "negative_grounds": [],
        "evidence": [],
        "risk": "low",
        "status": "not_started"
      },
      {
        "id": "11.1.32",
        "number": "11.1.32",
        "chapter": "11",
        "section": "11.1",
        "text": "Was photograph no.32, steering gear room general view showing access, representative of the condition as seen onboard at the time of the inspection and, if so, was it free of any areas for concern?",
        "short_text": "Steering gear room general view showing access",
        "vessel_types": [
          "Oil",
          "Chemical",
          "LPG",
          "LNG"
        ],
        "objective": "",
        "negative_grounds": [],
        "evidence": [],
        "risk": "low",
        "status": "not_started"
      },
      {
        "id": "11.1.33",
        "number": "11.1.33",
        "chapter": "11",
        "section": "11.1",
        "text": "Was photograph no.33, main steering gear, representative of the condition as seen onboard at the time of the inspection and, if so, was it free of any areas for concern?",
        "short_text": "Main steering gear",
        "vessel_types": [
          "Oil",
          "Chemical",
          "LPG",
          "LNG"
        ],
        "objective": "",
        "negative_grounds": [],
        "evidence": [],
        "risk": "low",
        "status": "not_started"
      },
      {
        "id": "11.1.40",
        "number": "11.1.40",
        "chapter": "11",
        "section": "11.1",
        "text": "Was photograph no.40, IG system pressure/vacuum-breaking (P/V) device, representative of the condition as seen onboard at the time of the inspection and, if so, was it free of any areas for concern?",
        "short_text": "IG system pressure/vacuum-breaking (P/V) device",
        "vessel_types": [
          "Oil",
          "Chemical"
        ],
        "objective": "",
        "negative_grounds": [],
        "evidence": [],
        "risk": "low",
        "status": "not_started"
      },
      {
        "id": "11.1.41",
        "number": "11.1.41",
        "chapter": "11",
        "section": "11.1",
        "text": "Was photograph no.41, IG system first non-return device (deck seal or double block and bleed arrangement), representative of the condition as seen onboard at the time of the inspection and, if so, was it free of any areas for concern?",
        "short_text": "IG system first non-return device (deck seal or double block and bleed arrangement)",
        "vessel_types": [
          "Oil",
          "Chemical"
        ],
        "objective": "",
        "negative_grounds": [],
        "evidence": [],
        "risk": "low",
        "status": "not_started"
      },
      {
        "id": "11.1.42",
        "number": "11.1.42",
        "chapter": "11",
        "section": "11.1",
        "text": "Was photograph no.42, one main cargo pump and, if in pump room, including bilges, representative of the condition as seen onboard at the time of the inspection and, if so, was it free of any areas for concern?",
        "short_text": "One main cargo pump and, if in pump room, including bilges",
        "vessel_types": [
          "Oil",
          "Chemical"
        ],
        "objective": "",
        "negative_grounds": [],
        "evidence": [],
        "risk": "low",
        "status": "not_started"
      },
      {
        "id": "11.1.50",
        "number": "11.1.50",
        "chapter": "11",
        "section": "11.1",
        "text": "Was photograph no.50, a cargo tank liquid dome including load and discharge valve, representative of the condition as seen onboard at the time of the inspection and, if so, was it free of any areas for concern?",
        "short_text": "A cargo tank liquid dome including load and discharge valve",
        "vessel_types": [
          "LPG"
        ],
        "objective": "",
        "negative_grounds": [],
        "evidence": [],
        "risk": "low",
        "status": "not_started"
      },
      {
        "id": "11.1.51",
        "number": "11.1.51",
        "chapter": "11",
        "section": "11.1",
        "text": "Was photograph no.51, electric motors for deepwell pumps, representative of the condition as seen onboard at the time of the inspection and, if so, was it free of any areas for concern?",
        "short_text": "Electric motors for deepwell pumps",
        "vessel_types": [
          "LPG"
        ],
        "objective": "",
        "negative_grounds": [],
        "evidence": [],
        "risk": "low",
        "status": "not_started"
      },
      {
        "id": "11.1.52",
        "number": "11.1.52",
        "chapter": "11",
        "section": "11.1",
        "text": "Was photograph no.52, compressor / motor room, representative of the condition as seen onboard at the time of the inspection and, if so, was it free of any areas for concern?",
        "short_text": "Compressor / motor room",
        "vessel_types": [
          "LPG"
        ],
        "objective": "",
        "negative_grounds": [],
        "evidence": [],
        "risk": "low",
        "status": "not_started"
      },
      {
        "id": "11.1.60",
        "number": "11.1.60",
        "chapter": "11",
        "section": "11.1",
        "text": "Was photograph no.60, a cargo tank liquid dome including load and discharge valve, representative of the condition as seen onboard at the time of the inspection and, if so, was it free of any areas for concern?",
        "short_text": "A cargo tank liquid dome including load and discharge valve",
        "vessel_types": [
          "LPG"
        ],
        "objective": "",
        "negative_grounds": [],
        "evidence": [],
        "risk": "low",
        "status": "not_started"
      },
      {
        "id": "11.1.61",
        "number": "11.1.61",
        "chapter": "11",
        "section": "11.1",
        "text": "Was photograph no.61, electric motors for deepwell pumps, representative of the condition as seen onboard at the time of the inspection and, if so, was it free of any areas for concern?",
        "short_text": "Electric motors for deepwell pumps",
        "vessel_types": [
          "LPG"
        ],
        "objective": "",
        "negative_grounds": [],
        "evidence": [],
        "risk": "low",
        "status": "not_started"
      },
      {
        "id": "11.1.62",
        "number": "11.1.62",
        "chapter": "11",
        "section": "11.1",
        "text": "Was photograph no.62, compressor room internal view, representative of the condition as seen onboard at the time of the inspection and, if so, was it free of any areas for concern?",
        "short_text": "Compressor room internal view",
        "vessel_types": [
          "LPG"
        ],
        "objective": "",
        "negative_grounds": [],
        "evidence": [],
        "risk": "low",
        "status": "not_started"
      },
      {
        "id": "11.1.70",
        "number": "11.1.70",
        "chapter": "11",
        "section": "11.1",
        "text": "Was photograph no.70, a cargo tank liquid dome including load and discharge valve, representative of the condition as seen onboard at the time of the inspection and, if so, was it free of any areas for concern?",
        "short_text": "A cargo tank liquid dome including load and discharge valve",
        "vessel_types": [
          "LNG"
        ],
        "objective": "",
        "negative_grounds": [],
        "evidence": [],
        "risk": "low",
        "status": "not_started"
      },
      {
        "id": "11.1.71",
        "number": "11.1.71",
        "chapter": "11",
        "section": "11.1",
        "text": "Was photograph no.71, a cargo tank vapour dome including cargo system relief valves, representative of the condition as seen onboard at the time of the inspection and, if so, was it free of any areas for concern?",
        "short_text": "A cargo tank vapour dome including cargo system relief valves",
        "vessel_types": [
          "LNG"
        ],
        "objective": "",
        "negative_grounds": [],
        "evidence": [],
        "risk": "low",
        "status": "not_started"
      },
      {
        "id": "11.1.72",
        "number": "11.1.72",
        "chapter": "11",
        "section": "11.1",
        "text": "Was photograph no.72, compressor house internal view, representative of the condition as seen onboard at the time of the inspection and, if so, was it free of any areas for concern?",
        "short_text": "Compressor house internal view",
        "vessel_types": [
          "LNG"
        ],
        "objective": "",
        "negative_grounds": [],
        "evidence": [],
        "risk": "low",
        "status": "not_started"
      },
      {
        "id": "11.1.80",
        "number": "11.1.80",
        "chapter": "11",
        "section": "11.1",
        "text": "Was photograph no.80, a cargo tank liquid dome including load and discharge valve, representative of the condition as seen onboard at the time of the inspection and, if so, was it free of any areas for concern?",
        "short_text": "A cargo tank liquid dome including load and discharge valve",
        "vessel_types": [
          "LNG"
        ],
        "objective": "",
        "negative_grounds": [],
        "evidence": [],
        "risk": "low",
        "status": "not_started"
      },
      {
        "id": "11.1.81",
        "number": "11.1.81",
        "chapter": "11",
        "section": "11.1",
        "text": "Was photograph no.81, general view of one Moss sphere, representative of the condition as seen onboard at the time of the inspection and, if so, was it free of any areas for concern?",
        "short_text": "General view of one moss sphere",
        "vessel_types": [
          "LNG"
        ],
        "objective": "",
        "negative_grounds": [],
        "evidence": [],
        "risk": "low",
        "status": "not_started"
      },
      {
        "id": "11.1.82",
        "number": "11.1.82",
        "chapter": "11",
        "section": "11.1",
        "text": "Was photograph no.82, compressor house internal view, representative of the condition as seen onboard at the time of the inspection and, if so, was it free of any areas for concern?",
        "short_text": "Compressor house internal view",
        "vessel_types": [
          "LNG"
        ],
        "objective": "",
        "negative_grounds": [],
        "evidence": [],
        "risk": "low",
        "status": "not_started"
      },
      {
        "id": "11.1.90",
        "number": "11.1.90",
        "chapter": "11",
        "section": "11.1",
        "text": "Was photograph no.90, bow mooring arrangement from forward looking aft showing chain stopper, representative of the condition as seen onboard at the time of the inspection and, if so, was it free of any areas for concern?",
        "short_text": "Bow mooring arrangement from forward looking aft showing chain stopper",
        "vessel_types": [
          "Oil"
        ],
        "objective": "",
        "negative_grounds": [],
        "evidence": [],
        "risk": "low",
        "status": "not_started"
      },
      {
        "id": "11.1.91",
        "number": "11.1.91",
        "chapter": "11",
        "section": "11.1",
        "text": "Was photograph no.91, bow mooring arrangement from aft looking forward showing winch, representative of the condition as seen onboard at the time of the inspection and, if so, was it free of any areas for concern?",
        "short_text": "Bow mooring arrangement from aft looking forward showing winch",
        "vessel_types": [
          "Oil"
        ],
        "objective": "",
        "negative_grounds": [],
        "evidence": [],
        "risk": "low",
        "status": "not_started"
      },
      {
        "id": "11.1.92",
        "number": "11.1.92",
        "chapter": "11",
        "section": "11.1",
        "text": "Was photograph no.92, general view of hose connection area, representative of the condition as seen onboard at the time of the inspection and, if so, was it free of any areas for concern?",
        "short_text": "General view of hose connection area",
        "vessel_types": [
          "Oil"
        ],
        "objective": "",
        "negative_grounds": [],
        "evidence": [],
        "risk": "low",
        "status": "not_started"
      },
      {
        "id": "11.1.93",
        "number": "11.1.93",
        "chapter": "11",
        "section": "11.1",
        "text": "Was photograph no.93, hose coupling arrangement, representative of the condition as seen onboard at the time of the inspection and, if so, was it free of any areas for concern?",
        "short_text": "Hose coupling arrangement",
        "vessel_types": [
          "Oil"
        ],
        "objective": "",
        "negative_grounds": [],
        "evidence": [],
        "risk": "low",
        "status": "not_started"
      },
      {
        "id": "11.1.94",
        "number": "11.1.94",
        "chapter": "11",
        "section": "11.1",
        "text": "Was photograph no.94, general view forward bow thruster room, representative of the condition as seen onboard at the time of the inspection and, if so, was it free of any areas for concern?",
        "short_text": "General view forward bow thruster room",
        "vessel_types": [
          "Oil"
        ],
        "objective": "",
        "negative_grounds": [],
        "evidence": [],
        "risk": "low",
        "status": "not_started"
      },
      {
        "id": "11.1.95",
        "number": "11.1.95",
        "chapter": "11",
        "section": "11.1",
        "text": "Was photograph no.95, forward bow thruster room showing one azimuth thruster, representative of the condition as seen onboard at the time of the inspection and, if so, was it free of any areas for concern?",
        "short_text": "Forward bow thruster room showing one azimuth thruster",
        "vessel_types": [
          "Oil"
        ],
        "objective": "",
        "negative_grounds": [],
        "evidence": [],
        "risk": "low",
        "status": "not_started"
      }
    ]
  },
  {
    "id": "C12",
    "title": "Ice Operations",
    "roles": [
      "Master",
      "Officers"
    ],
    "questions": [
      {
        "id": "12.1.4",
        "number": "12.1.4",
        "chapter": "12",
        "section": "12.1",
        "text": "",
        "short_text": "",
        "vessel_types": [],
        "objective": "",
        "negative_grounds": [
          "There was no company procedure which required that safety inspections of the cargo machinery rooms be",
          "conducted at appropriate intervals by the designated Safety Officer to identify hazards and potential hazards",
          "to health, safety and the environment.",
          "Records of safety inspections of the cargo machinery rooms were missing or incomplete.",
          "There was no checklist(s) provided to facilitate the safety inspections of the cargo machinery rooms.",
          "The accompanying officer was unfamiliar with the company procedure which required that safety inspections",
          "f the cargo machinery rooms were conducted at appropriate intervals by the designated Safety Officer.",
          "The accompanying officer was unfamiliar with any of the checks required to be conducted in accordance"
        ],
        "evidence": [
          "The company procedure which required that safety inspections of the cargo machinery rooms be conducted",
          "at appropriate intervals by the designated Safety Officer to identify hazards and potential hazards to health,",
          "safety and the environment.",
          "Records of safety inspections of the cargo machinery rooms including associated checklists.",
          "Records of regular testing of cargo machinery room air-lock audible and visual alarms and shut-down"
        ],
        "risk": "medium",
        "status": "not_started"
      },
      {
        "id": "12.1.1",
        "number": "12.1.1",
        "chapter": "12",
        "section": "12.1",
        "text": "Where the vessel traded in polar waters, had the Master, Chief Mate and officers in charge of a navigational watch undertaken the additional training required by the Polar Code?",
        "short_text": "Polar Code training",
        "vessel_types": [
          "Oil",
          "Chemical",
          "LPG",
          "LNG"
        ],
        "objective": "To ensure that ships operating in polar waters are appropriately manned by adequately qualified, trained and\nexperienced personnel.\nIndustry Guidelines\nOCIMF: Guidelines for the Development of a Polar Water Operational Manual.\nSection 2.1.6 Human Resources Management.\nGuidance: The PWOM should provide guidance for the human resources management, taking into account the\nanticipated ice conditions and requirements for ice navigation, increased levels of watchkeeping, hours of rest, fatigue\nand a p",
        "negative_grounds": [
          "The Polar Water Operational Manual did not define what additional training the Master, Chief Mate and",
          "fficers of the navigational watch must have to comply with the company Ice Navigator policy and the",
          "Certificate for Ships Operating in Polar Waters.",
          "Where the Master and/or Chief Mate were not substituted they were not in possession of a certificate of",
          "Advanced Training for Ships Operating in Polar Waters (unless the vessel was operating in open waters",
          "Where the Master and/or Chief Mate were not required to have Advanced Training for Ships Operating in",
          "Polar Waters, due to substitution or exclusively open water operations, the Master and/or Chief Mate did not",
          "have a certificate for Basic Training for Ships Operating in Polar Waters."
        ],
        "evidence": [
          "The vessel’s Polar Water Operational Manual.",
          "The training certificates for ships operating in polar waters for the Master, Chief Mate and officers in charge",
          "of a navigational watch.",
          "A copy of the certificate of competency and advanced training for the person(s) who had substituted for the",
          "Master and/or Chief Mate in the role of ice navigator."
        ],
        "risk": "medium",
        "status": "not_started"
      },
      {
        "id": "12.2.1",
        "number": "12.2.1",
        "chapter": "12",
        "section": "12.2",
        "text": "Were the Master and officers familiar with the company procedures to ensure the operability of the life-saving and fire-fighting systems and equipment in sub-zero temperatures, and had these procedures been complied with?",
        "short_text": "Life-saving and fire-fighting systems and equipment in sub-zero temperatures",
        "vessel_types": [
          "Oil",
          "Chemical",
          "LPG",
          "LNG"
        ],
        "objective": "To ensure the continuing operability of life-saving and fire-fighting equipment when operating in sub-zero\ntemperatures.",
        "negative_grounds": [
          "There were no company procedures to ensure that life-saving and fire-fighting systems and equipment",
          "remain operable in sub-zero temperatures.",
          "The accompanying officer was not familiar with the company procedures to ensure that life-saving and fire-",
          "fighting systems and equipment remain operable in sub-zero temperatures.",
          "The accompanying officer could not identify the locations of the drain points for the deck fire and/or foam",
          "There were no winterisation checklists available for use.",
          "There were no measures to ensure the operability of eye wash stations and de-contamination showers",
          "during freezing temperatures."
        ],
        "evidence": [
          "Company procedures to ensure that life-saving and fire-fighting systems and equipment remain operable in",
          "sub-zero temperatures.",
          "Winterisation checklists.",
          "Records of periodic inspections of safety-related systems during exposure to sub-zero temperatures."
        ],
        "risk": "high",
        "status": "not_started"
      },
      {
        "id": "12.3.1",
        "number": "12.3.1",
        "chapter": "12",
        "section": "12.3",
        "text": "Were the Master and officers familiar with the company procedures to ensure the operability of the engine room machinery and systems in sub-zero temperatures, and had these procedures been complied with?",
        "short_text": "Engine room machinery and systems in sub-zero temperatures",
        "vessel_types": [
          "Oil",
          "Chemical",
          "LPG",
          "LNG"
        ],
        "objective": "To ensure the continuing operability of the engine room machinery and systems when operating in sub-zero\ntemperatures.",
        "negative_grounds": [
          "There were no company procedures to ensure that engine room machinery and systems remain operable in",
          "sub-zero temperatures.",
          "The accompanying officer was not familiar with the company procedures to ensure that engine room",
          "machinery and systems remain operable in sub-zero temperatures.",
          "There were no winterisation checklists available for use.",
          "Company procedures to ensure that engine room machinery and systems remain operable in sub-zero",
          "temperatures had not been complied with, which may include:",
          "Prior to entering an area of low temperatures, failing to check, where applicable:"
        ],
        "evidence": [
          "Company procedures to ensure that engine room machinery and systems remain operable in sub-zero",
          "temperatures.",
          "Winterisation checklists."
        ],
        "risk": "high",
        "status": "not_started"
      },
      {
        "id": "12.4.1",
        "number": "12.4.1",
        "chapter": "12",
        "section": "12.4",
        "text": "Were the Master and officers familiar with the company procedures to ensure the operability of the cargo and ballast systems in sub-zero temperatures, and had these procedures been complied with?",
        "short_text": "Cargo and ballast systems in sub-zero temperatures",
        "vessel_types": [
          "Oil",
          "Chemical",
          "LPG",
          "LNG"
        ],
        "objective": "To ensure the continuing operability of the cargo and ballast systems when operating in sub-zero\ntemperatures.",
        "negative_grounds": [
          "There were no company procedures to ensure that cargo and ballast systems remain operable in sub-zero",
          "The accompanying officer was not familiar with the company procedures to ensure that cargo and ballast",
          "systems remain operable in sub-zero temperatures.",
          "There were no winterisation checklists available for use.",
          "Company procedures to ensure that cargo and ballast systems remain operable in sub-zero temperatures",
          "had not been complied with, which may include failing to:",
          "Test the integrity of deck lines prior to use to ensure they are tight.",
          "Check ballast water salinity and exchange if necessary."
        ],
        "evidence": [
          "Company procedures to ensure that cargo and ballast systems remain operable in sub-zero temperatures.",
          "Winterisation checklists.",
          "Records of equipment tests and checks prior to, during and on completion of cargo operations."
        ],
        "risk": "medium",
        "status": "not_started"
      },
      {
        "id": "12.5.1",
        "number": "12.5.1",
        "chapter": "12",
        "section": "12.5",
        "text": "Were the Master and officers familiar with the company procedures to ensure the operability of the deck machinery, including mooring systems, in sub-zero temperatures, and had these procedures been complied with?",
        "short_text": "Deck machinery and mooring equipment in sub-zero temperatures",
        "vessel_types": [
          "Oil",
          "Chemical",
          "LPG",
          "LNG"
        ],
        "objective": "To ensure the continuing operability of the deck machinery when operating in sub-zero temperatures.",
        "negative_grounds": [
          "There were no company procedures to ensure that deck machinery, including mooring systems, remains",
          "perable in sub-zero temperatures.",
          "The accompanying officer was not familiar with the company procedures to ensure that deck machinery,",
          "including mooring systems, remains operable in sub-zero temperatures.",
          "There were no winterisation checklists available for use.",
          "Periodic inspections of all deck machinery had not been undertaken during exposure to sub-zero",
          "temperatures to ensure the effectiveness of the precautions being taken.",
          "Company procedures to ensure that deck machinery, including mooring systems, remains operable in sub-"
        ],
        "evidence": [
          "Company procedures to ensure that deck machinery, including mooring systems, remains operable in sub-",
          "zero temperatures.",
          "Winterisation checklists.",
          "Records of periodic inspections of all deck machinery during exposure to sub-zero temperatures."
        ],
        "risk": "medium",
        "status": "not_started"
      },
      {
        "id": "12.6.1",
        "number": "12.6.1",
        "chapter": "12",
        "section": "12.6",
        "text": "Were the Master and officers familiar with the company procedures for navigating in areas affected by ice, and had they received suitable training?",
        "short_text": "Navigating in areas affected by ice",
        "vessel_types": [
          "Oil",
          "Chemical",
          "LPG",
          "LNG"
        ],
        "objective": "To ensure the Master and officers are prepared for navigating in areas affected by ice.",
        "negative_grounds": [],
        "evidence": [],
        "risk": "low",
        "status": "not_started"
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

    const prompt = `You are an expert maritime SIRE 2.0 inspection analyst. You have been given a SIRE 2.0 inspection report for vessel "${vessel.name}".

Extract ALL findings, observations, and deficiencies from this report.

SIRE 2.0 uses the following 12-chapter structure — use ONLY these chapter codes:
  C1  = Vessel, Operator and Inspection Particulars
  C2  = Certification and Documentation
  C3  = Crew Management
  C4  = Navigation
  C5  = Safety Management
  C6  = Pollution Prevention
  C7  = Maritime Security
  C8  = Cargo and Ballast Systems
  C9  = Mooring and Anchoring
  C10 = Machinery
  C11 = General Appearance and Condition (Photograph Comparison)
  C12 = Ice Operations

For each finding extract:
- The exact description of what was observed
- Which SIRE 2.0 chapter it falls under — use ONLY the codes above (C1–C12). Map by topic: certification/docs=C2, crew/training=C3, navigation/bridge=C4, safety/LSA/fire/drills=C5, pollution/MARPOL=C6, security/ISPS=C7, cargo/ballast/tanks=C8, mooring/anchoring=C9, machinery/engine=C10, condition/photographs=C11, ice=C12
- Question reference number if visible (e.g. 5.3.2)
- Severity: "obs" for observation/notable practice, "minor" for minor deficiency, "major" for major deficiency. Infer from labels like "Observable deficiency", "Not as expected" (obs/minor), "Deficiency" (minor/major)
- Inspector name and company if mentioned separately
- Inspection date if mentioned
- Any corrective action mentioned

If any information is missing or unclear, note it as null — do NOT guess.

Return ONLY valid JSON in this exact format:
{
  "inspection_date": "YYYY-MM-DD or null",
  "inspector": "name or null",
  "inspecting_company": "company name or null",
  "vessel_name": "vessel name from report or null",
  "total_findings": 0,
  "findings": [
    {
      "chapter": "C5",
      "severity": "obs|minor|major",
      "description": "exact finding description",
      "corrective_action": "recommended action or null",
      "question_ref": "e.g. 5.3.2 or null"
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
          const batchMatch = clean.match(/\{[\s\S]*\}/);
          if (!batchMatch) throw new Error('No JSON in AI response');
          const review = JSON.parse(batchMatch[0]);

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
    if (aiData.error) throw new Error(`AI API error: ${aiData.error.message || JSON.stringify(aiData.error)}`);
    const text = aiData.content?.[0]?.text;
    if (!text) throw new Error(`No response from AI — type: ${aiData.type || 'unknown'}, stop_reason: ${aiData.stop_reason || 'unknown'}`);
    const jsonMatch = text.match(/\{[\s\S]*\}/);
    if (!jsonMatch) throw new Error(`AI response did not contain valid JSON. Raw: ${text.substring(0, 200)}`);
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

// Delete a finding (admin only)
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
