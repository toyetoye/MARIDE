'use strict';
// db.js — MARIDE PostgreSQL adapter
// ─────────────────────────────────────────────────────────────────────────────
// Provides the SAME synchronous function signatures that server.js currently
// uses (readDB, writeDB, readCustDB, writeCustDB, etc.) but backs them with
// a Railway PostgreSQL database instead of flat JSON files.
//
// Pattern: in-memory cache + background sync to PostgreSQL every 3 seconds.
// This means zero changes required to any route handler in server.js.
//
// Startup: call await initMaRideDB() once before the server starts accepting
// requests. This loads all state from PostgreSQL into memory.
// ─────────────────────────────────────────────────────────────────────────────

const { Pool } = require('pg');

// ── Pool ──────────────────────────────────────────────────────────────────────
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.DATABASE_URL && process.env.DATABASE_URL.includes('railway.internal')
    ? false
    : { rejectUnauthorized: false },
  max: 5,
});
pool.on('error', err => console.error('[MARIDE DB] Pool error:', err.message));

// ── In-memory caches ──────────────────────────────────────────────────────────
let _main = null;  // { users, vessels, investigations, sessions }
let _cust = null;  // { equipment, defects, tempRepairs, pmLogs, alarmLogs, handovers, checklists, rounds }
let _sire = null;  // { preparations, findings, drillSessions, fleetFindings }
let _repo = null;  // { manuals }
let _pms  = null;  // { worksheets, running_hours, defects, assignments }

const _dirty  = { main: false, cust: false, sire: false, repo: false, pms: false };
let   _ready  = false;
let   _syncTimer = null;

// ── Default shapes ────────────────────────────────────────────────────────────
const DEFAULTS = {
  main: () => ({ users: [], vessels: [], investigations: [], sessions: [] }),
  cust: () => ({ equipment: [], defects: [], tempRepairs: [], pmLogs: [], alarmLogs: [], handovers: [], checklists: [], rounds: [] }),
  sire: () => ({ preparations: {}, findings: [], drillSessions: [], fleetFindings: [] }),
  repo: () => ({ manuals: [] }),
  pms:  () => ({ worksheets: [], running_hours: [], defects: [], assignments: [] }),
};

// ── Schema bootstrap ──────────────────────────────────────────────────────────
async function ensureSchema() {
  const c = await pool.connect();
  try {
    await c.query(`CREATE SCHEMA IF NOT EXISTS maride`);
    await c.query(`SET search_path TO maride`);
    await c.query(`
      CREATE TABLE IF NOT EXISTS state_store (
        key        TEXT PRIMARY KEY,
        data       JSONB NOT NULL DEFAULT '{}',
        updated_at TIMESTAMPTZ DEFAULT NOW()
      )
    `);
    // Seed missing keys with defaults
    for (const key of Object.keys(DEFAULTS)) {
      await c.query(`
        INSERT INTO state_store (key, data) VALUES ($1, $2::jsonb)
        ON CONFLICT (key) DO NOTHING
      `, [key, JSON.stringify(DEFAULTS[key]())]);
    }
    console.log('[MARIDE DB] Schema ready');
  } finally { c.release(); }
}

// ── PostgreSQL read/write ─────────────────────────────────────────────────────
async function pgRead(key) {
  const { rows } = await pool.query(
    `SELECT data FROM maride.state_store WHERE key = $1`, [key]
  );
  return rows.length ? rows[0].data : null;
}

async function pgWrite(key, data) {
  await pool.query(`
    INSERT INTO maride.state_store (key, data, updated_at)
    VALUES ($1, $2::jsonb, NOW())
    ON CONFLICT (key) DO UPDATE
      SET data = EXCLUDED.data, updated_at = NOW()
  `, [key, JSON.stringify(data)]);
}

// ── Background sync ───────────────────────────────────────────────────────────
async function syncDirty() {
  const writes = [];
  if (_dirty.main && _main) writes.push(pgWrite('main', _main).then(() => { _dirty.main = false; }));
  if (_dirty.cust && _cust) writes.push(pgWrite('cust', _cust).then(() => { _dirty.cust = false; }));
  if (_dirty.sire && _sire) writes.push(pgWrite('sire', _sire).then(() => { _dirty.sire = false; }));
  if (_dirty.repo && _repo) writes.push(pgWrite('repo', _repo).then(() => { _dirty.repo = false; }));
  if (_dirty.pms  && _pms)  writes.push(pgWrite('pms',  _pms).then(() => { _dirty.pms  = false; }));
  if (writes.length) {
    await Promise.all(writes);
    console.log(`[MARIDE DB] Synced ${writes.length} store(s) to PostgreSQL`);
  }
}

function startSyncTimer() {
  if (_syncTimer) return;
  _syncTimer = setInterval(() => {
    syncDirty().catch(e => console.error('[MARIDE DB] Sync error:', e.message));
  }, 3000);
  _syncTimer.unref(); // don't block process exit
}

// Flush on graceful shutdown
async function flushOnExit() {
  try { await syncDirty(); console.log('[MARIDE DB] Flushed on exit'); } catch (e) {}
  await pool.end().catch(() => {});
}
process.on('SIGTERM', () => flushOnExit().then(() => process.exit(0)));
process.on('SIGINT',  () => flushOnExit().then(() => process.exit(0)));

// ── Init — call once at server startup ───────────────────────────────────────
async function initMaRideDB() {
  if (_ready) return;
  await ensureSchema();

  // Load all stores from PostgreSQL
  const [main, cust, sire, repo, pms] = await Promise.all([
    pgRead('main'), pgRead('cust'), pgRead('sire'), pgRead('repo'), pgRead('pms'),
  ]);

  _main = main || DEFAULTS.main();
  _cust = cust || DEFAULTS.cust();
  _sire = sire || DEFAULTS.sire();
  _repo = repo || DEFAULTS.repo();
  _pms  = pms  || DEFAULTS.pms();

  // Ensure array fields exist (guard against schema drift)
  if (!_main.sessions)     _main.sessions     = [];
  if (!_cust.checklists)   _cust.checklists   = [];
  if (!_cust.rounds)       _cust.rounds       = [];
  if (!_sire.preparations) _sire.preparations = {};
  if (!_sire.findings)     _sire.findings     = [];

  _ready = true;
  startSyncTimer();

  const stats = {
    users:         _main.users.length,
    vessels:       _main.vessels.length,
    investigations:_main.investigations.length,
    equipment:     _cust.equipment.length,
    manuals:       _repo.manuals.length,
    findings:      _sire.findings.length,
  };
  console.log('[MARIDE DB] Loaded from PostgreSQL:', JSON.stringify(stats));
}

// ── Backward-compatible sync accessors ───────────────────────────────────────
// These are SYNCHRONOUS — exactly matching the original server.js signatures.

function readDB()    { return _main || DEFAULTS.main(); }
function writeDB(d)  { _main = d; _dirty.main = true; }

function readCustDB()   { return _cust || DEFAULTS.cust(); }
function writeCustDB(d) { _cust = d; _dirty.cust = true; }

function readSireDB()   { return _sire || DEFAULTS.sire(); }
function writeSireDB(d) { _sire = d; _dirty.sire = true; }

function readRepoDb()   { return _repo || DEFAULTS.repo(); }
function writeRepoDb(d) { _repo = d; _dirty.repo = true; }

function readPmsDb()    { return _pms || DEFAULTS.pms(); }
function savePmsDb(d)   { _pms = d; _dirty.pms = true; }

// ── Immediate write (for critical paths like approval emails) ─────────────────
async function flushNow() {
  await syncDirty();
}

// ── Health check for /health route ───────────────────────────────────────────
async function dbHealth() {
  try {
    await pool.query('SELECT 1');
    return {
      status: 'ok',
      ready: _ready,
      users:    _main?.users?.length ?? 0,
      vessels:  _main?.vessels?.length ?? 0,
      manuals:  _repo?.manuals?.length ?? 0,
      findings: _sire?.findings?.length ?? 0,
    };
  } catch (e) {
    return { status: 'error', message: e.message };
  }
}

module.exports = {
  // Init (call at startup)
  initMaRideDB,
  flushNow,
  dbHealth,
  // Main store
  readDB, writeDB,
  // Custodian store
  readCustDB, writeCustDB,
  // SIRE store
  readSireDB, writeSireDB,
  // Repository store
  readRepoDb, writeRepoDb,
  // PMS store
  readPmsDb, savePmsDb,
};
