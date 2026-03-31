// rag.js — FORCAP Oracle RAG Module
// Adds semantic vector search to MARIDE's manual repository.
// Connects to Railway PostgreSQL (pgvector) from Render.
//
// Required env vars:
//   RAILWAY_DATABASE_URL  — PostgreSQL connection string from Railway
//   OPENAI_API_KEY        — for text-embedding-3-small
//
// If either is missing, all functions no-op gracefully and the
// original keyword search falls back automatically.

'use strict';

const { Pool } = require('pg');

// ── Constants ────────────────────────────────────────────────────────────────
const EMBEDDING_MODEL = 'text-embedding-3-small';
const EMBEDDING_DIM   = 1536;
const CHUNK_SIZE      = 1800;   // chars ≈ 450 tokens
const CHUNK_OVERLAP   = 220;    // chars ≈ 55 tokens
const MIN_CHUNK       = 100;    // discard tiny orphans
const DEFAULT_TOP_K   = 6;
const EMBED_BATCH     = 100;    // OpenAI: max 2048, 100 is safe

// ── Pool ─────────────────────────────────────────────────────────────────────
let _pool = null;

function getPool() {
  if (_pool) return _pool;
  if (!process.env.RAILWAY_DATABASE_URL) return null;
  _pool = new Pool({
    connectionString: process.env.RAILWAY_DATABASE_URL,
    ssl: { rejectUnauthorized: false },
    max: 5,
    idleTimeoutMillis: 30000,
  });
  _pool.on('error', err => console.error('[RAG] Pool error:', err.message));
  return _pool;
}

function isEnabled() {
  return !!(process.env.RAILWAY_DATABASE_URL && process.env.OPENAI_API_KEY);
}

// ── Schema bootstrap ─────────────────────────────────────────────────────────
async function initSchema() {
  if (!isEnabled()) {
    console.log('[RAG] Disabled — set RAILWAY_DATABASE_URL + OPENAI_API_KEY to enable');
    return false;
  }
  const pool = getPool();
  try {
    await pool.query('CREATE EXTENSION IF NOT EXISTS vector');
    await pool.query('CREATE EXTENSION IF NOT EXISTS "uuid-ossp"');
    await pool.query('CREATE SCHEMA IF NOT EXISTS rag');

    await pool.query(`
      CREATE TABLE IF NOT EXISTS rag.manuals (
        id           TEXT PRIMARY KEY,
        filename     TEXT NOT NULL,
        vessel_id    TEXT,
        category     TEXT,
        equipment    TEXT,
        manufacturer TEXT,
        model        TEXT,
        summary      TEXT,
        chunk_count  INTEGER DEFAULT 0,
        indexed_at   TIMESTAMPTZ DEFAULT NOW()
      )
    `);

    await pool.query(`
      CREATE TABLE IF NOT EXISTS rag.chunks (
        id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        manual_id   TEXT NOT NULL REFERENCES rag.manuals(id) ON DELETE CASCADE,
        chunk_index INTEGER NOT NULL,
        content     TEXT NOT NULL,
        section     TEXT,
        embedding   VECTOR(${EMBEDDING_DIM}),
        created_at  TIMESTAMPTZ DEFAULT NOW()
      )
    `);

    await pool.query(`CREATE INDEX IF NOT EXISTS rag_chunks_manual_idx ON rag.chunks(manual_id)`);
    await pool.query(`
      CREATE INDEX IF NOT EXISTS rag_chunks_fts_idx
        ON rag.chunks USING gin(to_tsvector('english', content))
    `);
    // ivfflat requires ≥ lists*5 rows — silently ignored until then
    await pool.query(`
      CREATE INDEX IF NOT EXISTS rag_chunks_vec_idx
        ON rag.chunks USING ivfflat (embedding vector_cosine_ops) WITH (lists = 100)
    `).catch(() => {});

    console.log('[RAG] ✅ Schema ready on Railway PostgreSQL');
    return true;
  } catch (err) {
    console.error('[RAG] Schema init error:', err.message);
    return false;
  }
}

// ── Text cleaning & chunking ──────────────────────────────────────────────────
function isSectionHeading(text) {
  const t = text.trim();
  if (t.length > 120) return false;
  if (/^(chapter|section|part|appendix)\s+[\dA-Z]/i.test(t)) return true;
  if (/^\d+[\d.]*\s+[A-Z]/.test(t)) return true;
  if (t === t.toUpperCase() && /[A-Z]{3,}/.test(t) && t.length < 80) return true;
  return false;
}

function cleanText(raw) {
  return raw
    .replace(/\r\n/g, '\n').replace(/\r/g, '\n')
    .replace(/^\s*Page \d+ of \d+\s*$/gim, '')
    .replace(/^\s*\d+\s*$/gm, '')
    .replace(/-\n([a-z])/g, '$1')
    .replace(/\n{3,}/g, '\n\n')
    .replace(/[ \t]{2,}/g, ' ')
    .trim();
}

function chunkText(rawText) {
  const text     = cleanText(rawText);
  const paragraphs = text.split(/\n\n+/);
  const chunks   = [];
  let buffer     = '';
  let section    = 'General';
  let idx        = 0;

  const flush = buf => {
    const t = buf.trim();
    if (t.length >= MIN_CHUNK) chunks.push({ content: t, section, chunkIndex: idx++ });
  };

  for (const para of paragraphs) {
    const p = para.trim();
    if (!p) continue;
    if (isSectionHeading(p)) section = p.replace(/\s+/g, ' ').trim();

    if (buffer.length > 0 && buffer.length + p.length + 2 > CHUNK_SIZE) {
      flush(buffer);
      // overlap: carry last paragraph forward
      const prev    = buffer.split(/\n\n/);
      let overlap   = '';
      let ol        = 0;
      for (let i = prev.length - 1; i >= 0; i--) {
        if (ol + prev[i].length < CHUNK_OVERLAP) {
          overlap = prev[i] + (overlap ? '\n\n' + overlap : '');
          ol += prev[i].length;
        } else break;
      }
      buffer = overlap;
    }
    buffer = buffer ? buffer + '\n\n' + p : p;
  }
  flush(buffer);
  return chunks;
}

// ── Embedding (OpenAI via fetch — no SDK) ─────────────────────────────────────
async function embedBatch(texts) {
  const res = await fetch('https://api.openai.com/v1/embeddings', {
    method:  'POST',
    headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${process.env.OPENAI_API_KEY}` },
    body:    JSON.stringify({ model: EMBEDDING_MODEL, input: texts })
  });
  const data = await res.json();
  if (data.error) throw new Error('OpenAI embeddings: ' + data.error.message);
  return data.data.map(d => d.embedding);
}

// ── Index a manual ───────────────────────────────────────────────────────────
// manualRecord: the manual object from repo_db.json
// extractedText: the full text string from the sidecar .txt
async function indexManual(manualRecord, extractedText) {
  if (!isEnabled()) return { ok: false, reason: 'disabled' };
  const pool = getPool();
  if (!pool)  return { ok: false, reason: 'no_pool' };
  if (!extractedText || extractedText.trim().length < 50) return { ok: false, reason: 'no_text' };

  const { id, filename, vessel_id, category, equipment_name, maker, model, summary } = manualRecord;

  try {
    // Upsert manual metadata
    await pool.query(`
      INSERT INTO rag.manuals (id, filename, vessel_id, category, equipment, manufacturer, model, summary)
      VALUES ($1,$2,$3,$4,$5,$6,$7,$8)
      ON CONFLICT (id) DO UPDATE SET
        filename=EXCLUDED.filename, vessel_id=EXCLUDED.vessel_id,
        category=EXCLUDED.category, equipment=EXCLUDED.equipment,
        manufacturer=EXCLUDED.manufacturer, model=EXCLUDED.model,
        summary=EXCLUDED.summary, indexed_at=NOW()
    `, [id, filename, vessel_id||null, category||null, equipment_name||null, maker||null, model||null, summary||null]);

    // Clear old chunks
    await pool.query('DELETE FROM rag.chunks WHERE manual_id = $1', [id]);

    // Chunk
    const chunks = chunkText(extractedText);
    console.log(`[RAG] ${filename}: ${chunks.length} chunks to embed`);

    // Embed + store in batches
    for (let i = 0; i < chunks.length; i += EMBED_BATCH) {
      const batch = chunks.slice(i, i + EMBED_BATCH);
      const embs  = await embedBatch(batch.map(c => c.content));

      const client = await pool.connect();
      try {
        await client.query('BEGIN');
        for (let j = 0; j < batch.length; j++) {
          const c   = batch[j];
          const vec = `[${embs[j].join(',')}]`;
          await client.query(`
            INSERT INTO rag.chunks (manual_id, chunk_index, content, section, embedding)
            VALUES ($1,$2,$3,$4,$5::vector)
          `, [id, i + j, c.content, c.section||null, vec]);
        }
        await client.query('COMMIT');
      } catch (e) {
        await client.query('ROLLBACK');
        throw e;
      } finally {
        client.release();
      }
    }

    // Update chunk count
    await pool.query('UPDATE rag.manuals SET chunk_count=$1 WHERE id=$2', [chunks.length, id]);

    console.log(`[RAG] ✅ Indexed: ${filename} — ${chunks.length} chunks`);
    return { ok: true, chunks: chunks.length };
  } catch (err) {
    console.error('[RAG] Index error:', err.message);
    return { ok: false, reason: err.message };
  }
}

// ── Remove a manual's embeddings ─────────────────────────────────────────────
async function deleteManual(manualId) {
  if (!isEnabled()) return;
  const pool = getPool();
  if (!pool) return;
  try {
    await pool.query('DELETE FROM rag.manuals WHERE id = $1', [manualId]);
    console.log('[RAG] Deleted embeddings for manual:', manualId);
  } catch (e) {
    console.error('[RAG] Delete error:', e.message);
  }
}

// ── Semantic search ──────────────────────────────────────────────────────────
// Returns array of chunk rows, or null if RAG unavailable
async function search(question, filters = {}, topK = DEFAULT_TOP_K) {
  if (!isEnabled()) return null;
  const pool = getPool();
  if (!pool) return null;

  try {
    const [qVec]  = await embedBatch([question]);
    const vecStr  = `[${qVec.join(',')}]`;

    const conditions = ['1=1'];
    const params     = [vecStr, topK];
    let   p          = 3;

    if (filters.vessel_id && filters.vessel_id !== 'all') {
      conditions.push(`m.vessel_id = $${p++}`);
      params.push(filters.vessel_id);
    }
    if (filters.category && filters.category !== 'all') {
      conditions.push(`m.category = $${p++}`);
      params.push(filters.category);
    }
    if (filters.manual_id) {
      conditions.push(`m.id = $${p++}`);
      params.push(filters.manual_id);
    }

    const { rows } = await pool.query(`
      SELECT
        c.content,
        c.section,
        c.chunk_index,
        m.id          AS manual_id,
        m.filename,
        m.category,
        m.equipment,
        m.manufacturer,
        m.vessel_id,
        ROUND((1 - (c.embedding <=> $1::vector))::numeric, 3) AS similarity
      FROM rag.chunks  c
      JOIN rag.manuals m ON c.manual_id = m.id
      WHERE ${conditions.join(' AND ')}
      ORDER BY c.embedding <=> $1::vector
      LIMIT $2
    `, params);

    return rows.length ? rows : null;
  } catch (err) {
    console.error('[RAG] Search error:', err.message);
    return null;
  }
}

// ── Build context string from chunks (for Claude) ─────────────────────────────
function buildContext(chunks) {
  return chunks.map((c, i) => {
    const src = [
      c.filename,
      c.manufacturer ? `${c.manufacturer}${c.model ? ' ' + c.model : ''}` : null,
      c.vessel_id  ? `Vessel: ${c.vessel_id}` : 'Fleet-wide',
      c.section    ? `Section: ${c.section}` : null,
      `Relevance: ${c.similarity}`
    ].filter(Boolean).join(' | ');
    return `[REF ${i + 1} — ${src}]\n${c.content}`;
  }).join('\n\n' + '─'.repeat(60) + '\n\n');
}

// ── Status & stats ───────────────────────────────────────────────────────────
async function getStats() {
  if (!isEnabled()) return { enabled: false };
  const pool = getPool();
  if (!pool) return { enabled: false };
  try {
    const { rows } = await pool.query(`
      SELECT
        COUNT(DISTINCT m.id)::int AS manuals,
        COUNT(c.id)::int          AS chunks
      FROM rag.manuals m
      LEFT JOIN rag.chunks c ON c.manual_id = m.id
    `);
    return { enabled: true, ...rows[0] };
  } catch (e) {
    return { enabled: true, error: e.message };
  }
}

async function getChunkCount(manualId) {
  if (!isEnabled()) return null;
  const pool = getPool();
  if (!pool) return null;
  try {
    const { rows } = await pool.query(
      'SELECT chunk_count FROM rag.manuals WHERE id = $1', [manualId]
    );
    return rows[0]?.chunk_count ?? 0;
  } catch (e) { return null; }
}

module.exports = {
  initSchema,
  indexManual,
  deleteManual,
  search,
  buildContext,
  getStats,
  getChunkCount,
  isEnabled,
};
