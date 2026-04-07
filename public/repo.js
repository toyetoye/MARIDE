// repo.js — MARIDE Knowledge Repository Module
// Handles: vessel selector, manual cards, upload, Q&A (Oracle), service letters
// Loaded by index.html via <script src="repo.js"></script>

'use strict';

// ── State ─────────────────────────────────────────────────────────────────────
let repoVessels       = [];
let repoManuals       = [];
let repoSelectedVessel = null;
let repoSelectedCat   = 'all';
let repoSelectedFile  = null;

// ── Helpers (defined in index.html, available globally) ──────────────────────
// getToken(), getCurrentUser() — defined in index.html

const REPO_API = '';  // same origin

async function repoFetch(path, opts = {}) {
  const res = await fetch(REPO_API + path, {
    ...opts,
    headers: { 'x-auth-token': getToken(), 'Content-Type': 'application/json', ...(opts.headers || {}) }
  });
  return res;
}

// ── Init ──────────────────────────────────────────────────────────────────────
async function loadRepoVessels() {
  try {
    const res  = await repoFetch('/api/vessels');
    repoVessels = await res.json();
    repoRenderVesselSelector();
    repoRenderUploadBtn();
  } catch(e) {
    console.error('[Repo] loadRepoVessels:', e);
  }
}

// ── Vessel Selector ───────────────────────────────────────────────────────────
function repoRenderVesselSelector() {
  const el = document.getElementById('repoVesselSelector');
  if (!el) return;

  const currentVessel = repoSelectedVessel
    ? (repoVessels.find(v => v.id === repoSelectedVessel)?.name || 'Unknown')
    : 'All vessels';

  el.innerHTML = `
    <div style="position:relative;display:inline-block;">
      <select id="repoVesselDropdown"
        style="appearance:none;-webkit-appearance:none;background:var(--surface2,#1a1a1a);border:1px solid var(--border);border-radius:6px;color:var(--text);font-family:var(--mono);font-size:11px;padding:5px 32px 5px 10px;cursor:pointer;min-width:200px;"
        onchange="repoConfirmVesselChange(this.value)">
        <option value="">All vessels</option>
        ${repoVessels.map(v =>
          `<option value="${v.id}" ${repoSelectedVessel === v.id ? 'selected' : ''}>${v.name}</option>`
        ).join('')}
      </select>
      <span style="pointer-events:none;position:absolute;right:10px;top:50%;transform:translateY(-50%);font-size:10px;color:var(--text-dim);">▾</span>
    </div>`;
}

function repoConfirmVesselChange(vesselId) {
  const vesselName = vesselId
    ? (repoVessels.find(v => v.id === vesselId)?.name || 'Unknown')
    : 'All vessels';

  const confirmed = confirm('Switch to: ' + vesselName + '\n\nThis will load all manuals for this vessel.');
  if (!confirmed) {
    repoRenderVesselSelector();
    return;
  }
  repoSelectVessel(vesselId || null);
}

function repoSelectVessel(vesselId) {
  repoSelectedVessel = vesselId;
  repoSelectedCat    = 'all';
  repoRenderVesselSelector();
  repoRenderUploadBtn();
  repoLoadManuals();
}

// ── Upload Button (role-gated) ─────────────────────────────────────────────────
function repoRenderUploadBtn() {
  const el = document.getElementById('repoUploadBtn');
  if (!el) return;
  const user = getCurrentUser();
  if (!user) return;
  const canUpload = ['admin','superintendent','fleet_manager','deputy_fleet_manager','chief_engineer'].includes(user.role);
  if (!canUpload) { el.innerHTML = ''; return; }
  el.innerHTML = `<button class="btn-sm btn-sm-primary" onclick="openManualUpload()" style="font-size:10px;">
    ＋ UPLOAD MANUAL
  </button>`;
}

// ── Load Manuals ──────────────────────────────────────────────────────────────
async function repoLoadManuals() {
  const countEl = document.getElementById('repoSectionCount');
  const contentEl = document.getElementById('repoContent');
  if (countEl) countEl.textContent = 'Loading…';
  if (contentEl) contentEl.innerHTML = '<div style="font-family:var(--mono);font-size:10px;color:var(--text-dim);padding:20px;">Loading manuals…</div>';

  try {
    let url = '/api/repo/manuals';
    if (repoSelectedVessel) url += `?vessel_id=${repoSelectedVessel}`;
    const res = await repoFetch(url);
    repoManuals = await res.json();
    repoRenderCats();
    repoRender();
  } catch(e) {
    if (contentEl) contentEl.innerHTML = '<div style="font-family:var(--mono);font-size:10px;color:var(--red);padding:20px;">Failed to load manuals</div>';
  }
}

// ── Category Sidebar ──────────────────────────────────────────────────────────
function repoRenderCats() {
  const el = document.getElementById('repoCatList');
  if (!el) return;

  const cats = {};
  repoManuals.forEach(m => {
    if (m.superseded) return;
    const c = m.category || 'General';
    cats[c] = (cats[c] || 0) + 1;
  });

  const total = repoManuals.filter(m => !m.superseded).length;

  let html = `<div class="repo-cat-item ${repoSelectedCat === 'all' ? 'active' : ''}"
    onclick="repoSelectCat('all')"
    style="display:flex;justify-content:space-between;align-items:center;padding:7px 16px;cursor:pointer;font-size:12px;color:var(--text);">
    <span>All</span><span style="font-family:var(--mono);font-size:9px;color:var(--text-dim);">${total}</span>
  </div>`;

  Object.entries(cats).sort((a,b) => b[1]-a[1]).forEach(([cat, count]) => {
    const active = repoSelectedCat === cat;
    html += `<div class="repo-cat-item ${active ? 'active' : ''}"
      onclick="repoSelectCat('${cat.replace(/'/g,"\\'")}')"
      style="display:flex;justify-content:space-between;align-items:center;padding:7px 16px;cursor:pointer;font-size:12px;color:${active ? 'var(--amber)' : 'var(--text)'};">
      <span>${cat}</span><span style="font-family:var(--mono);font-size:9px;color:var(--text-dim);">${count}</span>
    </div>`;
  });

  el.innerHTML = html;
}

function repoSelectCat(cat) {
  repoSelectedCat = cat;
  repoRenderCats();
  repoRender();
}

// ── Manual Cards ──────────────────────────────────────────────────────────────
function repoRender() {
  const contentEl = document.getElementById('repoContent');
  const titleEl   = document.getElementById('repoSectionTitle');
  const countEl   = document.getElementById('repoSectionCount');
  const filterVal = (document.getElementById('repoFilterInput')?.value || '').toLowerCase();
  const showSuperseded = document.getElementById('repoShowSuperseded')?.checked;

  if (!contentEl) return;

  let manuals = repoManuals.filter(m => showSuperseded ? true : !m.superseded);
  if (repoSelectedCat !== 'all') manuals = manuals.filter(m => m.category === repoSelectedCat);
  if (filterVal) {
    manuals = manuals.filter(m =>
      (m.filename||'').toLowerCase().includes(filterVal) ||
      (m.equipment_name||'').toLowerCase().includes(filterVal) ||
      (m.maker||'').toLowerCase().includes(filterVal) ||
      (m.model||'').toLowerCase().includes(filterVal) ||
      (m.summary||'').toLowerCase().includes(filterVal)
    );
  }

  const vesselName = repoSelectedVessel
    ? (repoVessels.find(v => v.id === repoSelectedVessel)?.name || '')
    : 'All Vessels';

  if (titleEl) titleEl.textContent = repoSelectedCat === 'all' ? vesselName.toUpperCase() + ' — ALL MANUALS' : repoSelectedCat.toUpperCase();
  if (countEl) countEl.textContent = `${manuals.length} document${manuals.length !== 1 ? 's' : ''}`;

  if (!manuals.length) {
    contentEl.innerHTML = `<div style="font-family:var(--mono);font-size:10px;color:var(--text-dim);padding:24px;text-align:center;">
      ${repoSelectedVessel ? 'No manuals found. Upload the first one.' : 'Select a vessel above to view manuals.'}
    </div>`;
    return;
  }

  const user = getCurrentUser();
  const canEdit = user && ['admin','superintendent','fleet_manager','deputy_fleet_manager'].includes(user.role);

  contentEl.innerHTML = manuals.map(m => repoManualCard(m, canEdit)).join('');
}

function repoManualCard(m, canEdit) {
  const ragBadge = m.text_extracted
    ? `<span style="background:rgba(74,222,128,0.15);color:var(--green);border:1px solid rgba(74,222,128,0.3);border-radius:3px;font-family:var(--mono);font-size:8px;padding:1px 5px;">RAG ✓</span>`
    : `<span style="background:rgba(245,166,35,0.1);color:var(--amber);border:1px solid rgba(245,166,35,0.3);border-radius:3px;font-family:var(--mono);font-size:8px;padding:1px 5px;cursor:pointer;" onclick="repoReextract('${m.id}')">⚙ EXTRACT</span>`;

  const supersededBadge = m.superseded
    ? `<span style="background:rgba(239,68,68,0.1);color:#ef4444;border:1px solid rgba(239,68,68,0.3);border-radius:3px;font-family:var(--mono);font-size:8px;padding:1px 5px;">SUPERSEDED</span>`
    : '';

  const slBadge = m.service_letters?.length
    ? `<span style="background:rgba(96,165,250,0.1);color:#60a5fa;border:1px solid rgba(96,165,250,0.2);border-radius:3px;font-family:var(--mono);font-size:8px;padding:1px 5px;">${m.service_letters.length} SL</span>`
    : '';

  const vesselLabel = m.vessel_id
    ? (repoVessels.find(v => v.id === m.vessel_id)?.name || m.vessel_id)
    : 'Fleet-wide';

  return `<div style="background:var(--surface);border:1px solid var(--border);border-radius:8px;padding:14px 16px;margin-bottom:10px;">
    <div style="display:flex;align-items:flex-start;gap:10px;">
      <div style="font-size:22px;flex-shrink:0;">📄</div>
      <div style="flex:1;min-width:0;">
        <div style="display:flex;align-items:center;gap:6px;flex-wrap:wrap;margin-bottom:4px;">
          <span style="font-size:13px;font-weight:600;color:var(--text-bright);word-break:break-word;">${m.filename}</span>
          ${ragBadge} ${supersededBadge} ${slBadge}
        </div>
        <div style="font-family:var(--mono);font-size:9px;color:var(--amber);letter-spacing:1px;margin-bottom:4px;">${(m.category||'General').toUpperCase()}</div>
        ${m.equipment_name ? `<div style="font-size:11px;color:var(--text-dim);">${m.equipment_name}${m.maker ? ' · ' + m.maker : ''}${m.model ? ' / ' + m.model : ''}</div>` : ''}
        ${m.summary ? `<div style="font-size:11px;color:var(--text-dim);margin-top:4px;line-height:1.5;">${m.summary}</div>` : ''}
        <div style="display:flex;gap:10px;margin-top:8px;flex-wrap:wrap;">
          <span style="font-family:var(--mono);font-size:9px;color:var(--text-dim);">📦 ${(m.size_bytes/1024/1024).toFixed(1)}MB</span>
          <span style="font-family:var(--mono);font-size:9px;color:var(--text-dim);">🚢 ${vesselLabel}</span>
          <span style="font-family:var(--mono);font-size:9px;color:var(--text-dim);">v${m.version||'1.0'}</span>
          ${m.rev_date ? `<span style="font-family:var(--mono);font-size:9px;color:var(--text-dim);">Rev: ${m.rev_date}</span>` : ''}
          <span style="font-family:var(--mono);font-size:9px;color:var(--text-dim);">${m.uploaded_at ? m.uploaded_at.substring(0,10) : ''}</span>
        </div>
      </div>
      <div style="display:flex;flex-direction:column;gap:6px;flex-shrink:0;">
        <button class="btn-sm btn-sm-ghost" style="font-size:10px;" onclick="repoOpenFile('${m.id}')">📂 VIEW</button>
        ${canEdit ? `
        <button class="btn-sm btn-sm-ghost" style="font-size:10px;" onclick="repoAddSL('${m.id}')">+ SL</button>
        <button class="btn-sm btn-sm-ghost" style="font-size:10px;color:#ef4444;" onclick="repoDelete('${m.id}','${m.filename.replace(/'/g,"\\'")}')">🗑</button>
        ` : ''}
      </div>
    </div>
    ${m.service_letters?.length ? `
    <div style="margin-top:10px;border-top:1px solid var(--border);padding-top:8px;">
      <div style="font-family:var(--mono);font-size:8px;color:var(--text-dim);letter-spacing:1.5px;margin-bottom:6px;">SERVICE LETTERS / BULLETINS</div>
      ${m.service_letters.map(sl => `
        <div style="display:flex;align-items:center;gap:8px;padding:4px 0;font-size:11px;">
          <span style="font-family:var(--mono);font-size:9px;color:var(--amber);">${sl.ref||''}</span>
          <span style="color:var(--text);">${sl.title||''}</span>
          <span style="font-family:var(--mono);font-size:9px;color:var(--text-dim);margin-left:auto;">${sl.date||''}</span>
          <span style="font-family:var(--mono);font-size:8px;padding:1px 5px;border-radius:3px;background:${sl.action==='mandatory'?'rgba(239,68,68,0.15)':sl.action==='action_required'?'rgba(245,166,35,0.15)':'rgba(74,222,128,0.1)'};color:${sl.action==='mandatory'?'#ef4444':sl.action==='action_required'?'var(--amber)':'var(--green)'};">${(sl.action||'').replace('_',' ').toUpperCase()}</span>
        </div>`).join('')}
    </div>` : ''}
  </div>`;
}

// ── Open File (presigned URL) ─────────────────────────────────────────────────
function repoOpenFile(manualId) {
  window.open(`/api/repo/manuals/${manualId}/file?token=${getToken()}`, '_blank');
}

// ── Upload Flow ───────────────────────────────────────────────────────────────
function openManualUpload() {
  // Populate equipment link dropdown
  const eqSel = document.getElementById('repoEqLink');
  if (eqSel && repoSelectedVessel) {
    fetch(`/api/custodian/equipment?vessel_id=${repoSelectedVessel}`, {
      headers: { 'x-auth-token': getToken() }
    }).then(r => r.json()).then(eq => {
      eqSel.innerHTML = '<option value="">Not linked</option>';
      eq.forEach(e => {
        const opt = document.createElement('option');
        opt.value = e.id;
        opt.textContent = e.name;
        eqSel.appendChild(opt);
      });
    }).catch(() => {});
  }
  repoSelectedFile = null;
  document.getElementById('repoFileChosen').style.display = 'none';
  document.getElementById('repoFileChosen').textContent = '';
  document.getElementById('repoUploadErr').style.display = 'none';
  document.getElementById('repoUploadProgress').style.display = 'none';
  document.getElementById('repoProgBar').style.width = '0%';
  document.getElementById('repoUploadSubmit').disabled = false;
  document.getElementById('manualUploadModal').classList.add('open');
}

function repoFileSelected(input) {
  const file = input.files[0];
  if (!file) return;
  repoSelectedFile = file;
  const el = document.getElementById('repoFileChosen');
  el.textContent = `✓ ${file.name} (${(file.size/1024/1024).toFixed(1)}MB)`;
  el.style.display = 'block';
}

function repoHandleDrop(e) {
  e.preventDefault();
  const file = e.dataTransfer.files[0];
  if (!file) return;
  if (file.type !== 'application/pdf') {
    alert('Only PDF files are supported');
    return;
  }
  repoSelectedFile = file;
  const el = document.getElementById('repoFileChosen');
  el.textContent = `✓ ${file.name} (${(file.size/1024/1024).toFixed(1)}MB)`;
  el.style.display = 'block';
}

async function repoSubmitUpload() {
  if (!repoSelectedFile) {
    document.getElementById('repoUploadErr').textContent = 'Please select a PDF file first.';
    document.getElementById('repoUploadErr').style.display = 'block';
    return;
  }

  const submitBtn = document.getElementById('repoUploadSubmit');
  const errEl     = document.getElementById('repoUploadErr');
  const progEl    = document.getElementById('repoUploadProgress');
  const progBar   = document.getElementById('repoProgBar');
  const statusMsg = document.getElementById('repoUploadStatusMsg');

  submitBtn.disabled = true;
  errEl.style.display = 'none';
  progEl.style.display = 'block';
  statusMsg.textContent = 'Uploading to R2 storage…';
  progBar.style.width = '20%';

  try {
    const fd = new FormData();
    fd.append('file', repoSelectedFile);
    if (repoSelectedVessel) fd.append('vessel_id', repoSelectedVessel);
    fd.append('version', document.getElementById('repoVersion')?.value || '1.0');
    const eqLink = document.getElementById('repoEqLink')?.value;
    if (eqLink) fd.append('equipment_id', eqLink);

    progBar.style.width = '40%';
    statusMsg.textContent = 'Analysing with AI…';

    const res = await fetch('/api/repo/upload', {
      method: 'POST',
      headers: { 'x-auth-token': getToken() },
      body: fd
    });

    progBar.style.width = '90%';

    if (!res.ok) {
      const err = await res.json();
      throw new Error(err.error || 'Upload failed');
    }

    const manual = await res.json();
    progBar.style.width = '100%';
    statusMsg.textContent = `✓ Uploaded: ${manual.category} — ${manual.equipment_name || manual.filename}`;

    setTimeout(() => {
      document.getElementById('manualUploadModal').classList.remove('open');
      repoLoadManuals();
    }, 1200);

  } catch(e) {
    progEl.style.display = 'none';
    errEl.textContent = e.message;
    errEl.style.display = 'block';
    submitBtn.disabled = false;
  }
}

// ── Reextract text ────────────────────────────────────────────────────────────
async function repoReextract(manualId) {
  try {
    const res = await repoFetch(`/api/repo/manuals/${manualId}/reextract`, { method: 'POST' });
    const data = await res.json();
    alert(`Extraction started for: ${data.filename}\nThis runs in background — check back in ~30 seconds.`);
  } catch(e) {
    alert('Reextract failed: ' + e.message);
  }
}

// ── Delete ────────────────────────────────────────────────────────────────────
async function repoDelete(manualId, filename) {
  if (!confirm(`Delete "${filename}"?\n\nThis will remove the file from R2 storage and all embeddings. This cannot be undone.`)) return;
  try {
    const res = await repoFetch(`/api/repo/manuals/${manualId}`, { method: 'DELETE' });
    if (!res.ok) throw new Error((await res.json()).error);
    repoManuals = repoManuals.filter(m => m.id !== manualId);
    repoRenderCats();
    repoRender();
  } catch(e) {
    alert('Delete failed: ' + e.message);
  }
}

// ── Service Letters ───────────────────────────────────────────────────────────
let _repoSLManualId = null;

function repoAddSL(manualId) {
  _repoSLManualId = manualId;
  document.getElementById('repoSLManualId').value = manualId;
  document.getElementById('repoSLRef').value = '';
  document.getElementById('repoSLTitle').value = '';
  document.getElementById('repoSLDate').value = '';
  document.getElementById('repoSLNotes').value = '';
  document.getElementById('repoSLAction').value = 'for_information';
  document.getElementById('repoSLModal').classList.add('open');
}

async function repoSaveSL() {
  const manualId = document.getElementById('repoSLManualId').value;
  const ref   = document.getElementById('repoSLRef').value.trim();
  const title = document.getElementById('repoSLTitle').value.trim();
  const date  = document.getElementById('repoSLDate').value;
  const action= document.getElementById('repoSLAction').value;
  const notes = document.getElementById('repoSLNotes').value.trim();

  if (!ref || !title) { alert('Reference and title are required'); return; }

  try {
    const manual = repoManuals.find(m => m.id === manualId);
    if (!manual) throw new Error('Manual not found');

    const sl = { ref, title, date, action, notes, added_at: new Date().toISOString() };
    const sls = [...(manual.service_letters || []), sl];

    const res = await repoFetch(`/api/repo/manuals/${manualId}`, {
      method: 'PATCH',
      body: JSON.stringify({ service_letters: sls })
    });
    if (!res.ok) throw new Error((await res.json()).error);

    manual.service_letters = sls;
    document.getElementById('repoSLModal').classList.remove('open');
    repoRender();
  } catch(e) {
    alert('Save failed: ' + e.message);
  }
}

// ── Oracle Q&A ────────────────────────────────────────────────────────────────
let repoConversationHistory = [];
let repoIsFollowUp = false;

async function repoAsk() {
  const question = document.getElementById('repoQuestion')?.value.trim();
  if (!question) return;

  const btn     = document.getElementById('repoAskBtn');
  const answerEl= document.getElementById('repoAnswerBox');
  if (!answerEl) return;

  btn.disabled = true;
  btn.textContent = '…';
  answerEl.style.display = 'block';
  answerEl.innerHTML = `<div style="font-family:var(--mono);font-size:10px;color:var(--amber);">⟳ Searching manuals…</div>`;

  try {
    const body = {
      question,
      vessel_id:   repoSelectedVessel,
      category:    repoSelectedCat !== 'all' ? repoSelectedCat : undefined,
      history:     repoConversationHistory,
      is_follow_up:repoIsFollowUp
    };

    const res  = await fetch('/api/repo/search', {
      method: 'POST',
      headers: { 'x-auth-token': getToken(), 'Content-Type': 'application/json' },
      body: JSON.stringify(body)
    });
    const data = await res.json();
    const answer = data.answer || 'No answer returned.';

    // Add to conversation history
    if (!repoIsFollowUp) repoConversationHistory = [];
    repoConversationHistory.push({ role: 'user', content: question });
    repoConversationHistory.push({ role: 'assistant', content: answer });
    repoIsFollowUp = true;

    // Format answer (markdown bold/italic)
    const formatted = answer
      .replace(/\*\*([^*]+)\*\*/g, '<strong>$1</strong>')
      .replace(/\*([^*]+)\*/g, '<em>$1</em>')
      .replace(/\n/g, '<br>');

    const sourceHtml = data.sources?.length
      ? `<div style="margin-top:8px;padding-top:8px;border-top:1px solid var(--border);">
          <span style="font-family:var(--mono);font-size:8px;color:var(--text-dim);letter-spacing:1px;">SOURCES: </span>
          ${data.sources.map(s => `<span style="font-family:var(--mono);font-size:9px;color:var(--amber);">${s.filename}</span>`).join(' · ')}
          ${data.rag ? `<span style="font-family:var(--mono);font-size:8px;color:var(--green);margin-left:6px;">● RAG (${data.chunks_used} chunks)</span>` : ''}
        </div>`
      : '';

    const clearBtn = `<div style="margin-top:8px;">
      <button class="btn-sm btn-sm-ghost" style="font-size:9px;" onclick="repoClearConversation()">✕ New question</button>
    </div>`;

    answerEl.innerHTML = `
      <div style="font-size:12px;color:var(--text);line-height:1.7;">${formatted}</div>
      ${sourceHtml}
      ${clearBtn}`;

    document.getElementById('repoQuestion').value = '';

  } catch(e) {
    answerEl.innerHTML = `<div style="font-family:var(--mono);font-size:10px;color:var(--red);">Error: ${e.message}</div>`;
  } finally {
    btn.disabled = false;
    btn.textContent = 'ASK';
  }
}

function repoClearConversation() {
  repoConversationHistory = [];
  repoIsFollowUp = false;
  const answerEl = document.getElementById('repoAnswerBox');
  if (answerEl) answerEl.style.display = 'none';
  const q = document.getElementById('repoQuestion');
  if (q) { q.value = ''; q.focus(); }
}

// ── Enter key on question textarea ────────────────────────────────────────────
document.addEventListener('DOMContentLoaded', () => {
  const q = document.getElementById('repoQuestion');
  if (q) {
    q.addEventListener('keydown', e => {
      if (e.key === 'Enter' && !e.shiftKey) { e.preventDefault(); repoAsk(); }
    });
  }
});
