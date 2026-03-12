// ══════════════════════════════════════════════════════════════════════════════
// FORCAP PMS MODULE v2.30
// ══════════════════════════════════════════════════════════════════════════════
'use strict';

const PMS = (() => {

  // ── State ──────────────────────────────────────────────────────────────────
  let state = {
    tab: 'overview',
    vessel: null,
    vessels: [],
    equipPage: 1,
    equipTotal: 0,
    equipSearch: '',
    equipCriticality: 'all',
    equipRole: 'all',
    equipRoles: [],
    wsStatus: 'all',
    wsRoleSearch: '',
    stats: {},
    scheduleMonth: new Date().getMonth(),
    scheduleYear: new Date().getFullYear(),
    _wsComponents: [],  // cached component list for worksheet modal
  };

  // ── Constants ──────────────────────────────────────────────────────────────
  const CRIT_COLOR  = { Critical:'#ef4444', Significant:'#f59e0b', Standard:'#6b7280' };
  const STATUS_COLOR = {
    issued:'#3b82f6', wip:'#8b5cf6', awaiting_auth:'#f59e0b',
    authorised:'#22c55e', returned:'#ef4444', deferred:'#6b7280'
  };
  const STATUS_LABEL = {
    issued:'Issued', wip:'Work in Progress', awaiting_auth:'Awaiting Authorisation',
    authorised:'Authorised', returned:'Returned by CE', deferred:'Deferred'
  };
  const MONTHS = ['January','February','March','April','May','June','July','August','September','October','November','December'];

  // ── Helpers ────────────────────────────────────────────────────────────────
  const el  = id => document.getElementById(id);
  const fmt = n  => (n||0).toLocaleString();

  function getToken() { return localStorage.getItem('maride_token') || ''; }

  async function api(path, opts = {}) {
    const headers = { 'Content-Type':'application/json', 'x-auth-token':getToken(), ...(opts.headers||{}) };
    const res = await fetch(path, { ...opts, headers });
    if (!res.ok) {
      const txt = await res.text();
      throw new Error(txt);
    }
    return res.json();
  }

  function badge(text, color, small=false) {
    const fs = small ? '8px' : '9px', pad = small ? '2px 6px' : '3px 8px';
    return `<span style="display:inline-block;padding:${pad};border-radius:4px;font-family:var(--mono);font-size:${fs};font-weight:700;letter-spacing:1px;color:#fff;background:${color};">${text}</span>`;
  }

  function tmsaColor(pct) { return pct <= 5 ? '#22c55e' : pct <= 15 ? '#f59e0b' : '#ef4444'; }

  function toast(msg, type='info') {
    // Use the global toast function from index.html
    if (typeof window.toast === 'function') window.toast(msg);
    else console.log('[PMS toast]', type, msg);
  }

  function fmtDate(d) {
    if (!d) return '—';
    return new Date(d).toLocaleDateString('en-GB', { day:'2-digit', month:'short', year:'numeric' });
  }

  function isOverdue(ws) {
    return ws.due_date && new Date(ws.due_date) < new Date() && !['authorised','deferred'].includes(ws.status);
  }

  // ── ensure vessels loaded ──────────────────────────────────────────────────
  async function ensureVessels() {
    if (state.vessels.length) return;
    try {
      state.vessels = await api('/api/pms/vessels');
    } catch(e) { state.vessels = []; }
    if (!state.vessel && state.vessels.length) {
      state.vessel = (
        state.vessels.find(v => v.name.includes('Alfred Temile')) ||
        state.vessels.find(v => v.name.includes('Port Harcourt')) ||
        state.vessels[0]
      ).name;
    }
  }

  // ── Init ───────────────────────────────────────────────────────────────────
  async function init(tab) {
    if (tab) state.tab = tab;
    await ensureVessels();
    render();
  }

  // ── Vessel selector HTML ───────────────────────────────────────────────────
  function vesselSel(includeAll=false) {
    if (!state.vessels.length) return `<span style="font-family:var(--mono);font-size:9px;color:var(--text-dim);">Loading vessels…</span>`;
    const opts = (includeAll ? [{name:'All Vessels',vessel_type:''}] : [])
      .concat(state.vessels)
      .map(v => `<option value="${v.name}" ${v.name===state.vessel?'selected':''}>${v.name}${v.vessel_type?' ('+v.vessel_type+')':''}</option>`)
      .join('');
    return `<select onchange="PMS.setVessel(this.value)"
      style="font-family:var(--mono);font-size:10px;background:var(--surface2);border:1px solid var(--border);color:var(--text);padding:5px 10px;border-radius:4px;cursor:pointer;">${opts}</select>`;
  }

  function setVessel(name) { state.vessel=name; state.equipPage=1; state._wsComponents=[]; render(); }

  // ── Main render dispatcher ─────────────────────────────────────────────────
  function render() {
    const content = el('pmsContent');
    if (!content) return;
    ({
      overview:     renderOverview,
      equipment:    renderEquipment,
      schedule:     renderSchedule,
      worksheets:   renderWorksheets,
      runninghours: renderRunningHours,
      defects:      renderDefects,
      history:      renderHistory,
      predictive:   renderPredictive,
    }[state.tab] || renderOverview)();
  }

  // ════════════════════════════════════════════════════════════════════════════
  // 1. OVERVIEW
  // ════════════════════════════════════════════════════════════════════════════
  async function renderOverview() {
    const content = el('pmsContent');
    content.innerHTML = `
      <div style="max-width:1100px;">
        <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:20px;">
          <div>
            <div style="font-family:var(--mono);font-size:9px;color:var(--text-dim);letter-spacing:2px;">PMS — FLEET OVERVIEW</div>
            <div style="font-size:11px;color:var(--text-dim);margin-top:4px;">119,357 historical records across 6 vessels (2020–2026)</div>
          </div>
          <button onclick="PMS.refreshOverview()" style="font-family:var(--mono);font-size:9px;background:var(--surface2);border:1px solid var(--border);color:var(--text-dim);padding:5px 10px;border-radius:4px;cursor:pointer;">↻ REFRESH</button>
        </div>
        <div id="pmsOverviewInner"><div style="font-family:var(--mono);font-size:11px;color:var(--text-dim);padding:20px 0;">Loading fleet data…</div></div>
      </div>`;
    await refreshOverview();
  }

  async function refreshOverview() {
    const wrap = el('pmsOverviewInner');
    if (!wrap) return;
    try {
      const [data, stats] = await Promise.all([api('/api/pms/overview'), api('/api/pms/stats')]);
      state.stats = stats;
      const t = data.totals;
      wrap.innerHTML = `
        <div style="display:grid;grid-template-columns:repeat(4,1fr);gap:10px;margin-bottom:20px;">
          ${[['OVERDUE >1M', t.overdue_1m, '#ef4444'],
             ['ISSUED', t.issued, '#3b82f6'],
             ['AWAITING AUTH', t.awaiting, '#f59e0b'],
             ['HISTORICAL RECORDS', fmt(data.historical_records), '#8b5cf6']
            ].map(([l,v,c])=>`
            <div style="background:var(--surface);border:1px solid var(--border);border-top:3px solid ${c};border-radius:6px;padding:14px;">
              <div style="font-family:var(--mono);font-size:26px;font-weight:700;color:${c};line-height:1;">${v}</div>
              <div style="font-family:var(--mono);font-size:7px;color:var(--text-dim);letter-spacing:1.5px;margin-top:5px;">${l}</div>
            </div>`).join('')}
        </div>
        <div style="display:grid;grid-template-columns:repeat(2,1fr);gap:12px;margin-bottom:20px;">
          ${data.vessels.map(v => vesselCard(v)).join('')}
        </div>
        ${hotspotsHtml(data.vessels, stats)}`;
    } catch(e) {
      wrap.innerHTML = `<div style="font-family:var(--mono);font-size:11px;color:#ef4444;">Failed to load overview: ${e.message}</div>`;
    }
  }

  function vesselCard(v) {
    const tc = tmsaColor(v.tmsa_pct);
    const label = v.tmsa_pct <= 5 ? 'GOOD' : v.tmsa_pct <= 15 ? 'CAUTION' : 'CRITICAL';
    return `
      <div onclick="PMS.openVesselDashboard('${v.vessel_name}')"
        style="background:var(--surface);border:1px solid var(--border);border-radius:8px;padding:16px;cursor:pointer;transition:border-color 0.2s;"
        onmouseover="this.style.borderColor='var(--amber)'" onmouseout="this.style.borderColor='var(--border)'">
        <div style="display:flex;justify-content:space-between;align-items:flex-start;margin-bottom:12px;">
          <div>
            <div style="font-weight:600;font-size:13px;color:var(--text-bright);">${v.vessel_name}</div>
            <div style="font-family:var(--mono);font-size:9px;color:var(--text-dim);margin-top:2px;">${v.vessel_type} · click for dashboard</div>
          </div>
          <div style="text-align:right;">
            <div style="font-family:var(--mono);font-size:22px;font-weight:700;color:${tc};">${v.tmsa_pct}%</div>
            <div style="font-family:var(--mono);font-size:7px;color:${tc};letter-spacing:1px;">TMSA ${label}</div>
          </div>
        </div>
        <div style="display:grid;grid-template-columns:repeat(5,1fr);gap:5px;margin-bottom:12px;">
          ${[['Issued',v.issued,'#3b82f6'],['WIP',v.wip,'#8b5cf6'],
             ['Await Auth',v.awaiting,'#f59e0b'],['Deferred',v.deferred,'#6b7280'],
             ['Overdue',v.overdue_1m,'#ef4444']].map(([l,n,c])=>`
            <div style="background:var(--surface2);border-radius:4px;padding:6px 4px;text-align:center;border-top:2px solid ${c};">
              <div style="font-family:var(--mono);font-size:16px;font-weight:700;color:${c};">${n}</div>
              <div style="font-family:var(--mono);font-size:7px;color:var(--text-dim);">${l}</div>
            </div>`).join('')}
        </div>
        <div style="display:flex;justify-content:space-between;align-items:center;border-top:1px solid var(--border);padding-top:10px;">
          <div style="font-family:var(--mono);font-size:9px;color:var(--text-dim);">📁 ${fmt(v.historical_total)} records · ⚠ ${fmt(v.historical_adhoc)} ad-hoc</div>
          <span style="font-family:var(--mono);font-size:8px;color:var(--amber);">OPEN DASHBOARD →</span>
        </div>
      </div>`;
  }

  async function openVesselDashboard(vesselName) {
    state.vessel = vesselName;
    const content = el('pmsContent');
    content.innerHTML = `<div style="font-family:var(--mono);font-size:10px;color:var(--text-dim);">Loading ${vesselName}…</div>`;

    // Load worksheets for this vessel
    let ws = [];
    try { ws = await api('/api/pms/worksheets?vessel_name=' + encodeURIComponent(vesselName)); } catch(e){}

    const STATUS_TABS = [
      {key:'all',     label:'All',           color:'var(--amber)'},
      {key:'issued',  label:'Issued',        color:'#3b82f6'},
      {key:'wip',     label:'WIP',           color:'#8b5cf6'},
      {key:'awaiting_auth', label:'Awaiting Auth', color:'#f59e0b'},
      {key:'deferred',label:'Deferred',      color:'#6b7280'},
      {key:'returned',label:'Returned',      color:'#ef4444'},
      {key:'authorised',label:'Authorised',  color:'#22c55e'},
    ];
    const counts = {};
    STATUS_TABS.forEach(t => {
      counts[t.key] = t.key==='all' ? ws.length : ws.filter(w=>w.status===t.key).length;
    });

    let activeTab = 'all';

    function renderDashboard() {
      const filtered = activeTab==='all' ? ws : ws.filter(w=>w.status===activeTab);
      const od = filtered.filter(w=>isOverdue(w));

      content.innerHTML = `
        <div style="max-width:1000px;">
          <div style="display:flex;align-items:center;gap:12px;margin-bottom:20px;flex-wrap:wrap;">
            <button onclick="PMS.refreshOverview()" style="font-family:var(--mono);font-size:9px;background:transparent;border:none;color:var(--amber);cursor:pointer;padding:0;">← FLEET OVERVIEW</button>
            <div style="font-family:var(--mono);font-size:13px;font-weight:700;color:var(--text-bright);">${vesselName}</div>
            <div style="flex:1;"></div>
            <button onclick="PMS.openWsModal()" style="font-family:var(--mono);font-size:9px;background:var(--amber);color:#000;border:none;padding:6px 12px;border-radius:4px;cursor:pointer;font-weight:700;">+ ISSUE WORKSHEET</button>
          </div>

          <!-- Status tab bar -->
          <div style="display:flex;gap:4px;flex-wrap:wrap;margin-bottom:16px;">
            ${STATUS_TABS.map(t=>`
              <button onclick="PMS._vdTab('${t.key}')"
                style="font-family:var(--mono);font-size:8px;padding:5px 10px;border-radius:4px;cursor:pointer;letter-spacing:0.5px;
                  border:1px solid ${activeTab===t.key?t.color:'var(--border)'};
                  background:${activeTab===t.key?t.color:'var(--surface2)'};
                  color:${activeTab===t.key?'#fff':'var(--text-dim)'};">
                ${t.label.toUpperCase()} <span style="opacity:0.8;">(${counts[t.key]})</span>
              </button>`).join('')}
          </div>

          ${od.length&&activeTab!=='authorised'&&activeTab!=='deferred'?`
            <div style="background:rgba(239,68,68,0.1);border:1px solid #ef4444;border-radius:6px;padding:10px 14px;margin-bottom:12px;font-family:var(--mono);font-size:9px;color:#ef4444;">
              ⚠ ${od.length} OVERDUE WORKSHEET${od.length>1?'S':''} IN THIS VIEW
            </div>`:''}

          <div style="display:grid;gap:8px;">
            ${filtered.length===0
              ? `<div style="text-align:center;padding:40px;color:var(--text-dim);font-family:var(--mono);font-size:10px;">NO WORKSHEETS — ${activeTab.toUpperCase()}</div>`
              : filtered.sort((a,b)=>new Date(b.created_at)-new Date(a.created_at)).map(w=>wsCard(w)).join('')}
          </div>
        </div>`;

      // Re-bind the back button
      const backBtn = content.querySelector('button');
      if (backBtn) backBtn.onclick = () => { state.tab='overview'; refreshOverview().then(()=>{}); };
    }

    window.PMS._vdTab = (tab) => { activeTab=tab; renderDashboard(); };
    renderDashboard();
  }

  function hotspotsHtml(vessels, stats) {
    const all = {};
    vessels.forEach(v => {
      const key = Object.keys(stats).find(k => k.toLowerCase().includes(v.vessel_name.toLowerCase().split(' ')[0]) || v.vessel_name.toLowerCase().includes(k.toLowerCase().split(' ')[0]));
      const hist = key ? stats[key] : {};
      (hist.failure_hotspots||[]).forEach(h => {
        if (!all[h.code]) all[h.code] = {code:h.code,description:h.description,vessels:[],total:0};
        all[h.code].vessels.push(v.vessel_name);
        all[h.code].total += h.count;
      });
    });
    const sorted = Object.values(all).sort((a,b)=>b.total-a.total).slice(0,8);
    if (!sorted.length) return '';
    return `
      <div style="background:var(--surface);border:1px solid var(--border);border-radius:8px;padding:16px;">
        <div style="font-family:var(--mono);font-size:9px;color:var(--text-dim);letter-spacing:2px;margin-bottom:14px;">🤖 FLEET FAILURE HOTSPOTS — TOP AD-HOC COMPONENTS (2020–2026)</div>
        <div style="display:grid;gap:6px;">
          ${sorted.map((h,i)=>`
            <div style="display:flex;align-items:center;gap:10px;padding:8px 10px;background:var(--surface2);border-radius:4px;border-left:3px solid ${i<3?'#ef4444':'#f59e0b'};">
              <div style="font-family:var(--mono);font-size:9px;color:var(--amber);width:70px;flex-shrink:0;">${h.code}</div>
              <div style="flex:1;font-size:11px;color:var(--text);">${h.description||'—'}</div>
              <div style="font-family:var(--mono);font-size:9px;color:var(--text-dim);">${h.vessels.length}v</div>
              <div style="font-family:var(--mono);font-size:14px;font-weight:700;color:${i<3?'#ef4444':'#f59e0b'};width:36px;text-align:right;">${h.total}</div>
            </div>`).join('')}
        </div>
      </div>`;
  }

  function goTab(tab, vesselName) {
    if (vesselName) state.vessel = vesselName;
    state.tab = tab;
    document.querySelectorAll('.pms-nav-item').forEach(n=>n.classList.remove('active'));
    const tabMap = ['overview','equipment','schedule','worksheets','runninghours','defects','history','predictive'];
    const idx = tabMap.indexOf(tab);
    const items = document.querySelectorAll('.pms-nav-item');
    if (idx >= 0 && items[idx]) items[idx].classList.add('active');
    render();
  }

  // ════════════════════════════════════════════════════════════════════════════
  // 2. EQUIPMENT REGISTER
  // ════════════════════════════════════════════════════════════════════════════
  async function renderEquipment() {
    await ensureVessels();
    const content = el('pmsContent');
    // Freeze the filter bar: content div becomes position:relative, filter bar is sticky
    content.style.padding = '0';
    content.innerHTML = `
      <div style="position:sticky;top:0;z-index:10;background:var(--bg);padding:20px 32px 12px;border-bottom:1px solid var(--border);">
        <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:12px;">
          <div style="font-family:var(--mono);font-size:9px;color:var(--text-dim);letter-spacing:2px;">PMS — EQUIPMENT REGISTER</div>
          ${vesselSel()}
        </div>
        <div style="display:flex;gap:8px;flex-wrap:wrap;">
          <input id="pmsEqSearch" placeholder="Search component code or description…" value="${state.equipSearch}"
            oninput="PMS.equipSearch(this.value)"
            style="flex:1;min-width:200px;font-family:var(--mono);font-size:10px;background:var(--surface2);border:1px solid var(--border);color:var(--text);padding:6px 10px;border-radius:4px;">
          <select onchange="PMS.equipFilter('criticality',this.value)"
            style="font-family:var(--mono);font-size:10px;background:var(--surface2);border:1px solid var(--border);color:var(--text);padding:6px 10px;border-radius:4px;">
            <option value="all" ${state.equipCriticality==='all'?'selected':''}>All Criticality</option>
            <option value="Critical" ${state.equipCriticality==='Critical'?'selected':''}>🔴 Critical</option>
            <option value="Significant" ${state.equipCriticality==='Significant'?'selected':''}>🟡 Significant</option>
            <option value="Standard" ${state.equipCriticality==='Standard'?'selected':''}>⚪ Standard</option>
          </select>
          <select id="pmsEqRoleSel" onchange="PMS.equipFilter('role',this.value)"
            style="font-family:var(--mono);font-size:10px;background:var(--surface2);border:1px solid var(--border);color:var(--text);padding:6px 10px;border-radius:4px;">
            <option value="all">All Roles</option>
          </select>
        </div>
      </div>
      <div style="padding:16px 32px 28px;" id="pmsEquipTable">
        <div style="font-family:var(--mono);font-size:11px;color:var(--text-dim);">Loading…</div>
      </div>`;
    await loadEquipment();
  }

  async function loadEquipment() {
    const wrap = el('pmsEquipTable');
    if (!wrap) return;
    if (!state.vessel) { wrap.innerHTML = `<div style="font-family:var(--mono);font-size:11px;color:var(--text-dim);">Select a vessel above.</div>`; return; }
    try {
      const params = new URLSearchParams({
        vessel_name: state.vessel, page: state.equipPage, limit: 60,
        ...(state.equipSearch ? {search:state.equipSearch} : {}),
        ...(state.equipCriticality!=='all' ? {criticality:state.equipCriticality} : {}),
        ...(state.equipRole!=='all' ? {role:state.equipRole} : {}),
      });
      const data = await api(`/api/pms/equipment?${params}`);
      state.equipTotal = data.total;

      // Populate role dropdown once
      const roleSel = el('pmsEqRoleSel');
      if (roleSel && data.roles && roleSel.options.length === 1) {
        data.roles.forEach(r => {
          const o = document.createElement('option');
          o.value=r; o.textContent=r; if(r===state.equipRole) o.selected=true;
          roleSel.appendChild(o);
        });
      }

      const totalPages = Math.ceil(data.total/60);
      const critCounts = {Critical:0,Significant:0,Standard:0};
      data.components.forEach(c => { if(critCounts[c.criticality]!==undefined) critCounts[c.criticality]++; });

      wrap.innerHTML = `
        <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:10px;flex-wrap:wrap;gap:8px;">
          <div style="display:flex;gap:8px;align-items:center;">
            <span style="font-family:var(--mono);font-size:9px;color:var(--text-dim);">${fmt(data.total)} components · ${data.vessel_type||''}</span>
            ${badge(critCounts.Critical+' Critical','#ef4444',true)}
            ${badge(critCounts.Significant+' Significant','#f59e0b',true)}
          </div>
          <div style="display:flex;gap:6px;align-items:center;">
            ${totalPages>1?`
              <button onclick="PMS.equipPage(${state.equipPage-1})" ${state.equipPage<=1?'disabled':''} style="font-family:var(--mono);font-size:9px;padding:3px 8px;background:var(--surface2);border:1px solid var(--border);color:var(--text);border-radius:3px;cursor:pointer;">‹</button>
              <span style="font-family:var(--mono);font-size:9px;color:var(--text-dim);">${state.equipPage}/${totalPages}</span>
              <button onclick="PMS.equipPage(${state.equipPage+1})" ${state.equipPage>=totalPages?'disabled':''} style="font-family:var(--mono);font-size:9px;padding:3px 8px;background:var(--surface2);border:1px solid var(--border);color:var(--text);border-radius:3px;cursor:pointer;">›</button>
            `:''}
          </div>
        </div>
        <div style="overflow-x:auto;">
          <table style="width:100%;border-collapse:collapse;font-size:11px;">
            <thead><tr style="border-bottom:2px solid var(--border);">
              ${['CODE','DESCRIPTION','CRITICALITY','CUSTODIAN','FREQUENCY','JOBS','AD-HOC'].map(h=>`<th style="padding:6px 8px;text-align:left;font-family:var(--mono);font-size:8px;color:var(--text-dim);letter-spacing:1px;white-space:nowrap;">${h}</th>`).join('')}
            </tr></thead>
            <tbody>
              ${data.components.map((c,i)=>`
                <tr style="border-bottom:1px solid var(--border);${i%2===0?'background:var(--surface2);':''}">
                  <td style="padding:6px 8px;font-family:var(--mono);font-size:10px;color:var(--amber);white-space:nowrap;">${c.code}</td>
                  <td style="padding:6px 8px;color:var(--text);max-width:280px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;" title="${c.description||''}">${c.description||'—'}</td>
                  <td style="padding:6px 8px;">${badge(c.criticality,CRIT_COLOR[c.criticality]||'#6b7280',true)}</td>
                  <td style="padding:6px 8px;font-family:var(--mono);font-size:9px;color:var(--text-dim);">${c.primary_role||'—'}</td>
                  <td style="padding:6px 8px;font-family:var(--mono);font-size:9px;color:var(--text-dim);">${c.frequency||'—'}</td>
                  <td style="padding:6px 8px;font-family:var(--mono);font-size:10px;color:var(--text);text-align:right;">${fmt(c.job_count)}</td>
                  <td style="padding:6px 8px;font-family:var(--mono);font-size:10px;font-weight:${c.adhoc_count>5?'700':'400'};color:${c.adhoc_count>5?'#ef4444':c.adhoc_count>2?'#f59e0b':'var(--text-dim)'};text-align:right;">${c.adhoc_count||0}</td>
                </tr>`).join('')}
            </tbody>
          </table>
        </div>`;
    } catch(e) {
      wrap.innerHTML = `<div style="font-family:var(--mono);font-size:11px;color:#ef4444;">Error: ${e.message}</div>`;
    }
  }

  let _eqTimer;
  function equipSearch(val) { clearTimeout(_eqTimer); _eqTimer=setTimeout(()=>{ state.equipSearch=val; state.equipPage=1; loadEquipment(); },350); }
  function equipFilter(type,val) { if(type==='criticality') state.equipCriticality=val; else state.equipRole=val; state.equipPage=1; loadEquipment(); }
  function equipPage(p) { if(p<1) return; state.equipPage=p; loadEquipment(); }

  // ════════════════════════════════════════════════════════════════════════════
  // 3. MAINTENANCE SCHEDULE (3-month forecast)
  // ════════════════════════════════════════════════════════════════════════════
  async function renderSchedule() {
    await ensureVessels();
    const content = el('pmsContent');
    const m = state.scheduleMonth, y = state.scheduleYear;
    const prevM = m===0?11:m-1, prevY = m===0?y-1:y;
    const nextM = m===11?0:m+1, nextY = m===11?y+1:y;

    content.innerHTML = `
      <div style="max-width:1100px;">
        <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:16px;flex-wrap:wrap;gap:8px;">
          <div style="font-family:var(--mono);font-size:9px;color:var(--text-dim);letter-spacing:2px;">PMS — MAINTENANCE SCHEDULE</div>
          ${vesselSel()}
        </div>

        <div style="display:flex;align-items:center;gap:12px;margin-bottom:16px;flex-wrap:wrap;">
          <button onclick="PMS.scheduleNav(${prevM},${prevY})" style="font-family:var(--mono);font-size:10px;padding:5px 10px;background:var(--surface2);border:1px solid var(--border);color:var(--text);border-radius:4px;cursor:pointer;">‹ ${MONTHS[prevM].slice(0,3)}</button>
          <div style="font-family:var(--mono);font-size:13px;font-weight:700;color:var(--text-bright);min-width:160px;text-align:center;">${MONTHS[m]} ${y}</div>
          <button onclick="PMS.scheduleNav(${nextM},${nextY})" style="font-family:var(--mono);font-size:10px;padding:5px 10px;background:var(--surface2);border:1px solid var(--border);color:var(--text);border-radius:4px;cursor:pointer;">${MONTHS[nextM].slice(0,3)} ›</button>
          <div style="flex:1;"></div>
          <button onclick="PMS.previewMonth()" style="font-family:var(--mono);font-size:9px;background:var(--surface2);color:var(--text);border:1px solid var(--border);padding:6px 12px;border-radius:4px;cursor:pointer;">👁 PREVIEW DUE</button>
          <button id="btnIssueMonth" onclick="PMS.issueAll()" style="font-family:var(--mono);font-size:9px;background:var(--amber);color:#000;border:none;padding:6px 14px;border-radius:4px;cursor:pointer;font-weight:700;">⚡ ISSUE MONTH</button>
        </div>

        <div style="display:grid;grid-template-columns:repeat(3,1fr);gap:10px;margin-bottom:20px;">
          ${[0,1,2].map(offset => {
            const mm = (m+offset)%12, yy = m+offset>11?y+1:y;
            return `<div style="background:var(--surface);border:1px solid ${offset===0?'var(--amber)':'var(--border)'};border-radius:8px;padding:14px;${offset===0?'border-top:3px solid var(--amber);':''}">
              <div style="font-family:var(--mono);font-size:10px;color:${offset===0?'var(--amber)':'var(--text-dim)'};font-weight:${offset===0?'700':'400'};">${MONTHS[mm]} ${yy}</div>
              <div style="font-family:var(--mono);font-size:24px;font-weight:700;color:var(--text);margin:8px 0;" id="sched-count-${offset}">—</div>
              <div style="font-family:var(--mono);font-size:8px;color:var(--text-dim);letter-spacing:1px;">JOBS DUE</div>
            </div>`;
          }).join('')}
        </div>

        <div id="schedList"><div style="font-family:var(--mono);font-size:11px;color:var(--text-dim);">Loading schedule…</div></div>
      </div>`;

    await loadSchedule();
  }

  async function loadSchedule() {
    const wrap = el('schedList');
    if (!wrap || !state.vessel) return;
    try {
      // Load all worksheets for this vessel
      const vesselObj = state.vessels.find(v=>v.name===state.vessel);
      // We show worksheets due in current month + generate forecast from equipment register
      const m = state.scheduleMonth, y = state.scheduleYear;
      const monthStart = new Date(y, m, 1);
      const monthEnd   = new Date(y, m+1, 0, 23, 59, 59);

      // Load existing worksheets in this period
      const allWs = await api('/api/pms/worksheets?vessel_id=all&status=all');
      const vesselWs = allWs.filter(w => w.vessel_name === state.vessel);
      const monthWs = vesselWs.filter(w => {
        if (!w.due_date) return false;
        const d = new Date(w.due_date);
        return d >= monthStart && d <= monthEnd;
      });

      // Count for 3-month cards
      for (let offset=0; offset<3; offset++) {
        const mm=(m+offset)%12, yy=m+offset>11?y+1:y;
        const ms=new Date(yy,mm,1), me=new Date(yy,mm+1,0,23,59,59);
        const cnt = vesselWs.filter(w=>w.due_date&&new Date(w.due_date)>=ms&&new Date(w.due_date)<=me).length;
        const el2 = el(`sched-count-${offset}`);
        if (el2) el2.textContent = cnt;
      }

      if (!monthWs.length) {
        wrap.innerHTML = `
          <div style="background:var(--surface);border:1px solid var(--border);border-radius:8px;padding:20px;margin-bottom:12px;">
            <div style="font-family:var(--mono);font-size:10px;color:var(--text-dim);margin-bottom:10px;">NO WORKSHEETS ISSUED FOR ${MONTHS[m].toUpperCase()} ${y}</div>
            <div style="font-size:11px;color:var(--text-dim);line-height:1.8;margin-bottom:12px;">
              Click <strong style="color:var(--amber);">⚡ ISSUE MONTH</strong> to bulk-issue all planned maintenance worksheets due this month.<br>
              Or use <strong style="color:var(--amber);">👁 PREVIEW DUE</strong> to see which components are due first.
            </div>
            <div style="font-family:var(--mono);font-size:8px;color:var(--text-dim);border-top:1px solid var(--border);padding-top:10px;line-height:2;">
              CRITERIA FOR ISSUE MONTH: Components from equipment register where the frequency interval divides evenly into
              the months elapsed since Jan 2020. E.g. a 3 Month(s) component is due in Mar, Jun, Sep, Dec each year.
              1 Month(s) = every month · 3 Month(s) = quarterly · 6 Month(s) = bi-annual · 12 Month(s) = annual · 60 Month(s) = 5-year.
              Already-issued worksheets for the month are skipped (no duplicates).
            </div>
          </div>`;
        return;
      }

      // Group by status
      const byStatus = {};
      monthWs.forEach(w => { (byStatus[w.status]||=[]).push(w); });

      wrap.innerHTML = `
        <div style="display:flex;gap:8px;margin-bottom:12px;flex-wrap:wrap;">
          ${Object.entries(STATUS_LABEL).map(([s,l])=>{
            const cnt=(byStatus[s]||[]).length;
            return cnt>0?badge(`${cnt} ${l.toUpperCase()}`,STATUS_COLOR[s]):'';
          }).join('')}
        </div>
        <div style="display:grid;gap:6px;">
          ${monthWs.sort((a,b)=>new Date(a.due_date)-new Date(b.due_date)).map(ws=>schedWsRow(ws)).join('')}
        </div>`;
    } catch(e) {
      wrap.innerHTML = `<div style="font-family:var(--mono);font-size:11px;color:#ef4444;">Error: ${e.message}</div>`;
    }
  }

  function schedWsRow(ws) {
    const sc = STATUS_COLOR[ws.status]||'#6b7280';
    const od = isOverdue(ws);
    return `
      <div onclick="PMS._openWsDetail('${ws.id}')"
        style="display:flex;align-items:center;gap:10px;padding:10px 12px;background:var(--surface);border:1px solid var(--border);border-left:3px solid ${od?'#ef4444':sc};border-radius:6px;cursor:pointer;"
        onmouseover="this.style.background='var(--surface2)'" onmouseout="this.style.background='var(--surface)'">
        <div style="font-family:var(--mono);font-size:10px;color:var(--amber);width:100px;flex-shrink:0;">${ws.component_code||'—'}</div>
        <div style="flex:1;font-size:11px;color:var(--text);">${ws.short_description||ws.component_description||'—'}</div>
        <div style="font-family:var(--mono);font-size:9px;color:var(--text-dim);white-space:nowrap;">${ws.assigned_role||'—'}</div>
        <div style="font-family:var(--mono);font-size:9px;color:${od?'#ef4444':'var(--text-dim)'};white-space:nowrap;">${fmtDate(ws.due_date)}</div>
        ${badge(STATUS_LABEL[ws.status]||ws.status,sc,true)}
        ${badge(ws.criticality,CRIT_COLOR[ws.criticality]||'#6b7280',true)}
        ${od?badge('OVERDUE','#ef4444',true):''}
        <span style="font-family:var(--mono);font-size:9px;color:var(--text-dim);">›</span>
      </div>`;
  }

  function _openWsDetail(wsId) {
    // Navigate to Worksheets tab and filter to show this worksheet
    state.wsStatus = 'all';
    goTab('worksheets');
    // After render, highlight the specific worksheet
    setTimeout(() => {
      const el2 = document.querySelector('[data-wsid="'+wsId+'"]');
      if (el2) { el2.style.border='2px solid var(--amber)'; el2.scrollIntoView({behavior:'smooth',block:'center'}); }
    }, 300);
  }

  function scheduleNav(month, year) {
    state.scheduleMonth=month; state.scheduleYear=year;
    renderSchedule();
  }

  async function previewMonth() {
    const m = state.scheduleMonth + 1, y = state.scheduleYear;
    if (!state.vessel) { toast('Select a vessel first', 'error'); return; }
    try {
      const comps = await api('/api/pms/equipment/all?vessel_name=' + encodeURIComponent(state.vessel));
      if (!Array.isArray(comps)) { toast('Could not load equipment register', 'error'); return; }
      function isDue(freq, yr, mo) {
        if (!freq) return false;
        const match = freq.match(/(\d+)\s*Month/);
        if (!match) return false;
        const interval = parseInt(match[1]);
        const abs = (yr - 2020) * 12 + (mo - 1);
        return abs % interval === 0;
      }
      const due = comps.filter(c => isDue(c.frequency, y, m));
      const wrap = el('schedList');
      if (!wrap) return;
      if (!due.length) { wrap.innerHTML = `<div style="font-family:var(--mono);font-size:10px;color:var(--text-dim);padding:16px;">No components due in ${MONTHS[m-1]} ${y} based on equipment register frequencies.</div>`; return; }
      const CRIT_C = {Critical:'#ef4444',Significant:'#f59e0b',Standard:'#6b7280'};
      const byRole = {};
      due.forEach(c => { (byRole[c.primary_role||'Unassigned']||=[]).push(c); });
      wrap.innerHTML = `
        <div style="font-family:var(--mono);font-size:9px;color:var(--text-dim);margin-bottom:12px;letter-spacing:1px;">
          PREVIEW — ${due.length} COMPONENTS DUE IN ${MONTHS[m-1].toUpperCase()} ${y} (FROM EQUIPMENT REGISTER)
        </div>
        ${Object.entries(byRole).sort().map(([role,cs])=>`
          <div style="margin-bottom:12px;">
            <div style="font-family:var(--mono);font-size:9px;color:var(--amber);margin-bottom:6px;letter-spacing:1px;">${role} — ${cs.length} JOB${cs.length>1?'S':''}</div>
            ${cs.map(c=>`
              <div style="display:flex;gap:8px;padding:7px 10px;background:var(--surface);border:1px solid var(--border);border-left:3px solid ${CRIT_C[c.criticality]||'#6b7280'};border-radius:4px;margin-bottom:4px;align-items:center;">
                <span style="font-family:var(--mono);font-size:10px;color:var(--amber);min-width:100px;">${c.code}</span>
                <span style="font-size:11px;color:var(--text);flex:1;">${c.description||'—'}</span>
                <span style="font-family:var(--mono);font-size:8px;color:var(--text-dim);">${c.frequency}</span>
                <span style="font-family:var(--mono);font-size:8px;padding:2px 6px;border-radius:3px;color:#fff;background:${CRIT_C[c.criticality]||'#6b7280'};">${c.criticality}</span>
              </div>`).join('')}
          </div>`).join('')}
        <div style="margin-top:14px;">
          <button onclick="PMS.issueAll()" style="font-family:var(--mono);font-size:9px;background:var(--amber);color:#000;border:none;padding:8px 20px;border-radius:4px;cursor:pointer;font-weight:700;">⚡ ISSUE ALL ${due.length} WORKSHEETS FOR ${MONTHS[m-1].toUpperCase()} ${y}</button>
        </div>`;
    } catch(e) { toast('Error: ' + e.message, 'error'); }
  }

  async function issueAll() {
    const m = state.scheduleMonth + 1, y = state.scheduleYear;
    if (!state.vessel) { toast('Select a vessel first', 'error'); return; }
    const btn = el('btnIssueMonth');
    if (btn) { btn.disabled=true; btn.textContent='ISSUING…'; }
    try {
      const result = await api('/api/pms/issue-month', {
        method: 'POST',
        body: JSON.stringify({ vessel_name: state.vessel, year: y, month: m })
      });
      if (result.issued === 0) {
        toast(result.message || 'No new worksheets — already issued or none due', 'info');
      } else {
        toast(`Issued ${result.issued} worksheet${result.issued>1?'s':''} for ${MONTHS[m-1]} ${y}`, 'success');
      }
      await loadSchedule();
    } catch(e) {
      toast('Error: ' + e.message, 'error');
    } finally {
      const b = el('btnIssueMonth');
      if (b) { b.disabled=false; b.textContent='⚡ ISSUE MONTH'; }
    }
  }

  // ════════════════════════════════════════════════════════════════════════════
  // 4. WORKSHEETS
  // ════════════════════════════════════════════════════════════════════════════
  async function renderWorksheets() {
    await ensureVessels();
    const content = el('pmsContent');
    content.innerHTML = `
      <div style="max-width:1000px;">
        <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:16px;flex-wrap:wrap;gap:8px;">
          <div style="font-family:var(--mono);font-size:9px;color:var(--text-dim);letter-spacing:2px;">PMS — ISSUED WORKSHEETS</div>
          <div style="display:flex;gap:8px;align-items:center;">
            ${vesselSel()}
            <button onclick="PMS.openWsModal()" style="font-family:var(--mono);font-size:9px;background:var(--amber);color:#000;border:none;padding:6px 12px;border-radius:4px;cursor:pointer;font-weight:700;">+ ISSUE WORKSHEET</button>
          </div>
        </div>
        <div style="display:flex;align-items:center;justify-content:space-between;gap:8px;margin-bottom:16px;flex-wrap:wrap;">
          <div style="display:flex;gap:4px;flex-wrap:wrap;">
            ${['all','issued','wip','awaiting_auth','returned','deferred','authorised'].map(s=>`
              <button onclick="PMS.wsFilter('${s}')"
                style="font-family:var(--mono);font-size:8px;padding:4px 10px;border-radius:4px;cursor:pointer;letter-spacing:0.5px;
                  border:1px solid ${state.wsStatus===s?(STATUS_COLOR[s]||'var(--amber)'):'var(--border)'};
                  background:${state.wsStatus===s?(STATUS_COLOR[s]||'var(--amber)'):'var(--surface2)'};
                  color:${state.wsStatus===s?'#fff':'var(--text-dim)'};">
                ${s==='all'?'ALL':(STATUS_LABEL[s]||s).toUpperCase()}
              </button>`).join('')}
          </div>
          <input id="wsRoleFilter" placeholder="Filter by role/assignee…" value="${state.wsRoleSearch||''}"
            oninput="PMS.wsRoleSearch(this.value)"
            style="font-family:var(--mono);font-size:10px;background:var(--surface2);border:1px solid var(--border);color:var(--text);padding:5px 10px;border-radius:4px;width:180px;">
        </div>
        <div id="pmsWsList"><div style="font-family:var(--mono);font-size:11px;color:var(--text-dim);">Loading…</div></div>
      </div>
      ${wsModalHtml()}`;
    await loadWorksheets();
  }

  function wsModalHtml() { return ''; } // Modal now appended to body, not pmsContent

  // Complete worksheet modal
  function completeModalHtml(wsId) {
    return `
      <div id="pmsCompleteModal" style="display:flex;position:fixed;inset:0;background:rgba(0,0,0,0.65);z-index:300;align-items:center;justify-content:center;">
        <div style="background:var(--surface);border:1px solid var(--border);border-radius:8px;padding:24px;width:580px;max-height:85vh;overflow-y:auto;">
          <div style="font-family:var(--mono);font-size:10px;color:var(--amber);letter-spacing:2px;margin-bottom:20px;">COMPLETE WORKSHEET</div>
          <div style="display:grid;gap:12px;">
            <div>
              <label style="font-family:var(--mono);font-size:8px;color:var(--text-dim);display:block;margin-bottom:4px;">ENGINEER'S REPORT * <span style="color:#ef4444;">(Must be comprehensive — "Completed satisfactorily" is NOT adequate)</span></label>
              <textarea id="cmReport" rows="5" placeholder="Include: measurements taken, condition of component, observations, any anomalies found…"
                style="width:100%;box-sizing:border-box;font-family:var(--mono);font-size:11px;background:var(--surface2);border:1px solid var(--border);color:var(--text);padding:8px;border-radius:3px;resize:vertical;"></textarea>
              <div id="cmReportLen" style="font-family:var(--mono);font-size:8px;color:var(--text-dim);margin-top:3px;">0 characters (minimum 50 recommended)</div>
            </div>
            <div style="display:grid;grid-template-columns:1fr 1fr;gap:10px;">
              <div>
                <label style="font-family:var(--mono);font-size:8px;color:var(--text-dim);display:block;margin-bottom:4px;">COMPLETED BY (RANK)</label>
                <input id="cmRank" placeholder="e.g. 2nd Engineer" style="width:100%;box-sizing:border-box;font-family:var(--mono);font-size:11px;background:var(--surface2);border:1px solid var(--border);color:var(--text);padding:8px;border-radius:3px;">
              </div>
              <div>
                <label style="font-family:var(--mono);font-size:8px;color:var(--text-dim);display:block;margin-bottom:4px;">DATE COMPLETED *</label>
                <input id="cmDate" type="date" style="width:100%;box-sizing:border-box;font-family:var(--mono);font-size:11px;background:var(--surface2);border:1px solid var(--border);color:var(--text);padding:8px;border-radius:3px;">
              </div>
            </div>
            <div>
              <label style="font-family:var(--mono);font-size:8px;color:var(--text-dim);display:block;margin-bottom:4px;">PARTS USED</label>
              <input id="cmParts" placeholder="List parts used, or leave blank if none required" style="width:100%;box-sizing:border-box;font-family:var(--mono);font-size:11px;background:var(--surface2);border:1px solid var(--border);color:var(--text);padding:8px;border-radius:3px;">
            </div>
            <div>
              <label style="font-family:var(--mono);font-size:8px;color:var(--text-dim);display:block;margin-bottom:4px;">SHIP COMMENTS <span style="color:var(--text-dim);">(optional)</span></label>
              <input id="cmComments" placeholder="Any additional comments" style="width:100%;box-sizing:border-box;font-family:var(--mono);font-size:11px;background:var(--surface2);border:1px solid var(--border);color:var(--text);padding:8px;border-radius:3px;">
            </div>
            <div>
              <label style="display:flex;align-items:center;gap:8px;cursor:pointer;">
                <input type="checkbox" id="cmNoPartsChk">
                <span style="font-family:var(--mono);font-size:9px;color:var(--text-dim);">No parts required for this job</span>
              </label>
            </div>
          </div>
          <div style="display:flex;gap:8px;margin-top:20px;justify-content:flex-end;">
            <button onclick="document.getElementById('pmsCompleteModal').remove()" style="font-family:var(--mono);font-size:9px;padding:7px 16px;background:var(--surface2);border:1px solid var(--border);color:var(--text-dim);border-radius:4px;cursor:pointer;">CANCEL</button>
            <button onclick="PMS.submitComplete('${wsId}')" style="font-family:var(--mono);font-size:9px;padding:7px 20px;background:var(--amber);color:#000;border:none;border-radius:4px;cursor:pointer;font-weight:700;">POST COMPLETED WORKSHEET</button>
          </div>
        </div>
      </div>`;
  }

  async function loadWorksheets() {
    const wrap = el('pmsWsList');
    if (!wrap) return;
    try {
      const params = new URLSearchParams({ status: state.wsStatus });
      if (state.vessel) params.set('vessel_name', state.vessel);
      let data = await api(`/api/pms/worksheets?${params}`);
      if (state.wsRoleSearch) {
        const q = state.wsRoleSearch.toLowerCase();
        data = data.filter(w => (w.assigned_role||'').toLowerCase().includes(q) || (w.created_by||'').toLowerCase().includes(q));
      }

      if (!data.length) {
        wrap.innerHTML = `<div style="text-align:center;padding:40px;color:var(--text-dim);">
          <div style="font-size:32px;margin-bottom:12px;">📋</div>
          <div style="font-family:var(--mono);font-size:10px;">NO WORKSHEETS${state.wsStatus!=='all'?' — '+STATUS_LABEL[state.wsStatus].toUpperCase():''}</div>
          <div style="font-size:11px;margin-top:8px;">Issue worksheets using the button above.</div>
        </div>`;
        return;
      }

      const sorted = data.sort((a,b)=>new Date(b.created_at)-new Date(a.created_at));
      wrap.innerHTML = `<div style="display:grid;gap:8px;">${sorted.map(ws=>wsCard(ws)).join('')}</div>`;
    } catch(e) {
      wrap.innerHTML = `<div style="font-family:var(--mono);font-size:11px;color:#ef4444;">Error: ${e.message}</div>`;
    }
  }

  function wsCard(ws) {
    const sc = STATUS_COLOR[ws.status]||'#6b7280';
    const cc = CRIT_COLOR[ws.criticality]||'#6b7280';
    const od = isOverdue(ws);
    const canComplete = ['issued','returned','wip'].includes(ws.status);
    const canAuth = ws.status === 'awaiting_auth';
    return `
      <div data-wsid="${ws.id}" style="background:var(--surface);border:1px solid var(--border);border-left:3px solid ${od?'#ef4444':sc};border-radius:6px;padding:14px;">
        <div style="display:flex;align-items:flex-start;justify-content:space-between;gap:12px;">
          <div style="flex:1;min-width:0;">
            <div style="display:flex;gap:5px;align-items:center;margin-bottom:6px;flex-wrap:wrap;">
              <span style="font-family:var(--mono);font-size:10px;color:var(--amber);">${ws.component_code||'—'}</span>
              ${badge(ws.criticality,cc,true)}
              ${badge(STATUS_LABEL[ws.status]||ws.status,sc,true)}
              ${od?badge('OVERDUE','#ef4444',true):''}
              ${ws.type==='adhoc'?badge('AD-HOC','#8b5cf6',true):''}
              ${ws.type==='cbm'?badge('CBM','#06b6d4',true):''}
            </div>
            <div style="font-weight:600;font-size:12px;color:var(--text-bright);margin-bottom:4px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;">${ws.short_description||ws.component_description||'—'}</div>
            <div style="font-size:10px;color:var(--text-dim);">
              Assigned: <strong style="color:var(--text);">${ws.assigned_role||'—'}</strong>
              · Due: <strong style="color:${od?'#ef4444':'var(--text)'};">${fmtDate(ws.due_date)}</strong>
              · Issued by: ${ws.created_by||'—'} on ${fmtDate(ws.created_at)}
              ${ws.vessel_name?'· '+ws.vessel_name:''}
            </div>
            ${ws.engineers_report?`<div style="margin-top:8px;padding:8px;background:var(--surface2);border-radius:4px;font-size:10px;color:var(--text-dim);line-height:1.5;">${ws.engineers_report.slice(0,180)}${ws.engineers_report.length>180?'…':''}</div>`:''}
            ${ws.status==='returned'&&ws.returned_reason?`<div style="margin-top:6px;padding:6px 8px;background:rgba(239,68,68,0.1);border-radius:4px;font-size:10px;color:#ef4444;">⚠ Returned: ${ws.returned_reason}</div>`:''}
          </div>
          <div style="display:flex;gap:6px;flex-shrink:0;flex-direction:column;align-items:flex-end;">
            ${canComplete?`<button onclick="PMS.openCompleteModal('${ws.id}')" style="font-family:var(--mono);font-size:8px;padding:5px 10px;background:var(--amber);color:#000;border:none;border-radius:3px;cursor:pointer;font-weight:700;">COMPLETE</button>`:''}
            ${canAuth?`
              <button onclick="PMS.authorise('${ws.id}')" style="font-family:var(--mono);font-size:8px;padding:5px 10px;background:#22c55e;color:#fff;border:none;border-radius:3px;cursor:pointer;font-weight:700;">AUTHORISE ✓</button>
              <button onclick="PMS.returnWs('${ws.id}')" style="font-family:var(--mono);font-size:8px;padding:5px 10px;background:transparent;border:1px solid #ef4444;color:#ef4444;border-radius:3px;cursor:pointer;">RETURN</button>`:''}
            ${ws.status==='issued'?`<button onclick="PMS.deferWs('${ws.id}')" style="font-family:var(--mono);font-size:8px;padding:5px 10px;background:transparent;border:1px solid var(--border);color:var(--text-dim);border-radius:3px;cursor:pointer;">DEFER</button>`:''}
          </div>
        </div>
      </div>`;
  }

  function wsFilter(s) { state.wsStatus=s; renderWorksheets(); }
  function wsRoleSearch(v) { state.wsRoleSearch=v; loadWorksheets(); }

  async function openWsModal() {
    // Remove any existing modal
    const existing = document.getElementById('pmsWsModal');
    if (existing) existing.remove();

    // Always reload components for current vessel
    state._wsComponents = [];
    if (state.vessel) {
      try {
        const result = await api('/api/pms/equipment/all?vessel_name=' + encodeURIComponent(state.vessel));
        state._wsComponents = Array.isArray(result) ? result : [];
      } catch(e) {
        state._wsComponents = [];
        toast('Could not load component list: ' + e.message, 'error');
      }
    }

    const IS = 'width:100%;box-sizing:border-box;font-family:var(--mono);font-size:11px;background:var(--surface2);border:1px solid var(--border);color:var(--text);padding:8px;border-radius:3px;';
    const SS = 'width:100%;font-family:var(--mono);font-size:11px;background:var(--surface2);border:1px solid var(--border);color:var(--text);padding:8px;border-radius:3px;';
    const roles = [...new Set(['2nd Eng','3rd Eng','4th Eng','Elect','Cargo Eng','Chief Off','Chief Eng','Master',
      ...state._wsComponents.map(c=>c.primary_role).filter(Boolean)])].sort();

    const modal = document.createElement('div');
    modal.id = 'pmsWsModal';
    modal.style.cssText = 'position:fixed;inset:0;background:rgba(0,0,0,0.7);z-index:1000;display:flex;align-items:center;justify-content:center;';
    modal.innerHTML = `
      <div style="background:var(--surface);border:1px solid var(--border);border-radius:8px;padding:24px;width:620px;max-height:88vh;overflow-y:auto;position:relative;" onclick="event.stopPropagation()">
        <div style="font-family:var(--mono);font-size:10px;color:var(--amber);letter-spacing:2px;margin-bottom:20px;">ISSUE WORKSHEET — ${state.vessel||'Fleet'}</div>

        <div style="margin-bottom:4px;">
          <label style="font-family:var(--mono);font-size:8px;color:var(--text-dim);display:block;margin-bottom:4px;">COMPONENT CODE / DESCRIPTION *</label>
          <input id="wsCompSearch" placeholder="Type to search component code or description…" autocomplete="off"
            style="${IS}border-color:var(--amber);">
          <div id="wsCompDropdown" style="display:none;position:absolute;background:var(--surface);border:1px solid var(--amber);border-top:none;border-radius:0 0 4px 4px;max-height:220px;overflow-y:auto;z-index:20;left:24px;right:24px;"></div>
        </div>
        <div id="wsSelectedComp" style="display:none;padding:7px 10px;background:rgba(245,158,11,0.1);border:1px solid var(--amber);border-radius:4px;margin:8px 0 14px;font-family:var(--mono);font-size:10px;color:var(--amber);"></div>

        <input type="hidden" id="wsCode">
        <input type="hidden" id="wsCompDescHidden">

        <div style="display:grid;gap:12px;">
          <div>
            <label style="font-family:var(--mono);font-size:8px;color:var(--text-dim);display:block;margin-bottom:4px;">SHORT DESCRIPTION — JOB TO BE DONE *</label>
            <input id="wsShort" placeholder="e.g. 1000hr running maintenance — inspect & clean" style="${IS}">
          </div>
          <div>
            <label style="font-family:var(--mono);font-size:8px;color:var(--text-dim);display:block;margin-bottom:4px;">FULL JOB DESCRIPTION</label>
            <textarea id="wsFull" rows="3" placeholder="Detailed scope of work, measurements to take, parameters to record…" style="${IS}resize:vertical;"></textarea>
          </div>
          <div style="display:grid;grid-template-columns:1fr 1fr 1fr;gap:10px;">
            <div>
              <label style="font-family:var(--mono);font-size:8px;color:var(--text-dim);display:block;margin-bottom:4px;">CRITICALITY</label>
              <select id="wsCrit" style="${SS}">
                <option value="Critical">🔴 Critical</option>
                <option value="Significant">🟡 Significant</option>
                <option value="Standard" selected>⚪ Standard</option>
              </select>
            </div>
            <div>
              <label style="font-family:var(--mono);font-size:8px;color:var(--text-dim);display:block;margin-bottom:4px;">ASSIGN TO (ROLE) *</label>
              <select id="wsRole" style="${SS}">
                ${roles.map(r=>`<option value="${r}">${r}</option>`).join('')}
              </select>
            </div>
            <div>
              <label style="font-family:var(--mono);font-size:8px;color:var(--text-dim);display:block;margin-bottom:4px;">TYPE</label>
              <select id="wsType" style="${SS}">
                <option value="planned">Planned PM</option>
                <option value="adhoc">Ad-hoc</option>
                <option value="cbm">CBM Assessment</option>
              </select>
            </div>
          </div>
          <div style="display:grid;grid-template-columns:1fr 1fr;gap:10px;">
            <div>
              <label style="font-family:var(--mono);font-size:8px;color:var(--text-dim);display:block;margin-bottom:4px;">DUE DATE *</label>
              <input id="wsDue" type="date" style="${IS}">
            </div>
            <div>
              <label style="font-family:var(--mono);font-size:8px;color:var(--text-dim);display:block;margin-bottom:4px;">FREQUENCY / INTERVAL</label>
              <input id="wsFreq" readonly placeholder="Auto-filled from equipment register" style="${IS}color:var(--text-dim);">
            </div>
          </div>
          <div>
            <label style="font-family:var(--mono);font-size:8px;color:var(--text-dim);display:block;margin-bottom:4px;">SAFETY NOTES</label>
            <input id="wsSafety" placeholder="Required permits, PPE, precautions, LOTO requirements…" style="${IS}">
          </div>
        </div>

        <div style="display:flex;gap:8px;margin-top:20px;justify-content:flex-end;">
          <button id="wsCancelBtn" style="font-family:var(--mono);font-size:9px;padding:7px 16px;background:var(--surface2);border:1px solid var(--border);color:var(--text-dim);border-radius:4px;cursor:pointer;">CANCEL</button>
          <button id="wsSubmitBtn" style="font-family:var(--mono);font-size:9px;padding:7px 20px;background:var(--amber);color:#000;border:none;border-radius:4px;cursor:pointer;font-weight:700;">ISSUE WORKSHEET</button>
        </div>
      </div>`;

    document.body.appendChild(modal);

    // Update placeholder with component count
    const sp = document.getElementById('wsCompSearch');
    if (sp) sp.placeholder = state._wsComponents.length
      ? 'Click to browse ' + state._wsComponents.length + ' components, or type to search…'
      : 'No components loaded — check vessel selection';

    // Set default due date = end of current month
    const d = new Date(); d.setMonth(d.getMonth()+1); d.setDate(0);
    document.getElementById('wsDue').value = d.toISOString().split('T')[0];

    // Wire buttons via JS (not inline onclick)
    document.getElementById('wsCancelBtn').addEventListener('click', closeWsModal);
    document.getElementById('wsSubmitBtn').addEventListener('click', e => {
      e.stopPropagation();
      saveWs();
    });

    // Wire search input
    const searchInput = document.getElementById('wsCompSearch');
    const dropdown = document.getElementById('wsCompDropdown');

    // Show first 20 on focus if nothing typed yet
    searchInput.addEventListener('focus', function() {
      if (!this.value.trim() && state._wsComponents.length) {
        const q = '';
        const matches = state._wsComponents.slice(0, 20);
        renderDropdown(matches);
      }
    });

    function renderDropdown(matches) {
      if (!matches.length) { dropdown.style.display='none'; return; }
      const CRIT_C = {Critical:'#ef4444', Significant:'#f59e0b', Standard:'#6b7280'};
      dropdown.innerHTML = matches.map((c,i) => {
        const desc = (c.description||'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');
        return `<div class="wsCi" data-i="${i}" style="padding:8px 10px;cursor:pointer;border-bottom:1px solid var(--border);display:flex;gap:8px;align-items:center;">
          <span style="font-family:var(--mono);font-size:10px;color:var(--amber);min-width:90px;flex-shrink:0;">${c.code}</span>
          <span style="font-size:11px;color:var(--text);flex:1;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;">${desc}</span>
          <span style="font-family:var(--mono);font-size:8px;color:${CRIT_C[c.criticality]||'#6b7280'};flex-shrink:0;">${c.criticality||''}</span>
          <span style="font-family:var(--mono);font-size:8px;color:var(--text-dim);flex-shrink:0;">${c.primary_role||''}</span>
        </div>`;
      }).join('');
      dropdown._matches = matches;
      dropdown.style.display = 'block';
    }

    searchInput.addEventListener('input', function() {
      const val = this.value.trim();
      if (val.length < 1) { dropdown.style.display='none'; return; }
      const q = val.toLowerCase();
      const matches = state._wsComponents.filter(c =>
        c.code.toLowerCase().includes(q) || (c.description||'').toLowerCase().includes(q)
      ).slice(0, 40);

      if (!matches.length) { dropdown.style.display='none'; return; }

      renderDropdown(matches);
    });

    dropdown.addEventListener('click', function(e) {
      const item = e.target.closest('.wsCi');
      if (!item) return;
      const c = this._matches[parseInt(item.dataset.i)];
      if (!c) return;
      // Fill fields
      document.getElementById('wsCode').value = c.code;
      document.getElementById('wsCompDescHidden').value = c.description||'';
      document.getElementById('wsFreq').value = c.frequency||'';
      // Auto-select criticality
      const critSel = document.getElementById('wsCrit');
      for (const o of critSel.options) if (o.value === c.criticality) { o.selected=true; break; }
      // Auto-select role
      const roleSel = document.getElementById('wsRole');
      for (const o of roleSel.options) if (o.value === c.primary_role) { o.selected=true; break; }
      // Show confirmation
      const CRIT_C = {Critical:'#ef4444', Significant:'#f59e0b', Standard:'#6b7280'};
      const sel = document.getElementById('wsSelectedComp');
      sel.style.display = 'block';
      sel.innerHTML = `✓ <strong>${c.code}</strong> — ${(c.description||'').replace(/</g,'&lt;')} <span style="float:right;color:${CRIT_C[c.criticality]||'#6b7280'}">${c.criticality}</span>`;
      // Update search text and hide dropdown
      searchInput.value = c.code + (c.description ? ' — ' + c.description : '');
      dropdown.style.display = 'none';
    });

    // Hover effect on dropdown items
    dropdown.addEventListener('mouseover', e => { const t=e.target.closest('.wsCi'); if(t) t.style.background='var(--surface2)'; });
    dropdown.addEventListener('mouseout',  e => { const t=e.target.closest('.wsCi'); if(t) t.style.background=''; });

    // Close dropdown on outside click
    document.addEventListener('click', function outsideClick(e) {
      if (!dropdown.contains(e.target) && e.target !== searchInput) {
        dropdown.style.display='none';
        document.removeEventListener('click', outsideClick);
      }
    });

    // Close modal on backdrop click
    modal.addEventListener('click', e => { if (e.target === modal) closeWsModal(); });
  }

  function closeWsModal() {
    const m = document.getElementById('pmsWsModal');
    if (m) m.remove();
    // _wsComponents kept in cache — resets when vessel changes via setVessel()
  }

  async function saveWs() {
    const g = id => document.getElementById(id);
    const code = (g('wsCode')?.value || '').trim();
    const shortDesc = (g('wsShort')?.value || '').trim();
    const dueDate = g('wsDue')?.value || '';

    if (!code) { toast('Select a component from the dropdown first', 'error'); return; }
    if (!shortDesc) { toast('Short description is required', 'error'); return; }
    if (!dueDate) { toast('Due date is required', 'error'); return; }
    if (!state.vessel) { toast('No vessel selected', 'error'); return; }

    const btn = g('wsSubmitBtn');
    if (btn) { btn.disabled=true; btn.textContent='ISSUING…'; }

    const payload = {
      vessel_name: state.vessel,
      component_code: code,
      component_description: (g('wsCompDescHidden')?.value || '').trim(),
      short_description: shortDesc,
      full_description: (g('wsFull')?.value || '').trim(),
      assigned_role: g('wsRole')?.value || '2nd Eng',
      criticality: g('wsCrit')?.value || 'Standard',
      due_date: dueDate,
      type: g('wsType')?.value || 'planned',
      safety_notes: (g('wsSafety')?.value || '').trim(),
      frequency: (g('wsFreq')?.value || '').trim(),
    };

    try {
      const result = await api('/api/pms/worksheets', {
        method: 'POST',
        body: JSON.stringify(payload)
      });
      closeWsModal();
      toast('Worksheet issued: ' + result.id, 'success');
      await loadWorksheets();
    } catch(e) {
      const b = document.getElementById('wsSubmitBtn');
      if (b) { b.disabled=false; b.textContent='ISSUE WORKSHEET'; }
      toast('Failed to issue: ' + e.message, 'error');
    }
  }

  function openCompleteModal(wsId) {
    // Remove any existing modal
    const old = el('pmsCompleteModal');
    if (old) old.remove();
    document.body.insertAdjacentHTML('beforeend', completeModalHtml(wsId));
    // Set today's date
    const d=el('cmDate'); if(d) d.value=new Date().toISOString().split('T')[0];
    // Character counter
    const report=el('cmReport');
    if (report) report.addEventListener('input', ()=>{
      const len=el('cmReportLen');
      if(len) len.textContent=`${report.value.length} characters${report.value.length<50?' — please provide more detail':''}`;
      len.style.color = report.value.length < 50 ? '#ef4444' : 'var(--text-dim)';
    });
  }

  async function submitComplete(wsId) {
    const report=el('cmReport')?.value?.trim();
    if (!report || report.length < 20) { toast('Engineer\'s Report must be comprehensive','error'); return; }
    const noParts=el('cmNoPartsChk')?.checked;
    const parts=el('cmParts')?.value?.trim();
    if (!noParts && !parts) { toast('Either list parts used or check "No parts required"','error'); return; }
    try {
      await api(`/api/pms/worksheets/${wsId}`,{
        method:'PUT',
        body: JSON.stringify({
          action:'complete',
          engineers_report: report,
          completed_by_rank: el('cmRank')?.value?.trim(),
          completed_date: el('cmDate')?.value,
          parts_used: noParts ? 'No parts required' : parts,
          ship_comments: el('cmComments')?.value?.trim(),
        })
      });
      const m=el('pmsCompleteModal'); if(m) m.remove();
      toast('Worksheet posted — awaiting CE authorisation','success');
      await loadWorksheets();
    } catch(e) { toast('Error: '+e.message,'error'); }
  }

  async function authorise(wsId) {
    if (!confirm('Authorise this worksheet? No changes can be made after authorisation.')) return;
    try {
      await api(`/api/pms/worksheets/${wsId}`,{method:'PUT',body:JSON.stringify({action:'authorise'})});
      toast('Worksheet authorised and locked','success');
      await loadWorksheets();
    } catch(e) { toast('Error: '+e.message,'error'); }
  }

  async function returnWs(wsId) {
    const reason=prompt('Reason for returning (will be shown to officer — be specific about what is missing):');
    if (!reason?.trim()) return;
    try {
      await api(`/api/pms/worksheets/${wsId}`,{method:'PUT',body:JSON.stringify({action:'return',reason})});
      toast('Worksheet returned to officer','info');
      await loadWorksheets();
    } catch(e) { toast('Error: '+e.message,'error'); }
  }

  async function deferWs(wsId) {
    const until=prompt('Defer until date (YYYY-MM-DD):');
    const reason=prompt('Reason for deferral:');
    if (!until||!reason?.trim()) return;
    try {
      await api(`/api/pms/worksheets/${wsId}`,{method:'PUT',body:JSON.stringify({action:'defer',defer_until:until,defer_reason:reason})});
      toast('Worksheet deferred','info');
      await loadWorksheets();
    } catch(e) { toast('Error: '+e.message,'error'); }
  }

  // ════════════════════════════════════════════════════════════════════════════
  // 5. RUNNING HOURS
  // ════════════════════════════════════════════════════════════════════════════
  async function renderRunningHours() {
    await ensureVessels();
    const content = el('pmsContent');
    content.innerHTML = `
      <div style="max-width:1100px;">
        <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:16px;">
          <div style="font-family:var(--mono);font-size:9px;color:var(--text-dim);letter-spacing:2px;">PMS — RUNNING HOURS</div>
          ${vesselSel()}
        </div>
        <div id="rhEquipList"><div style="font-family:var(--mono);font-size:10px;color:var(--text-dim);">Loading equipment register…</div></div>
      </div>`;
    await loadRunningHours();
  }

  async function loadRunningHoursEquip() {
    if (!state.vessel) return [];
    try {
      const comps = await api('/api/pms/equipment/all?vessel_name=' + encodeURIComponent(state.vessel));
      return Array.isArray(comps) ? comps.filter(c => c.frequency && c.frequency.includes('Hour')) : [];
    } catch(e) { return []; }
  }

  function calcHrs() {} // replaced by inline _rhFlag

  function _rhFlag(input, code, prevReading, interval) {
    const val = parseFloat(input.value);
    const flagId = 'rh-flag-' + code.replace(/\./g,'_');
    const flagEl = document.getElementById(flagId);
    if (!flagEl) return;
    if (isNaN(val)) { flagEl.textContent=''; return; }
    const run = val - prevReading;
    if (run < 0) {
      flagEl.style.color='#ef4444';
      flagEl.textContent = '⚠ Cannot be less than last reading (' + prevReading + ')';
    } else if (interval && run >= interval) {
      flagEl.style.color='#ef4444';
      flagEl.textContent = '🚨 EXCEEDS INTERVAL (' + interval + ' hrs) — overdue by ' + Math.round(run-interval) + ' hrs';
    } else if (interval && run >= interval * 0.9) {
      flagEl.style.color='#f59e0b';
      flagEl.textContent = '⚠ Approaching interval limit (' + Math.round(interval-run) + ' hrs remaining)';
    } else if (run > 0) {
      flagEl.style.color='#22c55e';
      flagEl.textContent = '+' + run.toFixed(0) + ' hrs since last reading';
    }
  }

  async function _rhSaveRow(code) {
    const input = document.querySelector('.rhNewInput[data-code="'+code+'"]');
    if (!input) return;
    const newReading = parseFloat(input.value);
    const prevReading = parseFloat(input.dataset.prev||0);
    const desc = input.dataset.desc || '';
    if (isNaN(newReading) || newReading < 0) { toast('Enter a valid reading', 'error'); return; }
    if (newReading < prevReading) { toast('New reading cannot be less than previous ('+prevReading+')', 'error'); return; }
    try {
      await api('/api/pms/running-hours', {
        method: 'POST',
        body: JSON.stringify({
          vessel_name: state.vessel,
          component_code: code,
          assembly_name: desc,
          previous_reading: prevReading,
          new_reading: newReading
        })
      });
      toast('Hours logged for ' + code, 'success');
      input.value = '';
      const flagEl = document.getElementById('rh-flag-' + code.replace(/\./g,'_'));
      if (flagEl) flagEl.textContent = '';
      // Update the last reading cell in same row
      const row = input.closest('tr');
      if (row) {
        const cells = row.querySelectorAll('td');
        if (cells[3]) cells[3].textContent = newReading;
        if (cells[4]) cells[4].textContent = 'Just now';
        input.placeholder = 'Last: ' + newReading;
        input.dataset.prev = newReading;
      }
    } catch(e) { toast('Error: ' + e.message, 'error'); }
  }

  async function loadRunningHours() {
    const wrap = el('rhEquipList'); if (!wrap) return;
    if (!state.vessel) { wrap.innerHTML='<div style="font-family:var(--mono);font-size:10px;color:var(--text-dim);">Select a vessel above.</div>'; return; }

    wrap.innerHTML = '<div style="font-family:var(--mono);font-size:10px;color:var(--text-dim);">Loading…</div>';

    const [hrsComps, readings] = await Promise.all([
      loadRunningHoursEquip(),
      api('/api/pms/running-hours?vessel_name=' + encodeURIComponent(state.vessel)).catch(()=>[])
    ]);

    // Build last reading map
    const lastReading = {};
    readings.forEach(r => {
      if (!lastReading[r.component_code] || new Date(r.recorded_at) > new Date(lastReading[r.component_code].recorded_at)) {
        lastReading[r.component_code] = r;
      }
    });

    // Calculate monthly hours run flag: hours run in last 30 days
    const now = new Date();
    const monthAgo = new Date(now - 30*24*3600*1000);
    const monthlyHrs = {};
    readings.forEach(r => {
      if (new Date(r.recorded_at) >= monthAgo) {
        monthlyHrs[r.component_code] = (monthlyHrs[r.component_code]||0) + (r.hours_run||0);
      }
    });

    if (!hrsComps.length) {
      wrap.innerHTML = '<div style="font-family:var(--mono);font-size:10px;color:var(--text-dim);">No hours-based components in equipment register for this vessel.</div>';
      return;
    }

    // Group by assembly prefix (first 3 digits of code)
    const groups = {};
    hrsComps.forEach(c => {
      const prefix = c.code.split('.')[0];
      (groups[prefix]||=[]).push(c);
    });

    // Parse interval hours from frequency string
    function intervalHrs(freq) {
      const m = (freq||'').match(/(\d+)\s*Hour/);
      return m ? parseInt(m[1]) : null;
    }

    const IS = 'font-family:var(--mono);font-size:11px;background:var(--surface2);border:1px solid var(--border);color:var(--text);padding:6px 8px;border-radius:3px;width:110px;box-sizing:border-box;';

    wrap.innerHTML = `
      <div style="font-family:var(--mono);font-size:9px;color:var(--text-dim);margin-bottom:14px;letter-spacing:1px;">
        ${hrsComps.length} HOUR-BASED COMPONENTS — UPDATE RUNNING HOURS BELOW
      </div>
      <div style="overflow-x:auto;">
        <table style="width:100%;border-collapse:collapse;font-size:11px;">
          <thead><tr style="border-bottom:2px solid var(--border);position:sticky;top:0;background:var(--bg);">
            ${['CODE','DESCRIPTION','INTERVAL','LAST READING (hrs)','LAST UPDATED','NEW READING (hrs)',''].map(h=>
              `<th style="padding:7px 8px;text-align:left;font-family:var(--mono);font-size:8px;color:var(--text-dim);letter-spacing:1px;white-space:nowrap;">${h}</th>`
            ).join('')}
          </tr></thead>
          <tbody id="rhTableBody">
            ${hrsComps.map((c,i) => {
              const lr = lastReading[c.code];
              const lastHrs = lr ? lr.new_reading : '—';
              const lastDate = lr ? fmtDate(lr.recorded_at) : '—';
              const interval = intervalHrs(c.frequency);
              const mHrs = monthlyHrs[c.code]||0;
              // Flag if monthly hours > interval (overdue)
              const overdue = lr && interval && (lr.new_reading - (lastReading[c.code+'_prev']||0)) >= interval;
              // Flag if no reading logged and interval <= 1000hrs (should have recent reading)
              const noReading = !lr && interval && interval <= 2000;
              const rowBg = i%2===0 ? 'var(--surface)' : 'var(--surface2)';
              const CRIT_C = {Critical:'#ef4444',Significant:'#f59e0b',Standard:'#6b7280'};
              return `<tr style="border-bottom:1px solid var(--border);background:${rowBg};" data-code="${c.code}">
                <td style="padding:6px 8px;font-family:var(--mono);font-size:10px;color:var(--amber);white-space:nowrap;">${c.code}</td>
                <td style="padding:6px 8px;max-width:250px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;color:var(--text);" title="${(c.description||'').replace(/"/g,'')}">${c.description||'—'}</td>
                <td style="padding:6px 8px;font-family:var(--mono);font-size:9px;color:${CRIT_C[c.criticality]||'#6b7280'};white-space:nowrap;">${c.frequency}</td>
                <td style="padding:6px 8px;font-family:var(--mono);font-size:11px;font-weight:600;color:${noReading?'#ef4444':'var(--text)'};">${lastHrs}${noReading?' ⚠':''}</td>
                <td style="padding:6px 8px;font-family:var(--mono);font-size:9px;color:var(--text-dim);white-space:nowrap;">${lastDate}</td>
                <td style="padding:6px 8px;">
                  <input type="number" class="rhNewInput" data-code="${c.code}" data-prev="${lr?lr.new_reading:0}" data-desc="${(c.description||'').replace(/"/g,'&quot;')}"
                    placeholder="${lr ? 'Last: '+lr.new_reading : 'Enter hrs'}"
                    style="${IS}"
                    oninput="PMS._rhFlag(this,'${c.code}',${lr?lr.new_reading:0},${interval||0})">
                  <div id="rh-flag-${c.code.replace(/\./g,'_')}" style="font-family:var(--mono);font-size:8px;margin-top:2px;min-height:12px;"></div>
                </td>
                <td style="padding:6px 8px;">
                  <button onclick="PMS._rhSaveRow('${c.code}')" style="font-family:var(--mono);font-size:8px;background:var(--amber);color:#000;border:none;padding:4px 8px;border-radius:3px;cursor:pointer;font-weight:700;white-space:nowrap;">LOG</button>
                </td>
              </tr>`;
            }).join('')}
          </tbody>
        </table>
      </div>`;
  }

  async function logHrs() {} // replaced by _rhSaveRow inline

  // ════════════════════════════════════════════════════════════════════════════
  // 6. DEFECT LOG
  // ════════════════════════════════════════════════════════════════════════════
  async function renderDefects() {
    await ensureVessels();
    const content=el('pmsContent');
    content.innerHTML = `
      <div style="max-width:900px;">
        <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:16px;flex-wrap:wrap;gap:8px;">
          <div style="font-family:var(--mono);font-size:9px;color:var(--text-dim);letter-spacing:2px;">PMS — DEFECT LOG</div>
          <div style="display:flex;gap:8px;align-items:center;">
            ${vesselSel()}
            <button onclick="PMS.openDefectModal()" style="font-family:var(--mono);font-size:9px;background:var(--amber);color:#000;border:none;padding:6px 12px;border-radius:4px;cursor:pointer;font-weight:700;">+ LOG DEFECT</button>
          </div>
        </div>
        <div id="pmsDefectList"><div style="font-family:var(--mono);font-size:11px;color:var(--text-dim);">Loading…</div></div>
        <div id="pmsDefectModal" style="display:none;position:fixed;inset:0;background:rgba(0,0,0,0.65);z-index:300;align-items:center;justify-content:center;">
          <div style="background:var(--surface);border:1px solid var(--border);border-radius:8px;padding:24px;width:520px;max-height:80vh;overflow-y:auto;">
            <div style="font-family:var(--mono);font-size:10px;color:var(--amber);letter-spacing:2px;margin-bottom:16px;">LOG DEFECT</div>
            <div style="display:grid;gap:10px;">
              <div style="display:grid;grid-template-columns:1fr 1fr;gap:10px;">
                <div>
                  <label style="font-family:var(--mono);font-size:8px;color:var(--text-dim);display:block;margin-bottom:4px;">COMPONENT CODE</label>
                  <input id="defCode" placeholder="e.g. 350.10.01" style="width:100%;box-sizing:border-box;font-family:var(--mono);font-size:11px;background:var(--surface2);border:1px solid var(--border);color:var(--text);padding:7px;border-radius:3px;">
                </div>
                <div>
                  <label style="font-family:var(--mono);font-size:8px;color:var(--text-dim);display:block;margin-bottom:4px;">CRITICALITY</label>
                  <select id="defCrit" style="width:100%;font-family:var(--mono);font-size:11px;background:var(--surface2);border:1px solid var(--border);color:var(--text);padding:7px;border-radius:3px;">
                    <option value="Critical">🔴 Critical</option>
                    <option value="Significant">🟡 Significant</option>
                    <option value="Standard" selected>⚪ Standard</option>
                  </select>
                </div>
              </div>
              <div>
                <label style="font-family:var(--mono);font-size:8px;color:var(--text-dim);display:block;margin-bottom:4px;">DEFECT TITLE *</label>
                <input id="defTitle" placeholder="Short description of defect" style="width:100%;box-sizing:border-box;font-family:var(--mono);font-size:11px;background:var(--surface2);border:1px solid var(--border);color:var(--text);padding:7px;border-radius:3px;">
              </div>
              <div>
                <label style="font-family:var(--mono);font-size:8px;color:var(--text-dim);display:block;margin-bottom:4px;">DESCRIPTION *</label>
                <textarea id="defDesc" rows="3" placeholder="Full description of defect found…" style="width:100%;box-sizing:border-box;font-family:var(--mono);font-size:11px;background:var(--surface2);border:1px solid var(--border);color:var(--text);padding:7px;border-radius:3px;resize:vertical;"></textarea>
              </div>
              <div>
                <label style="font-family:var(--mono);font-size:8px;color:var(--text-dim);display:block;margin-bottom:4px;">REPORTED BY</label>
                <input id="defBy" placeholder="Officer rank / name" style="width:100%;box-sizing:border-box;font-family:var(--mono);font-size:11px;background:var(--surface2);border:1px solid var(--border);color:var(--text);padding:7px;border-radius:3px;">
              </div>
            </div>
            <div style="display:flex;gap:8px;margin-top:16px;justify-content:flex-end;">
              <button onclick="el('pmsDefectModal').style.display='none'" style="font-family:var(--mono);font-size:9px;padding:7px 16px;background:var(--surface2);border:1px solid var(--border);color:var(--text-dim);border-radius:4px;cursor:pointer;">CANCEL</button>
              <button onclick="PMS.saveDefect()" style="font-family:var(--mono);font-size:9px;padding:7px 20px;background:var(--amber);color:#000;border:none;border-radius:4px;cursor:pointer;font-weight:700;">LOG DEFECT</button>
            </div>
          </div>
        </div>
      </div>`;
    await loadDefects();
  }

  function openDefectModal() { const m=el('pmsDefectModal'); if(m) m.style.display='flex'; }

  async function loadDefects() {
    const wrap=el('pmsDefectList'); if(!wrap) return;
    try {
      const params=state.vessel?`?vessel_name=${encodeURIComponent(state.vessel)}`:'';
      const data=await api(`/api/pms/defects${params}`);
      if (!data.length) {
        wrap.innerHTML=`<div style="text-align:center;padding:40px;color:var(--text-dim);">
          <div style="font-size:32px;margin-bottom:12px;">✅</div>
          <div style="font-family:var(--mono);font-size:10px;">NO OPEN DEFECTS</div></div>`;
        return;
      }
      const open=data.filter(d=>d.status==='open'), closed=data.filter(d=>d.status!=='open');
      wrap.innerHTML=`
        <div style="display:flex;gap:8px;margin-bottom:12px;">
          ${badge(open.length+' OPEN','#ef4444')} ${badge(closed.length+' CLOSED','#22c55e')}
        </div>
        <div style="display:grid;gap:8px;">${data.map(d=>defectCard(d)).join('')}</div>`;
    } catch(e) { wrap.innerHTML=`<div style="color:#ef4444;font-size:11px;">${e.message}</div>`; }
  }

  function defectCard(d) {
    const cc=CRIT_COLOR[d.criticality]||'#6b7280';
    return `
      <div style="background:var(--surface);border:1px solid var(--border);border-left:3px solid ${d.status==='closed'?'#22c55e':cc};border-radius:6px;padding:14px;">
        <div style="display:flex;align-items:flex-start;justify-content:space-between;gap:10px;">
          <div style="flex:1;">
            <div style="display:flex;gap:5px;align-items:center;margin-bottom:6px;flex-wrap:wrap;">
              ${d.component_code?`<span style="font-family:var(--mono);font-size:10px;color:var(--amber);">${d.component_code}</span>`:''}
              ${badge(d.criticality,cc,true)}
              ${badge(d.status==='closed'?'CLOSED':'OPEN',d.status==='closed'?'#22c55e':'#ef4444',true)}
            </div>
            <div style="font-weight:600;font-size:12px;color:var(--text-bright);margin-bottom:4px;">${d.title||'—'}</div>
            <div style="font-size:11px;color:var(--text-dim);line-height:1.5;">${d.description||''}</div>
            <div style="font-family:var(--mono);font-size:9px;color:var(--text-dim);margin-top:6px;">Raised: ${fmtDate(d.raised_at)} · ${d.raised_by}${d.reported_by?' · '+d.reported_by:''}</div>
            ${d.updates?.length?`<div style="margin-top:6px;padding:5px 8px;background:var(--surface2);border-radius:4px;font-size:10px;color:var(--text-dim);">Latest: ${d.updates[d.updates.length-1].note}</div>`:''}
          </div>
          ${d.status==='open'?`<button onclick="PMS.closeDefect('${d.id}')" style="font-family:var(--mono);font-size:8px;padding:5px 10px;background:#22c55e;color:#fff;border:none;border-radius:3px;cursor:pointer;flex-shrink:0;">CLOSE</button>`:''}
        </div>
      </div>`;
  }

  async function saveDefect() {
    const title=el('defTitle')?.value?.trim(), desc=el('defDesc')?.value?.trim();
    if (!title||!desc) { toast('Title and description are required','error'); return; }
    try {
      await api('/api/pms/defects',{
        method:'POST',
        body: JSON.stringify({
          vessel_name: state.vessel,
          component_code: el('defCode')?.value?.trim(),
          title, description: desc,
          criticality: el('defCrit')?.value||'Standard',
          reported_by: el('defBy')?.value?.trim(),
        })
      });
      el('pmsDefectModal').style.display='none';
      toast('Defect logged','success');
      await loadDefects();
    } catch(e) { toast('Error: '+e.message,'error'); }
  }

  async function closeDefect(id) {
    const note=prompt('Closing note (what was done to resolve):');
    if (!note?.trim()) return;
    try {
      await api(`/api/pms/defects/${id}`,{method:'PUT',body:JSON.stringify({status:'closed',update_note:note})});
      toast('Defect closed','success');
      await loadDefects();
    } catch(e) { toast('Error: '+e.message,'error'); }
  }

  // ════════════════════════════════════════════════════════════════════════════
  // 7. JOB HISTORY
  // ════════════════════════════════════════════════════════════════════════════
  async function renderHistory() {
    await ensureVessels();
    const content=el('pmsContent');
    const stats=state.stats;
    content.innerHTML=`
      <div style="max-width:1000px;">
        <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:16px;">
          <div style="font-family:var(--mono);font-size:9px;color:var(--text-dim);letter-spacing:2px;">PMS — JOB HISTORY</div>
          ${vesselSel()}
        </div>
        <div style="background:var(--surface);border:1px solid var(--border);border-radius:8px;padding:20px;margin-bottom:16px;">
          <div style="font-family:var(--mono);font-size:9px;color:var(--amber);letter-spacing:1px;margin-bottom:14px;">📁 HISTORICAL RECORDS — PROP WORKSHEET ARCHIVE (2020–2026)</div>
          <div style="display:grid;grid-template-columns:repeat(3,1fr);gap:10px;margin-bottom:16px;">
            ${Object.entries(stats).map(([v,s])=>`
              <div style="background:var(--surface2);border-radius:6px;padding:12px;cursor:pointer;" onclick="PMS.setVessel('${v}');PMS.render();">
                <div style="font-family:var(--mono);font-size:9px;color:var(--amber);margin-bottom:6px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;">${v}</div>
                <div style="font-family:var(--mono);font-size:22px;font-weight:700;color:var(--text);">${(s.total_records||0).toLocaleString()}</div>
                <div style="font-family:var(--mono);font-size:7px;color:var(--text-dim);letter-spacing:1px;">RECORDS</div>
                <div style="margin-top:6px;display:flex;gap:8px;">
                  <span style="font-family:var(--mono);font-size:8px;color:var(--text-dim);">${s.adhoc_count||0} ad-hoc</span>
                  <span style="font-family:var(--mono);font-size:8px;color:var(--text-dim);">${Object.keys(s.done_by||{}).length} roles</span>
                </div>
              </div>`).join('')}
          </div>
          <div style="font-size:11px;color:var(--text-dim);line-height:1.8;">
            Full searchable worksheet history coming in Phase 1 completion. Completed worksheets from FORCAP appear here once authorised by CE.
          </div>
        </div>
        <div id="pmsHistoryLive"><div style="font-family:var(--mono);font-size:11px;color:var(--text-dim);">Loading completed worksheets…</div></div>
      </div>`;
    await loadHistoryLive();
  }

  async function loadHistoryLive() {
    const wrap=el('pmsHistoryLive'); if(!wrap) return;
    try {
      const params=new URLSearchParams({status:'authorised'});
      if (state.vessel) params.set('vessel_name',state.vessel);
      const data=await api(`/api/pms/worksheets?${params}`);
      if (!data.length) { wrap.innerHTML=`<div style="font-family:var(--mono);font-size:10px;color:var(--text-dim);">No authorised worksheets yet — completed and authorised worksheets will appear here.</div>`; return; }
      wrap.innerHTML=`
        <div style="font-family:var(--mono);font-size:9px;color:var(--text-dim);letter-spacing:1px;margin-bottom:10px;">COMPLETED WORKSHEETS (FORCAP)</div>
        <div style="display:grid;gap:6px;">
          ${data.map(ws=>`
            <div style="display:flex;gap:10px;padding:10px 12px;background:var(--surface);border:1px solid var(--border);border-left:3px solid #22c55e;border-radius:6px;align-items:center;">
              <div style="font-family:var(--mono);font-size:10px;color:var(--amber);width:100px;flex-shrink:0;">${ws.component_code||'—'}</div>
              <div style="flex:1;font-size:11px;color:var(--text);">${ws.short_description||'—'}</div>
              <div style="font-family:var(--mono);font-size:9px;color:var(--text-dim);">${ws.assigned_role||'—'}</div>
              <div style="font-family:var(--mono);font-size:9px;color:#22c55e;">${fmtDate(ws.authorised_at||ws.updated_at)}</div>
              ${badge('AUTHORISED','#22c55e',true)}
            </div>`).join('')}
        </div>`;
    } catch(e) { wrap.innerHTML=`<div style="color:#ef4444;font-size:11px;">${e.message}</div>`; }
  }

  // ════════════════════════════════════════════════════════════════════════════
  // 8. AI PREDICTIVE
  // ════════════════════════════════════════════════════════════════════════════
  function renderPredictive() {
    const hotspots=[
      {code:'906.10',desc:'Gas Detection System',vessels:4,count:96,risk:'HIGH'},
      {code:'320.xx',desc:'Main Generator Engines',vessels:4,count:160,risk:'HIGH'},
      {code:'535.xx',desc:'Air Compressors',vessels:4,count:89,risk:'HIGH'},
      {code:'233.10',desc:'Cargo Valve Hydraulic System',vessels:3,count:46,risk:'MEDIUM'},
      {code:'350.17/27/37',desc:'MGE Lube Oil Systems (LPG)',vessels:1,count:36,risk:'MEDIUM'},
      {code:'570.xx',desc:'HFO/LO Purifiers (LPG)',vessels:1,count:18,risk:'MEDIUM'},
    ];
    el('pmsContent').innerHTML=`
      <div style="max-width:900px;">
        <div style="font-family:var(--mono);font-size:9px;color:var(--text-dim);letter-spacing:2px;margin-bottom:20px;">PMS — AI PREDICTIVE ANALYSIS</div>
        <div style="background:var(--surface);border:1px solid var(--border);border-radius:8px;padding:20px;margin-bottom:16px;">
          <div style="font-family:var(--mono);font-size:9px;color:var(--amber);letter-spacing:1px;margin-bottom:14px;">⚠ FLEET FAILURE HOTSPOTS — 119,357 HISTORICAL RECORDS</div>
          <div style="display:grid;gap:8px;">
            ${hotspots.map((h,i)=>`
              <div style="display:flex;align-items:center;gap:12px;padding:10px 12px;background:var(--surface2);border-radius:4px;border-left:3px solid ${h.risk==='HIGH'?'#ef4444':'#f59e0b'};">
                <div style="font-family:var(--mono);font-size:10px;color:var(--amber);width:120px;flex-shrink:0;">${h.code}</div>
                <div style="flex:1;">
                  <div style="font-size:12px;color:var(--text-bright);">${h.desc}</div>
                  <div style="font-family:var(--mono);font-size:9px;color:var(--text-dim);margin-top:2px;">${h.vessels} vessel${h.vessels>1?'s':''} · ${h.count} ad-hoc jobs</div>
                </div>
                ${badge(h.risk+' RISK',h.risk==='HIGH'?'#ef4444':'#f59e0b')}
              </div>`).join('')}
          </div>
        </div>
        <div style="background:var(--surface);border:1px solid var(--border);border-radius:8px;padding:20px;">
          <div style="font-family:var(--mono);font-size:9px;color:var(--text-dim);letter-spacing:1px;margin-bottom:14px;">🤖 PREDICTIVE FEATURES — PHASE 4</div>
          ${[['Cross-fleet early warning','When a component fails on one vessel, check if sister vessels are approaching the same PM interval'],
             ['Repetitive failure detection','Flag components with 3+ ad-hoc jobs in 12 months for root cause investigation'],
             ['Running hours acceleration','When hours rate exceeds historical average, bring forward hours-based PMs'],
             ['Knowledge Repository link','When defect logged, automatically surface relevant OEM manual section'],
             ['Custodian scoring','Officer PM compliance score per trip, pre-populated into CE appraisal'],
            ].map(([f,d])=>`
            <div style="padding:10px 12px;background:var(--surface2);border-radius:4px;border-left:3px solid var(--border);margin-bottom:6px;">
              <div style="font-size:12px;color:var(--text);margin-bottom:3px;">${f}</div>
              <div style="font-size:11px;color:var(--text-dim);">${d}</div>
            </div>`).join('')}
        </div>
      </div>`;
  }

  // ── Also update the worksheets API call to support vessel_name filter ───────
  // (handled server-side, just need frontend to pass it)

  // ── CSS ────────────────────────────────────────────────────────────────────
  (() => {
    if (document.getElementById('pms-css')) return;
    const s=document.createElement('style');
    s.id='pms-css';
    s.textContent=`
      #pmsContent input:focus, #pmsContent select:focus, #pmsContent textarea:focus {
        outline:none; border-color:var(--amber) !important;
      }
      #pmsContent button:disabled { opacity:0.4; cursor:default; }
    `;
    document.head.appendChild(s);
  })();

  // ── Public ─────────────────────────────────────────────────────────────────
  return {
    init, render, setVessel,
    refreshOverview, goTab, openVesselDashboard, _openWsDetail,
    equipSearch, equipFilter, equipPage,
    wsFilter, wsRoleSearch, openWsModal, closeWsModal, saveWs,
    openCompleteModal, submitComplete, authorise, returnWs, deferWs,
    scheduleNav, issueAll, previewMonth,
    calcHrs, logHrs, _rhFlag, _rhSaveRow,
    openDefectModal, saveDefect, closeDefect,
  };

})();
window.PMS = PMS;
