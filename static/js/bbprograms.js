// ════════════════════════════════════════════════════════════════════════
//  BUG BOUNTY PROGRAMS MODULE — HackerOne & Bugcrowd integration
// ════════════════════════════════════════════════════════════════════════
'use strict';

let _bbpPlatform = 'hackerone';
let _bbpData     = { hackerone: null, bugcrowd: null };
let _bbpPage     = { hackerone: 1, bugcrowd: 1 };
let _bbpSearch   = '';
let _bbpLoading  = false;

// ─── Main entry ──────────────────────────────────────────────────────
function showBBProgramsPage() {
  const view = document.getElementById('view-bbprograms');
  if(!view) return;
  if(document.getElementById('bbp-main')) {
    _bbpRefreshView();
    return;
  }
  view.innerHTML = `
    <div class="bbp-header">
      <div>
        <div class="page-title">🏆 Bug Bounty Programs</div>
        <div class="page-desc">Explore programas de Bug Bounty de HackerOne e Bugcrowd sem sair da plataforma.</div>
      </div>
    </div>

    <!-- Platform tabs -->
    <div class="bbp-platform-tabs">
      <button class="bbp-tab active" id="bbp-tab-hackerone" onclick="bbpSwitchPlatform('hackerone')">
        <img src="https://www.hackerone.com/favicon.ico" onerror="this.style.display='none'" style="width:16px;height:16px;border-radius:2px">
        HackerOne
      </button>
      <button class="bbp-tab" id="bbp-tab-bugcrowd" onclick="bbpSwitchPlatform('bugcrowd')">
        <img src="https://www.bugcrowd.com/favicon.ico" onerror="this.style.display='none'" style="width:16px;height:16px;border-radius:2px">
        Bugcrowd
      </button>
    </div>

    <!-- Toolbar -->
    <div class="bbp-toolbar">
      <div class="bbp-search-wrap">
        <input type="text" id="bbp-search-input" placeholder="Pesquisar programas..."
               oninput="bbpOnSearch()" autocomplete="off" class="bbp-search-field">
      </div>
      <div class="bbp-filters">
        <select id="bbp-filter-bounty" onchange="bbpApplyFilter()" class="fi">
          <option value="">Qualquer recompensa</option>
          <option value="paid">Com recompensa</option>
          <option value="vdp">VDP (sem recompensa)</option>
        </select>
        <select id="bbp-filter-type" onchange="bbpApplyFilter()" class="fi">
          <option value="">Qualquer tipo</option>
          <option value="public">Público</option>
          <option value="private">Privado</option>
        </select>
        <button class="btn btn-primary" onclick="bbpLoad(true)">↻ Atualizar</button>
      </div>
    </div>

    <!-- Credentials notice -->
    <div id="bbp-creds-notice" class="bbp-notice" style="display:none">
      <span>⚙️ Configure as credenciais da API em</span>
      <button class="btn btn-secondary btn-sm" onclick="showPage('settings')">API Keys</button>
      <span>para acessar dados em tempo real. Campos: <b>hackerone_username</b> e <b>hackerone_token</b></span>
    </div>

    <!-- Programs grid -->
    <div id="bbp-main" class="bbp-programs-grid"></div>

    <!-- Pagination -->
    <div class="bbp-pagination" id="bbp-pagination" style="display:none">
      <button class="btn btn-secondary" id="bbp-prev-btn" onclick="bbpChangePage(-1)">← Anterior</button>
      <span id="bbp-page-info" style="color:var(--text3)">Página 1</span>
      <button class="btn btn-secondary" id="bbp-next-btn" onclick="bbpChangePage(1)">Próxima →</button>
    </div>
  `;
  bbpLoad();
}

// ─── Platform switch ─────────────────────────────────────────────────
function bbpSwitchPlatform(platform) {
  _bbpPlatform = platform;
  document.querySelectorAll('.bbp-tab').forEach(t => t.classList.remove('active'));
  document.getElementById(`bbp-tab-${platform}`)?.classList.add('active');
  _bbpPage[platform] = 1;
  _bbpSearch = '';
  const inp = document.getElementById('bbp-search-input');
  if(inp) inp.value = '';
  bbpLoad();
}

// ─── Search ──────────────────────────────────────────────────────────
let _bbpSearchTimer = null;
function bbpOnSearch() {
  clearTimeout(_bbpSearchTimer);
  _bbpSearchTimer = setTimeout(() => {
    _bbpSearch = document.getElementById('bbp-search-input')?.value.trim() || '';
    _bbpPage[_bbpPlatform] = 1;
    _bbpApplyClientFilter();
  }, 300);
}

function bbpApplyFilter() {
  _bbpPage[_bbpPlatform] = 1;
  _bbpApplyClientFilter();
}

// ─── Load data ───────────────────────────────────────────────────────
async function bbpLoad(force = false) {
  if(_bbpLoading) return;
  _bbpLoading = true;
  const main = document.getElementById('bbp-main');
  if(!main) { _bbpLoading = false; return; }

  main.innerHTML = `
    <div class="bbp-loading">
      <div class="spinner" style="width:32px;height:32px;border-width:3px"></div>
      <span>Carregando programas...</span>
    </div>`;

  try {
    const page = _bbpPage[_bbpPlatform];
    const q = encodeURIComponent(_bbpSearch);
    const url = `/api/bbprograms/${_bbpPlatform}?page=${page}&q=${q}`;
    const resp = await fetch(url, { headers: _authHeaders ? _authHeaders() : {} });

    if(resp.status === 401 || resp.status === 403) {
      _bbpShowCredsNotice(true);
      main.innerHTML = `<div class="bbp-empty">🔑 Credenciais não configuradas. Configure em <strong>API Keys</strong>.</div>`;
      _bbpLoading = false; return;
    }

    if(!resp.ok) {
      const err = await resp.json().catch(() => ({error: resp.statusText}));
      throw new Error(err.error || resp.statusText);
    }

    const data = await resp.json();
    _bbpData[_bbpPlatform] = data;
    _bbpShowCredsNotice(data.demo === true);
    _bbpRender(data);
  } catch(e) {
    main.innerHTML = `<div class="bbp-empty">⚠️ Erro ao carregar: ${e.message}</div>`;
  } finally {
    _bbpLoading = false;
  }
}

// ─── Apply client-side filter on cached data ─────────────────────────
function _bbpApplyClientFilter() {
  const data = _bbpData[_bbpPlatform];
  if(!data) { bbpLoad(true); return; }
  _bbpRender(data);
}

function _bbpRefreshView() {
  const data = _bbpData[_bbpPlatform];
  if(data) _bbpRender(data);
  else bbpLoad();
}

// ─── Render programs ─────────────────────────────────────────────────
function _bbpRender(data) {
  const main = document.getElementById('bbp-main');
  if(!main) return;

  let programs = data.programs || [];
  const totalPages = data.total_pages || 1;
  const currentPage = _bbpPage[_bbpPlatform];

  // Client-side filters
  const search = _bbpSearch.toLowerCase();
  const bountyFilter = document.getElementById('bbp-filter-bounty')?.value || '';
  const typeFilter   = document.getElementById('bbp-filter-type')?.value   || '';

  if(search) programs = programs.filter(p => (p.name||'').toLowerCase().includes(search) || (p.handle||'').toLowerCase().includes(search));
  if(bountyFilter === 'paid') programs = programs.filter(p => p.offers_bounties);
  if(bountyFilter === 'vdp')  programs = programs.filter(p => !p.offers_bounties);
  if(typeFilter === 'public')  programs = programs.filter(p => p.state === 'public_mode' || p.access_level === 'open');
  if(typeFilter === 'private') programs = programs.filter(p => p.state === 'soft_launch' || p.access_level === 'invite_only');

  if(!programs.length) {
    main.innerHTML = `<div class="bbp-empty">Nenhum programa encontrado. Tente alterar os filtros.</div>`;
    _bbpUpdatePagination(0, 1, 1);
    return;
  }

  main.innerHTML = programs.map(p => _bbpProgramCard(p)).join('');
  _bbpUpdatePagination(programs.length, currentPage, totalPages);
}

function _bbpProgramCard(p) {
  const isH1 = _bbpPlatform === 'hackerone';
  const name = p.name || p.company_name || 'Unknown';
  const handle = p.handle || p.code || '';
  const bounty = p.offers_bounties || p.allows_disclosure;
  const logoUrl = p.profile_picture_urls?.small || p.logo || '';
  const minBounty = p.min_bounty_table_value || p.bounty_min || 0;
  const maxBounty = p.max_bounty_table_value || p.bounty_max || 0;
  const state = p.state || p.access_level || '';
  const isPublic = state === 'public_mode' || state === 'open';
  const url = isH1
    ? `https://hackerone.com/${handle}`
    : `https://bugcrowd.com/${handle}`;
  const stats = p.statistics || {};
  const resolved = stats.resolved_report_count || p.total_rewards_given || 0;
  const submitted = stats.submitted_report_count || '';
  const scopes = (p.in_scope || []).map(s => s.asset_type || s.type || '').filter((v,i,a) => v && a.indexOf(v)===i).slice(0,4);

  return `
    <a href="${url}" target="_blank" rel="noopener noreferrer" class="bbp-program-card">
      <div class="bbp-card-header">
        <div class="bbp-card-logo">
          ${logoUrl ? `<img src="${logoUrl}" alt="${name}" onerror="this.style.display='none'">` : `<span>${name.charAt(0)}</span>`}
        </div>
        <div class="bbp-card-info">
          <div class="bbp-card-name">${_bbpEsc(name)}</div>
          <div class="bbp-card-handle">@${_bbpEsc(handle)}</div>
        </div>
        <div class="bbp-card-badges">
          ${bounty ? `<span class="bbp-badge bbp-badge-bounty">💰 Recompensa</span>` : `<span class="bbp-badge bbp-badge-vdp">VDP</span>`}
          ${isPublic ? `<span class="bbp-badge bbp-badge-public">🌐 Público</span>` : `<span class="bbp-badge bbp-badge-private">🔒 Privado</span>`}
        </div>
      </div>
      ${(minBounty || maxBounty) ? `
        <div class="bbp-card-bounty">
          💵 ${minBounty ? '$' + _bbpFmt(minBounty) : '—'} – ${maxBounty ? '$' + _bbpFmt(maxBounty) : '—'}
        </div>` : ''}
      ${scopes.length ? `<div class="bbp-card-scopes">${scopes.map(s=>`<span class="bbp-scope-tag">${_bbpEsc(s)}</span>`).join('')}</div>` : ''}
      ${resolved ? `<div class="bbp-card-stats">✓ ${_bbpFmt(resolved)} resolvidos${submitted ? ' · ' + _bbpFmt(submitted) + ' enviados' : ''}</div>` : ''}
    </a>`;
}

function _bbpUpdatePagination(count, current, total) {
  const pg = document.getElementById('bbp-pagination');
  const prev = document.getElementById('bbp-prev-btn');
  const next = document.getElementById('bbp-next-btn');
  const info = document.getElementById('bbp-page-info');
  if(!pg) return;
  pg.style.display = total > 1 ? 'flex' : 'none';
  if(prev) prev.disabled = current <= 1;
  if(next) next.disabled = current >= total;
  if(info) info.textContent = `Página ${current} de ${total}`;
}

function bbpChangePage(delta) {
  _bbpPage[_bbpPlatform] = Math.max(1, _bbpPage[_bbpPlatform] + delta);
  bbpLoad(true);
}

function _bbpShowCredsNotice(show) {
  const el = document.getElementById('bbp-creds-notice');
  if(el) el.style.display = show ? '' : 'none';
}

function _bbpEsc(s) {
  return String(s || '').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');
}
function _bbpFmt(n) {
  return Number(n).toLocaleString('pt-BR');
}
