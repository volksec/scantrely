/* bugbounty.js — "Bug Bounty Helper" and "External Tools" tabs.
 *
 * Pure client-side: every module just builds a URL for the entered domain
 * and opens it in a new tab (Google Dorking style, à la dorks.faisalahmed.me).
 */

function _bbhEnc(q) {
  return encodeURIComponent(q);
}

function _bbhGoogle(query) {
  return "https://www.google.com/search?q=" + _bbhEnc(query);
}

// Category keys map to the i18n keys used for the filter tabs.
const BBH_CATEGORIES = [
  {id: "", key: "bbh_cat_all"},
  {id: "dorks", key: "bbh_cat_dorks"},
  {id: "recon", key: "bbh_cat_recon"},
  {id: "archives", key: "bbh_cat_archives"},
  {id: "intel", key: "bbh_cat_intel"},
  {id: "files", key: "bbh_cat_files"},
];

const BBH_TAG_LABEL = {
  dorks: "DORKS",
  intel: "INTEL",
  recon: "RECON",
  files: "FILES",
  archives: "ARCHIVES",
};

// Each module: {id, label, cat, url(domain)}
const DORK_MODULES = [
  // ── Google Dorks ──
  {id:"dir_listing",     label:"Directory Listing",  cat:"dorks", url:d=>_bbhGoogle(`site:${d} intitle:"index of"`)},
  {id:"exposed_configs", label:"Exposed Configs",    cat:"dorks", url:d=>_bbhGoogle(`site:${d} ext:xml | ext:conf | ext:cnf | ext:reg | ext:inf | ext:rdp | ext:cfg | ext:ini | ext:env | ext:yml | ext:yaml | ext:json`)},
  {id:"db_files",        label:"DB Files",           cat:"dorks", url:d=>_bbhGoogle(`site:${d} ext:sql | ext:dbf | ext:mdb | ext:db | ext:sqlite`)},
  {id:"log_files",       label:"Log Files",          cat:"dorks", url:d=>_bbhGoogle(`site:${d} ext:log`)},
  {id:"backup_files",    label:"Backup Files",       cat:"dorks", url:d=>_bbhGoogle(`site:${d} ext:bak | ext:backup | ext:old | ext:swp | ext:save | ext:tar | ext:tar.gz | ext:zip | ext:7z | ext:rar`)},
  {id:"login_pages",     label:"Login Pages",        cat:"dorks", url:d=>_bbhGoogle(`site:${d} inurl:login | inurl:signin | inurl:logon | intitle:login`)},
  {id:"sql_errors",      label:"SQL Errors",         cat:"dorks", url:d=>_bbhGoogle(`site:${d} intext:"sql syntax near" | intext:"syntax error has occurred" | intext:"incorrect syntax near" | intext:"Warning: mysql_"`)},
  {id:"public_docs",     label:"Public Documents",   cat:"dorks", url:d=>_bbhGoogle(`site:${d} ext:pdf | ext:doc | ext:docx | ext:xls | ext:xlsx | ext:ppt | ext:pptx | ext:csv`)},
  {id:"phpinfo",         label:"phpinfo()",          cat:"dorks", url:d=>_bbhGoogle(`site:${d} intitle:"phpinfo()" "PHP Version"`)},
  {id:"shells",          label:"Shells / Backdoors", cat:"dorks", url:d=>_bbhGoogle(`site:${d} intitle:"shell" | inurl:shell.php | inurl:c99 | inurl:r57 | inurl:webshell`)},
  {id:"open_redirects",  label:"Open Redirects",     cat:"dorks", url:d=>_bbhGoogle(`site:${d} inurl:redirect= | inurl:url= | inurl:return= | inurl:next= | inurl:redir= | inurl:goto=`)},
  {id:"struts_rce",      label:"Struts RCE",         cat:"dorks", url:d=>_bbhGoogle(`site:${d} ext:action | ext:do inurl:struts`)},
  {id:"wp_files",        label:"WordPress Files",    cat:"dorks", url:d=>_bbhGoogle(`site:${d} inurl:wp-content | inurl:wp-includes | inurl:wp-admin | inurl:wp-config`)},
  {id:"git_exposed",     label:"Git Exposed",        cat:"dorks", url:d=>_bbhGoogle(`site:${d} inurl:.git intitle:"index of"`)},
  {id:"gitlab_config",   label:"GitLab Config",      cat:"dorks", url:d=>_bbhGoogle(`site:${d} inurl:.gitlab-ci.yml | inurl:.gitlab`)},
  {id:"env_files",       label:"ENV Files",          cat:"dorks", url:d=>_bbhGoogle(`site:${d} ext:env "DB_PASSWORD" | "API_KEY" | "SECRET_KEY"`)},
  {id:"htaccess",        label:"Htaccess / Info",    cat:"dorks", url:d=>_bbhGoogle(`site:${d} ext:htaccess | ext:htpasswd | intitle:"index of" ".htaccess"`)},
  {id:"install_setup",   label:"Install / Setup",    cat:"dorks", url:d=>_bbhGoogle(`site:${d} inurl:install | inurl:setup intitle:install`)},

  // ── OSINT & Intelligence ──
  {id:"pastebin",        label:"Pastebin Dumps",     cat:"intel", url:d=>_bbhGoogle(`site:pastebin.com "${d}"`)},
  {id:"linkedin",        label:"LinkedIn Employees", cat:"intel", url:d=>_bbhGoogle(`site:linkedin.com/in "${d}"`)},
  {id:"github_src",      label:"GitHub Source",      cat:"intel", url:d=>_bbhGoogle(`site:github.com "${d}"`)},
  {id:"threatcrowd",     label:"ThreatCrowd",        cat:"intel", url:d=>`https://www.threatcrowd.org/domain/${d}/`},
  {id:"openbugbounty",   label:"OpenBugBounty",      cat:"intel", url:d=>`https://www.openbugbounty.org/search/?search=${_bbhEnc(d)}`},
  {id:"reddit",          label:"Reddit Mentions",    cat:"intel", url:d=>_bbhGoogle(`site:reddit.com "${d}"`)},
  {id:"censys_ipv4",     label:"Censys (IPv4)",      cat:"intel", url:d=>`https://search.censys.io/search?resource=hosts&q=${_bbhEnc(d)}`},
  {id:"censys_domains",  label:"Censys (Domains)",   cat:"intel", url:d=>`https://search.censys.io/search?resource=hosts&q=${_bbhEnc('services.tls.certificates.leaf_data.subject.common_name: '+d)}`},
  {id:"censys_certs",    label:"Censys (Certs)",     cat:"intel", url:d=>`https://search.censys.io/certificates?q=${_bbhEnc(d)}`},
  {id:"shodan",          label:"Shodan Search",      cat:"intel", url:d=>`https://www.shodan.io/search?query=${_bbhEnc('hostname:'+d)}`},
  {id:"virustotal",      label:"VirusTotal",         cat:"intel", url:d=>`https://www.virustotal.com/gui/domain/${d}`},
  {id:"urlscan",         label:"Urlscan.io",         cat:"intel", url:d=>`https://urlscan.io/search/#${_bbhEnc(d)}`},
  {id:"wappalyzer",      label:"Wappalyzer",         cat:"intel", url:d=>`https://www.wappalyzer.com/lookup/${d}/`},
  {id:"builtwith",       label:"BuiltWith",          cat:"intel", url:d=>`https://builtwith.com/${d}`},
  {id:"censys_platform", label:"Censys Platform",    cat:"intel", url:d=>`https://platform.censys.io/search?q=${_bbhEnc(d)}`},
  {id:"publicwww",       label:"PublicWWW",          cat:"intel", url:d=>`https://publicwww.com/websites/${d}/`},
  {id:"zoomeye",         label:"ZoomEye",            cat:"intel", url:d=>`https://www.zoomeye.org/searchResult?q=${_bbhEnc(d)}`},
  {id:"jina",            label:"Jina AI",            cat:"intel", url:d=>`https://r.jina.ai/https://${d}`},

  // ── Recon & Subdomains ──
  {id:"find_subs",       label:"Find Subdomains",    cat:"recon", url:d=>_bbhGoogle(`site:*.${d} -www`)},
  {id:"deep_subs",       label:"Deep Subdomains",    cat:"recon", url:d=>_bbhGoogle(`site:*.${d} -site:www.${d}`)},
  {id:"crtsh",           label:"Crt.sh (Certificates)", cat:"recon", url:d=>`https://crt.sh/?q=%25.${_bbhEnc(d)}`},
  {id:"sec_headers",     label:"Security Headers",   cat:"recon", url:d=>`https://securityheaders.com/?q=${_bbhEnc(d)}`},
  {id:"ssllabs",         label:"SSL Labs",           cat:"recon", url:d=>`https://www.ssllabs.com/ssltest/analyze.html?d=${_bbhEnc(d)}`},

  // ── Specific Files ──
  {id:"wayback_swf",      label:"Wayback SWF",       cat:"files", url:d=>`https://web.archive.org/web/*/${d}/*.swf`},
  {id:"wayback_mime_swf", label:"Wayback MIME SWF",  cat:"files", url:d=>`https://web.archive.org/cdx/search/cdx?url=*.${d}/*&output=text&fl=original&collapse=urlkey&filter=mimetype:application/x-shockwave-flash`},
  {id:"crossdomain",      label:"Crossdomain.xml",   cat:"files", url:d=>`https://${d}/crossdomain.xml`},
  {id:"swf_google",       label:"SWF (Google)",      cat:"files", url:d=>_bbhGoogle(`site:${d} ext:swf`)},
  {id:"swf_yandex",       label:"SWF (Yandex)",      cat:"files", url:d=>`https://yandex.com/search/?text=${_bbhEnc('site:'+d+' ext:swf')}`},

  // ── Archives & History ──
  {id:"wayback_domain",  label:"Wayback Domain",     cat:"archives", url:d=>`https://web.archive.org/web/*/${d}`},
  {id:"wayback_full",    label:"Wayback Full",       cat:"archives", url:d=>`https://web.archive.org/web/*/${d}/*`},
  {id:"wayback_wp",      label:"Wayback WP",         cat:"archives", url:d=>`https://web.archive.org/web/*/${d}/wp-content/*`},
];

// External tools — fixed links, some take the current Bug Bounty Helper domain.
const EXT_TOOLS = [
  {id:"dnsbin",        label:"DNSBin (Request Interceptor)", icon:"📡", url:d=>"http://dnsbin.zhack.ca/"},
  {id:"hunterio",      label:"Hunter.io",                     icon:"📧", url:d=>d ? `https://hunter.io/search/${_bbhEnc(d)}` : "https://hunter.io/"},
  {id:"interactsh",    label:"Interactsh (OOB)",              icon:"🌐", url:d=>"https://app.interactsh.com/"},
  {id:"dnsdumpster",   label:"DNS Dumpster",                  icon:"🗑", url:d=>d ? `https://dnsdumpster.com/?q=${_bbhEnc(d)}` : "https://dnsdumpster.com/"},
  {id:"hackertarget",  label:"HackerTarget DNS",              icon:"🎯", url:d=>"https://hackertarget.com/dns-lookup/"},
  {id:"cyberchef",     label:"CyberChef",                     icon:"🍳", url:d=>"https://gchq.github.io/CyberChef/"},
  {id:"regex101",      label:"Regex101",                      icon:"🔣", url:d=>"https://regex101.com/"},
  {id:"jwtio",         label:"JWT.io",                        icon:"🔑", url:d=>"https://jwt.io/"},
  {id:"breachdir",     label:"Breach Directory",              icon:"🔓", url:d=>"https://breachdirectory.org/"},
  {id:"ipconverter",   label:"IP Converter",                  icon:"🔢", url:d=>"https://www.browserling.com/tools/ip-to-dec"},
  {id:"iptolong",      label:"IP to Long",                    icon:"🔢", url:d=>"https://www.browserling.com/tools/ip-to-dec"},
  {id:"domainhistory", label:"Domain History",                icon:"🕓", url:d=>d ? `https://viewdns.info/iphistory/?domain=${_bbhEnc(d)}` : "https://viewdns.info/iphistory/"},
  {id:"srccodesearch", label:"Source Code Search",            icon:"💻", url:d=>d ? `https://searchcode.com/?q=${_bbhEnc(d)}` : "https://searchcode.com/"},
  {id:"fbcert",        label:"FB Cert Transparency",          icon:"🛡", url:d=>d ? `https://developers.facebook.com/tools/ct/search/?q=${_bbhEnc(d)}` : "https://developers.facebook.com/tools/ct/"},
];

let _bbhActiveCat = "";

function _bbhDomain() {
  const inp = document.getElementById("bbh-domain");
  return inp ? inp.value.trim().replace(/^https?:\/\//, "").replace(/\/.*$/, "") : "";
}

function bbhOnDomainInput() {
  const d = _bbhDomain();
  try { localStorage.setItem("bbh_domain", d); } catch(e) {}
}

function bbhOpenModule(id) {
  const mod = DORK_MODULES.find(m => m.id === id);
  if (!mod) return;
  const d = _bbhDomain();
  if (!d) {
    alert(window.t ? window.t("bbh_enter_domain") : "Enter a domain above first.");
    return;
  }
  window.open(mod.url(d), "_blank", "noopener");
}

function bbhSetCategory(cat) {
  _bbhActiveCat = cat;
  renderBBHGrid();
  document.querySelectorAll("#bbh-cat-tabs .tab-btn").forEach(b => {
    b.classList.toggle("active", b.getAttribute("data-cat") === cat);
  });
}

function renderBBHCategoryTabs() {
  const wrap = document.getElementById("bbh-cat-tabs");
  if (!wrap) return;
  wrap.innerHTML = BBH_CATEGORIES.map(c => {
    const active = c.id === _bbhActiveCat ? " active" : "";
    return `<button type="button" class="tab-btn${active}" data-cat="${c.id}" onclick="bbhSetCategory('${c.id}')">${window.t(c.key)}</button>`;
  }).join("");
}

function renderBBHGrid() {
  const grid = document.getElementById("bbh-grid");
  if (!grid) return;
  const mods = _bbhActiveCat ? DORK_MODULES.filter(m => m.cat === _bbhActiveCat) : DORK_MODULES;
  grid.innerHTML = mods.map(m => {
    const tag = BBH_TAG_LABEL[m.cat] || "";
    return `<div class="bbh-card" style="padding:12px 14px;cursor:pointer;display:flex;align-items:center;justify-content:space-between;gap:8px" onclick="bbhOpenModule('${m.id}')">
      <span style="font-size:.82rem;color:var(--text1)">${m.label}</span>
      <span class="tab-count" style="font-family:var(--mono);font-size:.62rem;letter-spacing:.05em;opacity:.7">${tag}</span>
    </div>`;
  }).join("");
}

function renderExtTools() {
  const grid = document.getElementById("ext-grid");
  if (!grid) return;
  const d = _bbhDomain();
  grid.innerHTML = EXT_TOOLS.map(t => {
    return `<div class="bbh-card" style="padding:12px 14px;cursor:pointer;display:flex;align-items:center;gap:10px" onclick="window.open(${JSON.stringify(t.url(d))}, '_blank', 'noopener')">
      <span style="font-size:1.1rem">${t.icon}</span>
      <span style="font-size:.82rem;color:var(--text1)">${t.label}</span>
    </div>`;
  }).join("");
}

function showBBHelperPage() {
  // Auto-load domain from ?d= query param, or restore last used domain.
  let domain = "";
  try {
    const params = new URLSearchParams(window.location.search);
    domain = (params.get("d") || "").trim();
  } catch(e) {}
  if (!domain) {
    try { domain = localStorage.getItem("bbh_domain") || ""; } catch(e) {}
  }
  const inp = document.getElementById("bbh-domain");
  if (inp && domain) inp.value = domain;
  if (domain) {
    try { localStorage.setItem("bbh_domain", domain); } catch(e) {}
  }
  renderBBHCategoryTabs();
  renderBBHGrid();
  if (window.applyI18n) window.applyI18n();
}

function showExtToolsPage() {
  renderExtTools();
  if (window.applyI18n) window.applyI18n();
}
