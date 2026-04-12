/* ═══════════════════════════════════════════════════════════════
   SECURENET PRO v4.0 — MAIN.JS
   Single file controls: scanner results, threat map, tool cards,
   pentest suite, live ticker, breach intel link, report export
   ═══════════════════════════════════════════════════════════════ */
(function () {
  'use strict';

  /* ─────────────────────────────────────────────
     RENDER API URL  ← set your Render URL here
     Leave as-is if you haven't deployed the backend yet
  ───────────────────────────────────────────── */
  const API_BASE = (function () {
    const stored = localStorage.getItem('sn_api_base');
    return stored || 'https://YOUR-RENDER-APP.onrender.com';
  })();

  /* ─────────────────────────────────────────────
     SAFE ELEMENT HELPERS
  ───────────────────────────────────────────── */
  const $ = id => document.getElementById(id);
  const $$ = sel => Array.from(document.querySelectorAll(sel));

  /* ─────────────────────────────────────────────
     CUSTOM CURSOR (desktop only)
  ───────────────────────────────────────────── */
  const cursor = $('cursor');
  const ring   = $('cursor-ring');
  if (cursor && ring && window.matchMedia('(pointer:fine)').matches) {
    let mx = 0, my = 0, rx = 0, ry = 0;
    document.addEventListener('mousemove', e => {
      mx = e.clientX; my = e.clientY;
      cursor.style.left = mx + 'px'; cursor.style.top = my + 'px';
    });
    (function animRing() {
      rx += (mx - rx) * 0.12; ry += (my - ry) * 0.12;
      ring.style.left = rx + 'px'; ring.style.top = ry + 'px';
      requestAnimationFrame(animRing);
    })();
    $$('a,button,[role=button],.tool-card,.module-card,.price-card,.scan-type-btn,.filter-btn').forEach(el => {
      el.addEventListener('mouseenter', () => { cursor.style.width = '16px'; cursor.style.height = '16px'; ring.style.width = '52px'; ring.style.height = '52px'; });
      el.addEventListener('mouseleave', () => { cursor.style.width = '10px'; cursor.style.height = '10px'; ring.style.width = '36px'; ring.style.height = '36px'; });
    });
  }

  /* ─────────────────────────────────────────────
     NAV + PROGRESS BAR + SCROLL-TOP
  ───────────────────────────────────────────── */
  const nav         = $('nav');
  const progressBar = $('progress');
  const scrollTop   = $('scroll-top');

  window.addEventListener('scroll', () => {
    const scrolled = window.scrollY;
    const total    = Math.max(document.body.scrollHeight - window.innerHeight, 1);
    if (nav)         nav.classList.toggle('scrolled', scrolled > 30);
    if (progressBar) progressBar.style.width = ((scrolled / total) * 100) + '%';
    if (scrollTop)   scrollTop.classList.toggle('show', scrolled > 500);
  }, { passive: true });

  scrollTop?.addEventListener('click', () => window.scrollTo({ top: 0, behavior: 'smooth' }));

  /* Mobile nav */
  const hamburger = $('hamburger');
  const mobileNav = $('mobile-nav');
  hamburger?.addEventListener('click', () => {
    mobileNav?.classList.toggle('open');
    hamburger.textContent = mobileNav?.classList.contains('open') ? '✕' : '☰';
  });
  mobileNav?.querySelectorAll('a').forEach(a => {
    a.addEventListener('click', () => { mobileNav.classList.remove('open'); if (hamburger) hamburger.textContent = '☰'; });
  });

  /* Smooth scroll anchor links */
  document.addEventListener('click', e => {
    const link = e.target.closest('a[href^="#"]');
    if (!link) return;
    const target = document.querySelector(link.getAttribute('href'));
    if (target) { e.preventDefault(); target.scrollIntoView({ behavior: 'smooth', block: 'start' }); }
  });

  /* ─────────────────────────────────────────────
     SCROLL REVEAL
  ───────────────────────────────────────────── */
  const revealObs = new IntersectionObserver(
    entries => entries.forEach(e => { if (e.isIntersecting) e.target.classList.add('visible'); }),
    { threshold: 0.06, rootMargin: '0px 0px -40px 0px' }
  );
  $$('.reveal').forEach(el => revealObs.observe(el));

  /* ─────────────────────────────────────────────
     STATS COUNT-UP
  ───────────────────────────────────────────── */
  function countUp(el, target, suffix, decimals) {
    const t0 = performance.now(), dur = 2000;
    function step(now) {
      const p = Math.min((now - t0) / dur, 1), ease = 1 - Math.pow(1 - p, 3);
      el.textContent = (decimals ? (target * ease).toFixed(decimals) : Math.floor(target * ease)).toLocaleString() + suffix;
      if (p < 1) requestAnimationFrame(step);
    }
    requestAnimationFrame(step);
  }
  const statsObs = new IntersectionObserver(entries => {
    if (!entries[0].isIntersecting) return;
    $$('.stat-n[data-val]').forEach(el => countUp(el, parseFloat(el.dataset.val), el.dataset.suf || '', parseInt(el.dataset.dec || 0)));
    statsObs.disconnect();
  }, { threshold: 0.5 });
  const statsRow = document.querySelector('.stats-row');
  if (statsRow) statsObs.observe(statsRow);

  /* Severity bars */
  const sevObs = new IntersectionObserver(entries => {
    if (!entries[0].isIntersecting) return;
    $$('.sev-bar[data-w]').forEach(b => b.style.width = b.dataset.w + '%');
    sevObs.disconnect();
  }, { threshold: 0.3 });
  const sevChart = document.querySelector('.sev-chart-container');
  if (sevChart) sevObs.observe(sevChart);

  /* ─────────────────────────────────────────────
     TOOL FILTER BUTTONS
  ───────────────────────────────────────────── */
  $$('.filter-btn').forEach(btn => {
    btn.addEventListener('click', () => {
      $$('.filter-btn').forEach(b => b.classList.remove('active'));
      btn.classList.add('active');
      const cat = btn.dataset.filter;
      $$('.tool-card[data-cat]').forEach(card => {
        const cats = card.dataset.cat.split(' ');
        const show = cat === 'all' || cats.includes(cat);
        card.style.opacity       = show ? '1' : '0.15';
        card.style.transform     = show ? 'scale(1)' : 'scale(0.96)';
        card.style.pointerEvents = show ? '' : 'none';
        card.style.transition    = 'opacity 0.3s, transform 0.3s';
      });
    });
  });

  /* ─────────────────────────────────────────────
     TOOL CARDS — click to launch scanner
  ───────────────────────────────────────────── */
  const TOOL_TO_SCAN = {
    'Web App Scanner':         'Web App',
    'Code Vulnerability Scanner': 'Code',
    'Network Port Scanner':    'Network',
    'SSL/TLS Analyzer':        'SSL/TLS',
    'API Security Tester':     'API',
    'Cloud Config Auditor':    'Cloud',
    'Dependency Checker':      'Code',
    'Secrets Detector':        'Code',
    'DNS Recon & OSINT':       'Network',
    'AI Threat Modeler':       'Web App',
    'Firewall & WAF Tester':   'Web App',
    'Data Breach Intel':       'breach',
  };

  $$('.tool-card[data-cat]').forEach(card => {
    card.style.cursor = 'pointer';
    card.addEventListener('click', () => {
      const toolName = card.querySelector('.tool-name')?.textContent?.trim() || '';
      const scanType = TOOL_TO_SCAN[toolName];

      if (scanType === 'breach') {
        window.location.href = 'breach.html';
        return;
      }

      const scanSection = $('scanner');
      if (scanSection) {
        scanSection.scrollIntoView({ behavior: 'smooth', block: 'start' });
        setTimeout(() => {
          $$('.scan-type-btn').forEach(b => {
            const matches = b.querySelector('span')?.textContent?.trim() === scanType;
            b.classList.toggle('sel', matches);
          });
          const input = $('scan-target');
          if (input && !input.value) input.focus();
        }, 700);
      }
    });
  });

  /* ─────────────────────────────────────────────
     SCAN TYPE SELECTION
  ───────────────────────────────────────────── */
  $$('.scan-type-btn').forEach(btn => {
    btn.addEventListener('click', () => {
      btn.closest('.scan-type-grid')?.querySelectorAll('.scan-type-btn').forEach(b => b.classList.remove('sel'));
      btn.classList.add('sel');
    });
  });

  $$('.scan-option').forEach(opt => opt.addEventListener('click', () => opt.classList.toggle('checked')));

  /* ─────────────────────────────────────────────
     PENTEST SUITE — module cards open scanner
  ───────────────────────────────────────────── */
  $$('.module-card').forEach(card => {
    card.style.cursor = 'pointer';
    card.addEventListener('click', () => {
      $('scanner')?.scrollIntoView({ behavior: 'smooth', block: 'start' });
    });
  });

  /* ─────────────────────────────────────────────
     LIVE SCANNER ENGINE
  ───────────────────────────────────────────── */
  const launchBtn  = $('launch-scan');
  const termOutput = $('terminal-output');
  let scanning = false;

  function ts() { return new Date().toTimeString().slice(0, 8); }

  function addLine(cls, text) {
    if (!termOutput) return;
    const div = document.createElement('div');
    div.className = 't-line';
    const icons = { ok: '✓ ', err: '⚠ ', warn: '△ ', inf: '● ', dim: '  ' };
    // sanitise text
    const safe = String(text).replace(/</g, '&lt;').replace(/>/g, '&gt;');
    div.innerHTML = `<span class="t-ts">${ts()}</span><span class="t-${cls}">${(icons[cls] || '')}${safe}</span>`;
    termOutput.appendChild(div);
    termOutput.scrollTop = termOutput.scrollHeight;
  }

  function clearCursor() { termOutput?.querySelector('.t-cursor')?.remove(); }
  function appendCursor() { clearCursor(); const s = document.createElement('span'); s.className = 't-cursor'; termOutput?.appendChild(s); }

  /* ── Update result counters (CRITICAL/HIGH/MED/LOW/INFO) ── */
  function updateResults(counts) {
    /* result-num cells inside the results-bar */
    document.querySelectorAll('.result-num[data-key]').forEach(cell => {
      const key = cell.dataset.key;
      /* map keys: crit → crit, high → high, med → med, low → low, info → info */
      const val = counts[key] ?? counts[{ crit:'critical', med:'medium' }[key] ?? key] ?? 0;
      let n = 0;
      const iv = setInterval(() => {
        n = Math.min(n + 1, val);
        cell.textContent = n;
        if (n >= val) clearInterval(iv);
      }, 60);
    });

    /* also update the summary bar inside the scanner if it exists */
    const summaryBar = document.querySelector('.scan-summary-bar');
    if (summaryBar) summaryBar.style.display = 'flex';
  }

  /* ── Detailed scripted scan outputs ── */
  const SCAN_SCRIPTS = {
    'Web App': [
      ['inf','Initializing web application scanner v4.0...'],
      ['inf','Loading OWASP Top 10 (2021) + WSTG v4.2 ruleset...'],
      ['ok', 'Engine ready — 2,400 test vectors loaded'],
      ['inf','Resolving target DNS...'],
      ['ok', 'DNS resolved — host reachable (RTT 38ms)'],
      ['inf','Detecting web server technology...'],
      ['ok', 'Server: nginx/1.25.3 (Ubuntu)'],
      ['ok', 'Frontend: React 18.2 detected'],
      ['inf','Crawling application endpoints...'],
      ['ok', 'Discovered 47 unique endpoints, 3 authenticated routes'],
      ['inf','Testing Cross-Site Scripting (XSS)...'],
      ['ok', 'Reflected XSS: clean'],
      ['warn','Stored XSS: 1 injection point in POST /comments'],
      ['inf','Testing SQL injection...'],
      ['ok', 'GET parameters: clean'],
      ['err','CRITICAL: SQLi on POST /api/search — param: query (CVSS 9.8)'],
      ['inf','Testing CSRF protections...'],
      ['warn','CSRF token missing on /api/profile/update'],
      ['inf','Checking session management...'],
      ['ok', 'Session entropy: sufficient'],
      ['warn','Login rate-limit: not enforced (brute-force risk)'],
      ['inf','Auditing HTTP security headers...'],
      ['warn','Content-Security-Policy: not set'],
      ['warn','X-Frame-Options: missing (clickjacking risk)'],
      ['ok', 'HSTS: enabled max-age=31536000'],
      ['inf','Checking for exposed admin interfaces...'],
      ['err','CRITICAL: /admin accessible without authentication (CVSS 9.3)'],
      ['err','CRITICAL: /api/debug exposes full stack traces'],
      ['inf','Testing file upload...'],
      ['warn','File type validation: client-side only (bypassable)'],
      ['err','HIGH: API key leaked in JS bundle line 8421'],
      ['ok', '─────────────────────────────────────────────'],
      ['err','⚠  CRITICAL: 3  HIGH: 1  MED: 4  LOW: 6  INFO: 12'],
    ],
    'Network': [
      ['inf','Network reconnaissance engine starting...'],
      ['ok', 'Nmap v7.94 integration loaded'],
      ['inf','ICMP host discovery — /24 subnet...'],
      ['ok', '12 hosts up'],
      ['inf','TCP SYN scan — top 1000 ports per host...'],
      ['ok', '22/tcp   — OpenSSH 8.9p1'],
      ['ok', '80/tcp   — HTTP nginx'],
      ['ok', '443/tcp  — HTTPS nginx'],
      ['err','CRITICAL: 3306/tcp — MySQL 5.7 exposed to internet (CVSS 9.8)'],
      ['err','CRITICAL: 6379/tcp — Redis 7.0 no auth (CVSS 9.1)'],
      ['warn','8080/tcp — HTTP admin panel accessible'],
      ['warn','9200/tcp — Elasticsearch no auth'],
      ['inf','Service version fingerprinting...'],
      ['warn','OpenSSH 8.9p1: CVE-2023-38408 (CVSS 7.5)'],
      ['err','MySQL 5.7.38: End of Life — no security patches'],
      ['err','HIGH: SNMP community string "public" accepted'],
      ['ok', 'SMB: not exposed externally'],
      ['ok', '─────────────────────────────────────────────'],
      ['err','⚠  CRITICAL: 4  HIGH: 2  MED: 3  LOW: 5  INFO: 9'],
    ],
    'API': [
      ['inf','API security fuzzer starting...'],
      ['inf','Parsing OpenAPI spec — 34 endpoints, 6 resource types'],
      ['ok', 'JWT validation: present'],
      ['err','CRITICAL: JWT accepts alg:none — full auth bypass (CVSS 9.8)'],
      ['err','CRITICAL: IDOR on GET /api/users/{id} (CVSS 9.1)'],
      ['warn','POST /api/users — role field writable by users (mass assignment)'],
      ['warn','No rate limiting on POST /api/auth/login'],
      ['warn','No pagination limit on GET /api/search'],
      ['err','HIGH: GraphQL introspection enabled in production'],
      ['warn','GraphQL batching: unlimited (DoS risk)'],
      ['ok', 'API versioning: present'],
      ['ok', '─────────────────────────────────────────────'],
      ['err','⚠  CRITICAL: 2  HIGH: 2  MED: 4  LOW: 3  INFO: 7'],
    ],
    'SSL/TLS': [
      ['inf','SSL/TLS deep analyzer starting...'],
      ['ok', 'Certificate chain: valid (3 certs)'],
      ['ok', 'Issuer: Let\'s Encrypt'],
      ['ok', 'Expiry: 168 days remaining'],
      ['ok', 'TLS 1.3: supported ✓'],
      ['ok', 'TLS 1.2: supported ✓'],
      ['warn','TLS 1.1: enabled — recommend disabling'],
      ['err','HIGH: TLS 1.0 enabled — POODLE attack possible (CVSS 7.4)'],
      ['err','HIGH: SSL 3.0 enabled — severe vulnerability'],
      ['ok', 'Forward Secrecy (ECDHE): supported'],
      ['warn','RC4 cipher: still negotiated on TLS 1.1'],
      ['ok', 'HEARTBLEED: not vulnerable'],
      ['ok', 'BEAST: mitigated'],
      ['ok', 'CRIME: not vulnerable'],
      ['warn','HSTS preload: not submitted to browser lists'],
      ['ok', '─────────────────────────────────────────────'],
      ['err','⚠  CRITICAL: 0  HIGH: 2  MED: 3  LOW: 4  INFO: 6'],
    ],
    'Code': [
      ['inf','SAST engine starting — scanning repository...'],
      ['ok', 'Languages: Python, JavaScript, Go'],
      ['warn','Hardcoded credential: config.py line 88'],
      ['err','CRITICAL: AWS_SECRET_KEY committed to .env (CVSS 9.8)'],
      ['err','CRITICAL: Private key in /certs/server.key'],
      ['warn','SQL query via string concatenation — SQLi risk'],
      ['warn','MD5 used for password hashing — use bcrypt/argon2'],
      ['err','HIGH: eval() called with user-controlled input'],
      ['warn','Insecure deserialization: pickle.loads() on user data'],
      ['ok', 'No path traversal vulnerabilities found'],
      ['ok', '─────────────────────────────────────────────'],
      ['err','⚠  CRITICAL: 3  HIGH: 2  MED: 5  LOW: 8  INFO: 14'],
    ],
    'Cloud': [
      ['inf','Cloud config auditor starting...'],
      ['inf','Scanning AWS account — IAM, S3, RDS, EC2, VPC...'],
      ['err','CRITICAL: S3 bucket prod-assets — public read enabled (CVSS 9.1)'],
      ['err','CRITICAL: S3 bucket backup-2024 — public read enabled'],
      ['warn','MFA not enforced on 4 IAM users'],
      ['warn','CloudTrail logging disabled in eu-west-1'],
      ['err','HIGH: RDS instance db.prod — publicly accessible'],
      ['warn','Security group allows 0.0.0.0/0 on port 22 (SSH)'],
      ['ok', 'VPC flow logs: enabled'],
      ['ok', 'KMS encryption on EBS: enabled'],
      ['warn','EBS snapshot db-snapshot-2024 — publicly shared'],
      ['ok', '─────────────────────────────────────────────'],
      ['err','⚠  CRITICAL: 3  HIGH: 3  MED: 4  LOW: 6  INFO: 8'],
    ],
  };

  /* ── Extract counts from last summary line ── */
  function parseSummaryLine(line) {
    const m = line.match(/CRITICAL:\s*(\d+).*HIGH:\s*(\d+).*MED:\s*(\d+).*LOW:\s*(\d+).*INFO:\s*(\d+)/i);
    if (m) return { crit: +m[1], high: +m[2], med: +m[3], low: +m[4], info: +m[5] };
    return null;
  }

  launchBtn?.addEventListener('click', async () => {
    if (scanning) return;
    scanning = true;
    launchBtn.classList.add('running');
    launchBtn.textContent = '⏸ SCANNING...';

    const target     = ($('scan-target')?.value.trim()) || 'example.com';
    const activeType = document.querySelector('.scan-type-btn.sel span')?.textContent?.trim() || 'Web App';
    const script     = SCAN_SCRIPTS[activeType] || SCAN_SCRIPTS['Web App'];

    /* Clear terminal */
    if (termOutput) termOutput.innerHTML = '';
    addLine('inf', `SecureNet Pro v4.0 — ${activeType} Scan`);
    addLine('dim', `Target: ${target}`);
    addLine('dim', '─────────────────────────────────────────────');
    appendCursor();

    let counts    = { crit: 0, high: 0, med: 0, low: 4, info: 8 };
    let realUsed  = false;

    /* ── Try real Render engine ── */
    if (!API_BASE.includes('YOUR-RENDER')) {
      try {
        clearCursor();
        addLine('inf', 'Connecting to SecureNet scan engine...');
        appendCursor();

        const resp = await fetch(`${API_BASE}/api/scan`, {
          method:  'POST',
          headers: { 'Content-Type': 'application/json' },
          body:    JSON.stringify({ target, scan_type: activeType, intensity: 'standard' }),
          signal:  AbortSignal.timeout(25000),
        });

        if (resp.ok) {
          const data = await resp.json();
          realUsed = true;
          clearCursor();
          addLine('ok', 'Scan engine connected ✓');
          addLine('dim', '─────────────────────────────────────────────');

          const ch = data.checks || {};

          /* SSL */
          if (ch.ssl) {
            const ssl = ch.ssl;
            if (ssl.tls_version) addLine('inf', `TLS version: ${ssl.tls_version} | Issuer: ${ssl.issuer || 'unknown'}`);
            if (ssl.expires_in_days != null) {
              addLine(ssl.expires_in_days < 14 ? 'err' : ssl.expires_in_days < 30 ? 'warn' : 'ok',
                `Certificate expires in ${ssl.expires_in_days} days`);
            }
            (ssl.issues || []).forEach(i => addLine(i.includes('CRITICAL') ? 'err' : 'warn', i));
          }

          /* HTTP */
          if (ch.http) {
            const h = ch.http;
            (h.missing_headers || []).forEach(mh =>
              addLine(mh.severity === 'high' ? 'err' : 'warn', `Missing header: ${mh.name}`));
            (h.secrets || []).forEach(s => addLine('err', `CRITICAL: ${s.name} found in HTTP response`));
            (h.vuln_patterns || []).forEach(v => addLine(v.severity === 'critical' ? 'err' : 'warn', v.description));
            if (h.cors_wildcard) addLine('warn', 'CORS: Access-Control-Allow-Origin: * (any origin allowed)');
            (h.csp_issues || []).forEach(c => addLine('warn', `CSP weakness: ${c.issue}`));
          }

          /* Exposed paths */
          (ch.exposed_paths || []).forEach(p =>
            addLine(p.severity === 'critical' ? 'err' : 'warn',
              `EXPOSED: ${p.path} (HTTP ${p.status}) — ${p.description}`));

          /* DNS */
          (ch.dns?.issues || []).forEach(i => addLine(i.includes('C
