/* ═══════════════════════════════════════════════════
   SECURENET PRO — CORE JAVASCRIPT
   ═══════════════════════════════════════════════════ */

(function () {
  'use strict';

  /* ── Custom cursor ── */
  const cursor = document.getElementById('cursor');
  const ring = document.getElementById('cursor-ring');
  let mouseX = 0, mouseY = 0, ringX = 0, ringY = 0;

  document.addEventListener('mousemove', e => {
    mouseX = e.clientX; mouseY = e.clientY;
    cursor.style.left = mouseX + 'px';
    cursor.style.top  = mouseY + 'px';
  });

  function animateRing() {
    ringX += (mouseX - ringX) * 0.12;
    ringY += (mouseY - ringY) * 0.12;
    ring.style.left = ringX + 'px';
    ring.style.top  = ringY + 'px';
    requestAnimationFrame(animateRing);
  }
  animateRing();

  document.querySelectorAll('a,button,[role=button],.tool-card,.module-card,.flow-step,.finding-item,.scan-type-btn,.scan-option,.filter-btn,.price-card').forEach(el => {
    el.addEventListener('mouseenter', () => {
      cursor.style.width = '16px'; cursor.style.height = '16px';
      ring.style.width = '52px'; ring.style.height = '52px';
      ring.style.borderColor = 'rgba(0,229,255,0.6)';
    });
    el.addEventListener('mouseleave', () => {
      cursor.style.width = '10px'; cursor.style.height = '10px';
      ring.style.width = '36px'; ring.style.height = '36px';
      ring.style.borderColor = 'rgba(0,229,255,0.4)';
    });
  });

  /* ── Nav scroll behavior ── */
  const nav = document.getElementById('nav');
  const progressBar = document.getElementById('progress');
  const scrollTopBtn = document.getElementById('scroll-top');

  window.addEventListener('scroll', () => {
    const scrolled = window.scrollY;
    const total = document.body.scrollHeight - window.innerHeight;
    const pct = (scrolled / total) * 100;

    nav.classList.toggle('scrolled', scrolled > 30);
    progressBar.style.width = pct + '%';
    scrollTopBtn.classList.toggle('show', scrolled > 500);
  });

  scrollTopBtn.addEventListener('click', () => window.scrollTo({ top: 0, behavior: 'smooth' }));

  /* ── Mobile nav ── */
  const hamburger = document.getElementById('hamburger');
  const mobileNav = document.getElementById('mobile-nav');

  hamburger?.addEventListener('click', () => {
    mobileNav.classList.toggle('open');
    hamburger.textContent = mobileNav.classList.contains('open') ? '✕' : '☰';
  });

  mobileNav?.querySelectorAll('a').forEach(a => {
    a.addEventListener('click', () => {
      mobileNav.classList.remove('open');
      hamburger.textContent = '☰';
    });
  });

  /* ── Scroll reveal ── */
  const revealObserver = new IntersectionObserver(entries => {
    entries.forEach(e => { if (e.isIntersecting) { e.target.classList.add('visible'); } });
  }, { threshold: 0.06, rootMargin: '0px 0px -40px 0px' });

  document.querySelectorAll('.reveal').forEach(el => revealObserver.observe(el));

  /* ── Count-up animation ── */
  function countUp(el, target, suffix = '', decimals = 0) {
    const start = performance.now();
    const duration = 2000;
    function step(now) {
      const progress = Math.min((now - start) / duration, 1);
      const ease = 1 - Math.pow(1 - progress, 3);
      const val = target * ease;
      el.textContent = (decimals ? val.toFixed(decimals) : Math.floor(val)).toLocaleString() + suffix;
      if (progress < 1) requestAnimationFrame(step);
    }
    requestAnimationFrame(step);
  }

  const statsObserver = new IntersectionObserver(entries => {
    if (entries[0].isIntersecting) {
      document.querySelectorAll('.stat-n[data-val]').forEach(el => {
        const v = parseFloat(el.dataset.val);
        const s = el.dataset.suf || '';
        const d = parseInt(el.dataset.dec || 0);
        countUp(el, v, s, d);
      });
      statsObserver.disconnect();
    }
  }, { threshold: 0.5 });

  const statsRow = document.querySelector('.stats-row');
  if (statsRow) statsObserver.observe(statsRow);

  /* ── Severity bars ── */
  const sevObserver = new IntersectionObserver(entries => {
    if (entries[0].isIntersecting) {
      document.querySelectorAll('.sev-bar[data-w]').forEach(b => {
        b.style.width = b.dataset.w + '%';
      });
      sevObserver.disconnect();
    }
  }, { threshold: 0.3 });

  const sevChart = document.querySelector('.sev-chart-container');
  if (sevChart) sevObserver.observe(sevChart);

  /* ── Tool filter ── */
  const filterBtns = document.querySelectorAll('.filter-btn');
  const toolCards  = document.querySelectorAll('.tool-card[data-cat]');

  filterBtns.forEach(btn => {
    btn.addEventListener('click', () => {
      filterBtns.forEach(b => b.classList.remove('active'));
      btn.classList.add('active');
      const cat = btn.dataset.filter;
      toolCards.forEach(card => {
        const show = cat === 'all' || card.dataset.cat === cat;
        card.style.opacity = show ? '1' : '0.2';
        card.style.transform = show ? '' : 'scale(0.97)';
        card.style.pointerEvents = show ? '' : 'none';
      });
    });
  });

  /* ── Scan type selection ── */
  document.querySelectorAll('.scan-type-btn').forEach(btn => {
    btn.addEventListener('click', () => {
      btn.closest('.scan-type-grid').querySelectorAll('.scan-type-btn').forEach(b => b.classList.remove('sel'));
      btn.classList.add('sel');
    });
  });

  /* ── Scan option checkboxes ── */
  document.querySelectorAll('.scan-option').forEach(opt => {
    opt.addEventListener('click', () => opt.classList.toggle('checked'));
  });

  /* ── LIVE SCANNER ENGINE ── */
  const launchBtn = document.getElementById('launch-scan');
  const termOutput = document.getElementById('terminal-output');
  const resultCells = document.querySelectorAll('.result-num[data-key]');
  let scanning = false;

  function ts() {
    return new Date().toTimeString().slice(0, 8);
  }

  const SCAN_SCRIPTS = {
    'Web App': [
      ['inf', 'Initializing web application scanner module...'],
      ['inf', 'Loading OWASP Top 10 ruleset (2021 edition)...'],
      ['ok',  'Engine v4.2.1 ready'],
      ['inf', 'Resolving target domain...'],
      ['ok',  'DNS resolved → 104.21.87.44'],
      ['inf', 'Checking host availability...'],
      ['ok',  'Target reachable (RTT: 38ms)'],
      ['inf', 'Detecting web server technology...'],
      ['ok',  'Server: nginx/1.25.3 (Ubuntu)'],
      ['ok',  'Frontend: React 18.2.0 detected'],
      ['inf', 'Crawling application endpoints...'],
      ['ok',  'Discovered 47 unique endpoints'],
      ['ok',  'Found 3 authenticated routes'],
      ['inf', 'Testing for Cross-Site Scripting (XSS)...'],
      ['ok',  'Reflected XSS: no vulnerabilities found'],
      ['warn','Stored XSS: 1 potential injection point in /comments'],
      ['inf', 'Testing SQL injection vectors...'],
      ['ok',  'GET parameters: clean'],
      ['err', 'CRITICAL: SQLi detected on POST /api/search — param: query'],
      ['inf', 'Testing CSRF protections...'],
      ['warn','CSRF token missing on /api/profile/update'],
      ['inf', 'Checking authentication flows...'],
      ['ok',  'Session tokens: entropy sufficient'],
      ['warn','Login rate-limit: not enforced (brute-force risk)'],
      ['inf', 'Auditing HTTP security headers...'],
      ['warn','Content-Security-Policy: not set'],
      ['warn','X-Frame-Options: missing (clickjacking risk)'],
      ['ok',  'HSTS: enabled with max-age=31536000'],
      ['inf', 'Checking for exposed admin interfaces...'],
      ['err', 'CRITICAL: /admin accessible without authentication'],
      ['err', 'CRITICAL: /api/debug endpoint exposes stack traces'],
      ['inf', 'Testing file upload functionality...'],
      ['warn','File type validation: client-side only (bypassable)'],
      ['inf', 'Checking for sensitive data exposure...'],
      ['err', 'HIGH: API key leaked in JavaScript bundle (line 8421)'],
      ['inf', 'Scan complete. Compiling report...'],
      ['ok',  '─────────────────────────────────'],
      ['err', '⚠  CRITICAL: 3  HIGH: 1  MED: 4  LOW: 6  INFO: 12'],
    ],
    'Network': [
      ['inf', 'Initializing network reconnaissance engine...'],
      ['ok',  'Nmap integration loaded'],
      ['inf', 'Performing ICMP host discovery...'],
      ['ok',  '12 hosts up in /24 subnet'],
      ['inf', 'TCP SYN scan on top 1000 ports...'],
      ['ok',  '22/tcp  — OpenSSH 8.9p1'],
      ['ok',  '80/tcp  — HTTP (nginx)'],
      ['ok',  '443/tcp — HTTPS (nginx)'],
      ['err', 'CRITICAL: 3306/tcp — MySQL exposed to internet'],
      ['err', 'CRITICAL: 6379/tcp — Redis (no auth)'],
      ['warn','8080/tcp — HTTP admin panel'],
      ['warn','9200/tcp — Elasticsearch (no auth)'],
      ['inf', 'Service version fingerprinting...'],
      ['warn','OpenSSH 8.9p1: 2 known CVEs (CVE-2023-38408)'],
      ['err', 'MySQL 5.7.38: EOL — no longer receiving patches'],
      ['inf', 'Checking for SMB shares...'],
      ['ok',  'SMB not exposed externally'],
      ['inf', 'SNMP community string scan...'],
      ['err', 'HIGH: SNMP community "public" accepted'],
      ['inf', 'Scan complete.'],
      ['ok',  '─────────────────────────────────'],
      ['err', '⚠  CRITICAL: 4  HIGH: 2  MED: 3  LOW: 5  INFO: 9'],
    ],
    'API': [
      ['inf', 'Loading API security testing module...'],
      ['inf', 'Parsing OpenAPI specification...'],
      ['ok',  '34 endpoints discovered across 6 resource types'],
      ['inf', 'Testing authentication bypass...'],
      ['ok',  'JWT validation: present'],
      ['err', 'CRITICAL: JWT accepts "alg: none" — auth bypass possible'],
      ['inf', 'Testing BOLA (Broken Object Level Auth)...'],
      ['err', 'CRITICAL: GET /api/users/{id} — IDOR confirmed (can access any user)'],
      ['inf', 'Testing mass assignment...'],
      ['warn','POST /api/users — role field writable by users'],
      ['inf', 'Checking rate limiting...'],
      ['warn','POST /api/auth/login — no rate limit (brute-force risk)'],
      ['warn','GET /api/search — no pagination limit'],
      ['inf', 'GraphQL security checks...'],
      ['err', 'HIGH: Introspection enabled in production'],
      ['warn','GraphQL batching: unlimited (DoS risk)'],
      ['inf', 'Scan complete.'],
      ['ok',  '─────────────────────────────────'],
      ['err', '⚠  CRITICAL: 2  HIGH: 2  MED: 4  LOW: 3  INFO: 7'],
    ],
    'SSL/TLS': [
      ['inf', 'Loading SSL/TLS analyzer...'],
      ['ok',  'Certificate chain: valid (3 certs)'],
      ['ok',  'Issuer: Let\'s Encrypt Authority X3'],
      ['ok',  'Expires: 2026-09-14 (168 days remaining)'],
      ['ok',  'Subject Alternative Names: 4 domains covered'],
      ['inf', 'Testing protocol support...'],
      ['ok',  'TLS 1.3: supported ✓'],
      ['ok',  'TLS 1.2: supported ✓'],
      ['warn','TLS 1.1: enabled — recommend disable'],
      ['err', 'HIGH: TLS 1.0: enabled — vulnerable to POODLE'],
      ['err', 'HIGH: SSL 3.0: enabled — severe vulnerability'],
      ['inf', 'Auditing cipher suites...'],
      ['ok',  'Forward Secrecy: supported (ECDHE)'],
      ['warn','RC4 cipher suite: still negotiated on TLS 1.1'],
      ['inf', 'Vulnerability checks...'],
      ['ok',  'HEARTBLEED: not vulnerable'],
      ['ok',  'BEAST: mitigated'],
      ['ok',  'CRIME: not vulnerable'],
      ['warn','LUCKY13: partially mitigated'],
      ['inf', 'HSTS preload check...'],
      ['warn','HSTS preload: not submitted to browser lists'],
      ['inf', 'Scan complete.'],
      ['ok',  '─────────────────────────────────'],
      ['err', '⚠  CRITICAL: 0  HIGH: 2  MED: 3  LOW: 4  INFO: 6'],
    ],
  };

  function addLine(cls, text) {
    const div = document.createElement('div');
    div.className = 't-line';
    const icons = { ok:'✓ ', err:'⚠ ', warn:'△ ', inf:'● ', dim:'' };
    div.innerHTML = `<span class="t-ts">${ts()}</span><span class="t-${cls}">${(icons[cls]||'')}${text}</span>`;
    termOutput.appendChild(div);
    termOutput.scrollTop = termOutput.scrollHeight;
  }

  function clearCursor() {
    const cur = termOutput.querySelector('.t-cursor');
    if (cur) cur.remove();
  }

  function appendCursor() {
    clearCursor();
    const span = document.createElement('span');
    span.className = 't-cursor';
    termOutput.appendChild(span);
  }

  function updateResults(counts) {
    resultCells.forEach(cell => {
      const key = cell.dataset.key;
      if (counts[key] !== undefined) {
        let n = 0;
        const tgt = counts[key];
        const iv = setInterval(() => {
          n = Math.min(n + 1, tgt);
          cell.textContent = n;
          if (n >= tgt) clearInterval(iv);
        }, 50);
      }
    });
  }

  launchBtn?.addEventListener('click', () => {
    if (scanning) return;
    scanning = true;
    launchBtn.classList.add('running');
    launchBtn.textContent = '⏸ SCANNING...';

    const targetInput = document.getElementById('scan-target');
    const target = targetInput?.value.trim() || 'https://target.example.com';

    const activeType = document.querySelector('.scan-type-btn.sel span')?.textContent || 'Web App';
    const script = SCAN_SCRIPTS[activeType] || SCAN_SCRIPTS['Web App'];

    termOutput.innerHTML = '';
    addLine('inf', `SecureNet Pro v3.1 — ${activeType} Scan`);
    addLine('dim', `Target: ${target}`);
    addLine('dim', '─────────────────────────────────');
    appendCursor();

    let counts = { crit:0, high:0, med:0, low:0, info:0 };

    script.forEach((line, i) => {
      setTimeout(() => {
        clearCursor();
        addLine(line[0], line[1]);
        // Skip the final summary line (starts with ⚠) to avoid double-counting
        const isSummaryLine = line[1].startsWith('⚠');
        if (!isSummaryLine) {
          if (line[0] === 'err' && line[1].includes('CRITICAL')) counts.crit++;
          else if (line[0] === 'err') counts.high++;
          else if (line[0] === 'warn') counts.med++;
        }
        appendCursor();

        if (i === script.length - 1) {
          setTimeout(() => {
            clearCursor();
            scanning = false;
            launchBtn.classList.remove('running');
            launchBtn.textContent = '▶ RUN NEW SCAN';
            counts.low = 4; counts.info = 8;
            updateResults(counts);
          }, 300);
        }
      }, 180 + i * 210);
    });
  });

  /* ── Threat map animation ── */
  const mapCanvas = document.getElementById('threat-map-canvas');
  if (mapCanvas) {
    const attacks = [
      { x: 18, y: 35, label: 'RU' },
      { x: 76, y: 32, label: 'CN' },
      { x: 45, y: 58, label: 'NG' },
      { x: 22, y: 22, label: 'US' },
      { x: 55, y: 25, label: 'RO' },
    ];
    const defenses = [
      { x: 32, y: 45 },
      { x: 52, y: 38 },
      { x: 68, y: 52 },
    ];

    attacks.forEach(pt => {
      const el = document.createElement('div');
      el.className = 'attack-point';
      el.style.cssText = `left:${pt.x}%;top:${pt.y}%;`;
      el.title = pt.label;
      mapCanvas.appendChild(el);
    });

    defenses.forEach(pt => {
      const el = document.createElement('div');
      el.className = 'defend-point';
      el.style.cssText = `left:${pt.x}%;top:${pt.y}%;`;
      mapCanvas.appendChild(el);
    });

    // Draw animated attack lines on SVG
    const svg = document.getElementById('map-svg');
    if (svg) {
      function createLine(x1, y1, x2, y2, delay) {
        const line = document.createElementNS('http://www.w3.org/2000/svg', 'line');
        line.setAttribute('x1', x1 + '%'); line.setAttribute('y1', y1 + '%');
        line.setAttribute('x2', x2 + '%'); line.setAttribute('y2', y2 + '%');
        line.setAttribute('stroke', 'rgba(255,45,85,0.3)');
        line.setAttribute('stroke-width', '0.5');
        line.setAttribute('stroke-dasharray', '4 4');
        svg.appendChild(line);

        const anim = document.createElementNS('http://www.w3.org/2000/svg', 'animate');
        anim.setAttribute('attributeName', 'stroke-dashoffset');
        anim.setAttribute('from', '0'); anim.setAttribute('to', '-40');
        anim.setAttribute('dur', '2s'); anim.setAttribute('repeatCount', 'indefinite');
        anim.setAttribute('begin', delay + 's');
        line.appendChild(anim);
      }

      createLine(18, 35, 52, 38, 0);
      createLine(76, 32, 52, 38, 0.5);
      createLine(45, 58, 68, 52, 1);
      createLine(22, 22, 32, 45, 0.3);
      createLine(55, 25, 32, 45, 0.8);
    }
  }

  /* ── Ticker live generation ── */
  const tickerTrack = document.getElementById('ticker-track');
  if (tickerTrack) {
    const threats = [
      { txt: 'CVE-2024-6387 (OpenSSH RCE) — active exploitation detected', type: 'hl' },
      { txt: '3,214 new malware samples indexed in last 6 hours', type: '' },
      { txt: 'Log4Shell still exploited in 8% of enterprise environments', type: 'hl' },
      { txt: 'ZeroLogon attempts spiking from Eastern Europe IPs', type: 'hl' },
      { txt: '47 new CVEs published today across major vendors', type: '' },
      { txt: 'MOVEit vulnerability patched — update immediately', type: 'ok' },
      { txt: 'Ransomware group "BlackCat" targeting healthcare sector', type: 'hl' },
      { txt: 'CISA KEV updated with 6 new exploited vulnerabilities', type: '' },
      { txt: '12 critical RCEs patched in Microsoft Patch Tuesday', type: 'ok' },
      { txt: 'Supply chain attack via malicious npm packages detected', type: 'hl' },
    ];
    const content = threats.map(t =>
      `<span class="ticker-item"><span class="${t.type}">${t.txt}</span> &nbsp;·&nbsp; </span>`
    ).join('');
    tickerTrack.innerHTML = content + content; // doubled for seamless loop
  }

  /* ── Smooth scroll for nav links ── */
  document.querySelectorAll('a[href^="#"]').forEach(a => {
    a.addEventListener('click', e => {
      const target = document.querySelector(a.getAttribute('href'));
      if (target) {
        e.preventDefault();
        target.scrollIntoView({ behavior: 'smooth', block: 'start' });
      }
    });
  });

  /* ── Report tab switching ── */
  document.querySelectorAll('.report-tab-btn').forEach(btn => {
    btn.addEventListener('click', () => {
      document.querySelectorAll('.report-tab-btn').forEach(b => b.classList.remove('active'));
      btn.classList.add('active');
    });
  });

  /* ── Hero canvas particle field ── */
  const heroCanvas = document.getElementById('hero-particles');
  if (heroCanvas) {
    const ctx = heroCanvas.getContext('2d');
    let W, H, particles = [];

    function resize() {
      W = heroCanvas.width  = heroCanvas.offsetWidth;
      H = heroCanvas.height = heroCanvas.offsetHeight;
    }

    resize();
    window.addEventListener('resize', resize);

    for (let i = 0; i < 80; i++) {
      particles.push({
        x: Math.random() * W, y: Math.random() * H,
        vx: (Math.random() - 0.5) * 0.4,
        vy: (Math.random() - 0.5) * 0.4,
        r: Math.random() * 1.5 + 0.3,
        a: Math.random()
      });
    }

    function drawParticles() {
      ctx.clearRect(0, 0, W, H);
      particles.forEach((p, i) => {
        p.x += p.vx; p.y += p.vy;
        if (p.x < 0) p.x = W; if (p.x > W) p.x = 0;
        if (p.y < 0) p.y = H; if (p.y > H) p.y = 0;

        ctx.beginPath();
        ctx.arc(p.x, p.y, p.r, 0, Math.PI * 2);
        ctx.fillStyle = `rgba(0,229,255,${p.a * 0.6})`;
        ctx.fill();

        // draw connections
        for (let j = i + 1; j < particles.length; j++) {
          const q = particles[j];
          const dist = Math.hypot(p.x - q.x, p.y - q.y);
          if (dist < 100) {
            ctx.beginPath();
            ctx.moveTo(p.x, p.y);
            ctx.lineTo(q.x, q.y);
            ctx.strokeStyle = `rgba(0,229,255,${0.06 * (1 - dist/100)})`;
            ctx.lineWidth = 0.5;
            ctx.stroke();
          }
        }
      });
      requestAnimationFrame(drawParticles);
    }

    drawParticles();
  }

  /* ── Glitch text effect ── */
  function glitch(el) {
    const original = el.textContent;
    const chars = '01!@#$%^&*<>/\\|?';
    let iterations = 0;
    const iv = setInterval(() => {
      el.textContent = original.split('').map((char, idx) => {
        if (idx < iterations) return original[idx];
        return chars[Math.floor(Math.random() * chars.length)];
      }).join('');
      if (iterations >= original.length) {
        clearInterval(iv);
        el.textContent = original;
      }
      iterations += 1.5;
    }, 30);
  }

  document.querySelectorAll('.glitch-on-hover').forEach(el => {
    el.addEventListener('mouseenter', () => glitch(el));
  });

  /* ── Init ── */
  console.log('%cSecureNet Pro v3.1 | Loaded', 'color:#00e5ff;font-family:monospace;font-size:14px;');
  console.log('%c⚠ For authorized security testing only.', 'color:#ff2d55;font-family:monospace;');

})();
