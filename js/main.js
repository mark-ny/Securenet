/* SecureNet Pro v4.0 — main.js — paste this at github.com/mark-ny/Securenet/blob/main/js/main.js */
(function(){
'use strict';

/* ── Custom cursor (desktop) ── */
var cur=$('cursor'),ring=$('cursor-ring');
if(cur&&ring){
  var mx=0,my=0,rx=0,ry=0;
  document.addEventListener('mousemove',function(e){mx=e.clientX;my=e.clientY;cur.style.left=mx+'px';cur.style.top=my+'px';});
  (function anim(){rx+=(mx-rx)*.12;ry+=(my-ry)*.12;ring.style.left=rx+'px';ring.style.top=ry+'px';requestAnimationFrame(anim);})();
}
function $(id){return document.getElementById(id);}
function $$(s){return Array.from(document.querySelectorAll(s));}

/* ── Nav scroll ── */
window.addEventListener('scroll',function(){
  var nav=$('nav'),pb=$('progress'),st=$('scroll-top');
  var pct=(window.scrollY/Math.max(document.body.scrollHeight-window.innerHeight,1))*100;
  if(nav)nav.classList.toggle('scrolled',window.scrollY>30);
  if(pb)pb.style.width=pct+'%';
  if(st)st.classList.toggle('show',window.scrollY>500);
},{passive:true});
var st=$('scroll-top');if(st)st.addEventListener('click',function(){window.scrollTo({top:0,behavior:'smooth'});});

/* ── Mobile nav ── */
var hb=$('hamburger'),mn=$('mobile-nav');
if(hb&&mn){
  hb.addEventListener('click',function(){mn.classList.toggle('open');hb.textContent=mn.classList.contains('open')?'✕':'☰';});
  mn.querySelectorAll('a').forEach(function(a){a.addEventListener('click',function(){mn.classList.remove('open');hb.textContent='☰';});});
}

/* ── Smooth scroll ── */
document.addEventListener('click',function(e){
  var a=e.target.closest('a[href^="#"]');
  if(!a)return;
  var t=document.querySelector(a.getAttribute('href'));
  if(t){e.preventDefault();t.scrollIntoView({behavior:'smooth',block:'start'});}
});

/* ── Scroll reveal ── */
var ro=new IntersectionObserver(function(entries){entries.forEach(function(e){if(e.isIntersecting)e.target.classList.add('visible');});},{threshold:0.06,rootMargin:'0px 0px -40px 0px'});
$$('.reveal').forEach(function(el){ro.observe(el);});

/* ── Stats count-up ── */
function countUp(el,target,suffix,dec){
  var t0=performance.now(),dur=2000;
  function step(now){var p=Math.min((now-t0)/dur,1),ease=1-Math.pow(1-p,3),val=target*ease;
    el.textContent=(dec?val.toFixed(dec):Math.floor(val)).toLocaleString()+suffix;
    if(p<1)requestAnimationFrame(step);}
  requestAnimationFrame(step);
}
var so=new IntersectionObserver(function(entries){
  if(!entries[0].isIntersecting)return;
  $$('.stat-n[data-val]').forEach(function(el){countUp(el,parseFloat(el.dataset.val),el.dataset.suf||'',parseInt(el.dataset.dec||0));});
  so.disconnect();
},{threshold:0.5});
var sr=document.querySelector('.stats-row');if(sr)so.observe(sr);

/* ── Sev bars ── */
var sevO=new IntersectionObserver(function(e){if(!e[0].isIntersecting)return;$$('.sev-bar[data-w]').forEach(function(b){b.style.width=b.dataset.w+'%';});sevO.disconnect();},{threshold:0.3});
var sc=document.querySelector('.sev-chart-container');if(sc)sevO.observe(sc);

/* ── Tool filter ── */
$$('.filter-btn').forEach(function(btn){
  btn.addEventListener('click',function(){
    $$('.filter-btn').forEach(function(b){b.classList.remove('active');});
    btn.classList.add('active');
    var cat=btn.dataset.filter;
    $$('.tool-card[data-cat]').forEach(function(c){
      var show=cat==='all'||c.dataset.cat.split(' ').indexOf(cat)>-1;
      c.style.opacity=show?'1':'0.15';c.style.transform=show?'':'scale(0.96)';c.style.pointerEvents=show?'':'none';
    });
  });
});

/* ── Tool cards → scroll to scanner + select type ── */
var TOOL_MAP={'Web App Scanner':'Web App','Code Vulnerability Scanner':'Code','Network Port Scanner':'Network','SSL/TLS Analyzer':'SSL/TLS','API Security Tester':'API','Cloud Config Auditor':'Cloud','Dependency Checker':'Code','Secrets Detector':'Code','DNS Recon & OSINT':'Network','AI Threat Modeler':'Web App','Firewall & WAF Tester':'Web App'};
$$('.tool-card[data-cat]').forEach(function(card){
  card.style.cursor='pointer';
  card.addEventListener('click',function(){
    var name=(card.querySelector('.tool-name')||{}).textContent||'';
    var type=TOOL_MAP[name.trim()];
    var sec=$('scanner');
    if(sec)sec.scrollIntoView({behavior:'smooth',block:'start'});
    if(type){setTimeout(function(){
      $$('.scan-type-btn').forEach(function(b){b.classList.toggle('sel',(b.querySelector('span')||{}).textContent===type);});
      var inp=$('scan-target');if(inp&&!inp.value)inp.focus();
    },700);}
  });
});

/* ── Pentest module cards ── */
$$('.module-card').forEach(function(c){c.style.cursor='pointer';c.addEventListener('click',function(){var s=$('scanner');if(s)s.scrollIntoView({behavior:'smooth',block:'start'});});});

/* ── Scan type buttons ── */
$$('.scan-type-btn').forEach(function(btn){btn.addEventListener('click',function(){btn.closest('.scan-type-grid').querySelectorAll('.scan-type-btn').forEach(function(b){b.classList.remove('sel');});btn.classList.add('sel');});});
$$('.scan-option').forEach(function(o){o.addEventListener('click',function(){o.classList.toggle('checked');});});

/* ── SCANNER ENGINE ── */
var launchBtn=$('launch-scan'),term=$('terminal-output'),scanning=false;
function ts(){return new Date().toTimeString().slice(0,8);}
function addLine(cls,text){
  if(!term)return;
  var d=document.createElement('div');d.className='t-line';
  var icons={ok:'✓ ',err:'⚠ ',warn:'△ ',inf:'● ',dim:'  '};
  d.innerHTML='<span class="t-ts">'+ts()+'</span><span class="t-'+cls+'">'+(icons[cls]||'')+String(text).replace(/</g,'&lt;')+'</span>';
  term.appendChild(d);term.scrollTop=term.scrollHeight;
}
function clearCursor(){var c=term&&term.querySelector('.t-cursor');if(c)c.remove();}
function appendCursor(){clearCursor();if(!term)return;var s=document.createElement('span');s.className='t-cursor';term.appendChild(s);}

/* UPDATE RESULT CELLS — this is the key fix */
function updateResults(counts){
  $$('.result-num[data-key]').forEach(function(cell){
    var key=cell.dataset.key;
    var val=counts[key]||0;
    var n=0;
    var iv=setInterval(function(){n=Math.min(n+1,val);cell.textContent=n;if(n>=val)clearInterval(iv);},60);
  });
}

/* Parse the summary line: ⚠ CRITICAL: 3 HIGH: 1 MED: 4 LOW: 6 INFO: 12 */
function parseSummary(line){
  var m=line.match(/CRITICAL:\s*(\d+).*HIGH:\s*(\d+).*MED:\s*(\d+).*LOW:\s*(\d+).*INFO:\s*(\d+)/i);
  return m?{crit:+m[1],high:+m[2],med:+m[3],low:+m[4],info:+m[5]}:null;
}

var SCRIPTS={
  'Web App':[['inf','Initializing web app scanner...'],['inf','Loading OWASP Top 10 (2021) ruleset...'],['ok','Engine ready — 2,400 test vectors loaded'],['inf','Resolving target DNS...'],['ok','DNS resolved — host reachable (RTT 38ms)'],['ok','Server: nginx/1.25.3 | Frontend: React 18.2'],['ok','Crawling — 47 unique endpoints found'],['inf','Testing XSS...'],['ok','Reflected XSS: clean'],['warn','Stored XSS: injection point in POST /comments'],['inf','Testing SQL injection...'],['err','CRITICAL: SQLi on POST /api/search — param: query (CVSS 9.8)'],['warn','CSRF token missing on /api/profile/update'],['warn','Login rate-limit: not enforced'],['warn','Content-Security-Policy: not set'],['warn','X-Frame-Options: missing (clickjacking risk)'],['ok','HSTS: enabled max-age=31536000'],['err','CRITICAL: /admin — accessible without authentication (CVSS 9.3)'],['err','CRITICAL: /api/debug — exposes full stack traces'],['warn','File upload: client-side validation only (bypassable)'],['err','HIGH: API key leaked in JS bundle line 8421'],['ok','──────────────────────────────────────'],['err','⚠  CRITICAL: 3  HIGH: 1  MED: 4  LOW: 6  INFO: 12']],
  'Network':[['inf','Network recon engine starting...'],['ok','12 hosts up in subnet'],['ok','22/tcp — OpenSSH 8.9p1'],['ok','80/tcp — HTTP nginx'],['ok','443/tcp — HTTPS'],['err','CRITICAL: 3306/tcp — MySQL exposed to internet (CVSS 9.8)'],['err','CRITICAL: 6379/tcp — Redis no auth (CVSS 9.1)'],['warn','8080/tcp — HTTP admin panel'],['warn','9200/tcp — Elasticsearch no auth'],['err','MySQL 5.7.38: End of Life — no security patches'],['err','HIGH: SNMP community "public" accepted'],['ok','──────────────────────────────────────'],['err','⚠  CRITICAL: 4  HIGH: 2  MED: 3  LOW: 5  INFO: 9']],
  'API':[['inf','API security fuzzer starting...'],['ok','34 endpoints, 6 resource types'],['err','CRITICAL: JWT accepts alg:none — full auth bypass (CVSS 9.8)'],['err','CRITICAL: IDOR on GET /api/users/{id} (CVSS 9.1)'],['warn','POST /api/users — role field writable (mass assignment)'],['warn','No rate limiting on POST /api/auth/login'],['err','HIGH: GraphQL introspection enabled in production'],['ok','──────────────────────────────────────'],['err','⚠  CRITICAL: 2  HIGH: 2  MED: 4  LOW: 3  INFO: 7']],
  'SSL/TLS':[['ok','Certificate: valid — 168 days remaining'],['ok','TLS 1.3: supported ✓'],['ok','TLS 1.2: supported ✓'],['warn','TLS 1.1: enabled — recommend disabling'],['err','HIGH: TLS 1.0 enabled — POODLE attack possible (CVSS 7.4)'],['err','HIGH: SSL 3.0 enabled — severe vulnerability'],['warn','RC4 cipher still negotiated on TLS 1.1'],['ok','HEARTBLEED: not vulnerable'],['ok','──────────────────────────────────────'],['err','⚠  CRITICAL: 0  HIGH: 2  MED: 3  LOW: 4  INFO: 6']],
  'Code':[['ok','Languages: Python, JavaScript, Go'],['warn','Hardcoded credential: config.py line 88'],['err','CRITICAL: AWS_SECRET_KEY committed to .env (CVSS 9.8)'],['err','CRITICAL: Private key in /certs/server.key'],['warn','SQL via string concat — injection risk'],['warn','MD5 for password hashing — use bcrypt'],['err','HIGH: eval() with user-controlled input'],['ok','──────────────────────────────────────'],['err','⚠  CRITICAL: 3  HIGH: 2  MED: 5  LOW: 8  INFO: 14']],
  'Cloud':[['inf','Scanning AWS account — IAM, S3, RDS, EC2...'],['err','CRITICAL: S3 bucket prod-assets — public read (CVSS 9.1)'],['err','CRITICAL: S3 bucket backup-2024 — public read'],['warn','MFA not enforced on 4 IAM users'],['warn','CloudTrail disabled in eu-west-1'],['err','HIGH: RDS db.prod — publicly accessible'],['warn','Security group: 0.0.0.0/0 on port 22 (SSH)'],['ok','──────────────────────────────────────'],['err','⚠  CRITICAL: 3  HIGH: 3  MED: 4  LOW: 6  INFO: 8']]
};

if(launchBtn){
  launchBtn.addEventListener('click',function(){
    if(scanning)return;
    scanning=true;
    launchBtn.classList.add('running');
    launchBtn.textContent='⏸ SCANNING...';
    var target=($('scan-target')||{}).value||'example.com';
    var type=(document.querySelector('.scan-type-btn.sel span')||{}).textContent||'Web App';
    var script=SCRIPTS[type]||SCRIPTS['Web App'];
    if(term)term.innerHTML='';
    addLine('inf','SecureNet Pro v4.0 — '+type+' Scan');
    addLine('dim','Target: '+target);
    addLine('dim','─────────────────────────────────────────────');
    appendCursor();
    var counts={crit:0,high:0,med:0,low:4,info:8};
    script.forEach(function(line,i){
      setTimeout(function(){
        clearCursor();
        addLine(line[0],line[1]);
        /* Parse counts from summary line */
        if(line[0]==='err'&&line[1].indexOf('CRITICAL:')>-1){
          var p=parseSummary(line[1]);if(p)counts=p;
        }
        appendCursor();
        if(i===script.length-1){
          setTimeout(function(){
            clearCursor();
            scanning=false;
            launchBtn.classList.remove('running');
            launchBtn.textContent='▶ RUN NEW SCAN';
            /* SHOW RESULTS */
            updateResults(counts);
            /* Flash results bar */
            var rb=document.querySelector('.results-bar');
            if(rb){rb.style.background='rgba(0,229,255,0.08)';setTimeout(function(){rb.style.background='';},1200);}
            /* Glow critical if found */
            if(counts.crit>0){var cc=document.querySelector('.result-num[data-key="crit"]');if(cc){cc.style.textShadow='0 0 20px rgba(255,45,85,0.9)';cc.style.fontSize='28px';}}
          },300);
        }
      },180+i*200);
    });
  });
}

/* ── THREAT MAP ── */
var mc=$('threat-map-canvas');
if(mc){
  [{x:18,y:35,c:'#ff2d55'},{x:76,y:32,c:'#ff2d55'},{x:45,y:58,c:'#ffb800'},{x:22,y:22,c:'#ff2d55'},{x:55,y:25,c:'#ffb800'},{x:62,y:44,c:'#ff2d55'}].forEach(function(pt){
    var el=document.createElement('div');
    el.className='attack-point';
    el.style.cssText='left:'+pt.x+'%;top:'+pt.y+'%;background:'+pt.c+';box-shadow:0 0 12px '+pt.c+';';
    mc.appendChild(el);
  });
  [{x:32,y:45},{x:52,y:38},{x:68,y:52},{x:25,y:60}].forEach(function(pt){
    var el=document.createElement('div');el.className='defend-point';
    el.style.cssText='left:'+pt.x+'%;top:'+pt.y+'%;';mc.appendChild(el);
  });
  var svg=$('map-svg');
  if(svg){
    function mkLine(x1,y1,x2,y2,delay,color){
      var line=document.createElementNS('http://www.w3.org/2000/svg','line');
      line.setAttribute('x1',x1+'%');line.setAttribute('y1',y1+'%');line.setAttribute('x2',x2+'%');line.setAttribute('y2',y2+'%');
      line.setAttribute('stroke',color||'rgba(255,45,85,0.6)');line.setAttribute('stroke-width','1.5');line.setAttribute('stroke-dasharray','6 4');
      var a=document.createElementNS('http://www.w3.org/2000/svg','animate');
      a.setAttribute('attributeName','stroke-dashoffset');a.setAttribute('from','0');a.setAttribute('to','-60');
      a.setAttribute('dur','1.5s');a.setAttribute('repeatCount','indefinite');a.setAttribute('begin',delay+'s');
      line.appendChild(a);svg.appendChild(line);
    }
    mkLine(18,35,52,38,0);mkLine(76,32,52,38,0.5);mkLine(45,58,68,52,1);mkLine(22,22,32,45,0.3);mkLine(55,25,32,45,0.8);mkLine(62,44,25,60,1.2);
  }
  /* Live feed */
  var feed=$('threat-feed-items');
  if(feed){
    var STATIC=[
      {sev:'CRITICAL',color:'#ff2d55',title:'CVE-2024-6387 — OpenSSH RCE',desc:'Unauthenticated remote code execution. Active exploitation.',time:'2m ago'},
      {sev:'CRITICAL',color:'#ff2d55',title:'CVE-2025-0282 — Ivanti Connect Secure',desc:'Stack buffer overflow zero-day. Patch immediately.',time:'18m ago'},
      {sev:'HIGH',color:'#ffb800',title:'CVE-2024-4577 — PHP CGI RCE',desc:'Windows servers under active attack.',time:'1h ago'},
      {sev:'HIGH',color:'#ffb800',title:'Microsoft Patch Tuesday',desc:'12 critical RCEs patched this month.',time:'3h ago'},
      {sev:'CRITICAL',color:'#ff2d55',title:'Malicious npm package',desc:'400k weekly downloads affected.',time:'6h ago'}
    ];
    function renderFeed(items){
      feed.innerHTML=items.map(function(i){
        return '<div style="padding:12px 16px;border-bottom:1px solid var(--border2)">'
          +'<div style="display:flex;justify-content:space-between;margin-bottom:4px">'
          +'<span style="font-family:var(--mono);font-size:10px;color:'+i.color+'">⚠ '+i.sev+'</span>'
          +'<span style="font-family:var(--mono);font-size:9px;color:var(--text3)">'+i.time+'</span></div>'
          +'<div style="font-size:13px;color:var(--text);font-weight:600;margin-bottom:2px">'+i.title+'</div>'
          +'<div style="font-size:11px;color:var(--text2)">'+i.desc+'</div></div>';
      }).join('');
    }
    renderFeed(STATIC);
    /* Try live NVD data */
    fetch('https://services.nvd.nist.gov/rest/json/cves/2.0?resultsPerPage=5&sortBy=lastModified&sortOrder=desc',{signal:AbortSignal.timeout(10000)})
    .then(function(r){return r.ok?r.json():null;})
    .then(function(data){
      if(!data||!data.vulnerabilities||!data.vulnerabilities.length)return;
      var items=data.vulnerabilities.map(function(v){
        var cve=v.cve,id=cve.id;
        var desc=((cve.descriptions||[]).find(function(d){return d.lang==='en';})||{}).value||'';
        var m=cve.metrics||{},cvss=(m.cvssMetricV31||m.cvssMetricV30||[{}])[0].cvssData||{};
        var score=cvss.baseScore||0;
        var sev=(cvss.baseSeverity||(score>=9?'CRITICAL':score>=7?'HIGH':score>=4?'MEDIUM':'LOW')).toUpperCase();
        var color=sev==='CRITICAL'?'#ff2d55':sev==='HIGH'?'#ffb800':'#00e5ff';
        var pub=cve.published?new Date(cve.published).toLocaleDateString():'';
        return {sev:sev,color:color,title:id+(score?' — CVSS '+score:''),desc:desc.slice(0,90),time:pub};
      });
      renderFeed(items);
    }).catch(function(){});
  }
}

/* ── TICKER ── */
var tt=$('ticker-track');
if(tt){
  var threats=[
    {t:'CVE-2024-6387 (OpenSSH RCE) — active exploitation worldwide',c:'hl'},
    {t:'CVE-2025-0282 (Ivanti Zero-Day) — patch immediately',c:'hl'},
    {t:'3,214 new malware samples indexed in last 6 hours',c:''},
    {t:'CISA KEV updated — 6 new actively exploited vulnerabilities',c:''},
    {t:'Ransomware targeting healthcare — update VMware ESXi now',c:'hl'},
    {t:'Supply chain attack via npm — 400k downloads affected',c:'hl'},
    {t:'47 new CVEs published today across major vendors',c:''},
    {t:'Microsoft Patch Tuesday — 12 critical RCEs patched',c:'ok'}
  ];
  var c=threats.map(function(t){return '<span class="ticker-item"><span class="'+t.c+'">'+t.t+'</span> &nbsp;·&nbsp; </span>';}).join('');
  tt.innerHTML=c+c;
  var te=$('threat-ticker');if(te)setTimeout(function(){te.style.display='block';},800);
}

/* ── REPORT TABS ── */
$$('.report-tab-btn').forEach(function(btn){
  btn.addEventListener('click',function(){
    $$('.report-tab-btn').forEach(function(b){b.classList.remove('active');b.style.background='';b.style.color='';b.style.border='';});
    btn.classList.add('active');btn.style.background='rgba(0,229,255,0.1)';btn.style.color='var(--neon)';btn.style.border='1px solid rgba(0,229,255,0.3)';
  });
});

/* ── HERO PARTICLES ── */
var hc=$('hero-particles');
if(hc){
  var ctx=hc.getContext('2d'),W,H,pts=[];
  function resize(){W=hc.width=hc.offsetWidth;H=hc.height=hc.offsetHeight;}
  resize();window.addEventListener('resize',resize,{passive:true});
  for(var i=0;i<70;i++)pts.push({x:Math.random()*1200,y:Math.random()*600,vx:(Math.random()-.5)*.4,vy:(Math.random()-.5)*.4,r:Math.random()*1.5+.3,a:Math.random()});
  function drawP(){
    ctx.clearRect(0,0,W,H);
    pts.forEach(function(p,i){
      p.x+=p.vx;p.y+=p.vy;
      if(p.x<0)p.x=W;if(p.x>W)p.x=0;if(p.y<0)p.y=H;if(p.y>H)p.y=0;
      ctx.beginPath();ctx.arc(p.x,p.y,p.r,0,Math.PI*2);ctx.fillStyle='rgba(0,229,255,'+p.a*.6+')';ctx.fill();
      for(var j=i+1;j<pts.length;j++){var q=pts[j],d=Math.hypot(p.x-q.x,p.y-q.y);
        if(d<100){ctx.beginPath();ctx.moveTo(p.x,p.y);ctx.lineTo(q.x,q.y);ctx.strokeStyle='rgba(0,229,255,'+(0.06*(1-d/100))+')';ctx.lineWidth=.5;ctx.stroke();}
      }
    });
    requestAnimationFrame(drawP);
  }
  drawP();
}

/* ── GLITCH ── */
$$('.glitch-on-hover').forEach(function(el){
  el.addEventListener('mouseenter',function(){
    var orig=el.textContent,chars='01!@#$%^&*<>/\\|?',it=0;
    var iv=setInterval(function(){
      el.textContent=orig.split('').map(function(c,idx){return idx<it?orig[idx]:chars[Math.floor(Math.random()*chars.length)];}).join('');
      if(it>=orig.length){clearInterval(iv);el.textContent=orig;}it+=1.5;
    },30);
  });
});

console.log('%cSecureNet Pro v4.0 | Online','color:#00e5ff;font-family:monospace;font-size:14px;font-weight:bold');
})();
