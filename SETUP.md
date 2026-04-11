# SecureNet Pro v3.2 — Complete Setup Guide
## Stack: Supabase + Vercel + Render + PayPal + HaveIBeenPwned

---

## ✅ What's In This Version

| Feature | Status | How |
|---|---|---|
| Auth (signup/login/reset) | ✅ Real | Supabase Auth |
| Scan history & findings | ✅ Real | Supabase PostgreSQL |
| Realtime dashboard updates | ✅ Real | Supabase Realtime |
| Real security scan engine | ✅ Real | Render.com FastAPI |
| SSL/TLS checking | ✅ Real | Python ssl module |
| HTTP header analysis | ✅ Real | httpx + Python |
| Exposed path detection | ✅ Real | httpx async checks |
| CVE database search | ✅ Real | NVD API (free) |
| Data breach intelligence | ✅ Real | HaveIBeenPwned API |
| Notable breach database | ✅ Real | HIBP public API |
| PDF report export | ✅ Real | jsPDF (client-side) |
| PayPal payments | ✅ Real | PayPal REST API v2 |
| Plan upgrades | ✅ Real | PayPal → Supabase |

---

## STEP 1 — Supabase (10 min)

1. Create free account at **https://supabase.com**
2. New project → name it, pick a region, set DB password
3. SQL Editor → New Query → paste `supabase_schema.sql` → Run
4. Project Settings → API → copy:
   - **Project URL** → `SUPABASE_URL`
   - **anon public key** → `SUPABASE_KEY`
   - **service_role key** → `SUPABASE_SERVICE_KEY` (for backend only)
5. Open `js/supabase.js` → replace lines 7-8:
   ```js
   const SUPABASE_URL = 'https://YOUR_PROJECT.supabase.co';
   const SUPABASE_KEY = 'YOUR_ANON_KEY';
   ```

---

## STEP 2 — Render.com Backend (15 min)

1. Create free account at **https://render.com**
2. New → Web Service → Connect GitHub repo (push `api/` folder)
   OR: New → Web Service → Manual Deploy → Upload `api/` folder
3. Settings:
   - **Runtime**: Python 3.11
   - **Build command**: `pip install -r requirements.txt`
   - **Start command**: `uvicorn main:app --host 0.0.0.0 --port $PORT`
4. Environment Variables (add these in Render dashboard):
   ```
   SUPABASE_URL         = https://YOUR_PROJECT.supabase.co
   SUPABASE_SERVICE_KEY = YOUR_SERVICE_ROLE_KEY
   PAYPAL_CLIENT_ID     = (from PayPal developer dashboard)
   PAYPAL_CLIENT_SECRET = (from PayPal developer dashboard)
   HIBP_API_KEY         = (from haveibeenpwned.com/API/Key)
   APP_URL              = https://your-site.vercel.app
   ```
5. After deploy, copy your Render URL (e.g. `https://securenet-api.onrender.com`)
6. Replace `API_BASE` in these 3 files:
   - `js/dashboard.js` line 6
   - `breach.html` line with `const API_BASE`
   - `upgrade.html` line with `const API_BASE`

---

## STEP 3 — PayPal (10 min)

1. Go to **https://developer.paypal.com** → Log in
2. Apps & Credentials → Create App
   - **Sandbox** for testing, **Live** for real payments
3. Copy **Client ID** and **Secret** → add to Render env vars
4. In `upgrade.html` update the PAYPAL_BASE URL:
   - Sandbox: `https://api-m.sandbox.paypal.com` (testing)
   - Production: `https://api-m.paypal.com` (real money)
5. Update `APP_URL` env var to your Vercel URL so PayPal redirects correctly

---

## STEP 4 — HaveIBeenPwned API (5 min)

1. Go to **https://haveibeenpwned.com/API/Key** — £3.50/month
2. Copy your API key → add as `HIBP_API_KEY` in Render env vars
3. Without the key, breach.html still works using the public breach list API (limited to domain-name matching, not per-email checking)

---

## STEP 5 — Deploy to Vercel (5 min)

**Option A — Drag & Drop:**
1. Go to **https://vercel.com** → New Project
2. Drag the `securenet/` folder (everything EXCEPT the `api/` folder)
3. Get your live URL

**Option B — GitHub:**
```bash
git init && git add . && git commit -m "Deploy SecureNet Pro"
gh repo create securenet-pro --public --push
```
Then import repo in Vercel → auto-deploys on every push.

---

## File Structure

```
securenet/
├── index.html           ← Landing page (updated nav)
├── auth.html            ← Sign in / sign up
├── dashboard.html       ← Live dashboard (auth-protected)
├── breach.html          ← Data breach intelligence tool
├── upgrade.html         ← PayPal payment page
├── supabase_schema.sql  ← Run once in Supabase SQL editor
├── SETUP.md             ← This file
├── css/
│   └── main.css
├── js/
│   ├── main.js          ← Landing page interactivity
│   ├── supabase.js      ← Auth + DB (PUT YOUR KEYS HERE)
│   └── dashboard.js     ← Dashboard + PDF + scan engine
└── assets/
    └── favicon.svg

api/                     ← Deploy this separately on Render
├── main.py              ← FastAPI backend
└── requirements.txt
```

---

## Free Tier Limits

| Service | Free Limit | Notes |
|---|---|---|
| Supabase Auth | 50,000 MAU | More than enough |
| Supabase DB | 500MB | ~millions of scans |
| Supabase Realtime | 200 concurrent | Fine for early stage |
| Render Web Service | 750 hrs/month | Spins down after 15min inactivity |
| Vercel Hosting | 100GB bandwidth | Unlimited deployments |
| HIBP Public API | Unlimited | Breach list only |
| HIBP Full API | £3.50/month | Per-email checking |
| PayPal | 3.49% + $0.49/txn | No monthly fee |
| NVD CVE API | Unlimited | Free government API |

---

## Render Free Tier Note
The free Render tier **spins down after 15 minutes of inactivity**, causing a ~30-second cold start on the next request. To avoid this, upgrade to Render Starter ($7/month) or use a free uptime monitoring service like UptimeRobot to ping your API every 10 minutes.

---

## Revenue Model (when selling)

- **Free plan**: Ad-free, 10 scans/day → Build userbase
- **Pro $49/month**: Unlimited scans → PayPal recurring (add subscription billing)
- **Enterprise custom**: Direct sales, white-label
- **Per-breach-report**: Upsell detailed breach reports at $29 each

---

## ⚠️ Legal
This platform is for authorized security testing only.
Consult a lawyer before offering breach notification services commercially.
