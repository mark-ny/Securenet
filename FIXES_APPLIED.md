# Fixes Applied — 2026-08-08

Everything below was verified against the actual code (not guessed), and
re-tested in a headless browser at mobile viewport widths (375/390/414px)
after the fix. Full-page overflow is now 0px and there are zero JS console
errors on index.html, auth.html, dashboard.html, breach.html, and
upgrade.html.

## 1. Mobile layout was breaking (confirmed, now fixed)
`html` was missing `overflow-x: hidden` (only `body` had it), which let a
few absolutely-positioned decorative glow elements (`.orb`, used in the
hero and CTA sections) push the page's horizontal scroll area past the
viewport on narrow screens. Fixed in `css/main.css` by adding
`overflow-x: hidden` to the `html` rule as well.

## 2. Sections could render completely blank on mobile (found + fixed)
Content that fades in on scroll (`.reveal` elements — used throughout the
page) only becomes visible once a JS `IntersectionObserver` adds a
`visible` class. On a fast flick-scroll (very common on mobile) the
observer could fire *after* the user had already scrolled past, so the
section briefly rendered as a solid block of background color with
nothing on it. Reproduced this 2 times out of 3 in automated testing.

Fixed in `js/main.js`:
- The trigger zone (`rootMargin`) now extends 250px past the bottom of
  the viewport, so content starts fading in *before* it scrolls into
  view rather than exactly as it arrives.
- Added a 3-second failsafe timer that forces any remaining `.reveal`
  elements visible, so a section can never stay permanently blank even
  in a worst-case timing scenario.
- Re-tested 6 times after the fix: every run now shows full content
  (2,000–3,300 distinct colors in the screenshot) instead of a single
  flat color.

## 3. Login / Sign-up "Failed to fetch" — real cause + handling added
This comes from the Supabase client, not from any placeholder URL — the
`SUPABASE_URL` / `SUPABASE_KEY` in `js/supabase.js` are real (not the
`YOUR-RENDER-APP` style placeholder). A raw "Failed to fetch" from
Supabase almost always means one of:
- **The Supabase project is paused.** Free-tier Supabase projects
  auto-pause after about a week of no activity — this is the single most
  common cause of this exact symptom. Log into supabase.com and check
  your project isn't showing "Paused" — resume it if so.
- The site's requests are being blocked by an ad blocker/VPN/firewall.
- A CORS / Site URL restriction in Supabase's Auth settings.

I can't log into your Supabase dashboard to check which one, so instead
of leaving people stuck on a blank "Failed to fetch," `auth.html` and
`js/supabase.js` now:
- Show a real explanation on-screen ("Can't reach the server — this
  usually means the backend project is paused/asleep, or the request is
  being blocked...") instead of the raw browser error.
- Time out after 8 seconds if the Supabase SDK itself never loads (CDN
  blocked/offline) and tell the person to check their connection, rather
  than leaving the Sign In / Create Account buttons silently doing
  nothing forever.

**Action needed from you:** log into supabase.com and confirm the
`securenet` project is active (resume it if paused). That's the most
likely fix for the actual "Failed to fetch" you're seeing.

## 4. Hover glitch effect could get permanently stuck as scrambled text
`js/main.js` — the hover glitch effect re-read `el.textContent` as the
"original" text on every hover. If you hovered the same element again
before the previous scramble animation finished, it would capture the
*already-scrambled* text as the new baseline, so the letters could get
stuck as random characters instead of resolving back to normal.

Fixed: the true original text is now captured once into a
`data-glitch-original` attribute, and any in-flight scramble interval is
cancelled before a new one starts, so repeated/rapid hovers can no longer
corrupt the text.

## 5. Custom cursor threw errors on every page except the homepage
`css/main.css` sets `cursor: none` on `<body>` site-wide, but the custom
cursor dot/ring (`#cursor` / `#cursor-ring`) and the JS that draws them
only exist on `index.html`. On `auth.html`, `dashboard.html`,
`breach.html`, and `upgrade.html`, this meant an invisible mouse pointer
with nothing drawn in its place, and (where `js/main.js` happened to run)
a `TypeError` on every `mousemove`.

Fixed in `js/main.js`: the custom cursor now only activates when the
`#cursor`/`#cursor-ring` elements actually exist **and** the device has a
real mouse (`(hover: hover) and (pointer: fine)`), so touch devices keep
their native behavior and pages without the cursor markup are unaffected.

## 6. Scans / PayPal upgrade will not work yet — this one's on you
`js/dashboard.js` and `upgrade.html` both still point `API_BASE` at the
placeholder `https://YOUR-RENDER-APP.onrender.com`. This isn't a bug I
can fix from here — it means the Python backend (`main.py` / `api/main.py`,
identical copies — pick one as your Render root directory) has not been
deployed yet. Until you deploy it to Render and replace `API_BASE` in both
files with your real `*.onrender.com` URL, the dashboard correctly falls
back to demo/mock mode (this fallback is intentional, see
`API_CONFIGURED` in `dashboard.js`) and the PayPal flow in `upgrade.html`
will fail. `render.yaml` at the repo root is already a valid Render
deploy config (`uvicorn main:app`) — deploying is just a matter of
connecting the repo on render.com.

`breach.html` currently has no backend calls wired in at all — it's
presentational only right now, not connected to any API.
