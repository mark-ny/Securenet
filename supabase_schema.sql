-- ═══════════════════════════════════════════════════════
-- SECURENET PRO — SUPABASE DATABASE SCHEMA
-- Run this in: Supabase Dashboard → SQL Editor → New Query
-- ═══════════════════════════════════════════════════════

-- Enable UUID extension
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- ── PROFILES ──────────────────────────────────────────
CREATE TABLE IF NOT EXISTS public.profiles (
  id          UUID PRIMARY KEY REFERENCES auth.users(id) ON DELETE CASCADE,
  email       TEXT NOT NULL,
  full_name   TEXT,
  plan        TEXT NOT NULL DEFAULT 'free',  -- 'free' | 'pro' | 'enterprise'
  scan_count  INTEGER NOT NULL DEFAULT 0,
  created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- ── SCANS ─────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS public.scans (
  id                  UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  user_id             UUID NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
  target              TEXT NOT NULL,
  scan_type           TEXT NOT NULL,   -- 'Web App' | 'Network' | 'Code' | 'SSL/TLS' | 'API' | 'Cloud'
  intensity           TEXT NOT NULL DEFAULT 'standard',
  status              TEXT NOT NULL DEFAULT 'running',  -- 'running' | 'complete' | 'failed'
  findings_critical   INTEGER NOT NULL DEFAULT 0,
  findings_high       INTEGER NOT NULL DEFAULT 0,
  findings_medium     INTEGER NOT NULL DEFAULT 0,
  findings_low        INTEGER NOT NULL DEFAULT 0,
  duration_seconds    INTEGER,
  report_url          TEXT,
  created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at          TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- ── FINDINGS ──────────────────────────────────────────
CREATE TABLE IF NOT EXISTS public.findings (
  id            UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  user_id       UUID NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
  scan_id       UUID NOT NULL REFERENCES public.scans(id) ON DELETE CASCADE,
  title         TEXT NOT NULL,
  description   TEXT,
  severity      TEXT NOT NULL,       -- 'critical' | 'high' | 'medium' | 'low' | 'info'
  severity_rank INTEGER NOT NULL,    -- 1=critical, 2=high, 3=medium, 4=low, 5=info (for ordering)
  status        TEXT NOT NULL DEFAULT 'open',  -- 'open' | 'resolved' | 'accepted'
  cve           TEXT,
  cwe           TEXT,
  cvss_score    NUMERIC(3,1),
  remediation   TEXT,
  created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- ── INDEXES ───────────────────────────────────────────
CREATE INDEX IF NOT EXISTS scans_user_id_idx       ON public.scans(user_id);
CREATE INDEX IF NOT EXISTS scans_created_at_idx    ON public.scans(created_at DESC);
CREATE INDEX IF NOT EXISTS findings_user_id_idx    ON public.findings(user_id);
CREATE INDEX IF NOT EXISTS findings_scan_id_idx    ON public.findings(scan_id);
CREATE INDEX IF NOT EXISTS findings_severity_idx   ON public.findings(severity_rank);

-- ── ROW LEVEL SECURITY ────────────────────────────────
ALTER TABLE public.profiles  ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.scans     ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.findings  ENABLE ROW LEVEL SECURITY;

-- Profiles: users can only read/write their own profile
CREATE POLICY "profiles_self" ON public.profiles
  USING (auth.uid() = id)
  WITH CHECK (auth.uid() = id);

-- Scans: users can only access their own scans
CREATE POLICY "scans_self" ON public.scans
  USING (auth.uid() = user_id)
  WITH CHECK (auth.uid() = user_id);

-- Findings: users can only access their own findings
CREATE POLICY "findings_self" ON public.findings
  USING (auth.uid() = user_id)
  WITH CHECK (auth.uid() = user_id);

-- ── AUTO-UPDATE updated_at ────────────────────────────
CREATE OR REPLACE FUNCTION update_updated_at()
RETURNS TRIGGER AS $$
BEGIN
  NEW.updated_at = NOW();
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER scans_updated_at
  BEFORE UPDATE ON public.scans
  FOR EACH ROW EXECUTE FUNCTION update_updated_at();

CREATE TRIGGER profiles_updated_at
  BEFORE UPDATE ON public.profiles
  FOR EACH ROW EXECUTE FUNCTION update_updated_at();

-- ── AUTO-CREATE PROFILE ON SIGNUP ─────────────────────
CREATE OR REPLACE FUNCTION public.handle_new_user()
RETURNS TRIGGER AS $$
BEGIN
  INSERT INTO public.profiles (id, email, full_name)
  VALUES (
    NEW.id,
    NEW.email,
    COALESCE(NEW.raw_user_meta_data->>'full_name', split_part(NEW.email, '@', 1))
  )
  ON CONFLICT (id) DO NOTHING;
  RETURN NEW;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

CREATE OR REPLACE TRIGGER on_auth_user_created
  AFTER INSERT ON auth.users
  FOR EACH ROW EXECUTE FUNCTION public.handle_new_user();

-- ── REALTIME ──────────────────────────────────────────
-- Enable realtime for scans table (for live dashboard updates)
ALTER PUBLICATION supabase_realtime ADD TABLE public.scans;

-- Done! ✅
