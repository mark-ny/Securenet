/* ═══════════════════════════════════════════════════
   SECURENET PRO — SUPABASE CONFIG & AUTH
   Replace SUPABASE_URL and SUPABASE_KEY below with
   your values from supabase.com → Project Settings → API
   ═══════════════════════════════════════════════════ */

const SUPABASE_URL = 'https://ojpiiyulxyvndcwayorj.supabase.co';
const SUPABASE_KEY = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6Im9qcGlpeXVseHl2bmRjd2F5b3JqIiwicm9sZSI6ImFub24iLCJpYXQiOjE3NzU4NTg3ODksImV4cCI6MjA5MTQzNDc4OX0.LTW66Mo7TXlPvK1xSSkaJ4VuqMKL3afNMKQguTYf9N8';

/* ── Wait for supabase CDN to load, then init ── */
function initSupabase() {
  if (typeof window.supabase === 'undefined') {
    setTimeout(initSupabase, 50);
    return;
  }

  const sb = window.supabase.createClient(SUPABASE_URL, SUPABASE_KEY);

  /* ── Auth helpers ── */
  const Auth = {
    async signUp(email, password, fullName) {
      const { data, error } = await sb.auth.signUp({
        email, password,
        options: { data: { full_name: fullName } }
      });
      if (error) throw error;
      if (data.user) {
        await sb.from('profiles').upsert({
          id: data.user.id, email,
          full_name: fullName, plan: 'free', scan_count: 0
        });
      }
      return data;
    },

    async signIn(email, password) {
      const { data, error } = await sb.auth.signInWithPassword({ email, password });
      if (error) throw error;
      return data;
    },

    async signOut() {
      await sb.auth.signOut();
      window.location.href = 'index.html';
    },

    async getUser() {
      const { data: { user } } = await sb.auth.getUser();
      return user;
    },

    async getSession() {
      const { data: { session } } = await sb.auth.getSession();
      return session;
    },

    async requireAuth(redirectTo = 'auth.html') {
      const user = await this.getUser();
      if (!user) {
        window.location.href = redirectTo + '?auth=required';
        return null;
      }
      return user;
    }
  };

  /* ── Database helpers ── */
  const DB = {
    async getScans(userId, limit = 20) {
      const { data, error } = await sb
        .from('scans').select('*')
        .eq('user_id', userId)
        .order('created_at', { ascending: false })
        .limit(limit);
      if (error) throw error;
      return data;
    },

    async createScan(userId, target, scanType, intensity) {
      const { data, error } = await sb.from('scans').insert({
        user_id: userId, target, scan_type: scanType, intensity,
        status: 'running',
        findings_critical: 0, findings_high: 0,
        findings_medium: 0, findings_low: 0
      }).select().single();
      if (error) throw error;
      return data;
    },

    async updateScan(scanId, updates) {
      const { data, error } = await sb.from('scans')
        .update(updates).eq('id', scanId).select().single();
      if (error) throw error;
      return data;
    },

    async getFindings(userId, { severity, limit = 50 } = {}) {
      let q = sb.from('findings')
        .select('*, scans(target, scan_type)')
        .eq('user_id', userId)
        .order('severity_rank', { ascending: true })
        .limit(limit);
      if (severity) q = q.eq('severity', severity);
      const { data, error } = await q;
      if (error) throw error;
      return data;
    },

    async getProfile(userId) {
      const { data, error } = await sb.from('profiles')
        .select('*').eq('id', userId).single();
      if (error) throw error;
      return data;
    },

    async updateProfile(userId, updates) {
      const { error } = await sb.from('profiles')
        .update(updates).eq('id', userId);
      if (error) throw error;
    },

    async getDashboardStats(userId) {
      const [scansRes, findingsRes, profileRes] = await Promise.all([
        sb.from('scans').select('id, status, created_at, target').eq('user_id', userId),
        sb.from('findings').select('severity, status').eq('user_id', userId),
        sb.from('profiles').select('*').eq('id', userId).single()
      ]);
      const scans    = scansRes.data    || [];
      const findings = findingsRes.data || [];
      const profile  = profileRes.data  || {};
      const now      = new Date();
      const openCritical   = findings.filter(f => f.severity === 'critical' && f.status === 'open').length;
      const totalAssets    = [...new Set(scans.map(s => s.target))].length;
      const scansThisMonth = scans.filter(s => {
        const d = new Date(s.created_at);
        return d.getMonth() === now.getMonth() && d.getFullYear() === now.getFullYear();
      }).length;
      const crit = findings.filter(f => f.severity === 'critical' && f.status === 'open').length;
      const high = findings.filter(f => f.severity === 'high'     && f.status === 'open').length;
      const med  = findings.filter(f => f.severity === 'medium'   && f.status === 'open').length;
      const riskScore = Math.min(10, (crit * 4 + high * 2 + med * 0.5) / Math.max(1, totalAssets)).toFixed(1);
      return { openCritical, scansThisMonth, totalAssets, riskScore, profile };
    }
  };

  /* ── Realtime ── */
  const Realtime = {
    subscribeToScans(userId, callback) {
      return sb.channel('scans-changes')
        .on('postgres_changes', {
          event: '*', schema: 'public', table: 'scans',
          filter: `user_id=eq.${userId}`
        }, callback)
        .subscribe();
    }
  };

  /* ── Expose globally ── */
  window.SecureNet = { sb, Auth, DB, Realtime };

  /* ── Fire ready event so pages know SecureNet is available ── */
  window.dispatchEvent(new Event('securenet:ready'));
}

/* Start the init process */
if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', initSupabase);
} else {
  initSupabase();
}
