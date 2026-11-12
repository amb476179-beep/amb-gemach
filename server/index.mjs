// AMB גמ"ח – שרת API (Neon Functions). כל גמ"ח רואה רק את הנתונים שלו; רק מנהל המערכת (owner) רואה הכל.
import pg from 'pg';
import crypto from 'node:crypto';

const pool = new pg.Pool({ connectionString: process.env.DATABASE_URL, max: 5 });
pool.on('error', () => {}); // ניתוק של חיבור רדום – החיבור הבא ייפתח מחדש
const q = (text, values) => pool.query(text, values).then(r => r.rows);
const one = async (text, values) => (await q(text, values))[0] || null;

const CORS = { 'Access-Control-Allow-Origin': '*', 'Access-Control-Allow-Headers': 'Authorization, Content-Type', 'Access-Control-Allow-Methods': 'GET, POST, PUT, PATCH, DELETE, OPTIONS', 'Access-Control-Max-Age': '86400' };
const json = (status, body) => new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json; charset=utf-8', ...CORS } });
const err = (status, msg) => json(status, { error: msg });
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const USERNAME = /^[^'"<>\s]{2,64}$/;
const sha = s => crypto.createHash('sha256').update(s).digest('hex');
const SESSION_DAYS = 30;

// הגבלת ניסיונות (בזיכרון)
const hits = new Map();
function limited(key, max, windowMs) {
  const now = Date.now(), h = (hits.get(key) || []).filter(t => now - t < windowMs);
  h.push(now); hits.set(key, h);
  if (hits.size > 5000) for (const [k, v] of hits) if (!v.some(t => now - t < windowMs)) hits.delete(k);
  return h.length > max;
}
async function body(req, max = 1e6) {
  const t = await req.text();
  if (t.length > max) throw Object.assign(new Error('too_large'), { status: 413 });
  try { return t ? JSON.parse(t) : {}; } catch { throw Object.assign(new Error('bad_json'), { status: 400 }); }
}
async function auth(req) {
  const m = (req.headers.get('authorization') || '').match(/^Bearer ([A-Za-z0-9_-]{20,200})$/);
  if (!m) return null;
  return one(`SELECT u.id, u.username, u.role, u.gemach_id, u.permission, u.display_name, g.name AS gemach_name
    FROM sessions s JOIN users u ON u.id = s.user_id LEFT JOIN gemachim g ON g.id = u.gemach_id
    WHERE s.token_hash = $1 AND s.expires_at > now()`, [sha(m[1])]);
}
const pub = u => ({ username: u.username, role: u.role, gemach_id: u.gemach_id, permission: u.permission, display_name: u.display_name, gemach_name: u.gemach_name || null });
const isAdmin = u => u.role === 'gemach' || (u.role === 'staff' && u.permission === 'full');
const log = (u, gid, action, details = {}) => q('INSERT INTO audit_log (gemach_id, user_id, username, action, details) VALUES ($1,$2,$3,$4,$5)', [gid, u && u.id, u && u.username, action, details]).catch(() => {});
// לאיזה גמ"ח הבקשה מתייחסת: גמ"ח/צוות – רק לשלהם; בעלים – לפי g
function gidOf(u, g) {
  if (u.role === 'owner') return UUID.test(g || '') ? g : null;
  return u.gemach_id;
}
const newSession = async uid => {
  const token = crypto.randomBytes(32).toString('base64url');
  await q(`INSERT INTO sessions (token_hash, user_id, expires_at) VALUES ($1, $2, now() + interval '${SESSION_DAYS} days')`, [sha(token), uid]);
  q('DELETE FROM sessions WHERE expires_at < now()').catch(() => {});
  return token;
};
const defData = name => ({ gname: name, base: 0, loans: [], deps: [], lastSel: [], tasks: [] });

async function route(req) {
  const url = new URL(req.url), p = url.pathname.replace(/\/+$/, '') || '/', M = req.method;
  const ip = req.headers.get('x-forwarded-for')?.split(',')[0].trim() || 'x';
  if (M === 'OPTIONS') return new Response(null, { status: 204, headers: CORS });
  if (p === '/api/health') return json(200, { ok: true, owner: !!(await one("SELECT 1 FROM users WHERE role='owner' LIMIT 1")) });

  // ---- טופס בקשת הלוואה ציבורי ----
  let m = p.match(/^\/api\/apply\/([0-9a-f-]{36})$/i);
  if (m) {
    const g = await one('SELECT id, name FROM gemachim WHERE id = $1', [m[1]]);
    if (!g) return err(404, 'not_found');
    if (M === 'GET') return json(200, { name: g.name });
    if (M === 'POST') {
      if (limited('apply:' + ip, 5, 3600e3)) return err(429, 'too_many');
      const b = await body(req, 20000), d = {};
      for (const k of ['first', 'last', 'tz', 'phone', 'email', 'city', 'street', 'house', 'childName', 'amount', 'n', 'notes', 'arev1', 'arev1ph', 'arev2', 'arev2ph']) if (b[k] != null) d[k] = String(b[k]).slice(0, 300);
      if (!d.first || !d.phone) return err(400, 'missing');
      await q('INSERT INTO loan_applications (gemach_id, data) VALUES ($1, $2)', [g.id, d]);
      return json(201, { ok: true });
    }
  }

  // ---- הגדרה ראשונית של מנהל המערכת ----
  if (p === '/api/setup' && M === 'POST') {
    if (limited('setup:' + ip, 5, 3600e3)) return err(429, 'too_many');
    const b = await body(req), key = process.env.SETUP_KEY || '';
    if (!key || typeof b.key !== 'string' || b.key.length !== key.length || !crypto.timingSafeEqual(Buffer.from(b.key), Buffer.from(key))) return err(403, 'bad_key');
    if (await one("SELECT 1 FROM users WHERE role='owner'")) return err(409, 'owner_exists');
    const un = String(b.username || '').trim().toLowerCase();
    if (!USERNAME.test(un) || String(b.password || '').length < 6) return err(400, 'weak');
    if (await one('SELECT 1 FROM users WHERE username = $1', [un])) return err(409, 'taken');
    const u = await one("INSERT INTO users (username, password_hash, role) VALUES ($1, crypt($2, gen_salt('bf', 10)), 'owner') RETURNING id", [un, b.password]);
    return json(201, { token: await newSession(u.id), user: pub({ ...u, username: un, role: 'owner' }) });
  }

  // ---- כניסה ----
  if (p === '/api/login' && M === 'POST') {
    const b = await body(req), un = String(b.username || '').trim().toLowerCase();
    if (limited('login:' + ip, 20, 900e3) || limited('login:' + un, 8, 900e3)) return err(429, 'too_many');
    const u = await one(`SELECT u.id, u.username, u.role, u.gemach_id, u.permission, u.display_name, g.name AS gemach_name FROM users u LEFT JOIN gemachim g ON g.id = u.gemach_id
      WHERE u.username = $1 AND u.password_hash = crypt($2, u.password_hash)`, [un, String(b.password || '')]);
    if (!u) return err(401, 'bad_login');
    q('UPDATE users SET last_login = now() WHERE id = $1', [u.id]).catch(() => {});
    log(u, u.gemach_id, 'login');
    return json(200, { token: await newSession(u.id), user: pub(u) });
  }

  const u = await auth(req);
  if (!u) return err(401, 'no_session');

  if (p === '/api/me' && M === 'GET') return json(200, { user: pub(u) });
  if (p === '/api/logout' && M === 'POST') {
    const t = (req.headers.get('authorization') || '').slice(7);
    await q('DELETE FROM sessions WHERE token_hash = $1', [sha(t)]);
    return json(200, { ok: true });
  }
  if (p === '/api/password' && M === 'POST') {
    const b = await body(req);
    if (String(b.new || '').length < 6) return err(400, 'weak');
    const r = await q("UPDATE users SET password_hash = crypt($2, gen_salt('bf', 10)) WHERE id = $1 AND password_hash = crypt($3, password_hash) RETURNING id", [u.id, b.new, String(b.old || '')]);
    if (!r.length) return err(403, 'bad_password');
    log(u, u.gemach_id, 'password_change');
    return json(200, { ok: true });
  }

  // ---- נתוני הגמ"ח ----
  if (p === '/api/data') {
    const gid = gidOf(u, url.searchParams.get('g'));
    if (!gid) return err(400, 'no_gemach');
    if (M === 'GET') {
      const r = await one('SELECT data, version, updated_at FROM gemach_data WHERE gemach_id = $1', [gid]);
      return json(200, r ? r : { data: null, version: 0 });
    }
    if (M === 'PUT') {
      if (u.role === 'staff' && u.permission === 'view') return err(403, 'read_only');
      const b = await body(req, 12e6);
      if (!b.data || typeof b.data !== 'object' || !Array.isArray(b.data.loans)) return err(400, 'bad_data');
      const v = +b.version || 0;
      const r = v === 0
        ? await one('INSERT INTO gemach_data (gemach_id, data, version, updated_by) VALUES ($1, $2, 1, $3) ON CONFLICT (gemach_id) DO NOTHING RETURNING version', [gid, b.data, u.id])
        : await one('UPDATE gemach_data SET data = $2, version = version + 1, updated_at = now(), updated_by = $3 WHERE gemach_id = $1 AND version = $4 RETURNING version', [gid, b.data, u.id, v]);
      if (!r) return json(409, { error: 'conflict', ...(await one('SELECT data, version FROM gemach_data WHERE gemach_id = $1', [gid])) });
      if (typeof b.data.gname === 'string' && b.data.gname.trim() && u.role !== 'staff') q('UPDATE gemachim SET name = $2 WHERE id = $1', [gid, b.data.gname.trim().slice(0, 120)]).catch(() => {});
      log(u, gid, 'save', { note: String(b.note || '').slice(0, 200), loans: b.data.loans.length, deps: (b.data.deps || []).length });
      return json(200, { version: r.version });
    }
  }

  // ---- ניהול גמחים (בעלים) ----
  if (p === '/api/gemachs') {
    if (u.role !== 'owner') return err(403, 'owner_only');
    if (M === 'GET') return json(200, { gemachs: await q(`SELECT g.id, g.name, gu.username,
        (SELECT count(*) FROM users s WHERE s.gemach_id = g.id AND s.role = 'staff')::int AS staff,
        coalesce(jsonb_array_length(d.data->'loans'), 0) AS loans, coalesce(jsonb_array_length(d.data->'deps'), 0) AS deps, d.updated_at,
        (SELECT count(*) FROM support_messages m WHERE m.gemach_id = g.id AND m.sender_role = 'gemach' AND m.read_at IS NULL)::int AS unread
      FROM gemachim g LEFT JOIN users gu ON gu.gemach_id = g.id AND gu.role = 'gemach' LEFT JOIN gemach_data d ON d.gemach_id = g.id ORDER BY g.created_at`) });
    if (M === 'POST') {
      const b = await body(req), un = String(b.username || '').trim().toLowerCase(), name = String(b.name || '').trim().slice(0, 120);
      if (!name || !USERNAME.test(un) || String(b.password || '').length < 6) return err(400, 'weak');
      if (await one('SELECT 1 FROM users WHERE username = $1', [un])) return err(409, 'taken');
      const c = await pool.connect();
      try {
        await c.query('BEGIN');
        const g = (await c.query('INSERT INTO gemachim (name) VALUES ($1) RETURNING id', [name])).rows[0];
        await c.query("INSERT INTO users (username, password_hash, role, gemach_id) VALUES ($1, crypt($2, gen_salt('bf', 10)), 'gemach', $3)", [un, b.password, g.id]);
        await c.query('INSERT INTO gemach_data (gemach_id, data) VALUES ($1, $2)', [g.id, defData(name)]);
        await c.query('COMMIT');
        log(u, g.id, 'gemach_created', { name });
        return json(201, { id: g.id });
      } catch (e) { await c.query('ROLLBACK'); throw e; } finally { c.release(); }
    }
  }
  m = p.match(/^\/api\/gemachs\/([0-9a-f-]{36})(\/password)?$/i);
  if (m) {
    if (u.role !== 'owner') return err(403, 'owner_only');
    if (m[2] && M === 'POST') {
      const b = await body(req);
      if (String(b.password || '').length < 6) return err(400, 'weak');
      await q("UPDATE users SET password_hash = crypt($2, gen_salt('bf', 10)) WHERE gemach_id = $1 AND role = 'gemach'", [m[1], b.password]);
      await q("DELETE FROM sessions WHERE user_id IN (SELECT id FROM users WHERE gemach_id = $1 AND role = 'gemach')", [m[1]]);
      log(u, m[1], 'password_reset');
      return json(200, { ok: true });
    }
    if (!m[2] && M === 'DELETE') {
      const b = await body(req);
      const g = await one('SELECT name FROM gemachim WHERE id = $1', [m[1]]);
      if (!g) return err(404, 'not_found');
      if (b.confirm !== g.name) return err(400, 'confirm_name');
      await q('DELETE FROM gemachim WHERE id = $1', [m[1]]);
      log(u, null, 'gemach_deleted', { id: m[1], name: g.name });
      return json(200, { ok: true });
    }
  }

  // ---- משתמשי צוות של גמ"ח ----
  if (p === '/api/staff' || /^\/api\/staff\/[0-9a-f-]{36}$/i.test(p)) {
    const gid = gidOf(u, url.searchParams.get('g'));
    if (!gid || (u.role !== 'owner' && !isAdmin(u))) return err(403, 'admin_only');
    const sid = p.split('/')[3];
    if (p === '/api/staff' && M === 'GET') return json(200, { staff: await q("SELECT id, username, display_name, permission, last_login FROM users WHERE gemach_id = $1 AND role = 'staff' ORDER BY created_at", [gid]) });
    if (p === '/api/staff' && M === 'POST') {
      const b = await body(req), un = String(b.username || '').trim().toLowerCase();
      if (!USERNAME.test(un) || String(b.password || '').length < 6 || !['full', 'edit', 'view'].includes(b.permission)) return err(400, 'weak');
      if (await one('SELECT 1 FROM users WHERE username = $1', [un])) return err(409, 'taken');
      await q("INSERT INTO users (username, password_hash, role, gemach_id, permission, display_name) VALUES ($1, crypt($2, gen_salt('bf', 10)), 'staff', $3, $4, $5)", [un, b.password, gid, b.permission, String(b.display_name || '').slice(0, 80)]);
      log(u, gid, 'staff_added', { username: un, permission: b.permission });
      return json(201, { ok: true });
    }
    if (sid && M === 'PATCH') {
      const b = await body(req);
      if (b.permission && ['full', 'edit', 'view'].includes(b.permission)) await q("UPDATE users SET permission = $3 WHERE id = $1 AND gemach_id = $2 AND role = 'staff'", [sid, gid, b.permission]);
      if (b.password) {
        if (String(b.password).length < 6) return err(400, 'weak');
        await q("UPDATE users SET password_hash = crypt($3, gen_salt('bf', 10)) WHERE id = $1 AND gemach_id = $2 AND role = 'staff'", [sid, gid, b.password]);
        await q('DELETE FROM sessions WHERE user_id = $1', [sid]);
      }
      log(u, gid, 'staff_updated', { id: sid });
      return json(200, { ok: true });
    }
    if (sid && M === 'DELETE') {
      if (sid === u.id) return err(400, 'self');
      await q("DELETE FROM users WHERE id = $1 AND gemach_id = $2 AND role = 'staff'", [sid, gid]);
      log(u, gid, 'staff_removed', { id: sid });
      return json(200, { ok: true });
    }
  }

  // ---- צ'אט שירות לקוחות ----
  if (p === '/api/support/threads' && M === 'GET') {
    if (u.role !== 'owner') return err(403, 'owner_only');
    return json(200, { threads: await q(`SELECT g.id AS gemach_id, g.name, l.body AS last_body, l.sender_role AS last_from, l.created_at AS last_at,
        (SELECT count(*) FROM support_messages x WHERE x.gemach_id = g.id AND x.sender_role = 'gemach' AND x.read_at IS NULL)::int AS unread
      FROM gemachim g JOIN LATERAL (SELECT body, sender_role, created_at FROM support_messages s WHERE s.gemach_id = g.id ORDER BY created_at DESC LIMIT 1) l ON true ORDER BY l.created_at DESC`) });
  }
  if (p === '/api/support') {
    const gid = gidOf(u, url.searchParams.get('g'));
    if (!gid) return err(400, 'no_gemach');
    if (M === 'GET') {
      const rows = await q(`SELECT s.id, s.sender_role, s.body, s.created_at, coalesce(nullif(us.display_name, ''), us.username) AS by
        FROM support_messages s LEFT JOIN users us ON us.id = s.sender_user_id WHERE s.gemach_id = $1 ORDER BY s.created_at LIMIT 500`, [gid]);
      await q('UPDATE support_messages SET read_at = now() WHERE gemach_id = $1 AND read_at IS NULL AND sender_role = $2', [gid, u.role === 'owner' ? 'gemach' : 'owner']);
      return json(200, { messages: rows });
    }
    if (M === 'POST') {
      if (limited('msg:' + u.id, 30, 60e3)) return err(429, 'too_many');
      const b = await body(req, 10000), t = String(b.body || '').trim().slice(0, 2000);
      if (!t) return err(400, 'empty');
      const r = await one('INSERT INTO support_messages (gemach_id, sender_role, sender_user_id, body) VALUES ($1, $2, $3, $4) RETURNING id, created_at', [gid, u.role === 'owner' ? 'owner' : 'gemach', u.id, t]);
      return json(201, r);
    }
  }

  // ---- בקשות הלוואה ----
  if (p === '/api/applications' && M === 'GET') {
    const gid = gidOf(u, url.searchParams.get('g'));
    if (!gid) return err(400, 'no_gemach');
    return json(200, { applications: await q("SELECT id, data, status, created_at FROM loan_applications WHERE gemach_id = $1 AND (status = 'new' OR created_at > now() - interval '60 days') ORDER BY created_at DESC LIMIT 200", [gid]) });
  }
  m = p.match(/^\/api\/applications\/([0-9a-f-]{36})$/i);
  if (m && M === 'PATCH') {
    if (u.role === 'staff' && u.permission === 'view') return err(403, 'read_only');
    const gid = gidOf(u, url.searchParams.get('g')), b = await body(req);
    if (!gid || !['approved', 'rejected', 'new'].includes(b.status)) return err(400, 'bad');
    await q('UPDATE loan_applications SET status = $3, handled_at = now() WHERE id = $1 AND gemach_id = $2', [m[1], gid, b.status]);
    log(u, gid, 'application_' + b.status, { id: m[1] });
    return json(200, { ok: true });
  }

  // ---- יומן פעילות ----
  if (p === '/api/audit' && M === 'GET') {
    const gid = gidOf(u, url.searchParams.get('g'));
    if (!gid || (u.role !== 'owner' && !isAdmin(u))) return err(403, 'admin_only');
    return json(200, { log: await q('SELECT username, action, details, created_at FROM audit_log WHERE gemach_id = $1 ORDER BY created_at DESC LIMIT 200', [gid]) });
  }
  return err(404, 'not_found');
}

export default {
  async fetch(req) {
    try { return await route(req); }
    catch (e) {
      if (e && e.status) return err(e.status, e.message);
      console.error(e);
      return err(500, 'server_error');
    }
  },
};
