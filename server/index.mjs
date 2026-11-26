// AMB גמ"ח – שרת API (Neon Functions). כל גמ"ח רואה רק את הנתונים שלו; רק מנהל המערכת (owner) רואה הכל.
import crypto from 'node:crypto';

// חיבור ל-Neon דרך HTTP (אותו פרוטוקול של הדרייבר הרשמי) – בלי ספריות חיצוניות
const DB = new URL(process.env.DATABASE_URL);
const SQL_URL = process.env.SQL_HTTP_URL || 'https://' + DB.hostname.replace(/^[^.]+\./, 'api.') + '/sql';
const parse = (t, v) => {
  if (v === null) return null;
  if (t === 16) return v === 't';
  if (t === 20 || t === 21 || t === 23 || t === 700 || t === 701 || t === 1700) return Number(v);
  if (t === 114 || t === 3802) return JSON.parse(v);
  if (t === 1184 || t === 1114) { const d = new Date(v.replace(' ', 'T').replace(/([+-]\d\d)$/, '$1:00')); return isNaN(d) ? v : d.toISOString(); }
  return v;
};
async function q(text, values = []) {
  const r = await fetch(SQL_URL, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'Neon-Connection-String': process.env.DATABASE_URL, 'Neon-Raw-Text-Output': 'true', 'Neon-Array-Mode': 'true' },
    body: JSON.stringify({ query: text, params: values.map(v => v == null ? null : typeof v === 'object' ? JSON.stringify(v) : String(v)) }),
  });
  if (!r.ok) { const t = await r.text(); throw new Error('db ' + r.status + ': ' + t.slice(0, 300)); }
  const j = await r.json(), f = j.fields || [];
  return (j.rows || []).map(row => Object.fromEntries(row.map((v, i) => [f[i].name, parse(f[i].dataTypeID, v)])));
}
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
  return one(`SELECT u.id, u.username, u.role, u.gemach_id, u.permission, u.display_name, u.totp_on, g.name AS gemach_name
    FROM sessions s JOIN users u ON u.id = s.user_id LEFT JOIN gemachim g ON g.id = u.gemach_id
    WHERE s.token_hash = $1 AND s.expires_at > now()`, [sha(m[1])]);
}
const pub = u => ({ username: u.username, role: u.role, gemach_id: u.gemach_id, permission: u.permission, display_name: u.display_name, gemach_name: u.gemach_name || null, tfa: !!u.totp_on });
const isAdmin = u => u.role === 'gemach' || (u.role === 'staff' && u.permission === 'full');
const log = (u, gid, action, details = {}) => q('INSERT INTO audit_log (gemach_id, user_id, username, action, details) VALUES ($1,$2,$3,$4,$5)', [gid, u && u.id, u && u.username, action, details]).catch(() => {});
// לאיזה גמ"ח הבקשה מתייחסת: גמ"ח/צוות – רק לשלהם; בעלים – לפי g
function gidOf(u, g) {
  if (u.role === 'owner') return UUID.test(g || '') ? g : null;
  return u.gemach_id;
}
const ownerBlocked = async gid => !!(await one("SELECT 1 FROM gemachim WHERE id = $1 AND settings->>'owner_access' = 'false'", [gid]));
const newSession = async uid => {
  const token = crypto.randomBytes(32).toString('base64url');
  await q(`INSERT INTO sessions (token_hash, user_id, expires_at) VALUES ($1, $2, now() + interval '${SESSION_DAYS} days')`, [sha(token), uid]);
  q('DELETE FROM sessions WHERE expires_at < now()').catch(() => {});
  return token;
};
const defData = name => ({ gname: name, base: 0, loans: [], deps: [], lastSel: [], tasks: [] });

// ---- סיסמאות: לפחות 10 תווים, לא פשוטות מדי ----
const COMMON = new Set(['1234567890','0123456789','password12','password123','qwertyuiop','1q2w3e4r5t','abcdefghij','0987654321','1111111111','0000000000','aaaaaaaaaa','12345678910']);
const pwOk = (pw, un = '') => { pw = String(pw || ''); return pw.length >= 10 && pw.length <= 200 && new Set(pw).size >= 4 && !COMMON.has(pw.toLowerCase()) && pw.toLowerCase() !== String(un).toLowerCase(); };

// ---- ארון קבצים של נאון (S3 תואם, חתימה SigV4 בלי ספריות) ----
const DOCS = 'amb-docs', BAK = 'amb-backups';
const enc = s => encodeURIComponent(s).replace(/[!'()*]/g, c => '%' + c.charCodeAt(0).toString(16).toUpperCase());
const hm = (k, s) => crypto.createHmac('sha256', k).update(s).digest();
async function s3(method, path, { body, query, type } = {}) {
  const ep = new URL(process.env.AWS_ENDPOINT_URL_S3), env = process.env.AWS_REGION || '';
  const region = /^[a-z]{2}(-[a-z]+)+-\d+$/.test(env) ? env : 'us-east-2';
  const buf = body == null ? Buffer.alloc(0) : Buffer.isBuffer(body) ? body : Buffer.from(body);
  const amz = new Date().toISOString().replace(/[:-]|\.\d{3}/g, ''), day = amz.slice(0, 8);
  const ph = crypto.createHash('sha256').update(buf).digest('hex');
  const qs = Object.entries(query || {}).sort(([a], [b]) => (a < b ? -1 : 1)).map(([k, v]) => enc(k) + '=' + enc(v)).join('&');
  const uri = '/' + path.split('/').map(enc).join('/');
  const sh = 'host;x-amz-content-sha256;x-amz-date';
  const canon = [method, uri, qs, `host:${ep.host}\nx-amz-content-sha256:${ph}\nx-amz-date:${amz}\n`, sh, ph].join('\n');
  const scope = `${day}/${region}/s3/aws4_request`;
  const sts = ['AWS4-HMAC-SHA256', amz, scope, crypto.createHash('sha256').update(canon).digest('hex')].join('\n');
  const key = hm(hm(hm(hm('AWS4' + process.env.AWS_SECRET_ACCESS_KEY, day), region), 's3'), 'aws4_request');
  const sig = crypto.createHmac('sha256', key).update(sts).digest('hex');
  const headers = { 'x-amz-content-sha256': ph, 'x-amz-date': amz, Authorization: `AWS4-HMAC-SHA256 Credential=${process.env.AWS_ACCESS_KEY_ID}/${scope}, SignedHeaders=${sh}, Signature=${sig}` };
  if (type) headers['Content-Type'] = type;
  return fetch(ep.origin + uri + (qs ? '?' + qs : ''), { method, headers, body: buf.length ? buf : undefined });
}
const s3put = async (bucket, key, body, type) => { const r = await s3('PUT', bucket + '/' + key, { body, type }); if (!r.ok) throw new Error('s3 put ' + r.status + ' ' + (await r.text()).slice(0, 200)); };
const s3get = async (bucket, key) => { const r = await s3('GET', bucket + '/' + key); if (r.status === 404) return null; if (!r.ok) throw new Error('s3 get ' + r.status); return Buffer.from(await r.arrayBuffer()); };
const s3del = async (bucket, key) => { const r = await s3('DELETE', bucket + '/' + key); if (!r.ok && r.status !== 404) throw new Error('s3 del ' + r.status); };
async function s3list(bucket, prefix = '') {
  const keys = []; let token = null;
  for (let i = 0; i < 50; i++) {
    const r = await s3('GET', bucket, { query: { 'list-type': '2', prefix, ...(token ? { 'continuation-token': token } : {}) } });
    if (!r.ok) throw new Error('s3 list ' + r.status);
    const x = await r.text();
    for (const m of x.matchAll(/<Key>([^<]+)<\/Key>/g)) keys.push(m[1].replace(/&amp;/g, '&'));
    const nt = x.match(/<NextContinuationToken>([^<]+)<\/NextContinuationToken>/);
    if (/<IsTruncated>true<\/IsTruncated>/.test(x) && nt) token = nt[1].replace(/&amp;/g, '&'); else break;
  }
  return keys;
}

// ---- אימות דו-שלבי (TOTP, תקן RFC 6238) ----
const B32 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
const b32enc = buf => { let bits = 0, v = 0, o = ''; for (const x of buf) { v = ((v << 8) | x) & 0xfffff; bits += 8; while (bits >= 5) { o += B32[(v >>> (bits - 5)) & 31]; bits -= 5; } } if (bits > 0) o += B32[(v << (5 - bits)) & 31]; return o; };
const b32dec = s => { let bits = 0, v = 0; const o = []; for (const c of String(s).replace(/=+$/, '').toUpperCase()) { const i = B32.indexOf(c); if (i < 0) continue; v = ((v << 5) | i) & 0xffff; bits += 5; if (bits >= 8) { o.push((v >>> (bits - 8)) & 255); bits -= 8; } } return Buffer.from(o); };
const hotp = (secret, step) => { const b = Buffer.alloc(8); b.writeBigUInt64BE(BigInt(step)); const h = crypto.createHmac('sha1', b32dec(secret)).update(b).digest(), o = h[19] & 15; return String((h.readUInt32BE(o) & 0x7fffffff) % 1e6).padStart(6, '0'); };
function totpCheck(secret, code, last) { if (!/^\d{6}$/.test(code)) return 0; const st = Math.floor(Date.now() / 30000); for (let d = -1; d <= 1; d++) { const x = st + d; if (x > last && hotp(secret, x) === code) return x; } return 0; }
// בודק קוד אפליקציה או קוד שחזור (חד-פעמי); מחזיר true אם תקין
async function check2fa(u, raw) {
  const code = String(raw || '').replace(/[\s-]/g, '').toLowerCase();
  if (!code) return false;
  const st = totpCheck(u.totp_secret, code, +u.totp_last || 0);
  if (st) { const r = await q('UPDATE users SET totp_last = $2 WHERE id = $1 AND totp_last < $2 RETURNING id', [u.id, st]); return r.length > 0; }
  const h = sha(code), rh = Array.isArray(u.recovery_hashes) ? u.recovery_hashes : [];
  if (rh.includes(h)) { await q('UPDATE users SET recovery_hashes = $2 WHERE id = $1', [u.id, rh.filter(x => x !== h)]); return true; }
  return false;
}

// ---- גיבוי ----
async function runBackup(note = 'auto') {
  const day = new Date().toISOString().slice(0, 10), ids = await q('SELECT g.id, g.name FROM gemachim g JOIN gemach_data d ON d.gemach_id = g.id ORDER BY g.created_at');
  let n = 0;
  try {
    for (const g of ids) {
      const d = await one('SELECT data, version, updated_at FROM gemach_data WHERE gemach_id = $1', [g.id]);
      if (!d) continue;
      await s3put(BAK, `${day}/${g.id}.json`, JSON.stringify({ gemach: g, version: d.version, updated_at: d.updated_at, backed_up_at: new Date().toISOString(), data: d.data }), 'application/json');
      n++;
    }
    await s3put(BAK, `${day}/_index.json`, JSON.stringify(ids), 'application/json');
    // שמירה: 35 ימים אחרונים (גיבויי "לפני שחזור" נשמרים 120 יום)
    const old = new Date(Date.now() - 35 * 864e5).toISOString().slice(0, 10), old2 = new Date(Date.now() - 120 * 864e5).toISOString().slice(0, 10);
    for (const k of await s3list(BAK)) {
      const m = k.match(/^(pre-restore\/)?(\d{4}-\d{2}-\d{2})/);
      if (m && m[2] < (m[1] ? old2 : old)) await s3del(BAK, k);
    }
    await q('INSERT INTO backup_runs (day, gemachim, ok, note) VALUES ($1, $2, true, $3)', [day, n, note]);
    return { day, gemachim: n };
  } catch (e) {
    await q('INSERT INTO backup_runs (day, gemachim, ok, note) VALUES ($1, $2, false, $3)', [day, n, String(e.message).slice(0, 300)]).catch(() => {});
    throw e;
  }
}
const mimeOk = t => /^(image\/(jpeg|png|webp|gif)|application\/pdf)$/.test(t);

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
    if (!USERNAME.test(un)) return err(400, 'weak');
    if (!pwOk(b.password, un)) return err(400, 'short_pw');
    if (await one('SELECT 1 FROM users WHERE username = $1', [un])) return err(409, 'taken');
    const u = await one("INSERT INTO users (username, password_hash, role) VALUES ($1, crypt($2, gen_salt('bf', 10)), 'owner') RETURNING id", [un, b.password]);
    return json(201, { token: await newSession(u.id), user: pub({ ...u, username: un, role: 'owner' }) });
  }

  // ---- כניסה ----
  if (p === '/api/login' && M === 'POST') {
    const b = await body(req), un = String(b.username || '').trim().toLowerCase();
    if (limited('login:' + ip, 20, 900e3) || limited('login:' + un, 8, 900e3)) return err(429, 'too_many');
    const u = await one(`SELECT u.id, u.username, u.role, u.gemach_id, u.permission, u.display_name, u.totp_on, u.totp_secret, u.totp_last, u.recovery_hashes, g.name AS gemach_name FROM users u LEFT JOIN gemachim g ON g.id = u.gemach_id
      WHERE u.username = $1 AND u.password_hash = crypt($2, u.password_hash)`, [un, String(b.password || '')]);
    if (!u) return err(401, 'bad_login');
    if (u.totp_on) {
      if (!String(b.code || '').trim()) return json(401, { error: 'need_2fa',  });
      if (limited('2fa:' + u.id, 8, 900e3)) return err(429, 'too_many');
      if (!(await check2fa(u, b.code))) { log(u, u.gemach_id, 'login_2fa_failed'); return err(401, 'bad_code'); }
    }
    q('UPDATE users SET last_login = now() WHERE id = $1', [u.id]).catch(() => {});
    log(u, u.gemach_id, 'login');
    return json(200, { token: await newSession(u.id), user: pub(u) });
  }

  // ---- גיבוי לילי (מופעל ע"י מתזמן של נאון; הטוקן בנתיב, ובמסד נשמר רק ה-hash שלו) ----
  m = p.match(/^\/api\/cron\/backup\/([0-9a-f]{48})$/);
  if (m) {
    const k = await one("SELECT v FROM sys_kv WHERE k = 'cron_backup'");
    if (!k || k.v !== sha(m[1])) return err(403, 'bad_token');
    return json(200, await runBackup('auto'));
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
    if (!pwOk(b.new, u.username)) return err(400, 'short_pw');
    const r = await q("UPDATE users SET password_hash = crypt($2, gen_salt('bf', 10)) WHERE id = $1 AND password_hash = crypt($3, password_hash) RETURNING id", [u.id, b.new, String(b.old || '')]);
    if (!r.length) return err(403, 'bad_password');
    log(u, u.gemach_id, 'password_change');
    return json(200, { ok: true });
  }

  // ---- נתוני הגמ"ח ----
  if (p === '/api/data') {
    const gid = gidOf(u, url.searchParams.get('g'));
    if (!gid) return err(400, 'no_gemach');
    if (u.role === 'owner' && await ownerBlocked(gid)) return err(403, 'owner_blocked');
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

  // ---- אימות דו-שלבי ----
  if (p === '/api/2fa' && M === 'GET') return json(200, { on: !!u.totp_on, can: u.role === 'owner' || isAdmin(u) });
  if (p.startsWith('/api/2fa/') && M === 'POST') {
    if (u.role !== 'owner' && !isAdmin(u)) return err(403, 'admin_only');
    const b = await body(req), full = await one('SELECT id, username, totp_on, totp_secret, totp_last, recovery_hashes FROM users WHERE id = $1', [u.id]);
    if (limited('2fa-set:' + u.id, 20, 900e3)) return err(429, 'too_many');
    if (p === '/api/2fa/setup') {
      if (full.totp_on) return err(409, 'already_on');
      const secret = b32enc(crypto.randomBytes(20));
      await q('UPDATE users SET totp_secret = $2, totp_on = false, totp_last = 0 WHERE id = $1', [u.id, secret]);
      return json(200, { secret, uri: 'otpauth://totp/' + enc('AMB גמ״ח:' + full.username) + '?secret=' + secret + '&issuer=' + enc('AMB גמ״ח') });
    }
    if (p === '/api/2fa/enable') {
      if (full.totp_on || !full.totp_secret) return err(409, 'bad_state');
      const st = totpCheck(full.totp_secret, String(b.code || '').replace(/\s/g, ''), 0);
      if (!st) return err(400, 'bad_code');
      const codes = Array.from({ length: 8 }, () => { const h = crypto.randomBytes(5).toString('hex'); return h.slice(0, 5) + '-' + h.slice(5); });
      await q('UPDATE users SET totp_on = true, totp_last = $2, recovery_hashes = $3 WHERE id = $1', [u.id, st, codes.map(c => sha(c.replace('-', '')))]);
      log(u, u.gemach_id, 'tfa_enabled');
      return json(200, { codes });
    }
    if (p === '/api/2fa/disable') {
      if (!full.totp_on) return json(200, { ok: true });
      const pw = await one('SELECT 1 FROM users WHERE id = $1 AND password_hash = crypt($2, password_hash)', [u.id, String(b.password || '')]);
      if (!pw) return err(403, 'bad_password');
      if (!(await check2fa(full, b.code))) return err(400, 'bad_code');
      await q("UPDATE users SET totp_on = false, totp_secret = NULL, totp_last = 0, recovery_hashes = '[]' WHERE id = $1", [u.id]);
      log(u, u.gemach_id, 'tfa_disabled');
      return json(200, { ok: true });
    }
  }

  // ---- מסמכים (נשמרים בארון קבצים, לא בגוף נתוני הגמ"ח) ----
  if (p === '/api/doc' && M === 'POST') {
    const gid = gidOf(u, url.searchParams.get('g'));
    if (!gid) return err(400, 'no_gemach');
    if (u.role === 'staff' && u.permission === 'view') return err(403, 'read_only');
    if (u.role === 'owner' && await ownerBlocked(gid)) return err(403, 'owner_blocked');
    if (limited('doc:' + u.id, 40, 60e3)) return err(429, 'too_many');
    const b = await body(req, 3.6e6), type = String(b.type || '').toLowerCase();
    if (!mimeOk(type)) return err(415, 'bad_type');
    if (typeof b.data !== 'string' || !/^[A-Za-z0-9+/=]+$/.test(b.data)) return err(400, 'bad_data');
    const buf = Buffer.from(b.data, 'base64');
    if (buf.length > 2.6e6 || !buf.length) return err(413, 'file_too_large');
    const name = String(b.name || 'file').replace(/[\\/:*?"<>|\r\n]/g, '_').slice(0, 120);
    const r = await one('INSERT INTO doc_files (gemach_id, name, content_type, size, created_by) VALUES ($1,$2,$3,$4,$5) RETURNING id', [gid, name, type, buf.length, u.id]);
    try { await s3put(DOCS, gid + '/' + r.id, buf, type); } catch (e) { await q('DELETE FROM doc_files WHERE id = $1', [r.id]); throw e; }
    log(u, gid, 'doc_added', { name });
    return json(201, { id: r.id, name, type, size: buf.length });
  }
  m = p.match(/^\/api\/doc\/([0-9a-f-]{36})$/i);
  if (m) {
    const d = await one('SELECT id, gemach_id, name, content_type, size FROM doc_files WHERE id = $1', [m[1]]);
    if (!d || (u.role !== 'owner' && d.gemach_id !== u.gemach_id)) return err(404, 'not_found');
    if (u.role === 'owner' && await ownerBlocked(d.gemach_id)) return err(403, 'owner_blocked');
    if (M === 'GET') {
      const buf = await s3get(DOCS, d.gemach_id + '/' + d.id);
      if (!buf) return err(404, 'missing');
      return json(200, { name: d.name, type: d.content_type, data: buf.toString('base64') });
    }
    if (M === 'DELETE') {
      if (u.role === 'staff' && u.permission === 'view') return err(403, 'read_only');
      await s3del(DOCS, d.gemach_id + '/' + d.id);
      await q('DELETE FROM doc_files WHERE id = $1', [d.id]);
      log(u, d.gemach_id, 'doc_removed', { name: d.name });
      return json(200, { ok: true });
    }
  }

  // ---- גיבויים ----
  if (p === '/api/backups' && M === 'GET') {
    if (u.role !== 'owner' && !isAdmin(u)) return err(403, 'admin_only');
    const runs = await q('SELECT day, gemachim, ok, note, run_at FROM backup_runs ORDER BY id DESC LIMIT 40');
    return json(200, { runs: u.role === 'owner' ? runs : runs.map(r => ({ day: r.day, ok: r.ok, run_at: r.run_at })) });
  }
  if (p === '/api/backups/run' && M === 'POST') {
    if (u.role !== 'owner') return err(403, 'owner_only');
    if (limited('bk:' + u.id, 5, 3600e3)) return err(429, 'too_many');
    return json(200, await runBackup('manual'));
  }
  m = p.match(/^\/api\/backups\/(\d{4}-\d{2}-\d{2})\/([0-9a-f-]{36})$/i);
  if (m && M === 'GET') {
    if (u.role !== 'owner' && !(isAdmin(u) && u.gemach_id === m[2])) return err(403, 'admin_only');
    if (u.role === 'owner' && await ownerBlocked(m[2])) return err(403, 'owner_blocked');
    const buf = await s3get(BAK, m[1] + '/' + m[2] + '.json');
    return buf ? new Response(buf, { status: 200, headers: { 'Content-Type': 'application/json; charset=utf-8', ...CORS } }) : err(404, 'not_found');
  }
  if (p === '/api/backups/restore' && M === 'POST') {
    const b = await body(req), gid = gidOf(u, b.g || url.searchParams.get('g'));
    if (!gid || !/^\d{4}-\d{2}-\d{2}$/.test(String(b.day || ''))) return err(400, 'bad');
    if (u.role !== 'owner' && !isAdmin(u)) return err(403, 'admin_only');
    if (u.role === 'owner' && await ownerBlocked(gid)) return err(403, 'owner_blocked');
    const buf = await s3get(BAK, b.day + '/' + gid + '.json');
    if (!buf) return err(404, 'no_backup');
    let snap; try { snap = JSON.parse(buf.toString()); } catch { return err(500, 'bad_backup'); }
    if (!snap || !snap.data || !Array.isArray(snap.data.loans) || (snap.gemach && snap.gemach.id !== gid)) return err(500, 'bad_backup');
    const cur = await one('SELECT data, version FROM gemach_data WHERE gemach_id = $1', [gid]);
    if (cur) await s3put(BAK, 'pre-restore/' + new Date().toISOString().replace(/[:.]/g, '-') + '/' + gid + '.json', JSON.stringify({ gemach: { id: gid }, version: cur.version, data: cur.data }), 'application/json');
    const r = await one('UPDATE gemach_data SET data = $2, version = version + 1, updated_at = now(), updated_by = $3 WHERE gemach_id = $1 RETURNING version', [gid, snap.data, u.id]);
    if (!r) return err(404, 'no_data');
    log(u, gid, 'restore', { day: b.day });
    return json(200, { version: r.version });
  }

  // ---- ניהול גמחים (בעלים) ----
  if (p === '/api/gemachs') {
    if (u.role !== 'owner') return err(403, 'owner_only');
    if (M === 'GET') return json(200, { gemachs: (await q(`SELECT g.id, g.name, gu.username, coalesce(gu.totp_on, false) AS tfa, (g.settings->>'owner_access' = 'false') AS locked,
        (SELECT count(*) FROM users s WHERE s.gemach_id = g.id AND s.role = 'staff')::int AS staff,
        coalesce(jsonb_array_length(d.data->'loans'), 0) AS loans, coalesce(jsonb_array_length(d.data->'deps'), 0) AS deps, d.updated_at,
        (SELECT count(*) FROM support_messages m WHERE m.gemach_id = g.id AND m.sender_role = 'gemach' AND m.read_at IS NULL)::int AS unread
      FROM gemachim g LEFT JOIN users gu ON gu.gemach_id = g.id AND gu.role = 'gemach' LEFT JOIN gemach_data d ON d.gemach_id = g.id ORDER BY g.created_at`)).map(g => g.locked ? { ...g, loans: null, deps: null, updated_at: null } : g) });
    if (M === 'POST') {
      const b = await body(req), un = String(b.username || '').trim().toLowerCase(), name = String(b.name || '').trim().slice(0, 120);
      if (!name || !USERNAME.test(un)) return err(400, 'weak');
      if (!pwOk(b.password, un)) return err(400, 'short_pw');
      if (await one('SELECT 1 FROM users WHERE username = $1', [un])) return err(409, 'taken');
      // פקודה אחת = פעולה אטומית (גמ"ח + משתמש + נתונים התחלתיים)
      const g = await one(`WITH g AS (INSERT INTO gemachim (name) VALUES ($1) RETURNING id),
        u AS (INSERT INTO users (username, password_hash, role, gemach_id) SELECT $2, crypt($3, gen_salt('bf', 10)), 'gemach', id FROM g),
        d AS (INSERT INTO gemach_data (gemach_id, data) SELECT id, $4::jsonb FROM g) SELECT id FROM g`, [name, un, b.password, defData(name)]);
      log(u, g.id, 'gemach_created', { name });
      return json(201, { id: g.id });
    }
  }
  m = p.match(/^\/api\/gemachs\/([0-9a-f-]{36})(\/password|\/2fa-reset)?$/i);
  if (m) {
    if (u.role !== 'owner') return err(403, 'owner_only');
    if (m[2] === '/2fa-reset' && M === 'POST') {
      await q("UPDATE users SET totp_on = false, totp_secret = NULL, totp_last = 0, recovery_hashes = '[]' WHERE gemach_id = $1 AND role = 'gemach'", [m[1]]);
      log(u, m[1], 'tfa_reset_by_owner');
      return json(200, { ok: true });
    }
    if (m[2] === '/password' && M === 'POST') {
      const b = await body(req);
      if (!pwOk(b.password)) return err(400, 'short_pw');
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
      for (const d of await q('SELECT id FROM doc_files WHERE gemach_id = $1', [m[1]])) await s3del(DOCS, m[1] + '/' + d.id).catch(() => {});
      await q('DELETE FROM gemachim WHERE id = $1', [m[1]]);
      log(u, null, 'gemach_deleted', { id: m[1], name: g.name });
      return json(200, { ok: true });
    }
  }

  // ---- משתמשי צוות של גמ"ח ----
  if (p === '/api/staff' || /^\/api\/staff\/[0-9a-f-]{36}$/i.test(p)) {
    const gid = gidOf(u, url.searchParams.get('g'));
    if (!gid || (u.role !== 'owner' && !isAdmin(u))) return err(403, 'admin_only');
    if (u.role === 'owner' && await ownerBlocked(gid)) return err(403, 'owner_blocked');
    const sid = p.split('/')[3];
    if (p === '/api/staff' && M === 'GET') return json(200, { staff: await q("SELECT id, username, display_name, permission, last_login FROM users WHERE gemach_id = $1 AND role = 'staff' ORDER BY created_at", [gid]) });
    if (p === '/api/staff' && M === 'POST') {
      const b = await body(req), un = String(b.username || '').trim().toLowerCase();
      if (!USERNAME.test(un) || !['full', 'edit', 'view'].includes(b.permission)) return err(400, 'weak');
      if (!pwOk(b.password, un)) return err(400, 'short_pw');
      if (await one('SELECT 1 FROM users WHERE username = $1', [un])) return err(409, 'taken');
      await q("INSERT INTO users (username, password_hash, role, gemach_id, permission, display_name) VALUES ($1, crypt($2, gen_salt('bf', 10)), 'staff', $3, $4, $5)", [un, b.password, gid, b.permission, String(b.display_name || '').slice(0, 80)]);
      log(u, gid, 'staff_added', { username: un, permission: b.permission });
      return json(201, { ok: true });
    }
    if (sid && M === 'PATCH') {
      const b = await body(req);
      if (b.permission && ['full', 'edit', 'view'].includes(b.permission)) await q("UPDATE users SET permission = $3 WHERE id = $1 AND gemach_id = $2 AND role = 'staff'", [sid, gid, b.permission]);
      if (b.password) {
        if (!pwOk(b.password)) return err(400, 'short_pw');
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

  // ---- הגדרות פרטיות של הגמ"ח (חסימת גישת מנהל המערכת) ----
  if (p === '/api/settings') {
    if (u.role === 'owner') return err(403, 'gemach_only');
    if (M === 'GET') { const r = await one('SELECT settings FROM gemachim WHERE id = $1', [u.gemach_id]); return json(200, { owner_access: !(r && r.settings && r.settings.owner_access === false) }); }
    if (M === 'PATCH') {
      if (!isAdmin(u)) return err(403, 'admin_only');
      const b = await body(req);
      if (typeof b.owner_access !== 'boolean') return err(400, 'bad');
      await q("UPDATE gemachim SET settings = jsonb_set(coalesce(settings, '{}'::jsonb), '{owner_access}', to_jsonb($2::boolean)) WHERE id = $1", [u.gemach_id, b.owner_access]);
      log(u, u.gemach_id, b.owner_access ? 'owner_access_on' : 'owner_access_off');
      return json(200, { owner_access: b.owner_access });
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
      const rows = await q(`SELECT s.id, s.sender_role, s.body, s.created_at, s.file_name, s.file_type, coalesce(nullif(us.display_name, ''), us.username) AS by
        FROM support_messages s LEFT JOIN users us ON us.id = s.sender_user_id WHERE s.gemach_id = $1 ORDER BY s.created_at LIMIT 500`, [gid]);
      await q('UPDATE support_messages SET read_at = now() WHERE gemach_id = $1 AND read_at IS NULL AND sender_role = $2', [gid, u.role === 'owner' ? 'gemach' : 'owner']);
      return json(200, { messages: rows });
    }
    if (M === 'POST') {
      if (limited('msg:' + u.id, 30, 60e3)) return err(429, 'too_many');
      const b = await body(req, 3.2e6), f = b.file && typeof b.file === 'object' ? b.file : null;
      let t = String(b.body || '').trim().slice(0, 2000);
      if (f && (typeof f.data !== 'string' || f.data.length > 2.9e6 || !/^[A-Za-z0-9+/=]+$/.test(f.data))) return err(413, 'file_too_large');
      const fn = f ? String(f.name || 'file').replace(/[\\/:*?"<>|]/g, '_').slice(0, 120) : null;
      if (!t && fn) t = '📎 ' + fn;
      if (!t) return err(400, 'empty');
      const r = await one('INSERT INTO support_messages (gemach_id, sender_role, sender_user_id, body, file_name, file_type, file_data) VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING id, created_at', [gid, u.role === 'owner' ? 'owner' : 'gemach', u.id, t, fn, f ? String(f.type || '').slice(0, 100) : null, f ? f.data : null]);
      return json(201, r);
    }
  }

  m = p.match(/^\/api\/support\/file\/([0-9a-f-]{36})$/i);
  if (m && M === 'GET') {
    const r = await one('SELECT gemach_id, file_name, file_type, file_data FROM support_messages WHERE id = $1', [m[1]]);
    if (!r || !r.file_data || (u.role !== 'owner' && r.gemach_id !== u.gemach_id)) return err(404, 'not_found');
    return json(200, { name: r.file_name, type: r.file_type, data: r.file_data });
  }

  // ---- בקשות הלוואה ----
  if (p === '/api/applications' && M === 'GET') {
    const gid = gidOf(u, url.searchParams.get('g'));
    if (!gid) return err(400, 'no_gemach');
    if (u.role === 'owner' && await ownerBlocked(gid)) return err(403, 'owner_blocked');
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
    if (u.role === 'owner' && await ownerBlocked(gid)) return err(403, 'owner_blocked');
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
