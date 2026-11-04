'use strict';
// BactiFIND cloud server (Render Web Service + Render PostgreSQL).
// Stores documents by path ("users/{uid}", "labs/{labId}/isolates/{id}", …) and enforces who may read and write each path.
// Environment:
//   DATABASE_URL     Render PostgreSQL connection string (without it the server keeps data in memory — for testing only)
//   JWT_SECRET       long random string used to sign sign-in tokens (Render can generate it)
//   ADMIN_EMAILS     comma-separated admin account emails (they can give Premium and see usage statistics)
//   ALLOWED_ORIGINS  optional comma-separated list of web origins allowed to call the API (default: any)
//   PGSSL            optional: require | disable (default: SSL only for external *.render.com database URLs)
//   MAX_DEVICES      optional: signed-in devices per account (default 2; the oldest is signed out; admins unlimited)
//   PORT             set by Render

const http = require('http');
const crypto = require('crypto');

const PORT = +process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || '';
const ADMINS = new Set((process.env.ADMIN_EMAILS || '').split(',').map(s => s.trim().toLowerCase()).filter(Boolean));
const ORIGINS = (process.env.ALLOWED_ORIGINS || '').split(',').map(s => s.trim().replace(/\/+$/, '')).filter(Boolean); // browsers send origins without a trailing slash
// "*" in an origin matches one name part, e.g. https://*--bactifindpremium.netlify.app for Netlify preview deploys
const ORIGIN_RES = ORIGINS.map(o => new RegExp('^' + o.replace(/[.+?^${}()|[\]\\]/g, '\\$&').replace(/\*/g, '[a-z0-9-]+') + '$', 'i'));
const MAX_DEVICES = Math.max(1, +process.env.MAX_DEVICES || 2); // signed-in devices per account
const TOKEN_DAYS = 60;
const MAX_BODY = 8 * 1024 * 1024;
if (!JWT_SECRET || JWT_SECRET.length < 32) {
  if (process.env.DATABASE_URL) { console.error('JWT_SECRET must be set to at least 32 characters.'); process.exit(1); }
}
const SECRET = JWT_SECRET || crypto.randomBytes(32).toString('hex'); // memory mode only

// ---------------- Storage ----------------
function memoryStore() {
  const docs = new Map(), accounts = new Map(), usage = new Map(), sessions = new Map(), auditLog = [], hits = new Map();
  const copy = v => v == null ? null : JSON.parse(JSON.stringify(v));
  setInterval(() => { const now = Date.now(); hits.forEach((h, k) => { if (now - h.t > 3600e3) hits.delete(k); }); }, 600e3).unref();
  return {
    kind: 'memory',
    async init() {},
    async hit(key, windowMs) { const now = Date.now(), h = hits.get(key); if (!h || now - h.t > windowMs) { hits.set(key, { t: now, n: 1 }); return 1; } return ++h.n; },
    async createSession(s) { sessions.set(s.sid, copy(s)); },
    async sessionValid(sid, uid) { const s = sessions.get(sid); return !!(s && s.uid === uid); },
    async sessionsOf(uid) { return [...sessions.values()].filter(s => s.uid === uid).sort((a, b) => b.created_at - a.created_at).map(copy); },
    async deleteSession(sid) { sessions.delete(sid); },
    async deleteSessionsOf(uid, keepSid) { [...sessions.values()].forEach(s => { if (s.uid === uid && s.sid !== keepSid) sessions.delete(s.sid); }); },
    async audit(entry) { auditLog.push(copy(entry)); },
    async auditList(limit) { return auditLog.slice().sort((a, b) => b.at - a.at).slice(0, limit).map(copy); },
    async get(path) { return copy(docs.get(path)); },
    async put(path, data) { docs.set(path, copy(data)); },
    async del(path) { docs.delete(path); },
    async children(parent, q) {
      let rows = [...docs.entries()].filter(([p]) => p.slice(0, p.lastIndexOf('/')) === parent).map(([p, d]) => Object.assign({ id: p.slice(p.lastIndexOf('/') + 1) }, copy(d)));
      if (q.eq) rows = rows.filter(r => r[q.eq[0]] === q.eq[1]);
      if (q.gt) rows = rows.filter(r => (+r[q.gt[0]] || 0) > q.gt[1]);
      if (q.order) rows.sort((a, b) => (+a[q.order] || 0) - (+b[q.order] || 0));
      return rows.slice(0, q.limit);
    },
    async tx(fn) { return fn(this); },
    async accountByEmail(email) { return copy([...accounts.values()].find(a => a.email === email) || null); },
    async accountById(uid) { return copy(accounts.get(uid) || null); },
    async createAccount(a) { if ([...accounts.values()].some(x => x.email === a.email)) return false; accounts.set(a.uid, copy(a)); return true; },
    async setPassword(uid, pass) { const a = accounts.get(uid); if (a) a.pass = pass; },
    async setStatus(uid, status) { const a = accounts.get(uid); if (a) a.status = status; },
    async accountsWithStatus(list) { return [...accounts.values()].filter(a => list.includes(a.status)).sort((a, b) => b.created_at - a.created_at).slice(0, 200).map(a => ({ uid: a.uid, email: a.email, created_at: a.created_at, status: a.status, info: copy(a.info || null) })); },
    async count(day, name, module) { const k = `${day}|${name}|${module}`; usage.set(k, (usage.get(k) || 0) + 1); },
    async stats(sinceDay) { const out = {}; usage.forEach((n, k) => { const [d, name, m] = k.split('|'); if (d >= sinceDay) { const key = `${name}|${m}`; out[key] = (out[key] || 0) + n; } }); return Object.entries(out).map(([k, n]) => { const [name, module] = k.split('|'); return { name, module, n }; }).sort((a, b) => b.n - a.n); }
  };
}

function pgStore(url) {
  const { Pool } = require('pg');
  // Render's internal URL (host "dpg-…-a") needs no SSL; external Render, Neon and Supabase URLs do. PGSSL=require|disable overrides.
  const useSsl = process.env.PGSSL ? process.env.PGSSL === 'require' : /\.render\.com|neon\.tech|supabase\.co|sslmode=require/.test(url);
  const pool = new Pool({ connectionString: url, ssl: useSsl ? { rejectUnauthorized: false } : false, max: 5 });
  pool.on('error', e => console.error('Idle database connection dropped:', e.message)); // the pool reconnects on the next query
  const make = q => ({
    kind: 'postgres',
    async get(path) { const r = await q('SELECT data FROM docs WHERE path = $1', [path]); return r.rows[0] ? r.rows[0].data : null; },
    async put(path, data) {
      await q('INSERT INTO docs (path, parent, data, updated_at) VALUES ($1, $2, $3, $4) ON CONFLICT (path) DO UPDATE SET data = EXCLUDED.data, updated_at = EXCLUDED.updated_at',
        [path, path.slice(0, path.lastIndexOf('/')), JSON.stringify(data), Date.now()]);
    },
    async del(path) { await q('DELETE FROM docs WHERE path = $1', [path]); },
    async children(parent, o) {
      const args = [parent], where = ['parent = $1'];
      if (o.eq) { args.push(o.eq[0], String(o.eq[1])); where.push(`data ->> $${args.length - 1} = $${args.length}`); }
      if (o.gt) { args.push(o.gt[0], o.gt[1]); where.push(`COALESCE((data ->> $${args.length - 1})::numeric, 0) > $${args.length}`); }
      let sql = `SELECT path, data FROM docs WHERE ${where.join(' AND ')}`;
      if (o.order) { args.push(o.order); sql += ` ORDER BY COALESCE((data ->> $${args.length})::numeric, 0)`; }
      args.push(o.limit); sql += ` LIMIT $${args.length}`;
      const r = await q(sql, args);
      return r.rows.map(x => Object.assign({ id: x.path.slice(x.path.lastIndexOf('/') + 1) }, x.data));
    },
    async accountByEmail(email) { const r = await q('SELECT * FROM accounts WHERE email = $1', [email]); return r.rows[0] || null; },
    async accountById(uid) { const r = await q('SELECT * FROM accounts WHERE uid = $1', [uid]); return r.rows[0] || null; },
    async createAccount(a) { const r = await q('INSERT INTO accounts (uid, email, pass, created_at, status, info) VALUES ($1, $2, $3, $4, $5, $6) ON CONFLICT (email) DO NOTHING', [a.uid, a.email, a.pass, a.created_at, a.status, a.info ? JSON.stringify(a.info) : null]); return r.rowCount === 1; },
    async setPassword(uid, pass) { await q('UPDATE accounts SET pass = $2 WHERE uid = $1', [uid, pass]); },
    async setStatus(uid, status) { await q('UPDATE accounts SET status = $2 WHERE uid = $1', [uid, status]); },
    async accountsWithStatus(list) { const r = await q('SELECT uid, email, created_at, status, info FROM accounts WHERE status = ANY($1) ORDER BY created_at DESC LIMIT 200', [list]); return r.rows.map(x => Object.assign(x, { created_at: +x.created_at })); },
    async count(day, name, module) { await q('INSERT INTO usage (day, name, module, n) VALUES ($1, $2, $3, 1) ON CONFLICT (day, name, module) DO UPDATE SET n = usage.n + 1', [day, name, module]); },
    async stats(sinceDay) { const r = await q('SELECT name, module, SUM(n)::int AS n FROM usage WHERE day >= $1 GROUP BY name, module ORDER BY n DESC LIMIT 200', [sinceDay]); return r.rows; },
    async createSession(s) { await q('INSERT INTO sessions (sid, uid, created_at, label) VALUES ($1, $2, $3, $4)', [s.sid, s.uid, s.created_at, s.label]); },
    async sessionValid(sid, uid) { const r = await q('SELECT 1 FROM sessions WHERE sid = $1 AND uid = $2', [sid, uid]); return r.rowCount === 1; },
    async sessionsOf(uid) { const r = await q('SELECT sid, uid, created_at, label FROM sessions WHERE uid = $1 ORDER BY created_at DESC', [uid]); return r.rows.map(x => Object.assign(x, { created_at: +x.created_at })); },
    async deleteSession(sid) { await q('DELETE FROM sessions WHERE sid = $1', [sid]); },
    async deleteSessionsOf(uid, keepSid) { await q('DELETE FROM sessions WHERE uid = $1 AND sid <> $2', [uid, keepSid || '']); },
    async audit(entry) { await q('INSERT INTO audit (at, data) VALUES ($1, $2)', [entry.at, JSON.stringify(entry)]); },
    async hit(key, windowMs) {
      const now = Date.now();
      if (Math.random() < 0.02) await q('DELETE FROM ratelimit WHERE t < $1', [now - 3600e3]); // tidy old counters now and then
      const r = await q(`INSERT INTO ratelimit (k, t, n) VALUES ($1, $2, 1) ON CONFLICT (k) DO UPDATE SET
          n = CASE WHEN ratelimit.t < $3 THEN 1 ELSE ratelimit.n + 1 END, t = CASE WHEN ratelimit.t < $3 THEN $2 ELSE ratelimit.t END RETURNING n`, [key, now, now - windowMs]);
      return r.rows[0].n;
    },
    async auditList(limit) { const r = await q('SELECT data FROM audit ORDER BY at DESC LIMIT $1', [limit]); return r.rows.map(x => x.data); }
  });
  const base = make((sql, args) => pool.query(sql, args));
  base.init = async () => {
    await pool.query(`CREATE TABLE IF NOT EXISTS accounts (uid text PRIMARY KEY, email text UNIQUE NOT NULL, pass text NOT NULL, created_at bigint NOT NULL);
      CREATE TABLE IF NOT EXISTS docs (path text PRIMARY KEY, parent text NOT NULL, data jsonb NOT NULL, updated_at bigint NOT NULL);
      CREATE INDEX IF NOT EXISTS docs_parent ON docs (parent);
      CREATE TABLE IF NOT EXISTS usage (day date NOT NULL, name text NOT NULL, module text NOT NULL, n integer NOT NULL DEFAULT 0, PRIMARY KEY (day, name, module));
      CREATE TABLE IF NOT EXISTS sessions (sid text PRIMARY KEY, uid text NOT NULL, created_at bigint NOT NULL, label text);
      CREATE INDEX IF NOT EXISTS sessions_uid ON sessions (uid);
      CREATE TABLE IF NOT EXISTS audit (id bigserial PRIMARY KEY, at bigint NOT NULL, data jsonb NOT NULL);
      ALTER TABLE accounts ADD COLUMN IF NOT EXISTS status text;
      ALTER TABLE accounts ADD COLUMN IF NOT EXISTS info jsonb;
      CREATE TABLE IF NOT EXISTS ratelimit (k text PRIMARY KEY, t bigint NOT NULL, n integer NOT NULL);
      UPDATE accounts a SET status = CASE WHEN EXISTS (SELECT 1 FROM docs d WHERE d.path = 'entitlements/' || a.uid AND d.data ->> 'premium' = 'true') THEN 'approved' ELSE 'pending' END WHERE a.status IS NULL;`);
    // Accounts made before admin approval existed: approved if they already had Premium, otherwise waiting for approval (query above)
  };
  base.tx = async fn => {
    const c = await pool.connect();
    try { await c.query('BEGIN'); const r = await fn(make((sql, args) => c.query(sql, args))); await c.query('COMMIT'); return r; }
    catch (e) { await c.query('ROLLBACK').catch(() => {}); throw e; }
    finally { c.release(); }
  };
  return base;
}

const store = process.env.DATABASE_URL ? pgStore(process.env.DATABASE_URL) : memoryStore();
// Database host only (no user or password), shown by /api/health so you can see which database is in use
const DB_HOST = (() => { try { return process.env.DATABASE_URL ? new URL(process.env.DATABASE_URL).hostname : null; } catch (_) { return 'unparsable DATABASE_URL'; } })();

// ---------------- Passwords and tokens ----------------
const b64u = b => Buffer.from(b).toString('base64').replace(/=+$/, '').replace(/\+/g, '-').replace(/\//g, '_');
function hashPassword(pw) {
  const salt = crypto.randomBytes(16);
  return new Promise((ok, bad) => crypto.scrypt(pw, salt, 64, { N: 16384, r: 8, p: 1 }, (e, k) => e ? bad(e) : ok(`scrypt$${salt.toString('hex')}$${k.toString('hex')}`)));
}
function checkPassword(pw, stored) {
  const [alg, salt, hash] = String(stored).split('$');
  if (alg !== 'scrypt' || !salt || !hash) return Promise.resolve(false);
  return new Promise(ok => crypto.scrypt(pw, Buffer.from(salt, 'hex'), 64, { N: 16384, r: 8, p: 1 }, (e, k) => ok(!e && crypto.timingSafeEqual(k, Buffer.from(hash, 'hex')))));
}
// Each sign-in is a session (one device); the token carries its id (sid) so ending the session ends the token
function signToken(acc, sid) {
  const head = b64u(JSON.stringify({ alg: 'HS256', typ: 'JWT' }));
  const body = b64u(JSON.stringify({ sub: acc.uid, email: acc.email, sid, iat: Math.floor(Date.now() / 1000), exp: Math.floor(Date.now() / 1000) + TOKEN_DAYS * 86400 }));
  return `${head}.${body}.${b64u(crypto.createHmac('sha256', SECRET).update(`${head}.${body}`).digest())}`;
}
function readToken(tok) {
  const p = String(tok || '').split('.');
  if (p.length !== 3) return null;
  const want = Buffer.from(b64u(crypto.createHmac('sha256', SECRET).update(`${p[0]}.${p[1]}`).digest()));
  const got = Buffer.from(p[2]);
  if (want.length !== got.length || !crypto.timingSafeEqual(want, got)) return null;
  try { const c = JSON.parse(Buffer.from(p[1].replace(/-/g, '+').replace(/_/g, '/'), 'base64').toString()); return c.exp > Date.now() / 1000 && c.sid ? { uid: c.sub, email: c.email, sid: c.sid } : null; } catch (_) { return null; }
}
// New session for a sign-in; beyond MAX_DEVICES the oldest sessions end (admins are not limited)
async function startSession(acc, req) {
  const sid = newId(24), ua = String(req.headers['user-agent'] || '');
  const label = /Android/i.test(ua) ? (/; wv\)/.test(ua) ? 'Android app' : 'Android browser') : /iPhone|iPad/i.test(ua) ? 'iPhone / iPad' : /Windows/i.test(ua) ? 'Windows browser' : /Mac OS/i.test(ua) ? 'Mac browser' : 'Browser';
  await store.createSession({ sid, uid: acc.uid, created_at: Date.now(), label });
  if (!ADMINS.has(acc.email)) {
    const all = await store.sessionsOf(acc.uid);
    for (const s of all.slice(MAX_DEVICES)) await store.deleteSession(s.sid);
  }
  return sid;
}
const newId = n => { const a = 'abcdefghjkmnpqrstuvwxyz23456789'; let s = ''; crypto.randomBytes(n).forEach(b => { s += a[b % a.length]; }); return s; };

// ---------------- Access rules (mirror the app's expectations) ----------------
const isAdmin = u => !!(u && ADMINS.has(u.email));
// New accounts wait for an admin: 'pending' until approved, or 'rejected'. Admin accounts are always approved.
const statusOf = acc => ADMINS.has(acc.email) ? 'approved' : (acc.status || 'pending');
// Details given at sign-up (shown to the admin when approving). Optional for older app versions; when sent, all are required.
const INFO_FIELDS = { firstName: 60, lastName: 60, designation: 80, institute: 150, phone: 20 };
function readInfo(x) {
  if (x == null) return null;
  if (!isObj(x) || !keysOnly(x, Object.keys(INFO_FIELDS))) throw new HttpError(400, 'auth/bad-details', 'Fill in your details');
  const out = {};
  for (const [k, max] of Object.entries(INFO_FIELDS)) {
    const v = String(x[k] == null ? '' : x[k]).replace(/\s+/g, ' ').trim();
    if (!v || v.length > max) throw new HttpError(400, 'auth/bad-details', 'Fill in your details');
    out[k] = v;
  }
  if (!/^\+?[0-9][0-9 -]{6,18}$/.test(out.phone)) throw new HttpError(400, 'auth/bad-phone', 'Enter a valid phone number');
  return out;
}
const SEG = /^[A-Za-z0-9_.~%-]{1,150}$/;
function parsePath(p, docPath) {
  if (typeof p !== 'string' || p.length > 400) return null;
  const s = p.split('/');
  if (s.some(x => !SEG.test(x) || x === '.' || x === '..')) return null;
  if (docPath ? s.length % 2 !== 0 : s.length % 2 !== 1) return null;
  return s;
}
const STREAMS = ['isolates', 'qclog'];
const keysOnly = (o, allowed) => Object.keys(o || {}).every(k => allowed.includes(k));
async function labOf(db, labId) { return db.get(`labs/${labId}`); }
async function isMember(db, labId, u) { return !!(u && await db.get(`labs/${labId}/members/${u.uid}`)); }
async function isOwner(db, labId, u) { const l = await labOf(db, labId); return !!(u && l && l.owner === u.uid); }

async function canRead(db, s, u) {
  if (!u) return false;
  const [c, id, sub] = s;
  if (c === 'users' && s.length === 2) return id === u.uid || isAdmin(u);
  if (c === 'users' && s.length === 4) return id === u.uid && (sub === 'backup' || sub === 'meta');
  if (c === 'admins' && s.length === 2) return id === u.uid;
  if (c === 'entitlements' && s.length === 2) return id === u.uid || isAdmin(u);
  if (c === 'joinCodes' && s.length === 2) return true;
  if (c === 'labs' && s.length === 2) { if (await isMember(db, id, u)) return true; const l = await labOf(db, id); return !!(l && l.owner === u.uid); }
  if (c === 'labs' && s.length === 4 && (sub === 'members' || STREAMS.includes(sub))) return isMember(db, id, u);
  return false;
}
// data = the document as it will be after the write (merge already applied); old = current document or null
async function canWrite(db, s, u, data, old) {
  if (!u) return false;
  const [c, id, sub] = s;
  if (c === 'users' && s.length === 2) return id === u.uid && keysOnly(data, ['email', 'name', 'createdAt', 'lastSeen', 'labId']) && String(data.email || '').toLowerCase() === u.email;
  if (c === 'users' && s.length === 4) return id === u.uid && (sub === 'backup' || sub === 'meta');
  if (c === 'entitlements' && s.length === 2) return isAdmin(u);
  if (c === 'joinCodes' && s.length === 2) return !old && keysOnly(data, ['labId']) && typeof data.labId === 'string' && isOwner(db, data.labId, u);
  if (c === 'labs' && s.length === 2) return old ? (old.owner === u.uid && data.owner === old.owner) : data.owner === u.uid;
  if (c === 'labs' && s.length === 4 && sub === 'members') {
    if (old || s[3] !== u.uid) return false;
    const lab = await labOf(db, id);
    if (!lab) return false;
    if (lab.owner === u.uid) return true;
    if (data.role !== 'member' || typeof data.code !== 'string' || !SEG.test(data.code)) return false;
    const jc = await db.get(`joinCodes/${data.code}`);
    return !!(jc && jc.labId === id);
  }
  if (c === 'labs' && s.length === 4 && STREAMS.includes(sub)) {
    if (!(await isMember(db, id, u))) return false;
    if (!old) return data.by === u.uid;
    return (old.by === u.uid || await isOwner(db, id, u)) && data.by === old.by;
  }
  return false;
}
async function canDelete(db, s, u, old) {
  if (!u || !old) return false;
  const [c, id, sub] = s;
  if (c === 'users' && s.length === 4) return id === u.uid && (sub === 'backup' || sub === 'meta');
  if (c === 'joinCodes' && s.length === 2) return isOwner(db, old.labId, u);
  if (c === 'labs' && s.length === 2) return old.owner === u.uid;
  if (c === 'labs' && s.length === 4 && sub === 'members') return s[3] === u.uid || isOwner(db, id, u);
  if (c === 'labs' && s.length === 4 && STREAMS.includes(sub)) return (await isMember(db, id, u)) && (old.by === u.uid || await isOwner(db, id, u));
  return false;
}
async function canList(db, s, u, q) {
  if (!u) return false;
  if (s.length === 1 && s[0] === 'users') return isAdmin(u) && !!q.eq && q.eq[0] === 'email';
  if (s.length === 3 && s[0] === 'labs' && (s[2] === 'members' || STREAMS.includes(s[2]))) return isMember(db, s[1], u);
  return false;
}

// ---------------- HTTP helpers ----------------
class HttpError extends Error { constructor(status, code, message) { super(message || code); this.status = status; this.code = code; } }
const deny = () => new HttpError(403, 'permission-denied', 'Not allowed');
// Attempt limits (sign-in, sign-up, password, statistics) are counted in the store, so they also hold
// when several copies of the server run at once (Neon Functions)
async function limit(key, max, windowMs) {
  if ((await store.hit(key, windowMs)) > max) throw new HttpError(429, 'too-many-requests', 'Too many attempts — try again later');
}
function readBody(req) {
  return new Promise((ok, bad) => {
    let size = 0; const chunks = [];
    req.on('data', c => { size += c.length; if (size > MAX_BODY) { bad(new HttpError(413, 'too-large', 'Request too large')); req.destroy(); } else chunks.push(c); });
    req.on('end', () => { if (!chunks.length) return ok({}); try { ok(JSON.parse(Buffer.concat(chunks).toString())); } catch (_) { bad(new HttpError(400, 'bad-json', 'Invalid JSON')); } });
    req.on('error', bad);
  });
}
function cors(req, res) {
  const o = req.headers.origin;
  res.setHeader('Access-Control-Allow-Origin', !ORIGINS.length ? '*' : (o && ORIGIN_RES.some(re => re.test(o)) ? o : ORIGINS.find(x => !x.includes('*')) || 'null'));
  res.setHeader('Vary', 'Origin');
  res.setHeader('Access-Control-Allow-Headers', 'Authorization, Content-Type');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
  res.setHeader('Access-Control-Max-Age', '86400');
}
const send = (res, status, obj) => { res.writeHead(status, { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store' }); res.end(JSON.stringify(obj)); };
const ipOf = req => String(req.headers['x-forwarded-for'] || req.socket.remoteAddress || '').split(',')[0].trim();
const EMAIL = /^[^\s@]{1,64}@[^\s@]{1,190}\.[^\s@]{2,}$/;
const NUM_FIELDS = ['updatedAt', 'at', 'createdAt'];
function listQuery(b) {
  const q = { limit: Math.min(Math.max(+b.max || 500, 1), 500) };
  if (b.where) {
    const [f, op, v] = b.where;
    if (op === '==' && f === 'email' && typeof v === 'string') q.eq = [f, v.toLowerCase()];
    else if (op === '>' && NUM_FIELDS.includes(f) && Number.isFinite(+v)) q.gt = [f, +v];
    else throw new HttpError(400, 'bad-query', 'Unsupported query');
  }
  if (b.order) { if (!NUM_FIELDS.includes(b.order)) throw new HttpError(400, 'bad-query', 'Unsupported order'); q.order = b.order; }
  return q;
}
const isObj = v => v && typeof v === 'object' && !Array.isArray(v);

// ---------------- Routes ----------------
async function handle(req, res) {
  cors(req, res);
  if (req.method === 'OPTIONS') { res.writeHead(204); return res.end(); }
  const url = new URL(req.url, 'http://x');
  const route = `${req.method} ${url.pathname}`;
  const auth = String(req.headers.authorization || '');
  let user = auth.startsWith('Bearer ') ? readToken(auth.slice(7)) : null;
  let ended = false; // the token is valid but its session was ended (signed in on too many devices, signed out elsewhere, password reset)
  if (user && !(await store.sessionValid(user.sid, user.uid))) { user = null; ended = true; }
  const need = () => { if (!user) throw ended ? new HttpError(401, 'session-ended', 'Signed out on this device') : new HttpError(401, 'unauthenticated', 'Sign in again'); };
  // Data routes: the account must be approved by an admin
  const needApproved = async () => {
    need(); if (isAdmin(user)) return;
    const acc = await store.accountById(user.uid), s = acc ? statusOf(acc) : 'pending';
    if (s !== 'approved') throw new HttpError(403, s === 'rejected' ? 'account-rejected' : 'account-pending', s === 'rejected' ? 'This account was not approved' : 'Waiting for admin approval');
  };
  const pub = acc => ({ uid: acc.uid, email: acc.email, status: statusOf(acc) });
  // Premium changes are recorded in the admin activity log
  const logPremium = (s, data) => s[0] === 'entitlements' && s.length === 2 && store.audit({ at: Date.now(), by: user.email, action: data.premium ? 'premium-given' : 'premium-removed', uid: s[1], email: data.email || '', until: data.until || null });

  if (route === 'GET /' || route === 'GET /api/health') return send(res, 200, { ok: true, service: 'bactifind-api', store: store.kind, dbHost: DB_HOST });

  if (route === 'POST /api/auth/signup' || route === 'POST /api/auth/signin') {
    const b = await readBody(req);
    const email = String(b.email || '').trim().toLowerCase(), pw = String(b.password || '');
    await limit(`auth:${ipOf(req)}`, 30, 15 * 60e3);
    if (!EMAIL.test(email)) throw new HttpError(400, 'auth/invalid-email', 'Enter a valid email address');
    if (route.endsWith('signup')) {
      if (pw.length < 8 || pw.length > 200) throw new HttpError(400, 'auth/weak-password', 'Use a password of at least 8 characters');
      const info = readInfo(b.info);
      const acc = { uid: newId(20), email, pass: await hashPassword(pw), created_at: Date.now(), status: ADMINS.has(email) ? 'approved' : 'pending', info };
      if (!(await store.createAccount(acc))) throw new HttpError(409, 'auth/email-already-in-use', 'An account with this email already exists');
      return send(res, 200, { token: signToken(acc, await startSession(acc, req)), user: pub(acc) });
    }
    await limit(`signin:${email}`, 10, 15 * 60e3);
    const acc = await store.accountByEmail(email);
    if (!acc || !(await checkPassword(pw, acc.pass))) throw new HttpError(401, 'auth/invalid-credential', 'Wrong email or password');
    return send(res, 200, { token: signToken(acc, await startSession(acc, req)), user: pub(acc) });
  }
  // Signed-in devices: list, sign out this one, sign out all others
  if (route === 'GET /api/auth/sessions') {
    need();
    const all = await store.sessionsOf(user.uid);
    return send(res, 200, { max: isAdmin(user) ? null : MAX_DEVICES, sessions: all.map(s => ({ label: s.label, created_at: s.created_at, current: s.sid === user.sid })) });
  }
  if (route === 'POST /api/auth/signout') { if (user) await store.deleteSession(user.sid); return send(res, 200, { ok: true }); }
  if (route === 'POST /api/auth/signout-others') { need(); await store.deleteSessionsOf(user.uid, user.sid); return send(res, 200, { ok: true }); }
  if (route === 'GET /api/auth/me') {
    need();
    const acc = await store.accountById(user.uid);
    if (!acc) throw new HttpError(401, 'unauthenticated', 'Account not found');
    return send(res, 200, { user: pub(acc), admin: isAdmin(user) });
  }
  if (route === 'POST /api/auth/password') {
    need();
    const b = await readBody(req);
    await limit(`pw:${user.uid}`, 10, 15 * 60e3);
    const acc = await store.accountById(user.uid);
    if (!acc || !(await checkPassword(String(b.old || ''), acc.pass))) throw new HttpError(401, 'auth/invalid-credential', 'Current password is wrong');
    if (String(b.password || '').length < 8) throw new HttpError(400, 'auth/weak-password', 'Use a password of at least 8 characters');
    await store.setPassword(user.uid, await hashPassword(String(b.password)));
    await store.deleteSessionsOf(user.uid, user.sid); // a new password signs out every other device
    return send(res, 200, { ok: true });
  }

  // Documents
  if (route === 'POST /api/doc/get') {
    await needApproved(); const b = await readBody(req), s = parsePath(b.path, true); if (!s) throw new HttpError(400, 'bad-path', 'Bad path');
    if (s[0] === 'admins') return send(res, 200, { data: s[1] === user.uid && isAdmin(user) ? { role: 'admin' } : null }); // admins come from ADMIN_EMAILS
    if (!(await canRead(store, s, user))) throw deny();
    return send(res, 200, { data: await store.get(b.path) });
  }
  if (route === 'POST /api/doc/set') {
    await needApproved(); const b = await readBody(req), s = parsePath(b.path, true); if (!s || !isObj(b.data)) throw new HttpError(400, 'bad-request', 'Bad path or data');
    await store.tx(async db => {
      const old = await db.get(b.path), data = b.merge && old ? Object.assign({}, old, b.data) : b.data;
      if (!(await canWrite(db, s, user, data, old))) throw deny();
      await db.put(b.path, data);
      await logPremium(s, data);
    });
    return send(res, 200, { ok: true });
  }
  if (route === 'POST /api/doc/delete') {
    await needApproved(); const b = await readBody(req), s = parsePath(b.path, true); if (!s) throw new HttpError(400, 'bad-path', 'Bad path');
    await store.tx(async db => {
      const old = await db.get(b.path);
      if (!old) return;
      if (!(await canDelete(db, s, user, old))) throw deny();
      await db.del(b.path);
    });
    return send(res, 200, { ok: true });
  }
  if (route === 'POST /api/doc/list') {
    await needApproved(); const b = await readBody(req), s = parsePath(b.coll, false); if (!s) throw new HttpError(400, 'bad-path', 'Bad collection');
    const q = listQuery(b);
    if (!(await canList(store, s, user, q))) throw deny();
    return send(res, 200, { rows: await store.children(b.coll, q) });
  }
  if (route === 'POST /api/doc/batch') {
    await needApproved(); const b = await readBody(req);
    if (!Array.isArray(b.items) || b.items.length > 500) throw new HttpError(400, 'bad-request', 'Up to 500 items');
    await store.tx(async db => {
      for (const it of b.items) {
        const [path, data] = Array.isArray(it) ? it : [];
        const s = parsePath(path, true); if (!s || !isObj(data)) throw new HttpError(400, 'bad-request', 'Bad item');
        if (!(await canWrite(db, s, user, data, await db.get(path)))) throw deny();
        await db.put(path, data);
        await logPremium(s, data);
      }
    });
    return send(res, 200, { ok: true });
  }

  // Usage statistics: anonymous counts of opened modules
  if (route === 'POST /api/track') {
    const b = await readBody(req);
    await limit(`track:${ipOf(req)}`, 600, 3600e3);
    const name = String(b.name || ''), mod = String((b.params && b.params.module) || '');
    if (!/^[a-z_]{1,40}$/.test(name) || !/^[A-Za-z0-9_-]{0,40}$/.test(mod)) throw new HttpError(400, 'bad-request', 'Bad event');
    await store.count(new Date().toISOString().slice(0, 10), name, mod);
    return send(res, 200, { ok: true });
  }
  if (route === 'GET /api/admin/stats') {
    need(); if (!isAdmin(user)) throw deny();
    const days = Math.min(Math.max(+url.searchParams.get('days') || 30, 1), 365);
    return send(res, 200, { days, rows: await store.stats(new Date(Date.now() - days * 864e5).toISOString().slice(0, 10)) });
  }
  if (route === 'POST /api/admin/temp-password') {
    need(); if (!isAdmin(user)) throw deny();
    const b = await readBody(req), acc = await store.accountById(String(b.uid || ''));
    if (!acc) throw new HttpError(404, 'not-found', 'No such account');
    const pw = newId(10);
    await store.setPassword(acc.uid, await hashPassword(pw));
    await store.deleteSessionsOf(acc.uid, null); // the old password's devices are signed out
    await store.audit({ at: Date.now(), by: user.email, action: 'temp-password', uid: acc.uid, email: acc.email });
    return send(res, 200, { password: pw });
  }
  // Accounts waiting for approval (and rejected ones, which can still be approved later)
  if (route === 'GET /api/admin/pending') {
    need(); if (!isAdmin(user)) throw deny();
    const rows = (await store.accountsWithStatus(['pending', 'rejected'])).filter(a => !ADMINS.has(a.email));
    return send(res, 200, { rows });
  }
  // Approve (with Premium for `months`, or no expiry when months is null) or reject a new account
  if (route === 'POST /api/admin/approve') {
    need(); if (!isAdmin(user)) throw deny();
    const b = await readBody(req), acc = await store.accountById(String(b.uid || ''));
    if (!acc) throw new HttpError(404, 'not-found', 'No such account');
    const approve = b.approve !== false, months = b.months == null ? null : +b.months;
    if (approve && months != null && !(months > 0 && months <= 120)) throw new HttpError(400, 'bad-request', 'Bad months');
    const until = approve && months ? Date.now() + months * 30.44 * 864e5 : null;
    await store.tx(async db => {
      await db.setStatus(acc.uid, approve ? 'approved' : 'rejected');
      await db.put(`entitlements/${acc.uid}`, approve ? { premium: true, until, email: acc.email, by: user.uid, at: Date.now() } : { premium: false, email: acc.email, by: user.uid, at: Date.now() });
      await db.audit({ at: Date.now(), by: user.email, action: approve ? 'account-approved' : 'account-rejected', uid: acc.uid, email: acc.email, until });
    });
    return send(res, 200, { ok: true, status: approve ? 'approved' : 'rejected' });
  }
  if (route === 'GET /api/admin/audit') {
    need(); if (!isAdmin(user)) throw deny();
    return send(res, 200, { rows: await store.auditList(Math.min(Math.max(+url.searchParams.get('limit') || 100, 1), 500)) });
  }

  throw new HttpError(404, 'not-found', 'Not found');
}

// One request: Node's own server (Render, tests) and the Neon Functions adapter (neon/index.mjs) both call this
const dispatch = (req, res) => handle(req, res).catch(e => {
  const status = e instanceof HttpError ? e.status : 500;
  if (status === 500) console.error(e);
  if (!res.headersSent) send(res, status, { error: e.code || 'internal', message: status === 500 ? 'Server error' : e.message });
});
const server = http.createServer(dispatch);

if (require.main === module) {
  store.init().then(() => server.listen(PORT, () => console.log(`BactiFIND API on :${PORT} (${store.kind} store)`)))
    .catch(e => { console.error('Database setup failed:', e); process.exit(1); });
}
module.exports = { server, store, dispatch, readToken, signToken };
