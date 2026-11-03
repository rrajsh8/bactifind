'use strict';
// BactiFIND cloud server (Render Web Service + Render PostgreSQL).
// Stores documents by path ("users/{uid}", "labs/{labId}/isolates/{id}", …) and enforces who may read and write each path.
// Environment:
//   DATABASE_URL     Render PostgreSQL connection string (without it the server keeps data in memory — for testing only)
//   JWT_SECRET       long random string used to sign sign-in tokens (Render can generate it)
//   ADMIN_EMAILS     comma-separated admin account emails (they can give Premium and see usage statistics)
//   ALLOWED_ORIGINS  optional comma-separated list of web origins allowed to call the API (default: any)
//   PGSSL            optional: require | disable (default: SSL only for external *.render.com database URLs)
//   PORT             set by Render

const http = require('http');
const crypto = require('crypto');

const PORT = +process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || '';
const ADMINS = new Set((process.env.ADMIN_EMAILS || '').split(',').map(s => s.trim().toLowerCase()).filter(Boolean));
const ORIGINS = (process.env.ALLOWED_ORIGINS || '').split(',').map(s => s.trim()).filter(Boolean);
const TOKEN_DAYS = 60;
const MAX_BODY = 8 * 1024 * 1024;
if (!JWT_SECRET || JWT_SECRET.length < 32) {
  if (process.env.DATABASE_URL) { console.error('JWT_SECRET must be set to at least 32 characters.'); process.exit(1); }
}
const SECRET = JWT_SECRET || crypto.randomBytes(32).toString('hex'); // memory mode only

// ---------------- Storage ----------------
function memoryStore() {
  const docs = new Map(), accounts = new Map(), usage = new Map();
  const copy = v => v == null ? null : JSON.parse(JSON.stringify(v));
  return {
    kind: 'memory',
    async init() {},
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
    async count(day, name, module) { const k = `${day}|${name}|${module}`; usage.set(k, (usage.get(k) || 0) + 1); },
    async stats(sinceDay) { const out = {}; usage.forEach((n, k) => { const [d, name, m] = k.split('|'); if (d >= sinceDay) { const key = `${name}|${m}`; out[key] = (out[key] || 0) + n; } }); return Object.entries(out).map(([k, n]) => { const [name, module] = k.split('|'); return { name, module, n }; }).sort((a, b) => b.n - a.n); }
  };
}

function pgStore(url) {
  const { Pool } = require('pg');
  // Render's internal URL (host "dpg-…-a") needs no SSL; its external URL (…render.com) does. PGSSL=require|disable overrides.
  const useSsl = process.env.PGSSL ? process.env.PGSSL === 'require' : /\.render\.com/.test(url);
  const pool = new Pool({ connectionString: url, ssl: useSsl ? { rejectUnauthorized: false } : false, max: 5 });
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
    async createAccount(a) { const r = await q('INSERT INTO accounts (uid, email, pass, created_at) VALUES ($1, $2, $3, $4) ON CONFLICT (email) DO NOTHING', [a.uid, a.email, a.pass, a.created_at]); return r.rowCount === 1; },
    async setPassword(uid, pass) { await q('UPDATE accounts SET pass = $2 WHERE uid = $1', [uid, pass]); },
    async count(day, name, module) { await q('INSERT INTO usage (day, name, module, n) VALUES ($1, $2, $3, 1) ON CONFLICT (day, name, module) DO UPDATE SET n = usage.n + 1', [day, name, module]); },
    async stats(sinceDay) { const r = await q('SELECT name, module, SUM(n)::int AS n FROM usage WHERE day >= $1 GROUP BY name, module ORDER BY n DESC LIMIT 200', [sinceDay]); return r.rows; }
  });
  const base = make((sql, args) => pool.query(sql, args));
  base.init = async () => {
    await pool.query(`CREATE TABLE IF NOT EXISTS accounts (uid text PRIMARY KEY, email text UNIQUE NOT NULL, pass text NOT NULL, created_at bigint NOT NULL);
      CREATE TABLE IF NOT EXISTS docs (path text PRIMARY KEY, parent text NOT NULL, data jsonb NOT NULL, updated_at bigint NOT NULL);
      CREATE INDEX IF NOT EXISTS docs_parent ON docs (parent);
      CREATE TABLE IF NOT EXISTS usage (day date NOT NULL, name text NOT NULL, module text NOT NULL, n integer NOT NULL DEFAULT 0, PRIMARY KEY (day, name, module));`);
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
function signToken(acc) {
  const head = b64u(JSON.stringify({ alg: 'HS256', typ: 'JWT' }));
  const body = b64u(JSON.stringify({ sub: acc.uid, email: acc.email, iat: Math.floor(Date.now() / 1000), exp: Math.floor(Date.now() / 1000) + TOKEN_DAYS * 86400 }));
  return `${head}.${body}.${b64u(crypto.createHmac('sha256', SECRET).update(`${head}.${body}`).digest())}`;
}
function readToken(tok) {
  const p = String(tok || '').split('.');
  if (p.length !== 3) return null;
  const want = Buffer.from(b64u(crypto.createHmac('sha256', SECRET).update(`${p[0]}.${p[1]}`).digest()));
  const got = Buffer.from(p[2]);
  if (want.length !== got.length || !crypto.timingSafeEqual(want, got)) return null;
  try { const c = JSON.parse(Buffer.from(p[1].replace(/-/g, '+').replace(/_/g, '/'), 'base64').toString()); return c.exp > Date.now() / 1000 ? { uid: c.sub, email: c.email } : null; } catch (_) { return null; }
}
const newId = n => { const a = 'abcdefghjkmnpqrstuvwxyz23456789'; let s = ''; crypto.randomBytes(n).forEach(b => { s += a[b % a.length]; }); return s; };

// ---------------- Access rules (mirror the app's expectations) ----------------
const isAdmin = u => !!(u && ADMINS.has(u.email));
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
const hits = new Map(); // simple in-memory rate limiter
function limit(key, max, windowMs) {
  const now = Date.now(), h = hits.get(key);
  if (!h || now - h.t > windowMs) { hits.set(key, { t: now, n: 1 }); return; }
  if (++h.n > max) throw new HttpError(429, 'too-many-requests', 'Too many attempts — try again later');
}
setInterval(() => { const now = Date.now(); hits.forEach((h, k) => { if (now - h.t > 3600e3) hits.delete(k); }); }, 600e3).unref();
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
  res.setHeader('Access-Control-Allow-Origin', !ORIGINS.length ? '*' : (o && ORIGINS.includes(o) ? o : ORIGINS[0]));
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
  const user = auth.startsWith('Bearer ') ? readToken(auth.slice(7)) : null;
  const need = () => { if (!user) throw new HttpError(401, 'unauthenticated', 'Sign in again'); };

  if (route === 'GET /' || route === 'GET /api/health') return send(res, 200, { ok: true, service: 'bactifind-api', store: store.kind });

  if (route === 'POST /api/auth/signup' || route === 'POST /api/auth/signin') {
    const b = await readBody(req);
    const email = String(b.email || '').trim().toLowerCase(), pw = String(b.password || '');
    limit(`auth:${ipOf(req)}`, 30, 15 * 60e3);
    if (!EMAIL.test(email)) throw new HttpError(400, 'auth/invalid-email', 'Enter a valid email address');
    if (route.endsWith('signup')) {
      if (pw.length < 8 || pw.length > 200) throw new HttpError(400, 'auth/weak-password', 'Use a password of at least 8 characters');
      const acc = { uid: newId(20), email, pass: await hashPassword(pw), created_at: Date.now() };
      if (!(await store.createAccount(acc))) throw new HttpError(409, 'auth/email-already-in-use', 'An account with this email already exists');
      return send(res, 200, { token: signToken(acc), user: { uid: acc.uid, email } });
    }
    limit(`signin:${email}`, 10, 15 * 60e3);
    const acc = await store.accountByEmail(email);
    if (!acc || !(await checkPassword(pw, acc.pass))) throw new HttpError(401, 'auth/invalid-credential', 'Wrong email or password');
    return send(res, 200, { token: signToken(acc), user: { uid: acc.uid, email } });
  }
  if (route === 'GET /api/auth/me') {
    need();
    const acc = await store.accountById(user.uid);
    if (!acc) throw new HttpError(401, 'unauthenticated', 'Account not found');
    return send(res, 200, { user: { uid: acc.uid, email: acc.email }, admin: isAdmin(user) });
  }
  if (route === 'POST /api/auth/password') {
    need();
    const b = await readBody(req);
    limit(`pw:${user.uid}`, 10, 15 * 60e3);
    const acc = await store.accountById(user.uid);
    if (!acc || !(await checkPassword(String(b.old || ''), acc.pass))) throw new HttpError(401, 'auth/invalid-credential', 'Current password is wrong');
    if (String(b.password || '').length < 8) throw new HttpError(400, 'auth/weak-password', 'Use a password of at least 8 characters');
    await store.setPassword(user.uid, await hashPassword(String(b.password)));
    return send(res, 200, { ok: true });
  }

  // Documents
  if (route === 'POST /api/doc/get') {
    need(); const b = await readBody(req), s = parsePath(b.path, true); if (!s) throw new HttpError(400, 'bad-path', 'Bad path');
    if (s[0] === 'admins') return send(res, 200, { data: s[1] === user.uid && isAdmin(user) ? { role: 'admin' } : null }); // admins come from ADMIN_EMAILS
    if (!(await canRead(store, s, user))) throw deny();
    return send(res, 200, { data: await store.get(b.path) });
  }
  if (route === 'POST /api/doc/set') {
    need(); const b = await readBody(req), s = parsePath(b.path, true); if (!s || !isObj(b.data)) throw new HttpError(400, 'bad-request', 'Bad path or data');
    await store.tx(async db => {
      const old = await db.get(b.path), data = b.merge && old ? Object.assign({}, old, b.data) : b.data;
      if (!(await canWrite(db, s, user, data, old))) throw deny();
      await db.put(b.path, data);
    });
    return send(res, 200, { ok: true });
  }
  if (route === 'POST /api/doc/delete') {
    need(); const b = await readBody(req), s = parsePath(b.path, true); if (!s) throw new HttpError(400, 'bad-path', 'Bad path');
    await store.tx(async db => {
      const old = await db.get(b.path);
      if (!old) return;
      if (!(await canDelete(db, s, user, old))) throw deny();
      await db.del(b.path);
    });
    return send(res, 200, { ok: true });
  }
  if (route === 'POST /api/doc/list') {
    need(); const b = await readBody(req), s = parsePath(b.coll, false); if (!s) throw new HttpError(400, 'bad-path', 'Bad collection');
    const q = listQuery(b);
    if (!(await canList(store, s, user, q))) throw deny();
    return send(res, 200, { rows: await store.children(b.coll, q) });
  }
  if (route === 'POST /api/doc/batch') {
    need(); const b = await readBody(req);
    if (!Array.isArray(b.items) || b.items.length > 500) throw new HttpError(400, 'bad-request', 'Up to 500 items');
    await store.tx(async db => {
      for (const it of b.items) {
        const [path, data] = Array.isArray(it) ? it : [];
        const s = parsePath(path, true); if (!s || !isObj(data)) throw new HttpError(400, 'bad-request', 'Bad item');
        if (!(await canWrite(db, s, user, data, await db.get(path)))) throw deny();
        await db.put(path, data);
      }
    });
    return send(res, 200, { ok: true });
  }

  // Usage statistics: anonymous counts of opened modules
  if (route === 'POST /api/track') {
    const b = await readBody(req);
    limit(`track:${ipOf(req)}`, 600, 3600e3);
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
    return send(res, 200, { password: pw });
  }

  throw new HttpError(404, 'not-found', 'Not found');
}

const server = http.createServer((req, res) => {
  handle(req, res).catch(e => {
    const status = e instanceof HttpError ? e.status : 500;
    if (status === 500) console.error(e);
    if (!res.headersSent) send(res, status, { error: e.code || 'internal', message: status === 500 ? 'Server error' : e.message });
  });
});

if (require.main === module) {
  store.init().then(() => server.listen(PORT, () => console.log(`BactiFIND API on :${PORT} (${store.kind} store)`)))
    .catch(e => { console.error('Database setup failed:', e); process.exit(1); });
}
module.exports = { server, store, readToken, signToken };
