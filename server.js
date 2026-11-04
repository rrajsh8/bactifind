'use strict';
// BactiFIND cloud server (Render Web Service + Render PostgreSQL).
// Stores documents by path ("users/{uid}", "labs/{labId}/isolates/{id}", …) and enforces who may read and write each path.
// Environment:
//   DATABASE_URL     Render PostgreSQL connection string (without it the server keeps data in memory — for testing only)
//   JWT_SECRET       long random string used to sign sign-in tokens (Render can generate it)
//   ADMIN_EMAILS     comma-separated main admin emails: they approve accounts, give Premium, and add or remove other admins
//                    (added admins are kept in the database document config/admins and can do everything except manage admins)
//   SIGNUP_ALERT_URL optional: address that gets a short POST (no personal details) when a new account waits for approval,
//                    for example an ntfy.sh topic, so the admin's phone shows a notification
//   ALLOWED_ORIGINS  optional comma-separated list of web origins allowed to call the API (default: any)
//   PGSSL            optional: require | disable (default: SSL only for external *.render.com database URLs)
//   MAX_DEVICES      optional: signed-in devices per account (default 2; the oldest is signed out; admins unlimited)
//   STORAGE_LIMIT_MB optional: cloud space per account, for its backup plus the lab records it added (default 2 MB,
//                    so about 425 full accounts fit the 1 GB free Neon plan with room for the database itself). Admins have no limit.
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
// Cloud space per account (characters of stored data): 1 GB plan − ~150 MB for the database, indexes and history ≈ 850 MB ÷ 2 MB ≈ 425 full accounts
const STORAGE_LIMIT = Math.round((+process.env.STORAGE_LIMIT_MB > 0 ? +process.env.STORAGE_LIMIT_MB : 2) * 1048576);
// Size of one stored document as counted against the limit: backup pieces by their text, other documents as JSON
const docSize = d => !d ? 0 : typeof d.v === 'string' ? d.v.length : JSON.stringify(d).length;
const MAX_BODY = 8 * 1024 * 1024;
if (!JWT_SECRET || JWT_SECRET.length < 32) {
  if (process.env.DATABASE_URL) { console.error('JWT_SECRET must be set to at least 32 characters.'); process.exit(1); }
}
const SECRET = JWT_SECRET || crypto.randomBytes(32).toString('hex'); // memory mode only

// ---------------- Storage ----------------
function memoryStore() {
  const docs = new Map(), accounts = new Map(), sessions = new Map(), auditLog = [], hits = new Map();
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
    async deleteSessionsBefore(t) { [...sessions.values()].forEach(s => { if (s.created_at < t) sessions.delete(s.sid); }); },
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
    async allAccounts(limit) {
      return [...accounts.values()].sort((a, b) => b.created_at - a.created_at).slice(0, limit).map(a => ({
        uid: a.uid, email: a.email, created_at: a.created_at, status: a.status, info: copy(a.info || null), ent: copy(docs.get(`entitlements/${a.uid}`) || null),
        last_seen: Math.max(0, ...[...sessions.values()].filter(s => s.uid === a.uid).map(s => s.created_at)) || null }));
    },
    async updateAccount(uid, ch) { const a = accounts.get(uid); if (!a) return false; if (ch.email && [...accounts.values()].some(x => x.email === ch.email && x.uid !== uid)) return false; Object.assign(a, copy(ch)); return true; },
    async deleteAccount(uid) { accounts.delete(uid); [...sessions.values()].forEach(s => { if (s.uid === uid) sessions.delete(s.sid); }); },
    async docsUnder(prefix) { return [...docs.entries()].filter(([p]) => p.startsWith(prefix)).map(([path, data]) => ({ path, data: copy(data) })); },
    async memberDocs(uid) { return [...docs.entries()].filter(([p]) => /^labs\/[^/]+\/members\/[^/]+$/.test(p) && p.endsWith('/' + uid)).map(([path, data]) => ({ path, data: copy(data) })); },
    async countChildren(parent) { let n = 0; docs.forEach((_, p) => { if (p.slice(0, p.lastIndexOf('/')) === parent) n++; }); return n; },
    async usage(uid) {
      let backup = 0, lab = 0;
      docs.forEach((d, p) => {
        const par = p.slice(0, p.lastIndexOf('/'));
        if (par === `users/${uid}/backup`) backup += docSize(d);
        else if (/^labs\/[^/]+\/(isolates|qclog)$/.test(par) && d.by === uid) lab += docSize(d);
      });
      return { backup, lab };
    },
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
    async allAccounts(limit) {
      const r = await q(`SELECT a.uid, a.email, a.created_at, a.status, a.info, d.data AS ent, (SELECT MAX(s.created_at) FROM sessions s WHERE s.uid = a.uid) AS last_seen
        FROM accounts a LEFT JOIN docs d ON d.path = 'entitlements/' || a.uid ORDER BY a.created_at DESC LIMIT $1`, [limit]);
      return r.rows.map(x => Object.assign(x, { created_at: +x.created_at, last_seen: x.last_seen == null ? null : +x.last_seen }));
    },
    async updateAccount(uid, ch) {
      try { const r = await q('UPDATE accounts SET email = COALESCE($2, email), info = COALESCE($3, info) WHERE uid = $1', [uid, ch.email || null, ch.info ? JSON.stringify(ch.info) : null]); return r.rowCount === 1; }
      catch (e) { if (e.code === '23505') return false; throw e; } // 23505: the new email belongs to another account
    },
    async deleteAccount(uid) { await q('DELETE FROM sessions WHERE uid = $1', [uid]); await q('DELETE FROM accounts WHERE uid = $1', [uid]); },
    async docsUnder(prefix) { const r = await q('SELECT path, data FROM docs WHERE left(path, length($1)) = $1', [prefix]); return r.rows; },
    async memberDocs(uid) { const r = await q("SELECT path, data FROM docs WHERE parent LIKE 'labs/%/members' AND path = parent || '/' || $1", [uid]); return r.rows; },
    async countChildren(parent) { const r = await q('SELECT COUNT(*)::int AS n FROM docs WHERE parent = $1', [parent]); return r.rows[0].n; },
    async usage(uid) {
      const b = await q("SELECT COALESCE(SUM(CASE WHEN jsonb_typeof(data -> 'v') = 'string' THEN length(data ->> 'v') ELSE length(data::text) END), 0)::bigint AS n FROM docs WHERE parent = $1", [`users/${uid}/backup`]);
      const l = await q("SELECT COALESCE(SUM(length(data::text)), 0)::bigint AS n FROM docs WHERE (parent LIKE 'labs/%/isolates' OR parent LIKE 'labs/%/qclog') AND data ->> 'by' = $1", [uid]);
      return { backup: +b.rows[0].n, lab: +l.rows[0].n };
    },
    async createSession(s) { await q('INSERT INTO sessions (sid, uid, created_at, label) VALUES ($1, $2, $3, $4)', [s.sid, s.uid, s.created_at, s.label]); },
    async sessionValid(sid, uid) { const r = await q('SELECT 1 FROM sessions WHERE sid = $1 AND uid = $2', [sid, uid]); return r.rowCount === 1; },
    async sessionsOf(uid) { const r = await q('SELECT sid, uid, created_at, label FROM sessions WHERE uid = $1 ORDER BY created_at DESC', [uid]); return r.rows.map(x => Object.assign(x, { created_at: +x.created_at })); },
    async deleteSession(sid) { await q('DELETE FROM sessions WHERE sid = $1', [sid]); },
    async deleteSessionsOf(uid, keepSid) { await q('DELETE FROM sessions WHERE uid = $1 AND sid <> $2', [uid, keepSid || '']); },
    async deleteSessionsBefore(t) { await q('DELETE FROM sessions WHERE created_at < $1', [t]); },
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
  // Now and then remove sessions whose sign-in has expired (phones reset or lost never sign out)
  if (Math.random() < 0.05) await store.deleteSessionsBefore(Date.now() - TOKEN_DAYS * 864e5);
  if (!adminSet().has(acc.email)) {
    const all = await store.sessionsOf(acc.uid);
    for (const s of all.slice(MAX_DEVICES)) await store.deleteSession(s.sid);
  }
  return sid;
}
const newId = n => { const a = 'abcdefghjkmnpqrstuvwxyz23456789'; let s = ''; crypto.randomBytes(n).forEach(b => { s += a[b % a.length]; }); return s; };

// ---------------- Access rules (mirror the app's expectations) ----------------
// Admins: the main ones from ADMIN_EMAILS, plus the ones a main admin added (document config/admins, which the
// document routes cannot read or write). Each server copy re-reads the list at most every 30 s.
let addedAdmins = new Set(), addedAt = 0;
const ADDED_PATH = 'config/admins';
async function refreshAdmins(force) {
  if (!force && Date.now() - addedAt < 30e3) return;
  const d = await store.get(ADDED_PATH);
  addedAdmins = new Set(((d && d.emails) || []).map(e => String(e).toLowerCase()));
  addedAt = Date.now();
}
async function saveAdded(list) {
  const emails = [...new Set(list.map(e => String(e).toLowerCase()))].filter(e => !ADMINS.has(e)).slice(0, 50);
  await store.put(ADDED_PATH, { emails });
  addedAdmins = new Set(emails); addedAt = Date.now();
}
const adminSet = () => addedAdmins.size ? new Set([...ADMINS, ...addedAdmins]) : ADMINS;
const isAdmin = u => !!(u && adminSet().has(u.email));
const isMainAdmin = u => !!(u && ADMINS.has(u.email));
// New accounts wait for an admin: 'pending' until approved, or 'rejected'. Admin accounts are always approved.
const statusOf = acc => adminSet().has(acc.email) ? 'approved' : (acc.status || 'pending');
// Optional phone notification for new sign-ups (SIGNUP_ALERT_URL). No personal details are sent.
async function signupAlert() {
  const to = process.env.SIGNUP_ALERT_URL;
  if (!to || typeof fetch !== 'function') return;
  const ctl = new AbortController(), t = setTimeout(() => ctl.abort(), 3000);
  try { await fetch(to, { method: 'POST', body: 'A new BactiFIND account is waiting for your approval. Open the app: Options > Account.', headers: { Title: 'BactiFIND: new account', Tags: 'bust_in_silhouette' }, signal: ctl.signal }); }
  catch (e) { console.error('Sign-up alert failed:', e.message); } finally { clearTimeout(t); }
}
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
// The caller's address: the LAST x-forwarded-for entry is the one added by the host's own proxy (Render, Neon).
// Earlier entries come from the caller and can be made up, which would get around the attempt limits.
const ipOf = req => { const xs = String(req.headers['x-forwarded-for'] || '').split(',').map(s => s.trim()).filter(Boolean); return xs.length ? xs[xs.length - 1] : String(req.socket.remoteAddress || ''); };
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
  // Cloud space: a backup piece counts against its account, a lab record against the member who added it (data.by)
  const spaceOwner = (s, data) => s[0] === 'users' && s.length === 4 && s[2] === 'backup' ? s[1] : s[0] === 'labs' && s.length === 4 && STREAMS.includes(s[2]) ? String((data && data.by) || '') : null;
  const storageOf = async (db, acc) => { const u = await db.usage(acc.uid); return { used: u.backup + u.lab, backup: u.backup, lab: u.lab, limit: adminSet().has(acc.email) ? null : STORAGE_LIMIT }; };
  const withStorage = async acc => Object.assign(pub(acc), { storage: await storageOf(store, acc) });
  // writes = [{ s, data, old }] about to be stored (checked before anything is written). Only a net growth is
  // checked, so making data smaller or deleting it always works, even when an account is over the limit.
  async function checkSpace(db, writes) {
    const grow = new Map();
    writes.forEach(w => { const o = spaceOwner(w.s, w.data); if (o) grow.set(o, (grow.get(o) || 0) + docSize(w.data) - docSize(w.old)); });
    for (const [uid, add] of grow) {
      if (add <= 0 || (uid === user.uid && isAdmin(user))) continue; // admins have no limit
      const acc = await db.accountById(uid); if (!acc || adminSet().has(acc.email)) continue;
      const u = await db.usage(uid), after = u.backup + u.lab + add;
      if (after > STORAGE_LIMIT) throw new HttpError(413, 'storage-full', `Cloud space is full: ${(after / 1048576).toFixed(2)} MB of ${(STORAGE_LIMIT / 1048576).toFixed(2)} MB would be used`);
    }
  }
  // Premium changes are recorded in the admin activity log
  const logPremium = (s, data) => s[0] === 'entitlements' && s.length === 2 && store.audit({ at: Date.now(), by: user.email, action: data.premium ? 'premium-given' : 'premium-removed', uid: s[1], email: data.email || '', until: data.until || null });

  if (route === 'GET /' || route === 'GET /api/health') return send(res, 200, { ok: true, service: 'bactifind-api', store: store.kind, dbHost: DB_HOST });
  await refreshAdmins();

  if (route === 'POST /api/auth/signup' || route === 'POST /api/auth/signin') {
    const b = await readBody(req);
    const email = String(b.email || '').trim().toLowerCase(), pw = String(b.password || '');
    await limit(`auth:${ipOf(req)}`, 30, 15 * 60e3);
    if (!EMAIL.test(email)) throw new HttpError(400, 'auth/invalid-email', 'Enter a valid email address');
    if (route.endsWith('signup')) {
      if (pw.length < 8 || pw.length > 200) throw new HttpError(400, 'auth/weak-password', 'Use a password of at least 8 characters');
      const info = readInfo(b.info);
      const acc = { uid: newId(20), email, pass: await hashPassword(pw), created_at: Date.now(), status: adminSet().has(email) ? 'approved' : 'pending', info };
      if (!(await store.createAccount(acc))) throw new HttpError(409, 'auth/email-already-in-use', 'An account with this email already exists');
      if (acc.status === 'pending') await signupAlert();
      return send(res, 200, { token: signToken(acc, await startSession(acc, req)), user: await withStorage(acc) });
    }
    await limit(`signin:${email}`, 10, 15 * 60e3);
    const acc = await store.accountByEmail(email);
    if (!acc || !(await checkPassword(pw, acc.pass))) throw new HttpError(401, 'auth/invalid-credential', 'Wrong email or password');
    return send(res, 200, { token: signToken(acc, await startSession(acc, req)), user: await withStorage(acc) });
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
    return send(res, 200, { user: await withStorage(acc), admin: isAdmin(user), mainAdmin: isMainAdmin(user) });
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
    if (s[0] === 'admins') return send(res, 200, { data: s[1] === user.uid && isAdmin(user) ? { role: 'admin', main: isMainAdmin(user) } : null }); // admins come from ADMIN_EMAILS and config/admins
    if (!(await canRead(store, s, user))) throw deny();
    return send(res, 200, { data: await store.get(b.path) });
  }
  if (route === 'POST /api/doc/set') {
    await needApproved(); const b = await readBody(req), s = parsePath(b.path, true); if (!s || !isObj(b.data)) throw new HttpError(400, 'bad-request', 'Bad path or data');
    await store.tx(async db => {
      const old = await db.get(b.path), data = b.merge && old ? Object.assign({}, old, b.data) : b.data;
      if (!(await canWrite(db, s, user, data, old))) throw deny();
      await checkSpace(db, [{ s, data, old }]);
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
      // Check every item (access, then cloud space) before writing any of them
      const writes = [];
      for (const it of b.items) {
        const [path, data] = Array.isArray(it) ? it : [];
        const s = parsePath(path, true); if (!s || !isObj(data)) throw new HttpError(400, 'bad-request', 'Bad item');
        const old = await db.get(path);
        if (!(await canWrite(db, s, user, data, old))) throw deny();
        writes.push({ path, s, data, old });
      }
      await checkSpace(db, writes);
      for (const w of writes) { await db.put(w.path, w.data); await logPremium(w.s, w.data); }
    });
    return send(res, 200, { ok: true });
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
    const rows = (await store.accountsWithStatus(['pending', 'rejected'])).filter(a => !adminSet().has(a.email));
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

  // Every account, newest first, with sign-up details, Premium and the last sign-in
  if (route === 'GET /api/admin/accounts') {
    need(); if (!isAdmin(user)) throw deny();
    const admins = adminSet();
    const rows = (await store.allAccounts(2000)).map(a => ({
      uid: a.uid, email: a.email, created_at: a.created_at, status: statusOf(a), info: a.info || null, last_seen: a.last_seen || null,
      premium: a.ent ? { premium: !!a.ent.premium, until: a.ent.until || null } : null,
      admin: admins.has(a.email) ? (ADMINS.has(a.email) ? 'main' : 'added') : null }));
    return send(res, 200, { rows });
  }
  // Change an account's email and/or sign-up details. A new email signs the account out everywhere.
  if (route === 'POST /api/admin/account/update') {
    need(); if (!isAdmin(user)) throw deny();
    const b = await readBody(req), acc = await store.accountById(String(b.uid || ''));
    if (!acc) throw new HttpError(404, 'not-found', 'No such account');
    if (ADMINS.has(acc.email) && acc.uid !== user.uid) throw new HttpError(403, 'permission-denied', 'A main admin account can only be changed by its owner');
    const ch = {};
    if (b.info != null) ch.info = readInfo(b.info);
    if (b.email != null) {
      const email = String(b.email).trim().toLowerCase();
      if (!EMAIL.test(email)) throw new HttpError(400, 'auth/invalid-email', 'Enter a valid email address');
      if (email !== acc.email) {
        if (ADMINS.has(acc.email)) throw new HttpError(400, 'bad-request', 'Change a main admin email in the server settings (ADMIN_EMAILS)');
        ch.email = email;
      }
    }
    if (!ch.info && !ch.email) return send(res, 200, { ok: true });
    if (!(await store.updateAccount(acc.uid, ch))) throw new HttpError(409, 'auth/email-already-in-use', 'Another account already uses this email');
    if (ch.email) {
      await store.deleteSessionsOf(acc.uid, null); // tokens carry the email, so the user signs in again with the new one
      const ent = await store.get(`entitlements/${acc.uid}`); if (ent) await store.put(`entitlements/${acc.uid}`, Object.assign(ent, { email: ch.email }));
      for (const m of await store.memberDocs(acc.uid)) await store.put(m.path, Object.assign(m.data, { email: ch.email }));
      if (addedAdmins.has(acc.email)) await saveAdded([...addedAdmins].map(e => e === acc.email ? ch.email : e));
    }
    await store.audit({ at: Date.now(), by: user.email, action: 'account-edited', uid: acc.uid, email: ch.email || acc.email, from: ch.email ? acc.email : undefined });
    return send(res, 200, { ok: true });
  }
  // Delete an account with its backup, Premium and lab memberships. Its records in shared labs stay with the lab.
  // A lab it owned passes to another member, or is deleted when it has no other members.
  if (route === 'POST /api/admin/account/delete') {
    need(); if (!isAdmin(user)) throw deny();
    const b = await readBody(req), acc = await store.accountById(String(b.uid || ''));
    if (!acc) throw new HttpError(404, 'not-found', 'No such account');
    if (acc.uid === user.uid) throw new HttpError(400, 'bad-request', 'You cannot delete your own account here');
    if (ADMINS.has(acc.email)) throw new HttpError(403, 'permission-denied', 'Main admin accounts cannot be deleted');
    if (addedAdmins.has(acc.email) && !isMainAdmin(user)) throw new HttpError(403, 'permission-denied', 'Only a main admin can delete an admin account');
    await store.tx(async db => {
      for (const m of await db.memberDocs(acc.uid)) {
        const labId = m.path.split('/')[1], lab = await db.get(`labs/${labId}`);
        await db.del(m.path);
        if (!lab || lab.owner !== acc.uid) continue;
        const others = await db.docsUnder(`labs/${labId}/members/`);
        if (others.length) { // oldest remaining member becomes the owner
          const heir = others.sort((x, y) => (+x.data.at || 0) - (+y.data.at || 0))[0];
          await db.put(`labs/${labId}`, Object.assign(lab, { owner: heir.path.split('/')[3] }));
          await db.put(heir.path, Object.assign(heir.data, { role: 'owner' }));
        } else { // nobody left: remove the lab, its data and its join code
          for (const d of await db.docsUnder(`labs/${labId}/`)) await db.del(d.path);
          await db.del(`labs/${labId}`);
          if (lab.code) await db.del(`joinCodes/${lab.code}`);
        }
      }
      for (const d of await db.docsUnder(`users/${acc.uid}/`)) await db.del(d.path);
      await db.del(`users/${acc.uid}`);
      await db.del(`entitlements/${acc.uid}`);
      await db.deleteAccount(acc.uid);
      await db.audit({ at: Date.now(), by: user.email, action: 'account-deleted', uid: acc.uid, email: acc.email });
    });
    if (addedAdmins.has(acc.email)) await saveAdded([...addedAdmins].filter(e => e !== acc.email));
    return send(res, 200, { ok: true });
  }
  // What is stored for an account: backup items (with counts), devices and labs. ?export=1 also returns the
  // full backup and the data of its labs, for download; exports are recorded in the activity log.
  if (route === 'GET /api/admin/user-data') {
    need(); if (!isAdmin(user)) throw deny();
    const acc = await store.accountById(String(url.searchParams.get('uid') || ''));
    if (!acc) throw new HttpError(404, 'not-found', 'No such account');
    const full = url.searchParams.get('export') === '1';
    const meta = await store.get(`users/${acc.uid}/meta/backup`), parts = await store.docsUnder(`users/${acc.uid}/backup/`);
    const byPath = new Map(parts.map(p => [p.path, p.data])), backup = {}, items = [];
    Object.entries((meta && meta.keys) || {}).forEach(([k, info]) => {
      let v = '';
      for (let i = 0; i < (info.parts || 1); i++) { const d = byPath.get(`users/${acc.uid}/backup/${encodeURIComponent(k)}~${i}`); v += (d && d.v) || ''; }
      let count = null; try { const j = JSON.parse(v); if (Array.isArray(j)) count = j.length; else if (j && typeof j === 'object') count = Object.keys(j).length; } catch (_) {}
      items.push({ key: k, size: v.length, count });
      if (full) backup[k] = v;
    });
    const labs = [];
    for (const m of await store.memberDocs(acc.uid)) {
      const id = m.path.split('/')[1], lab = await store.get(`labs/${id}`);
      if (!lab) continue;
      const row = { id, name: lab.name, role: lab.owner === acc.uid ? 'owner' : 'member', code: lab.code || null,
        members: await store.countChildren(`labs/${id}/members`), isolates: await store.countChildren(`labs/${id}/isolates`), qclog: await store.countChildren(`labs/${id}/qclog`) };
      if (full) {
        const all = await store.docsUnder(`labs/${id}/`), pick = sub => all.filter(d => d.path.split('/')[2] === sub).map(d => Object.assign({ id: d.path.split('/')[3] }, d.data));
        Object.assign(row, { memberList: pick('members'), isolateList: pick('isolates'), qclogList: pick('qclog') });
      }
      labs.push(row);
    }
    const out = {
      account: { uid: acc.uid, email: acc.email, status: statusOf(acc), created_at: +acc.created_at, info: acc.info || null },
      premium: await store.get(`entitlements/${acc.uid}`),
      devices: (await store.sessionsOf(acc.uid)).map(s => ({ label: s.label, created_at: s.created_at })),
      backup: { at: (meta && meta.at) || null, items }, labs, storage: await storageOf(store, acc) };
    if (full) { out.backupData = backup; await store.audit({ at: Date.now(), by: user.email, action: 'data-exported', uid: acc.uid, email: acc.email }); }
    return send(res, 200, out);
  }
  // Admins: list (any admin); add or remove (main admins only). Main admins are set in ADMIN_EMAILS.
  if (route === 'GET /api/admin/admins') {
    need(); if (!isAdmin(user)) throw deny();
    await refreshAdmins(true);
    return send(res, 200, { main: [...ADMINS], added: [...addedAdmins].filter(e => !ADMINS.has(e)), canManage: isMainAdmin(user) });
  }
  if (route === 'POST /api/admin/admins') {
    need(); if (!isMainAdmin(user)) throw new HttpError(403, 'permission-denied', 'Only a main admin can add or remove admins');
    const b = await readBody(req), email = String(b.email || '').trim().toLowerCase(), add = b.add !== false;
    if (!EMAIL.test(email)) throw new HttpError(400, 'auth/invalid-email', 'Enter a valid email address');
    if (ADMINS.has(email)) throw new HttpError(400, 'bad-request', 'This is a main admin (set in the server settings)');
    await refreshAdmins(true);
    const list = new Set(addedAdmins);
    if (add) list.add(email); else list.delete(email);
    await saveAdded([...list]);
    const acc = await store.accountByEmail(email);
    if (acc && add) await store.setStatus(acc.uid, 'approved');
    if (acc && !add) await store.deleteSessionsOf(acc.uid, null); // the admin screens close on their devices at once
    await store.audit({ at: Date.now(), by: user.email, action: add ? 'admin-added' : 'admin-removed', uid: acc ? acc.uid : null, email });
    return send(res, 200, { ok: true, added: [...addedAdmins] });
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
