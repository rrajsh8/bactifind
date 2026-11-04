'use strict';
// Server tests in memory mode (no database needed): npm test
process.env.ADMIN_EMAILS = 'admin@lab.test';
process.env.ALLOWED_ORIGINS = 'https://site.test,https://*--site.test';
process.env.MAX_DEVICES = '2';
// TEST_DATABASE_URL = run against a throwaway PostgreSQL database (e.g. a Neon branch); otherwise in memory. Never use the live database.
if (process.env.TEST_DATABASE_URL) process.env.DATABASE_URL = process.env.TEST_DATABASE_URL; else delete process.env.DATABASE_URL;
if (process.env.DATABASE_URL && !process.env.JWT_SECRET) process.env.JWT_SECRET = require('crypto').randomBytes(32).toString('hex');
const assert = require('assert');
const { server, store } = require('./server');

let base, passed = 0;
const call = async (path, body, token, method) => {
  const r = await fetch(base + path, { method: method || (body ? 'POST' : 'GET'), headers: Object.assign({ 'Content-Type': 'application/json' }, token ? { Authorization: 'Bearer ' + token } : {}), body: body ? JSON.stringify(body) : undefined });
  return { status: r.status, body: await r.json() };
};
const ok = async (p, b, t) => { const r = await call(p, b, t); assert.strictEqual(r.status, 200, `${p} → ${r.status} ${JSON.stringify(r.body)}`); return r.body; };
const no = async (p, b, t, status) => { const r = await call(p, b, t); assert.strictEqual(r.status, status || 403, `${p} should fail with ${status || 403}, got ${r.status} ${JSON.stringify(r.body)}`); return r.body; };
const test = async (name, fn) => { await fn(); passed++; console.log('✔', name); };

(async () => {
  // TEST_BASE_URL = test a server that is already running (e.g. a Neon Function on a test branch, deployed with
  // ADMIN_EMAILS=admin@lab.test, ALLOWED_ORIGINS=https://site.test,https://*--site.test and MAX_DEVICES=2)
  if (process.env.TEST_BASE_URL) { base = process.env.TEST_BASE_URL.replace(/\/+$/, ''); console.log(`server: ${base}`); }
  else {
    await store.init();
    console.log(`store: ${store.kind}`);
    await new Promise(r => server.listen(0, r));
    base = `http://127.0.0.1:${server.address().port}`;
  }
  const get = (p, t) => ok('/api/doc/get', { path: p }, t).then(b => b.data);
  const set = (p, data, t, merge) => ok('/api/doc/set', { path: p, data, merge }, t);

  let admin, alice, bob, eve;
  await test('sign-up, sign-in and validation', async () => {
    await no('/api/auth/signup', { email: 'bad', password: 'longenough' }, null, 400);
    await no('/api/auth/signup', { email: 'a@lab.test', password: 'short' }, null, 400);
    admin = await ok('/api/auth/signup', { email: 'Admin@Lab.test', password: 'adminpass1' });
    const info = { firstName: 'Alice', lastName: 'Rao', designation: 'Assistant Professor', institute: 'GMC Nagpur', phone: '+91 98765 43210' };
    await no('/api/auth/signup', { email: 'x1@lab.test', password: 'longenough', info: Object.assign({}, info, { institute: ' ' }) }, null, 400);
    await no('/api/auth/signup', { email: 'x2@lab.test', password: 'longenough', info: Object.assign({}, info, { phone: 'call me' }) }, null, 400);
    await no('/api/auth/signup', { email: 'x3@lab.test', password: 'longenough', info: Object.assign({}, info, { premium: true }) }, null, 400);
    alice = await ok('/api/auth/signup', { email: 'alice@lab.test', password: 'alicepass1', info });
    bob = await ok('/api/auth/signup', { email: 'bob@lab.test', password: 'bobpass123' });
    eve = await ok('/api/auth/signup', { email: 'eve@lab.test', password: 'evepass123' });
    await no('/api/auth/signup', { email: 'alice@lab.test', password: 'another123' }, null, 409);
    await no('/api/auth/signin', { email: 'alice@lab.test', password: 'wrongpass' }, null, 401);
    const s = await ok('/api/auth/signin', { email: 'ALICE@lab.test', password: 'alicepass1' });
    assert.strictEqual(s.user.uid, alice.user.uid);
    const me = await ok('/api/auth/me', null, admin.token);
    assert.strictEqual(me.admin, true);
    await no('/api/auth/me', null, 'forged.token.here', 401);
    await no('/api/doc/get', { path: 'users/x' }, null, 401);
  });

  await test('new accounts wait for admin approval', async () => {
    assert.strictEqual(alice.user.status, 'pending');
    assert.strictEqual(admin.user.status, 'approved'); // admins never wait
    const blocked = await no('/api/doc/get', { path: `users/${alice.user.uid}` }, alice.token);
    assert.strictEqual(blocked.error, 'account-pending');
    await no('/api/doc/set', { path: `users/${alice.user.uid}`, data: { email: 'alice@lab.test' } }, alice.token);
    await no('/api/doc/batch', { items: [] }, alice.token);
    assert.strictEqual((await ok('/api/auth/me', null, alice.token)).user.status, 'pending');
    // only admins see and decide
    await no('/api/admin/pending', null, alice.token);
    await no('/api/admin/approve', { uid: alice.user.uid }, alice.token);
    const list = await ok('/api/admin/pending', null, admin.token);
    const mine = rows => rows.filter(r => r.email.endsWith('@lab.test')); // a test database copy may hold other accounts
    assert.deepStrictEqual(mine(list.rows).map(r => r.email).sort(), ['alice@lab.test', 'bob@lab.test', 'eve@lab.test']);
    assert.deepStrictEqual(list.rows.find(r => r.email === 'alice@lab.test').info, { firstName: 'Alice', lastName: 'Rao', designation: 'Assistant Professor', institute: 'GMC Nagpur', phone: '+91 98765 43210' });
    assert.strictEqual(list.rows.find(r => r.email === 'bob@lab.test').info, null); // older app versions send no details
    await no('/api/admin/approve', { uid: alice.user.uid, months: -1 }, admin.token, 400);
    await ok('/api/admin/approve', { uid: alice.user.uid, months: 12 }, admin.token);
    await ok('/api/admin/approve', { uid: bob.user.uid, months: null }, admin.token);
    await ok('/api/admin/approve', { uid: eve.user.uid, approve: false }, admin.token);
    assert.strictEqual((await ok('/api/auth/me', null, alice.token)).user.status, 'approved');
    const ent = await get(`entitlements/${alice.user.uid}`, alice.token);
    assert.ok(ent.premium && ent.until > Date.now() + 300 * 864e5);
    assert.strictEqual((await get(`entitlements/${bob.user.uid}`, bob.token)).until, null);
    assert.strictEqual((await no('/api/doc/get', { path: `users/${eve.user.uid}` }, eve.token)).error, 'account-rejected');
    assert.deepStrictEqual(mine((await ok('/api/admin/pending', null, admin.token)).rows).map(r => [r.email, r.status]), [['eve@lab.test', 'rejected']]);
    const log = await ok('/api/admin/audit', null, admin.token);
    assert.ok(log.rows.some(r => r.action === 'account-approved' && r.email === 'alice@lab.test'));
    assert.ok(log.rows.some(r => r.action === 'account-rejected' && r.email === 'eve@lab.test'));
    // a rejected account can still be approved later
    await ok('/api/admin/approve', { uid: eve.user.uid, months: 1 }, admin.token);
    await ok('/api/doc/get', { path: `users/${eve.user.uid}` }, eve.token);
  });

  await test('profiles: own only; email must match the account', async () => {
    await set(`users/${alice.user.uid}`, { email: 'alice@lab.test', createdAt: 1 }, alice.token);
    await no('/api/doc/set', { path: `users/${alice.user.uid}`, data: { email: 'other@lab.test' } }, alice.token);
    await no('/api/doc/set', { path: `users/${alice.user.uid}`, data: { email: 'alice@lab.test', premium: true } }, alice.token);
    await no('/api/doc/set', { path: `users/${bob.user.uid}`, data: { email: 'bob@lab.test' } }, alice.token);
    await no('/api/doc/get', { path: `users/${alice.user.uid}` }, bob.token);
    assert.ok(await get(`users/${alice.user.uid}`, admin.token)); // admin can read profiles
  });

  await test('admins come from ADMIN_EMAILS only', async () => {
    assert.deepStrictEqual(await get(`admins/${admin.user.uid}`, admin.token), { role: 'admin' });
    assert.strictEqual(await get(`admins/${alice.user.uid}`, alice.token), null);
    await no('/api/doc/set', { path: `admins/${alice.user.uid}`, data: { role: 'admin' } }, alice.token);
  });

  await test('Premium: only admins can give it; users read their own', async () => {
    await no('/api/doc/set', { path: `entitlements/${alice.user.uid}`, data: { premium: true } }, alice.token);
    await set(`entitlements/${alice.user.uid}`, { premium: true, until: null }, admin.token);
    assert.strictEqual((await get(`entitlements/${alice.user.uid}`, alice.token)).premium, true);
    await no('/api/doc/get', { path: `entitlements/${alice.user.uid}` }, bob.token);
    const found = await ok('/api/doc/list', { coll: 'users', where: ['email', '==', 'ALICE@lab.test'], max: 5 }, admin.token);
    assert.strictEqual(found.rows.length, 1);
    await no('/api/doc/list', { coll: 'users', where: ['email', '==', 'alice@lab.test'] }, bob.token);
  });

  await test('cloud backup is private to the account', async () => {
    await set(`users/${alice.user.uid}/backup/k~0`, { v: 'data' }, alice.token);
    await ok('/api/doc/batch', { items: [[`users/${alice.user.uid}/backup/k~1`, { v: 'more' }], [`users/${alice.user.uid}/meta/backup`, { at: 1, keys: {} }]] }, alice.token);
    assert.strictEqual((await get(`users/${alice.user.uid}/backup/k~1`, alice.token)).v, 'more');
    await no('/api/doc/get', { path: `users/${alice.user.uid}/backup/k~0` }, bob.token);
    await no('/api/doc/batch', { items: [[`users/${alice.user.uid}/backup/k~0`, { v: 'x' }]] }, bob.token);
  });

  const lab = 'lab' + Date.now();
  await test('labs: create, join with a valid code only', async () => {
    await no('/api/doc/set', { path: `labs/${lab}`, data: { name: 'L', owner: bob.user.uid } }, alice.token); // cannot create a lab for someone else
    await set(`labs/${lab}`, { name: 'Micro Lab', owner: alice.user.uid }, alice.token);
    await set(`labs/${lab}/members/${alice.user.uid}`, { role: 'owner' }, alice.token);
    await no('/api/doc/set', { path: 'joinCodes/ABC123', data: { labId: lab } }, bob.token); // only the owner makes codes
    await set('joinCodes/ABC123', { labId: lab }, alice.token);
    await no('/api/doc/set', { path: 'joinCodes/ABC123', data: { labId: 'other' } }, alice.token); // codes cannot be changed
    await set(`labs/${lab}`, { name: 'Micro Lab', owner: alice.user.uid, code: 'ABC123' }, alice.token);
    await no('/api/doc/set', { path: `labs/${lab}`, data: { name: 'Taken', owner: bob.user.uid } }, alice.token); // owner cannot change
    await no('/api/doc/get', { path: `labs/${lab}` }, bob.token); // not a member yet
    await no('/api/doc/set', { path: `labs/${lab}/members/${bob.user.uid}`, data: { role: 'member', code: 'WRONG1' } }, bob.token);
    await no('/api/doc/set', { path: `labs/${lab}/members/${bob.user.uid}`, data: { role: 'owner', code: 'ABC123' } }, bob.token);
    await no('/api/doc/set', { path: `labs/${lab}/members/${eve.user.uid}`, data: { role: 'member', code: 'ABC123' } }, bob.token); // cannot add others
    await set(`labs/${lab}/members/${bob.user.uid}`, { role: 'member', code: 'ABC123' }, bob.token);
    assert.strictEqual((await get(`labs/${lab}`, bob.token)).name, 'Micro Lab');
    const members = await ok('/api/doc/list', { coll: `labs/${lab}/members` }, bob.token);
    assert.strictEqual(members.rows.length, 2);
  });

  await test('lab data: members only; authors (or owner) change their own records', async () => {
    await set(`labs/${lab}/isolates/i1`, { patientId: 'P1', by: alice.user.uid, updatedAt: 100 }, alice.token);
    await no('/api/doc/set', { path: `labs/${lab}/isolates/i2`, data: { patientId: 'P2', by: alice.user.uid, updatedAt: 1 } }, bob.token); // cannot write as someone else
    await set(`labs/${lab}/isolates/i2`, { patientId: 'P2', by: bob.user.uid, updatedAt: 200 }, bob.token);
    await no('/api/doc/set', { path: `labs/${lab}/isolates/i1`, data: { patientId: 'X', by: alice.user.uid, updatedAt: 300 } }, bob.token); // bob cannot edit alice's record
    await set(`labs/${lab}/isolates/i2`, { patientId: 'P2b', by: bob.user.uid, updatedAt: 250 }, alice.token); // owner can
    await no('/api/doc/set', { path: `labs/${lab}/isolates/i2`, data: { patientId: 'P2c', by: alice.user.uid, updatedAt: 260 } }, alice.token); // author cannot be changed
    await no('/api/doc/set', { path: `labs/${lab}/notes/n1`, data: { by: alice.user.uid } }, alice.token); // only isolates and qclog
    await no('/api/doc/get', { path: `labs/${lab}/isolates/i1` }, eve.token);
    await no('/api/doc/list', { coll: `labs/${lab}/isolates` }, eve.token);
    const since = await ok('/api/doc/list', { coll: `labs/${lab}/isolates`, where: ['updatedAt', '>', 150], order: 'updatedAt' }, bob.token);
    assert.deepStrictEqual(since.rows.map(r => r.id), ['i2']);
    await no('/api/doc/list', { coll: `labs/${lab}/isolates`, where: ['patientId', '==', 'P1'] }, bob.token, 400); // unsupported query
  });

  await test('leaving and removing members', async () => {
    await no('/api/doc/delete', { path: `labs/${lab}/members/${alice.user.uid}` }, bob.token); // bob cannot remove the owner
    await ok('/api/doc/delete', { path: `labs/${lab}/members/${bob.user.uid}` }, alice.token); // owner removes bob
    await no('/api/doc/get', { path: `labs/${lab}/isolates/i1` }, bob.token);
  });

  await test('password change and admin temporary password', async () => {
    await no('/api/auth/password', { old: 'nope', password: 'newpass123' }, bob.token, 401);
    await ok('/api/auth/password', { old: 'bobpass123', password: 'newpass123' }, bob.token);
    await ok('/api/auth/signin', { email: 'bob@lab.test', password: 'newpass123' });
    await no('/api/admin/temp-password', { uid: bob.user.uid }, alice.token);
    const t = await ok('/api/admin/temp-password', { uid: bob.user.uid }, admin.token);
    await ok('/api/auth/signin', { email: 'bob@lab.test', password: t.password });
  });

  await test('usage statistics: anonymous counts, admin-only report', async () => {
    await ok('/api/track', { name: 'open_module', params: { module: 'qc-modal' } });
    await ok('/api/track', { name: 'open_module', params: { module: 'qc-modal' } });
    await no('/api/track', { name: 'open_module', params: { module: '<script>' } }, null, 400);
    await no('/api/admin/stats', null, alice.token);
    const s = await call('/api/admin/stats?days=30', null, admin.token);
    assert.strictEqual(s.status, 200);
    assert.deepStrictEqual(s.body.rows.find(r => r.module === 'qc-modal').n, 2);
  });

  await test('device limit: a third sign-in ends the oldest session', async () => {
    const c1 = await ok('/api/auth/signup', { email: 'carol@lab.test', password: 'carolpass1' });
    const c2 = await ok('/api/auth/signin', { email: 'carol@lab.test', password: 'carolpass1' });
    await ok('/api/auth/me', null, c1.token);
    const c3 = await ok('/api/auth/signin', { email: 'carol@lab.test', password: 'carolpass1' });
    const gone = await no('/api/auth/me', null, c1.token, 401);
    assert.strictEqual(gone.error, 'session-ended');
    await ok('/api/auth/me', null, c2.token); await ok('/api/auth/me', null, c3.token);
    const list = await ok('/api/auth/sessions', null, c3.token);
    assert.strictEqual(list.sessions.length, 2); assert.strictEqual(list.max, 2);
    assert.strictEqual(list.sessions.filter(s => s.current).length, 1);
    // sign out others, then sign out this device
    await ok('/api/auth/signout-others', {}, c3.token);
    await no('/api/auth/me', null, c2.token, 401);
    await ok('/api/auth/signout', {}, c3.token);
    await no('/api/auth/me', null, c3.token, 401);
    // admins are not limited
    const a2 = await ok('/api/auth/signin', { email: 'admin@lab.test', password: 'adminpass1' });
    await ok('/api/auth/signin', { email: 'admin@lab.test', password: 'adminpass1' });
    await ok('/api/auth/signin', { email: 'admin@lab.test', password: 'adminpass1' });
    await ok('/api/auth/me', null, admin.token); await ok('/api/auth/me', null, a2.token);
  });

  await test('password change signs out other devices', async () => {
    const d1 = await ok('/api/auth/signup', { email: 'dan@lab.test', password: 'danpass123' });
    const d2 = await ok('/api/auth/signin', { email: 'dan@lab.test', password: 'danpass123' });
    await ok('/api/auth/password', { old: 'danpass123', password: 'dannewpass1' }, d2.token);
    await no('/api/auth/me', null, d1.token, 401);
    await ok('/api/auth/me', null, d2.token);
  });

  await test('admin activity log records Premium changes', async () => {
    const log = await ok('/api/admin/audit', null, admin.token);
    const given = log.rows.find(r => r.action === 'premium-given' && r.uid === alice.user.uid);
    assert.ok(given, 'premium-given entry for alice');
    assert.strictEqual(given.by, 'admin@lab.test');
    assert.ok(log.rows.some(r => r.action === 'temp-password'));
    await no('/api/admin/audit', null, eve.token);
  });

  await test('allowed origins, including Netlify preview wildcards', async () => {
    const cors = async o => (await fetch(base + '/api/health', { headers: { Origin: o } })).headers.get('access-control-allow-origin');
    assert.strictEqual(await cors('https://site.test'), 'https://site.test');
    assert.strictEqual(await cors('https://6aea8d0a--site.test'), 'https://6aea8d0a--site.test');
    assert.notStrictEqual(await cors('https://evil.test'), 'https://evil.test');
    assert.notStrictEqual(await cors('https://x.evil--site.test.evil'), 'https://x.evil--site.test.evil');
  });

  await test('bad paths are rejected', async () => {
    await no('/api/doc/get', { path: '../etc/passwd' }, alice.token, 400);
    await no('/api/doc/get', { path: 'users' }, alice.token, 400);
    await no('/api/doc/list', { coll: 'labs' }, alice.token);
  });

  console.log(`\nAll ${passed} test groups passed.`);
  server.close();
  process.exit(0); // the database pool would otherwise keep the process open
})().catch(e => { console.error('✖', e.message); process.exit(1); });
