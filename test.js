'use strict';
// Server tests in memory mode (no database needed): npm test
process.env.ADMIN_EMAILS = 'admin@lab.test';
process.env.ALLOWED_ORIGINS = 'https://site.test,https://*--site.test';
process.env.MAX_DEVICES = '2';
process.env.STORAGE_LIMIT_MB = '0.05'; // about 52 KB per account, so the cloud-space test stays small
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
    assert.deepStrictEqual(await get(`admins/${admin.user.uid}`, admin.token), { role: 'admin', main: true });
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

  await test('usage statistics are gone: nothing is collected or reported', async () => {
    await no('/api/track', { name: 'open_module', params: { module: 'qc-modal' } }, null, 404);
    await no('/api/admin/stats?days=30', null, admin.token, 404);
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

  await test('admin: list every account, edit details, view data, delete', async () => {
    const info = { firstName: 'Frank', lastName: 'Das', designation: 'Tutor', institute: 'AIIMS', phone: '9876543210' };
    let frank = await ok('/api/auth/signup', { email: 'frank@lab.test', password: 'frankpass1', info });
    const gina = await ok('/api/auth/signup', { email: 'gina@lab.test', password: 'ginapass12' });
    await ok('/api/admin/approve', { uid: frank.user.uid, months: 12 }, admin.token);
    await ok('/api/admin/approve', { uid: gina.user.uid, months: 12 }, admin.token);
    // list
    await no('/api/admin/accounts', null, alice.token);
    const all = (await ok('/api/admin/accounts', null, admin.token)).rows;
    const f = all.find(r => r.email === 'frank@lab.test');
    assert.strictEqual(f.status, 'approved'); assert.strictEqual(f.info.institute, 'AIIMS'); assert.strictEqual(f.premium.premium, true); assert.ok(f.last_seen > 0);
    assert.strictEqual(all.find(r => r.email === 'admin@lab.test').admin, 'main');
    // edit details and email
    await no('/api/admin/account/update', { uid: frank.user.uid, info: Object.assign({}, info, { designation: 'X' }) }, alice.token);
    await no('/api/admin/account/update', { uid: frank.user.uid, info: Object.assign({}, info, { phone: 'nope' }) }, admin.token, 400);
    await ok('/api/admin/account/update', { uid: frank.user.uid, info: Object.assign({}, info, { designation: 'Assistant Professor' }) }, admin.token);
    await no('/api/admin/account/update', { uid: frank.user.uid, email: 'gina@lab.test' }, admin.token, 409);
    await no('/api/admin/account/update', { uid: admin.user.uid, email: 'boss@lab.test' }, admin.token, 400); // main admin email lives in ADMIN_EMAILS
    await ok('/api/admin/account/update', { uid: frank.user.uid, email: 'Frank2@lab.test' }, admin.token);
    await no('/api/auth/me', null, frank.token, 401); // signed out: sign in with the new email
    frank = await ok('/api/auth/signin', { email: 'frank2@lab.test', password: 'frankpass1' });
    const f2 = (await ok('/api/admin/accounts', null, admin.token)).rows.find(r => r.uid === frank.user.uid);
    assert.strictEqual(f2.email, 'frank2@lab.test'); assert.strictEqual(f2.info.designation, 'Assistant Professor');
    // data: a backup and a lab that frank owns and gina joined
    const fu = frank.user.uid, flab = 'flab' + Date.now();
    await set(`users/${fu}/backup/bactifind-whonet-batch~0`, { v: '[{"id":1},' }, frank.token);
    await set(`users/${fu}/backup/bactifind-whonet-batch~1`, { v: '{"id":2},{"id":3}]' }, frank.token);
    await set(`users/${fu}/meta/backup`, { at: 5, keys: { 'bactifind-whonet-batch': { parts: 2, hash: 'h' } } }, frank.token);
    await set(`labs/${flab}`, { name: 'Frank Lab', owner: fu, code: 'FRK123' }, frank.token);
    await set(`labs/${flab}/members/${fu}`, { role: 'owner', at: 1 }, frank.token);
    await set('joinCodes/FRK123', { labId: flab }, frank.token);
    await set(`labs/${flab}/members/${gina.user.uid}`, { role: 'member', code: 'FRK123', at: 2 }, gina.token);
    await set(`labs/${flab}/isolates/g1`, { patientId: 'G1', by: gina.user.uid, updatedAt: 10 }, gina.token);
    await no(`/api/admin/user-data?uid=${fu}`, null, alice.token);
    const d = await ok(`/api/admin/user-data?uid=${fu}`, null, admin.token);
    assert.deepStrictEqual(d.backup.items, [{ key: 'bactifind-whonet-batch', size: 28, count: 3 }]);
    assert.strictEqual(d.backupData, undefined); // the summary has no contents
    assert.deepStrictEqual([d.labs[0].role, d.labs[0].members, d.labs[0].isolates], ['owner', 2, 1]);
    const x = await ok(`/api/admin/user-data?uid=${fu}&export=1`, null, admin.token);
    assert.strictEqual(x.backupData['bactifind-whonet-batch'], '[{"id":1},{"id":2},{"id":3}]');
    assert.strictEqual(x.labs[0].isolateList[0].patientId, 'G1');
    assert.ok((await ok('/api/admin/audit', null, admin.token)).rows.some(r => r.action === 'data-exported' && r.uid === fu));
    // delete
    await no('/api/admin/account/delete', { uid: fu }, alice.token);
    await no('/api/admin/account/delete', { uid: admin.user.uid }, admin.token, 400); // not yourself
    await ok('/api/admin/account/delete', { uid: fu }, admin.token);
    await no('/api/auth/me', null, frank.token, 401);
    await no('/api/auth/signin', { email: 'frank2@lab.test', password: 'frankpass1' }, null, 401);
    await no(`/api/admin/user-data?uid=${fu}`, null, admin.token, 404);
    assert.strictEqual((await get(`labs/${flab}`, gina.token)).owner, gina.user.uid); // the lab passes to the remaining member
    assert.strictEqual((await get(`labs/${flab}/members/${gina.user.uid}`, gina.token)).role, 'owner');
    assert.strictEqual((await get(`labs/${flab}/isolates/g1`, gina.token)).patientId, 'G1'); // shared records stay
    if (!process.env.TEST_BASE_URL) { assert.strictEqual(await store.get(`users/${fu}/meta/backup`), null); assert.strictEqual(await store.get(`entitlements/${fu}`), null); }
    assert.ok((await ok('/api/admin/audit', null, admin.token)).rows.some(r => r.action === 'account-deleted' && r.uid === fu));
  });

  await test('cloud space per account: backup plus own lab records, admins unlimited', async () => {
    const lim = 0.05 * 1048576, u = alice.user.uid, big = n => ({ v: 'x'.repeat(n) });
    const me = (await ok('/api/auth/me', null, alice.token)).user.storage;
    assert.strictEqual(me.limit, Math.round(lim));
    await set(`users/${u}/backup/q~0`, big(30000), alice.token);
    const full = await no('/api/doc/batch', { items: [[`users/${u}/backup/q~1`, big(15000)], [`users/${u}/backup/q~2`, big(15000)]] }, alice.token, 413);
    assert.strictEqual(full.error, 'storage-full');
    assert.strictEqual(await get(`users/${u}/backup/q~1`, alice.token), null); // nothing of a refused batch is written
    await set(`users/${u}/backup/q~0`, big(45000), alice.token); // replacing a piece counts only the difference
    await no('/api/doc/set', { path: `labs/${lab}/isolates/big1`, data: { by: u, updatedAt: 999, pad: 'y'.repeat(9000) } }, alice.token, 413); // lab records count too
    await set(`users/${u}/backup/q~0`, big(10), alice.token); // shrinking always works
    await set(`labs/${lab}/isolates/big1`, { by: u, updatedAt: 999, pad: 'y'.repeat(9000) }, alice.token);
    const after = (await ok('/api/auth/me', null, alice.token)).user.storage;
    assert.ok(after.lab >= 9000 && after.backup < 100, JSON.stringify(after));
    await ok('/api/doc/delete', { path: `labs/${lab}/isolates/big1` }, alice.token);
    await ok('/api/doc/delete', { path: `users/${u}/backup/q~0` }, alice.token);
    // admins are not limited
    await set(`users/${admin.user.uid}/backup/a~0`, big(80000), admin.token);
    assert.strictEqual((await ok('/api/auth/me', null, admin.token)).user.storage.limit, null);
    await ok('/api/doc/delete', { path: `users/${admin.user.uid}/backup/a~0` }, admin.token);
  });

  await test('admins: main admins add and remove other admins', async () => {
    const harry = await ok('/api/auth/signup', { email: 'harry@lab.test', password: 'harrypass1' });
    assert.strictEqual(harry.user.status, 'pending');
    await no('/api/admin/admins', { email: 'harry@lab.test' }, alice.token);
    await ok('/api/admin/admins', { email: 'Harry@lab.test' }, admin.token);
    const me = await ok('/api/auth/me', null, harry.token);
    assert.deepStrictEqual([me.admin, me.mainAdmin, me.user.status], [true, false, 'approved']);
    await ok('/api/admin/accounts', null, harry.token); // an added admin can do admin work
    await no('/api/admin/admins', { email: 'alice@lab.test' }, harry.token); // but cannot manage admins
    await no('/api/admin/account/delete', { uid: admin.user.uid }, harry.token);
    assert.deepStrictEqual((await ok('/api/admin/admins', null, admin.token)).added, ['harry@lab.test']);
    await no('/api/admin/admins', { email: 'admin@lab.test', add: false }, admin.token, 400); // main admins stay
    await ok('/api/admin/admins', { email: 'harry@lab.test', add: false }, admin.token);
    await no('/api/auth/me', null, harry.token, 401); // removed admins are signed out
    const h2 = await ok('/api/auth/signin', { email: 'harry@lab.test', password: 'harrypass1' });
    assert.strictEqual((await ok('/api/auth/me', null, h2.token)).admin, false);
    await no('/api/admin/accounts', null, h2.token);
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

  if (!process.env.TEST_BASE_URL) await test('expired sessions are cleaned up', async () => {
    await store.createSession({ sid: 'old1', uid: 'gone', created_at: Date.now() - 61 * 864e5, label: 'Browser' });
    await store.createSession({ sid: 'new1', uid: 'gone', created_at: Date.now(), label: 'Browser' });
    await store.deleteSessionsBefore(Date.now() - 60 * 864e5);
    assert.deepStrictEqual((await store.sessionsOf('gone')).map(s => s.sid), ['new1']);
  });

  // Last on purpose: it uses up this address's sign-in attempts
  await test('attempt limit cannot be dodged with a made-up forwarded address', async () => {
    let status = 0;
    for (let i = 0; i < 35 && status !== 429; i++) {
      const r = await fetch(base + '/api/auth/signin', { method: 'POST', headers: { 'Content-Type': 'application/json', 'X-Forwarded-For': `10.0.${i}.1, 9.9.9.9` }, body: JSON.stringify({ email: 'nobody@lab.test', password: 'wrongpass1' }) });
      status = r.status;
    }
    assert.strictEqual(status, 429, 'should be blocked after 30 attempts');
  });

  console.log(`\nAll ${passed} test groups passed.`);
  server.close();
  process.exit(0); // the database pool would otherwise keep the process open
})().catch(e => { console.error('✖', e.message); process.exit(1); });
