import express from 'express';
import helmet from 'helmet';
import bcrypt from 'bcryptjs';
import { createClient } from '@libsql/client';
import { randomBytes, createHash, createHmac, createCipheriv, createDecipheriv } from 'node:crypto';
import { courses as SEED } from './seed.js';

const PROD = process.env.NODE_ENV === 'production';
const SECRET = process.env.JWT_SECRET || (PROD ? '' : 'dev-only-secret');
if (!SECRET) throw new Error('Set JWT_SECRET before running in production.');

/* ---------- database: local file by default, Turso (hosted SQLite) when TURSO_DATABASE_URL is set ---------- */
const db = createClient({ url: process.env.TURSO_DATABASE_URL || 'file:' + (process.env.DB_FILE || 'lms.db'), authToken: process.env.TURSO_AUTH_TOKEN });
const R = (sql, ...args) => db.execute({ sql, args });
const Q = async (sql, ...args) => (await R(sql, ...args)).rows.map(r => ({ ...r }));
const G = async (sql, ...args) => (await Q(sql, ...args))[0];
const SCHEMA = `
create table if not exists users(id text primary key,name text,email text unique,pw text,role text,req text default '',must int default 0,totp text default '',totp_on int default 0);
create table if not exists sessions(id text primary key,u text,exp int);
create table if not exists hits(k text primary key,n int,t int);
create table if not exists courses(id text primary key,owner text,icon text,title text,descr text,lessons text,quiz text,assign text);
create table if not exists enr(u text,c text,primary key(u,c));
create table if not exists done(u text,c text,i int,primary key(u,c,i));
create table if not exists scores(id integer primary key autoincrement,u text,c text,s int,n int,d int);
create table if not exists subs(id text primary key,u text,c text,a text,text text,g int,fb text);`;
const rid = () => randomBytes(6).toString('hex');
const insUser = async (id, name, email, pw, role, req = '') => R('insert into users(id,name,email,pw,role,req) values(?,?,?,?,?,?)', id, name, email, await bcrypt.hash(pw, 10), role, req);
const ready = (async () => {
  await db.executeMultiple(SCHEMA);
  if (!(await G('select 1 x from users')) && process.env.SEED !== '0') {
    for (const u of [['a1', 'Admin Hina', 'admin@ilmora.pk', 'admin'], ['i1', 'Sara Khan', 'sara@ilmora.pk', 'instructor'], ['s1', 'Ali Raza', 'ali@ilmora.pk', 'student']]) await insUser(u[0], u[1], u[2], 'demo1234', u[3]);
    for (const c of SEED) await R('insert into courses values(?,?,?,?,?,?,?,?)', c.id, c.by, c.icon, c.title, c.desc, JSON.stringify(c.lessons), JSON.stringify(c.quiz), JSON.stringify(c.assign));
    await R('insert into enr values(?,?)', 's1', 'c1'); for (const i of [0, 1]) await R('insert into done values(?,?,?)', 's1', 'c1', i);
  }
  const AE = (process.env.ADMIN_EMAIL || '').toLowerCase();
  if (AE && process.env.ADMIN_PASSWORD && !(await G('select 1 x from users where email=?', AE))) await insUser(rid(), 'Administrator', AE, process.env.ADMIN_PASSWORD, 'admin');
})();

/* ---------- crypto helpers: sessions, 2FA (TOTP) ---------- */
const sh = s => createHash('sha256').update(s).digest('hex');
const K = createHash('sha256').update(SECRET).digest();
const enc = t => { const iv = randomBytes(12), c = createCipheriv('aes-256-gcm', K, iv), e = Buffer.concat([c.update(t, 'utf8'), c.final()]); return [iv, c.getAuthTag(), e].map(b => b.toString('base64')).join('.') };
const dec = s => { const [iv, tag, e] = s.split('.').map(x => Buffer.from(x, 'base64')), d = createDecipheriv('aes-256-gcm', K, iv); d.setAuthTag(tag); return Buffer.concat([d.update(e), d.final()]).toString('utf8') };
const B32 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
const b32 = buf => { let bits = '', o = ''; for (const b of buf) bits += b.toString(2).padStart(8, '0'); for (let i = 0; i < bits.length; i += 5) o += B32[parseInt(bits.slice(i, i + 5).padEnd(5, '0'), 2)]; return o };
const unb32 = s => { let bits = ''; for (const c of s) bits += B32.indexOf(c).toString(2).padStart(5, '0'); const o = []; for (let i = 0; i + 8 <= bits.length; i += 8) o.push(parseInt(bits.slice(i, i + 8), 2)); return Buffer.from(o) };
const hotp = (key, ctr) => { const b = Buffer.alloc(8); b.writeBigUInt64BE(BigInt(ctr)); const h = createHmac('sha1', key).update(b).digest(), o = h[19] & 15; return String((h.readUInt32BE(o) & 0x7fffffff) % 1e6).padStart(6, '0') };
const totpOk = (secret, code) => { const key = unb32(secret), c = Math.floor(Date.now() / 30000); return [-1, 0, 1].some(d => hotp(key, c + d) === String(code).trim()) };
const CN = PROD ? '__Host-sid' : 'sid', DAY = 864e5, CO = { httpOnly: true, secure: PROD, sameSite: 'lax', path: '/' };
const startSession = async (res, uid) => { const sid = randomBytes(24).toString('base64url'); await R('insert into sessions values(?,?,?)', sh(sid), uid, Date.now() + DAY); res.cookie(CN, sid, { ...CO, maxAge: DAY }) };
const getSid = req => (req.headers.cookie || '').split(';').map(s => s.trim()).find(s => s.startsWith(CN + '='))?.slice(CN.length + 1);
const DUMMY = bcrypt.hashSync('not-a-real-password', 10);

/* ---------- course helpers ---------- */
const J = x => { try { return JSON.parse(x || '[]') } catch { return [] } };
const course = r => ({ id: r.id, by: r.owner, icon: r.icon, title: r.title, desc: r.descr, lessons: J(r.lessons), quiz: J(r.quiz), assign: J(r.assign) });
const getC = async id => { const r = await G('select * from courses where id=?', id); return r && course(r) };
const canEdit = (u, c) => u.role === 'admin' || (u.role === 'instructor' && c.by === u.id);
const str = (x, n) => String(x ?? '').trim().slice(0, n);
const arr = x => Array.isArray(x) ? x : [];
const cleanC = b => ({
  icon: str(b.icon, 4) || '📘', title: str(b.title, 120), desc: str(b.desc, 400),
  lessons: arr(b.lessons).map(l => str(l, 300)).filter(Boolean).slice(0, 100),
  quiz: arr(b.quiz).slice(0, 100).map(x => ({ q: str(x?.q, 300), o: arr(x?.o).slice(0, 4).map(s => str(s, 200)), a: Number.isInteger(x?.a) ? x.a : -1 }))
    .filter(x => x.q && x.o.length === 4 && x.o.every(Boolean) && x.a >= 0 && x.a < 4),
  assign: arr(b.assign).slice(0, 50).map(x => ({ id: /^[a-z0-9]{1,16}$/i.test(x?.id) ? x.id : rid().slice(0, 8), t: str(x?.t, 500), due: /^\d{4}-\d{2}-\d{2}$/.test(x?.due) ? x.due : '' })).filter(x => x.t)
});
const fail = (res, code, error) => res.status(code).json({ error });

/* ---------- rate limiting stored in the database (survives restarts and serverless instances) ---------- */
const ip = req => String(req.headers['x-vercel-forwarded-for'] || req.ip).split(',')[0].trim();
const bk = (k, win) => k + ':' + Math.floor(Date.now() / (win * 1000));
const bump = async (k, win) => {
  const r = await G('insert into hits(k,n,t) values(?,1,?) on conflict(k) do update set n=n+1 returning n', bk(k, win), Date.now());
  if (Math.random() < 0.02) { R('delete from hits where t<?', Date.now() - DAY).catch(() => { }); R('delete from sessions where exp<?', Date.now()).catch(() => { }) }
  return r.n;
};
const count = async (k, win) => (await G('select n from hits where k=?', bk(k, win)))?.n || 0;
const lim = (name, max, win) => async (req, res, next) => (await bump(name + ':' + ip(req), win)) > max ? fail(res, 429, 'Too many requests. Wait a few minutes and try again.') : next();

/* ---------- app + security middleware ---------- */
const app = express();
if (PROD) app.set('trust proxy', 1);
app.disable('x-powered-by');
app.use(helmet({
  contentSecurityPolicy: {
    useDefaults: false, directives: {
      defaultSrc: ["'self'"], scriptSrc: ["'self'"], scriptSrcAttr: ["'unsafe-inline'"], styleSrc: ["'self'", "'unsafe-inline'", 'https://fonts.googleapis.com'],
      fontSrc: ['https://fonts.gstatic.com'], imgSrc: ["'self'", 'data:'], mediaSrc: ["'self'", 'blob:'], connectSrc: ["'self'"],
      objectSrc: ["'none'"], baseUri: ["'self'"], formAction: ["'self'"], frameAncestors: ["'none'"]
    }
  }, crossOriginEmbedderPolicy: false
}));
app.use(express.json({ limit: '200kb' }));
app.use((q, s, n) => ready.then(() => n(), n));
app.use('/api', (req, res, next) => ['GET', 'HEAD'].includes(req.method) || req.get('x-requested-with') === 'fetch' ? next() : fail(res, 403, 'Blocked request.'));
const wrap = fn => (a, b, c) => Promise.resolve(fn(a, b, c)).catch(c);
const r = (m, p, ...f) => app[m](p, ...f.map(wrap));
app.use('/api', wrap(lim('api', 300, 60)));

const auth = async (req, res, next) => {
  const sid = getSid(req); const u = sid && await G('select u.id,u.name,u.email,u.role,u.req,u.must,u.totp,u.totp_on,u.pw from sessions s join users u on u.id=s.u where s.id=? and s.exp>?', sh(sid), Date.now());
  if (!u) return fail(res, 401, 'Please sign in again.');
  if (u.must && !['/api/state', '/api/password', '/api/logout'].includes(req.path)) return fail(res, 403, 'Change your password first.');
  req.u = u; req.sid = sh(sid); next();
};
const need = (...roles) => (req, res, next) => roles.includes(req.u.role) ? next() : fail(res, 403, 'You do not have permission to do that.');
const loadC = async (req, res, next) => { req.c = await getC(req.params.id); req.c ? next() : fail(res, 404, 'Course not found.') };
const edit = (req, res, next) => canEdit(req.u, req.c) ? next() : fail(res, 403, 'You can only change your own courses.');
const enrolled = async (req, res, next) => (await G('select 1 x from enr where u=? and c=?', req.u.id, req.c.id)) ? next() : fail(res, 403, 'Enroll in this course first.');
const AUTHL = lim('auth', 15, 600);

/* ---------- accounts ---------- */
r('post', '/api/signup', AUTHL, async (req, res) => {
  const name = str(req.body.name, 60), email = str(req.body.email, 120).toLowerCase(), pw = String(req.body.password ?? '');
  if (name.length < 2) return fail(res, 400, 'Enter your full name.');
  if (!/^\S+@\S+\.\S+$/.test(email)) return fail(res, 400, 'Enter a valid email address.');
  if (pw.length < 8 || pw.length > 100) return fail(res, 400, 'Use a password of 8 or more characters.');
  if (await G('select 1 x from users where email=?', email)) return fail(res, 409, 'That email already has an account. Sign in instead.');
  const id = rid(); await insUser(id, name, email, pw, 'student', req.body.role === 'instructor' ? 'instructor' : '');
  await startSession(res, id); res.json({ ok: true });
});
r('post', '/api/login', AUTHL, async (req, res) => {
  const email = str(req.body.email, 120).toLowerCase(), lk = 'lock:' + email;
  if (await count(lk, 900) >= 5) return fail(res, 429, 'Too many failed attempts for this account. Wait 15 minutes.');
  const u = await G('select * from users where email=?', email), ok = await bcrypt.compare(String(req.body.password ?? ''), u ? u.pw : DUMMY);
  const bad = async m => { await bump(lk, 900); return fail(res, 401, m) };
  if (!u || !ok) return bad('Email or password is wrong. Check both and try again.');
  if (u.totp_on) {
    const code = String(req.body.code ?? '').trim(); if (!code) return res.json({ need2fa: true });
    if (!totpOk(dec(u.totp), code)) return bad('That authenticator code is wrong or expired.');
  }
  await startSession(res, u.id); res.json({ ok: true });
});
r('post', '/api/logout', async (req, res) => { const sid = getSid(req); if (sid) await R('delete from sessions where id=?', sh(sid)); res.clearCookie(CN, CO); res.json({ ok: true }) });
r('post', '/api/password', auth, AUTHL, async (req, res) => {
  const nw = String(req.body.new ?? ''); if (!(await bcrypt.compare(String(req.body.old ?? ''), req.u.pw))) return fail(res, 401, 'Your current password is wrong.');
  if (nw.length < 8 || nw.length > 100) return fail(res, 400, 'Use a new password of 8 or more characters.');
  await R('update users set pw=?,must=0 where id=?', await bcrypt.hash(nw, 10), req.u.id); await R('delete from sessions where u=? and id!=?', req.u.id, req.sid); res.json({ ok: true });
});
r('post', '/api/2fa/setup', auth, AUTHL, async (req, res) => {
  if (req.u.totp_on) return fail(res, 409, 'Two-factor is already on.');
  const secret = b32(randomBytes(20)); await R('update users set totp=?,totp_on=0 where id=?', enc(secret), req.u.id);
  res.json({ secret, uri: `otpauth://totp/Ilmora:${encodeURIComponent(req.u.email)}?secret=${secret}&issuer=Ilmora` });
});
r('post', '/api/2fa/enable', auth, AUTHL, async (req, res) => {
  if (!req.u.totp || req.u.totp_on) return fail(res, 400, 'Start the setup again.');
  if (!totpOk(dec(req.u.totp), req.body.code)) return fail(res, 400, 'That code is wrong or expired. Try the next one.');
  await R('update users set totp_on=1 where id=?', req.u.id); res.json({ ok: true });
});
r('post', '/api/2fa/disable', auth, AUTHL, async (req, res) => {
  if (!req.u.totp_on || !(await bcrypt.compare(String(req.body.password ?? ''), req.u.pw)) || !totpOk(dec(req.u.totp), req.body.code)) return fail(res, 400, 'Password or code is wrong.');
  await R("update users set totp='',totp_on=0 where id=?", req.u.id); res.json({ ok: true });
});
r('get', '/api/public', async (q, res) => res.json({
  courses: (await G('select count(*) n from courses')).n, students: (await G("select count(*) n from users where role='student'")).n,
  lessons: (await Q('select lessons from courses')).reduce((n, x) => n + J(x.lessons).length, 0)
}));

/* ---------- state: only what the signed-in role may see ---------- */
r('get', '/api/state', auth, async (req, res) => {
  const u = req.u, ad = u.role === 'admin', st = u.role === 'student';
  const all = (await Q('select * from courses')).map(course), eid = new Set(all.filter(c => canEdit(u, c)).map(c => c.id));
  const vis = x => ad || (st ? x.u === u.id : eid.has(x.c));
  const courses = all.map(c => eid.has(c.id) ? c : { ...c, quiz: c.quiz.map(({ q, o }) => ({ q, o })) });
  const enrRows = (await Q('select * from enr')).filter(vis), enr = {}; enrRows.forEach(x => (enr[x.u] = enr[x.u] || []).push(x.c));
  const done = {}; (await Q('select * from done')).filter(vis).forEach(x => (done[x.u + x.c] = done[x.u + x.c] || []).push(x.i));
  const subs = (await Q('select * from subs')).filter(vis).map(x => ({ id: x.id, u: x.u, c: x.c, a: x.a, text: x.text, g: x.g, fb: x.fb || '' }));
  const scores = (await Q('select u,c,s,n,d from scores')).filter(vis);
  const ids = new Set([u.id, ...all.map(c => c.by), ...subs.map(s => s.u), ...enrRows.map(x => x.u)]);
  const users = (await Q('select id,name,email,role,req from users')).filter(x => ad || ids.has(x.id))
    .map(x => x.id === u.id ? { ...x, totp: !!u.totp_on, must: !!u.must } : ad ? x : { id: x.id, name: x.name, role: x.role });
  res.json({ me: u.id, users, courses, enr, done, scores, subs });
});

/* ---------- courses ---------- */
r('post', '/api/courses', auth, need('instructor', 'admin'), async (req, res) => {
  const c = cleanC(req.body); if (!c.title || !c.desc) return fail(res, 400, 'Add a title and a description.');
  await R('insert into courses values(?,?,?,?,?,?,?,?)', rid(), req.u.id, c.icon, c.title, c.desc, JSON.stringify(c.lessons), '[]', '[]'); res.json({ ok: true });
});
r('put', '/api/courses/:id', auth, loadC, edit, async (req, res) => {
  const c = cleanC(req.body); if (!c.title || !c.desc) return fail(res, 400, 'A course needs a title and a description.');
  await R('update courses set icon=?,title=?,descr=?,lessons=?,quiz=?,assign=? where id=?', c.icon, c.title, c.desc, JSON.stringify(c.lessons), JSON.stringify(c.quiz), JSON.stringify(c.assign), req.c.id); res.json({ ok: true });
});
r('delete', '/api/courses/:id', auth, loadC, edit, async (req, res) => {
  for (const t of ['enr', 'done', 'scores', 'subs']) await R(`delete from ${t} where c=?`, req.c.id); await R('delete from courses where id=?', req.c.id); res.json({ ok: true });
});
r('post', '/api/courses/:id/enroll', auth, need('student'), loadC, async (req, res) => { await R('insert or ignore into enr values(?,?)', req.u.id, req.c.id); res.json({ ok: true }) });
r('post', '/api/courses/:id/lessons/:i/toggle', auth, need('student'), loadC, enrolled, async (req, res) => {
  const i = Number(req.params.i); if (!Number.isInteger(i) || i < 0 || i >= req.c.lessons.length) return fail(res, 400, 'That lesson does not exist.');
  (await G('select 1 x from done where u=? and c=? and i=?', req.u.id, req.c.id, i)) ? await R('delete from done where u=? and c=? and i=?', req.u.id, req.c.id, i) : await R('insert into done values(?,?,?)', req.u.id, req.c.id, i); res.json({ ok: true });
});
r('post', '/api/courses/:id/quiz', auth, need('student'), loadC, enrolled, async (req, res) => {
  const a = arr(req.body.answers), n = req.c.quiz.length; if (!n) return fail(res, 400, 'This quiz has no questions yet.');
  const s = req.c.quiz.reduce((t, q, i) => t + (a[i] === q.a ? 1 : 0), 0);
  await R('insert into scores(u,c,s,n,d) values(?,?,?,?,?)', req.u.id, req.c.id, s, n, Date.now()); res.json({ s, n });
});
r('post', '/api/courses/:id/submit', auth, need('student'), loadC, enrolled, async (req, res) => {
  const aid = str(req.body.a, 20), text = str(req.body.text, 5000);
  if (!req.c.assign.some(x => x.id === aid)) return fail(res, 404, 'Assignment not found.');
  if (!text) return fail(res, 400, 'Write your answer before submitting.');
  if (await G('select 1 x from subs where u=? and a=?', req.u.id, aid)) return fail(res, 409, 'You already submitted this assignment.');
  await R('insert into subs values(?,?,?,?,?,?,?)', rid(), req.u.id, req.c.id, aid, text, null, ''); res.json({ ok: true });
});
r('post', '/api/subs/:id/grade', auth, need('instructor', 'admin'), async (req, res) => {
  const s = await G('select * from subs where id=?', req.params.id), c = s && await getC(s.c);
  if (!c || !canEdit(req.u, c)) return fail(res, 403, 'You can only grade submissions for your own courses.');
  const g = Number(req.body.g); if (!Number.isInteger(g) || g < 0 || g > 100) return fail(res, 400, 'Enter a score from 0 to 100.');
  await R('update subs set g=?,fb=? where id=?', g, str(req.body.fb, 1000), s.id); res.json({ ok: true });
});

/* ---------- admin ---------- */
r('patch', '/api/users/:id', auth, need('admin'), async (req, res) => {
  if (req.params.id === req.u.id) return fail(res, 400, 'You cannot change your own role.');
  if (!['student', 'instructor', 'admin'].includes(req.body.role)) return fail(res, 400, 'Unknown role.');
  await R("update users set role=?,req='' where id=?", req.body.role, req.params.id); res.json({ ok: true });
});
r('post', '/api/users/:id/approve', auth, need('admin'), async (req, res) => {
  if ((await G('select req from users where id=?', req.params.id))?.req !== 'instructor') return fail(res, 400, 'This user has no pending request.');
  await R("update users set role='instructor',req='' where id=?", req.params.id); res.json({ ok: true });
});
r('post', '/api/users/:id/reset', auth, need('admin'), async (req, res) => {
  const id = req.params.id; if (id === req.u.id) return fail(res, 400, 'Use Account to change your own password.');
  const temp = randomBytes(9).toString('base64url');
  await R("update users set pw=?,must=1,totp='',totp_on=0 where id=?", await bcrypt.hash(temp, 10), id); await R('delete from sessions where u=?', id); res.json({ temp });
});
r('delete', '/api/users/:id', auth, need('admin'), async (req, res) => {
  const id = req.params.id; if (id === req.u.id) return fail(res, 400, 'You cannot remove your own account.');
  for (const t of ['enr', 'done', 'scores', 'subs', 'sessions']) await R(`delete from ${t} where u=?`, id);
  await R('update courses set owner=? where owner=?', req.u.id, id); await R('delete from users where id=?', id); res.json({ ok: true });
});

app.use('/api', (q, res) => fail(res, 404, 'Not found.'));
app.use((e, q, res, n) => { console.error(e); fail(res, 500, 'Server error. Try again.') });
export default app;
