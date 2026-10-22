import { env } from 'cloudflare:workers';
import { createClient } from '@libsql/client/web';
import { Buffer } from 'node:buffer';
import { scrypt as nodeScrypt, timingSafeEqual } from 'node:crypto';

const SESSION_DAYS = 30;
const MAX_BODY = 100 * 1024;
const MAX_BODY_WITH_PHOTO = 12 * 1024 * 1024;
const MAX_PHOTOS = 5;
const IMAGE_MAX_BYTES = 2 * 1024 * 1024;
const RESET_MINUTES = 60;
const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/;

class HttpError extends Error {
  constructor(status, message){ super(message); this.status = status; }
}

/* ---------- small helpers ---------- */
const enc = new TextEncoder();
const hex = b => [...new Uint8Array(b)].map(x => x.toString(16).padStart(2, '0')).join('');
const randHex = n => hex(crypto.getRandomValues(new Uint8Array(n)));
const randB64url = n => Buffer.from(crypto.getRandomValues(new Uint8Array(n))).toString('base64url');
const sha256 = async t => hex(await crypto.subtle.digest('SHA-256', enc.encode(t)));
const escHtml = s => String(s).replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));

const json = (status, body, headers = {}) => new Response(
  body === undefined ? null : JSON.stringify(body),
  { status, headers: { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store', 'X-Content-Type-Options': 'nosniff', ...headers } }
);

function parseCookies(req){
  const out = {};
  String(req.headers.get('cookie') || '').split(';').forEach(part => {
    const i = part.indexOf('=');
    if (i > 0) out[part.slice(0, i).trim()] = part.slice(i + 1).trim();
  });
  return out;
}
const sessionCookie = (value, maxAge) =>
  `sid=${value}; HttpOnly; SameSite=Lax; Path=/; Secure${maxAge == null ? '' : '; Max-Age=' + maxAge}`;

async function readJson(req, limit = MAX_BODY){
  const type = String(req.headers.get('content-type') || '');
  if (!type.toLowerCase().startsWith('application/json')) throw new HttpError(415, 'Send JSON.');
  if (Number(req.headers.get('content-length') || 0) > limit) throw new HttpError(413, 'That request is too large.');
  const txt = await req.text();
  if (txt.length > limit) throw new HttpError(413, 'That request is too large.');
  try { return JSON.parse(txt || '{}'); } catch (e) { throw new HttpError(400, 'Bad JSON.'); }
}

/* ---------- database (Turso over HTTP) ---------- */
let _client;
const getClient = () => _client || (_client = createClient({
  url: String(env.TURSO_DATABASE_URL).replace(/^libsql:\/\//, 'https://'),
  authToken: env.TURSO_AUTH_TOKEN
}));
const plain = rs => rs.rows.map(r => Object.fromEntries(rs.columns.map((c, i) => [c, r[i]])));
const wrap = exec => ({
  all: async (sql, args = []) => plain(await exec().execute({ sql, args })),
  get: async (sql, args = []) => plain(await exec().execute({ sql, args }))[0],
  run: async (sql, args = []) => {
    const r = await exec().execute({ sql, args });
    return { changes: r.rowsAffected, lastInsertRowid: r.lastInsertRowid == null ? null : Number(r.lastInsertRowid) };
  }
});
const DB = {
  ...wrap(getClient),
  async transaction(fn){
    const tx = await getClient().transaction('write');
    try {
      const out = await fn(wrap(() => tx));
      await tx.commit();
      return out;
    } catch (e) {
      try { await tx.rollback(); } catch (_) {}
      throw e;
    } finally { tx.close(); }
  }
};

/* ---------- activity log ---------- */
async function logChange(action, detail, userId){
  console.log(action + (detail ? ': ' + detail : ''));
  if (userId){
    try { await DB.run('INSERT INTO activity (user_id, action, detail) VALUES (?, ?, ?)', [userId, action, detail || null]); }
    catch (e) {}
  }
}

/* ---------- rate limits (stored in the database, because Workers have no shared memory) ---------- */
async function rlHit(key, windowMs){
  const now = Date.now();
  const r = await DB.get(`INSERT INTO rate_limits (key, count, reset_at) VALUES (?, 1, ?)
    ON CONFLICT(key) DO UPDATE SET
      count = CASE WHEN reset_at <= ? THEN 1 ELSE count + 1 END,
      reset_at = CASE WHEN reset_at <= ? THEN ? ELSE reset_at END
    RETURNING count`, [key, now + windowMs, now, now, now + windowMs]);
  return r.count;
}
const allow = async (key, max, windowMs) => (await rlHit(key, windowMs)) <= max;
async function tooManyFailures(key){
  const r = await DB.get('SELECT count FROM rate_limits WHERE key = ? AND reset_at > ?', [key, Date.now()]);
  return !!r && r.count >= 10;
}
const noteFailure = key => rlHit(key, 15 * 60000);
const clearFailures = key => DB.run('DELETE FROM rate_limits WHERE key = ?', [key]);

/* ---------- passwords (same scrypt format as before, so old logins keep working) ---------- */
const scryptKey = (pw, salt) => new Promise((resolve, reject) =>
  nodeScrypt(pw, salt, 64, { N: 16384, r: 8, p: 1, maxmem: 64 * 1024 * 1024 }, (err, key) => err ? reject(err) : resolve(key)));

async function hashPassword(password){
  const salt = Buffer.from(crypto.getRandomValues(new Uint8Array(16)));
  const key = await scryptKey(password, salt);
  return 'scrypt$' + salt.toString('hex') + '$' + key.toString('hex');
}
async function verifyPassword(password, stored){
  const [alg, saltHex, keyHex] = String(stored).split('$');
  if (alg !== 'scrypt' || !saltHex || !keyHex) return false;
  const expected = Buffer.from(keyHex, 'hex');
  const key = await scryptKey(password, Buffer.from(saltHex, 'hex'));
  return key.length === expected.length && timingSafeEqual(key, expected);
}
let dummyHash = null;

/* ---------- sessions ---------- */
async function startSession(userId){
  const token = randB64url(32);
  await DB.run('INSERT INTO sessions (token_hash, user_id, expires_at) VALUES (?, ?, ?)',
    [await sha256(token), userId, Date.now() + SESSION_DAYS * 86400000]);
  return sessionCookie(token, null);   // no Max-Age: logs out when the browser is closed
}

async function currentUser(req){
  const token = parseCookies(req).sid;
  if (!token) return null;
  const hash = await sha256(token);
  const row = await DB.get(`
    SELECT u.id, u.name, u.email, u.role, u.avatar, s.expires_at
    FROM sessions s JOIN users u ON u.id = s.user_id
    WHERE s.token_hash = ?`, [hash]);
  if (!row) return null;
  if (row.expires_at < Date.now()){
    await DB.run('DELETE FROM sessions WHERE token_hash = ?', [hash]);
    return null;
  }
  return { id: row.id, name: row.name, email: row.email, role: row.role,
           avatar: row.avatar ? '/uploads/' + row.avatar : null };
}
async function requireUser(req){
  const u = await currentUser(req);
  if (!u) throw new HttpError(401, 'Please log in first.');
  return u;
}
async function requireAdmin(req){
  const u = await requireUser(req);
  if (u.role !== 'admin') throw new HttpError(403, 'Admins only.');
  return u;
}

/* ---------- photos (stored in the database) ---------- */
function parseImage(dataUrl){
  if (dataUrl == null || dataUrl === '') return null;
  const m = /^data:image\/jpeg;base64,([A-Za-z0-9+/]+={0,2})$/.exec(String(dataUrl));
  if (!m) throw new HttpError(400, 'The photo must be a JPEG image.');
  const bytes = Buffer.from(m[1], 'base64');
  if (bytes.length > IMAGE_MAX_BYTES) throw new HttpError(400, 'That photo is too large (at most 2 MB).');
  if (bytes.length < 4 || bytes[0] !== 0xFF || bytes[1] !== 0xD8 || bytes[2] !== 0xFF){
    throw new HttpError(400, 'The photo must be a JPEG image.');
  }
  return { name: randHex(12) + '.jpg', b64: m[1] };
}
function parseImages(body){
  let list = body.images;
  if (list == null) list = body.image ? [body.image] : [];
  if (!Array.isArray(list)) throw new HttpError(400, 'Photos must be a list.');
  if (list.length > MAX_PHOTOS) throw new HttpError(400, 'You can add at most ' + MAX_PHOTOS + ' photos.');
  return list.map(parseImage).filter(Boolean);
}
async function deleteImage(name){
  if (!name || !/^[a-f0-9]{24}\.jpg$/.test(name)) return;
  try { await DB.run('DELETE FROM images WHERE name = ?', [name]); } catch (e) {}
}

/* ---------- email (Brevo) ---------- */
async function sendEmail({ to, toName, subject, html, textBody }){
  const res = await fetch('https://api.brevo.com/v3/smtp/email', {
    method: 'POST',
    headers: { accept: 'application/json', 'content-type': 'application/json', 'api-key': env.BREVO_API_KEY },
    body: JSON.stringify({
      sender: { name: env.MAIL_FROM_NAME || 'Secondhand Atlas', email: env.MAIL_FROM_EMAIL },
      to: [{ email: to, name: toName }], subject, htmlContent: html, textContent: textBody
    }),
    signal: AbortSignal.timeout(15000)
  });
  if (!res.ok){
    let msg = '';
    try { msg = (await res.json()).message || ''; } catch (e) {}
    throw new Error('Brevo answered ' + res.status + (msg ? ': ' + msg : ''));
  }
}
const mailReady = () => !!(env.BREVO_API_KEY && env.MAIL_FROM_EMAIL);

async function deliverResetLink(user, link){
  if (!mailReady()){ console.log('RESET LINK (email not set up) for ' + user.email + ': ' + link); return; }
  try{
    await sendEmail({
      to: user.email, toName: user.name,
      subject: 'Reset your Secondhand Atlas password',
      textBody: 'Hi ' + user.name + ',\n\nSomeone asked to reset the password for your Secondhand Atlas account. Open this link to choose a new one (it works once and expires in ' + RESET_MINUTES + ' minutes):\n\n' + link + '\n\nIf you did not ask for this, you can ignore this email. Your password will not change.',
      html: '<div style="font-family:Arial,Helvetica,sans-serif;max-width:480px;margin:0 auto;color:#1D2B33;line-height:1.5">' +
        '<h2 style="margin:0 0 12px">Reset your password</h2><p>Hi ' + escHtml(user.name) + ',</p>' +
        '<p>Someone asked to reset the password for your Secondhand Atlas account. Use the button below to choose a new one. It works once and expires in ' + RESET_MINUTES + ' minutes.</p>' +
        '<p style="margin:24px 0"><a href="' + escHtml(link) + '" style="background:#1D2B33;color:#ffffff;padding:12px 20px;border-radius:6px;text-decoration:none;font-weight:bold;display:inline-block">Choose a new password</a></p>' +
        '<p style="font-size:14px;color:#586870">Button not working? Copy this link into your browser:<br>' + escHtml(link) + '</p>' +
        '<p style="font-size:14px;color:#586870">If you did not ask for this, you can ignore this email. Your password will not change.</p></div>'
    });
  }catch(e){ console.error('Could not send the reset email to ' + user.email + ': ' + e.message); }
}

async function deliverTransferNotice({ fromName, toEmail, toName, itemName, link }){
  if (!mailReady()){ console.log('OBJECT PASSED ON (email not set up) to ' + toEmail + ': ' + link); return; }
  try{
    await sendEmail({
      to: toEmail, toName: toName || toEmail,
      subject: fromName + ' passed "' + itemName + '" to you on Secondhand Atlas',
      textBody: fromName + ' passed "' + itemName + '" to you.\n\nLog in (or register with this same email address) and add your chapter to become its new owner:\n\n' + link + '\n\nIf you were not expecting this, you can ignore this email.',
      html: '<div style="font-family:Arial,Helvetica,sans-serif;max-width:480px;margin:0 auto;color:#242424;line-height:1.5">' +
        '<h2 style="margin:0 0 12px">An object was passed to you</h2>' +
        '<p>' + escHtml(fromName) + ' passed <b>' + escHtml(itemName) + '</b> to you.</p>' +
        '<p>Log in, or register with this same email address, and add your chapter to become its new owner.</p>' +
        '<p style="margin:24px 0"><a href="' + escHtml(link) + '" style="background:#0F6CBD;color:#ffffff;padding:12px 20px;border-radius:4px;text-decoration:none;font-weight:bold;display:inline-block">Open Secondhand Atlas</a></p>' +
        '<p style="font-size:14px;color:#616161">If you were not expecting this, you can ignore this email.</p></div>'
    });
  }catch(e){ console.error('Could not send the transfer email to ' + toEmail + ': ' + e.message); }
}

/* ---------- validation ---------- */
function text(value, label, max){
  const s = String(value == null ? '' : value).trim();
  if (!s) throw new HttpError(400, label + ' is required.');
  if (s.length > max) throw new HttpError(400, label + ' is too long (at most ' + max + ' characters).');
  return s;
}
function coords(lat, lng){
  if (typeof lat !== 'number' || typeof lng !== 'number' || !Number.isFinite(lat) || !Number.isFinite(lng) || Math.abs(lat) > 90 || Math.abs(lng) > 180){
    throw new HttpError(400, 'Search for your place or click the map to choose a location.');
  }
  return [lat, lng];
}
function chapterFields(src){
  const story = text(src.story, 'The story', 2000);
  const [lat, lng] = coords(src.lat, src.lng);
  const place = src.place == null || src.place === '' ? null : text(src.place, 'The place name', 160);
  return { story, lat, lng, place };
}

/* ---------- items ---------- */
async function loadItems(onlyId, viewer){
  const items = onlyId == null
    ? await DB.all('SELECT id, name, price, image, created_by FROM items ORDER BY id')
    : await DB.all('SELECT id, name, price, image, created_by FROM items WHERE id = ?', [onlyId]);
  const chapters = onlyId == null
    ? await DB.all('SELECT * FROM chapters ORDER BY id')
    : await DB.all('SELECT * FROM chapters WHERE item_id = ? ORDER BY id', [onlyId]);
  const transfers = onlyId == null
    ? await DB.all('SELECT item_id, to_email FROM transfers')
    : await DB.all('SELECT item_id, to_email FROM transfers WHERE item_id = ?', [onlyId]);
  const photoRows = onlyId == null
    ? await DB.all('SELECT item_id, name FROM item_images ORDER BY item_id, position')
    : await DB.all('SELECT item_id, name FROM item_images WHERE item_id = ? ORDER BY position', [onlyId]);
  const photosBy = new Map();
  for (const p of photoRows){
    if (!photosBy.has(p.item_id)) photosBy.set(p.item_id, []);
    photosBy.get(p.item_id).push(p.name);
  }
  const namesOf = i => photosBy.get(i.id) || (i.image ? [i.image] : []);
  const tById = new Map(transfers.map(t => [t.item_id, t]));
  const byId = new Map(items.map(i => [i.id, {
    id: i.id, name: i.name, price: i.price,
    images: namesOf(i).map(n => '/uploads/' + n),
    image: namesOf(i)[0] ? '/uploads/' + namesOf(i)[0] : null,
    createdBy: i.created_by, chapters: []
  }]));
  for (const c of chapters){
    const item = byId.get(c.item_id);
    if (item) item.chapters.push({
      owner: c.owner_name, userId: c.user_id, story: c.story,
      lat: c.lat, lng: c.lng, place: c.place, year: c.year, createdAt: c.created_at
    });
  }
  for (const it of byId.values()){
    const last = it.chapters[it.chapters.length - 1];
    it.ownerId = (last && last.userId) || it.createdBy;
    const t = tById.get(it.id);
    it.passedOn = !!t;
    if (t && viewer){
      if (viewer.id === it.ownerId) it.passedTo = t.to_email;
      if (viewer.email === t.to_email) it.passedToYou = true;
    }
    delete it.createdBy;
  }
  return [...byId.values()];
}

const insertChapter = (runner, itemId, userId, ownerName, ch) => runner.run(`
  INSERT INTO chapters (item_id, user_id, owner_name, story, lat, lng, place, year)
  VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
  [itemId, userId, ownerName, ch.story, ch.lat, ch.lng, ch.place, new Date().getFullYear()]);

/* ---------- API routes ---------- */
async function api(req, pathname){
  const method = req.method;
  const ip = req.headers.get('cf-connecting-ip') || 'unknown';
  const base = env.SITE_URL || new URL(req.url).origin;

  // block other websites from making changes on a logged-in person's behalf
  if (method !== 'GET' && method !== 'HEAD'){
    const origin = req.headers.get('origin');
    if (origin){
      let host = '';
      try { host = new URL(origin).host; } catch (e) {}
      if (host !== new URL(req.url).host) throw new HttpError(403, 'Cross-site requests are not allowed.');
    }
  }

  if (pathname === '/api/me' && method === 'GET'){
    return json(200, { user: await currentUser(req) });
  }

  /* another person's public page */
  const pu = pathname.match(/^\/api\/users\/(\w+)$/);
  if (pu && method === 'GET'){
    await requireUser(req);
    const uid = pu[1];
    const u = await DB.get("SELECT id, name, avatar, created_at FROM users WHERE id = ? AND role != 'admin'", [uid]);
    if (!u) throw new HttpError(404, 'That person no longer exists.');
    const items = await DB.all('SELECT id, name, price, image, created_at FROM items WHERE created_by = ? ORDER BY id DESC', [uid]);
    const chapters = await DB.all(`
      SELECT i.name AS item_name, c.story, c.year, c.created_at
      FROM chapters c JOIN items i ON i.id = c.item_id
      WHERE c.user_id = ? ORDER BY c.id DESC`, [uid]);
    return json(200, {
      user: { id: u.id, name: u.name, avatar: u.avatar ? '/uploads/' + u.avatar : null, createdAt: u.created_at },
      items: items.map(i => ({ id: i.id, name: i.name, price: i.price, image: i.image ? '/uploads/' + i.image : null, createdAt: i.created_at })),
      chapters
    });
  }

  /* profile */
  if (pathname === '/api/profile' && method === 'GET'){
    const me = await requireUser(req);
    const row = await DB.get('SELECT created_at FROM users WHERE id = ?', [me.id]);
    const stats = await DB.get(`SELECT
      (SELECT COUNT(*) FROM items WHERE created_by = ?) AS items,
      (SELECT COUNT(*) FROM chapters WHERE user_id = ?) AS chapters`, [me.id, me.id]);
    return json(200, { user: { ...me, createdAt: row ? row.created_at : null }, stats });
  }

  if (pathname === '/api/profile' && method === 'POST'){
    const me = await requireUser(req);
    if (!(await allow('profile:' + me.id, 30, 3600000))) throw new HttpError(429, 'Too many changes. Please try again later.');
    const body = await readJson(req);
    const name = String(body.name || '').trim();
    const email = String(body.email || '').trim().toLowerCase();
    if (name.length < 2)  throw new HttpError(400, 'Enter your name.');
    if (name.length > 60) throw new HttpError(400, 'That name is too long.');
    if (!EMAIL_RE.test(email) || email.length > 254) throw new HttpError(400, 'Enter a valid email address.');

    const emailChanged = email !== me.email;
    if (emailChanged){
      const key = 'pwcheck:' + me.id;
      if (await tooManyFailures(key)) throw new HttpError(429, 'Too many wrong passwords. Wait a few minutes and try again.');
      const full = await DB.get('SELECT password_hash FROM users WHERE id = ?', [me.id]);
      const ok = await verifyPassword(String(body.currentPassword || '').slice(0, 200), full.password_hash);
      if (!ok){ await noteFailure(key); throw new HttpError(403, 'Your current password is incorrect.'); }
      await clearFailures(key);
      if (await DB.get('SELECT 1 AS x FROM users WHERE email = ? AND id != ?', [email, me.id])){
        throw new HttpError(409, 'Another account already uses this email address.');
      }
    }
    await DB.transaction(async tx => {
      await tx.run('UPDATE users SET name = ?, email = ? WHERE id = ?', [name, email, me.id]);
      await tx.run('UPDATE chapters SET owner_name = ? WHERE user_id = ?', [name, me.id]);
      if (emailChanged) await tx.run('UPDATE transfers SET to_email = ? WHERE to_email = ?', [email, me.email]);
    });
    await logChange('PROFILE UPDATED', name + ' <' + email + '>' + (emailChanged ? ' (email changed from ' + me.email + ')' : ''), me.id);
    return json(200, { user: { id: me.id, name, email, role: me.role, avatar: me.avatar } });
  }

  if (pathname === '/api/profile/photo' && method === 'POST'){
    const me = await requireUser(req);
    if (!(await allow('avatar:' + me.id, 20, 3600000))) throw new HttpError(429, 'Too many changes. Please try again later.');
    const body = await readJson(req, 4 * 1024 * 1024);
    const img = parseImage(body.image);
    if (!img) throw new HttpError(400, 'Choose a photo.');
    const old = await DB.get('SELECT avatar FROM users WHERE id = ?', [me.id]);
    await DB.transaction(async tx => {
      await tx.run('INSERT INTO images (name, data) VALUES (?, ?)', [img.name, img.b64]);
      await tx.run('UPDATE users SET avatar = ? WHERE id = ?', [img.name, me.id]);
    });
    if (old && old.avatar) await deleteImage(old.avatar);
    await logChange('PROFILE PHOTO CHANGED', me.name + ' <' + me.email + '>', me.id);
    return json(200, { avatar: '/uploads/' + img.name });
  }

  if (pathname === '/api/profile/photo' && method === 'DELETE'){
    const me = await requireUser(req);
    const old = await DB.get('SELECT avatar FROM users WHERE id = ?', [me.id]);
    await DB.run('UPDATE users SET avatar = NULL WHERE id = ?', [me.id]);
    if (old && old.avatar) await deleteImage(old.avatar);
    await logChange('PROFILE PHOTO REMOVED', me.name + ' <' + me.email + '>', me.id);
    return json(200, { avatar: null });
  }

  if (pathname === '/api/change-password' && method === 'POST'){
    const me = await requireUser(req);
    const body = await readJson(req);
    const current = String(body.currentPassword || '').slice(0, 200);
    const next = String(body.newPassword || '');
    if (next.length < 8)   throw new HttpError(400, 'Use a password with at least 8 characters.');
    if (next.length > 200) throw new HttpError(400, 'That password is too long.');
    const key = 'pwcheck:' + me.id;
    if (await tooManyFailures(key)) throw new HttpError(429, 'Too many wrong passwords. Wait a few minutes and try again.');
    const full = await DB.get('SELECT password_hash FROM users WHERE id = ?', [me.id]);
    if (!(await verifyPassword(current, full.password_hash))){
      await noteFailure(key);
      throw new HttpError(403, 'Your current password is incorrect.');
    }
    await clearFailures(key);
    if (next === current) throw new HttpError(400, 'Choose a password different from your current one.');
    await DB.run('UPDATE users SET password_hash = ? WHERE id = ?', [await hashPassword(next), me.id]);
    const token = parseCookies(req).sid;
    await DB.run('DELETE FROM sessions WHERE user_id = ? AND token_hash != ?', [me.id, await sha256(token || '')]);
    await logChange('PASSWORD CHANGED', me.name + ' <' + me.email + '>', me.id);
    return json(200, { ok: true });
  }

  if (pathname === '/api/register' && method === 'POST'){
    const body = await readJson(req);
    const name = String(body.name || '').trim();
    const email = String(body.email || '').trim().toLowerCase();
    const password = String(body.password || '');
    if (name.length < 2)   throw new HttpError(400, 'Enter your name.');
    if (name.length > 60)  throw new HttpError(400, 'That name is too long.');
    if (!EMAIL_RE.test(email) || email.length > 254) throw new HttpError(400, 'Enter a valid email address.');
    if (password.length < 8)   throw new HttpError(400, 'Use a password with at least 8 characters.');
    if (password.length > 200) throw new HttpError(400, 'That password is too long.');

    const ipKey = 'reg:' + ip;
    if (await tooManyFailures(ipKey)) throw new HttpError(429, 'Too many sign-ups from here. Try again later.');
    if (await DB.get('SELECT 1 AS x FROM users WHERE email = ?', [email])){
      throw new HttpError(409, 'An account with this email already exists. Try logging in.');
    }
    await noteFailure(ipKey);

    const id = 'u_' + randHex(8);
    await DB.run('INSERT INTO users (id, name, email, password_hash) VALUES (?, ?, ?, ?)',
      [id, name, email, await hashPassword(password)]);
    const cookie = await startSession(id);
    await logChange('NEW ACCOUNT', name + ' <' + email + '>', id);
    return json(201, { user: { id, name, email, role: 'user' } }, { 'Set-Cookie': cookie });
  }

  if (pathname === '/api/login' && method === 'POST'){
    const body = await readJson(req);
    const email = String(body.email || '').trim().toLowerCase();
    const password = String(body.password || '').slice(0, 200);
    const key = 'login:' + ip + ':' + email;
    if (await tooManyFailures(key)) throw new HttpError(429, 'Too many tries. Wait a few minutes and try again.');

    const user = await DB.get('SELECT * FROM users WHERE email = ?', [email]);
    let ok = false;
    if (user) ok = await verifyPassword(password, user.password_hash);
    else {
      if (!dummyHash) dummyHash = await hashPassword('not-a-real-password');
      await verifyPassword(password, dummyHash);
    }
    if (!user || !ok){
      await noteFailure(key);
      throw new HttpError(401, 'Email or password is incorrect.');
    }
    await clearFailures(key);
    const cookie = await startSession(user.id);
    await logChange('LOGIN', user.name + ' <' + user.email + '>', user.id);
    return json(200, { user: { id: user.id, name: user.name, email: user.email, role: user.role } }, { 'Set-Cookie': cookie });
  }

  if (pathname === '/api/logout' && method === 'POST'){
    const who = await currentUser(req);
    const token = parseCookies(req).sid;
    if (token) await DB.run('DELETE FROM sessions WHERE token_hash = ?', [await sha256(token)]);
    if (who) await logChange('LOGOUT', who.name + ' <' + who.email + '>', who.id);
    return json(200, { ok: true }, { 'Set-Cookie': sessionCookie('', 0) });
  }

  /* forgot / reset password */
  if (pathname === '/api/forgot-password' && method === 'POST'){
    const body = await readJson(req);
    const email = String(body.email || '').trim().toLowerCase();
    if (!(await allow('forgot-ip:' + ip, 10, 3600000))) throw new HttpError(429, 'Too many requests. Please try again later.');
    if (!EMAIL_RE.test(email) || email.length > 254) throw new HttpError(400, 'Enter a valid email address.');
    if (!(await allow('forgot-mail:' + email, 3, 3600000))) throw new HttpError(429, 'Too many requests for this email. Try again later.');
    const user = await DB.get('SELECT id, name, email FROM users WHERE email = ?', [email]);
    if (!user) throw new HttpError(404, 'No account is registered with this email address.');

    const token = randB64url(32);
    await DB.run('DELETE FROM password_resets WHERE user_id = ?', [user.id]);
    await DB.run('INSERT INTO password_resets (token_hash, user_id, expires_at) VALUES (?, ?, ?)',
      [await sha256(token), user.id, Date.now() + RESET_MINUTES * 60000]);
    await deliverResetLink(user, base + '/reset.html?token=' + encodeURIComponent(token));
    await logChange('PASSWORD RESET REQUESTED', user.name + ' <' + user.email + '>', user.id);
    return json(200, { ok: true });
  }

  if (pathname === '/api/reset-password' && method === 'POST'){
    const body = await readJson(req);
    const token = String(body.token || '');
    const password = String(body.password || '');
    if (!(await allow('reset-ip:' + ip, 20, 900000))) throw new HttpError(429, 'Too many tries. Please wait a few minutes.');
    if (password.length < 8)   throw new HttpError(400, 'Use a password with at least 8 characters.');
    if (password.length > 200) throw new HttpError(400, 'That password is too long.');

    const invalid = () => new HttpError(400, 'This link is invalid or has expired. Ask for a new one.');
    if (!token || token.length > 200) throw invalid();
    const tokenHash = await sha256(token);
    const row = await DB.get('SELECT user_id, expires_at FROM password_resets WHERE token_hash = ?', [tokenHash]);
    if (!row || row.expires_at < Date.now()) throw invalid();

    const newHash = await hashPassword(password);
    if (!(await DB.run('DELETE FROM password_resets WHERE token_hash = ?', [tokenHash])).changes) throw invalid();

    await DB.run('UPDATE users SET password_hash = ? WHERE id = ?', [newHash, row.user_id]);
    await DB.run('DELETE FROM password_resets WHERE user_id = ?', [row.user_id]);
    await DB.run('DELETE FROM sessions WHERE user_id = ?', [row.user_id]);
    const who = await DB.get('SELECT name, email FROM users WHERE id = ?', [row.user_id]);
    if (who) await logChange('PASSWORD RESET', who.name + ' <' + who.email + '>', row.user_id);
    return json(200, { ok: true });
  }

  /* items */
  if (pathname === '/api/items' && method === 'GET'){
    return json(200, { items: await loadItems(null, await currentUser(req)) });
  }

  if (pathname === '/api/items' && method === 'POST'){
    const me = await requireUser(req);
    if (me.role === 'admin') throw new HttpError(403, 'Admin accounts can only view objects.');
    const body = await readJson(req, MAX_BODY_WITH_PHOTO);
    const name = text(body.name, 'The object name', 80);
    let price = body.price == null || body.price === '' ? 0 : body.price;
    if (!Number.isInteger(price) || price < 0 || price > 10000000){
      throw new HttpError(400, 'Price must be a whole number of pesos (0 or more).');
    }
    const ch = chapterFields(body.chapter || {});
    const imgs = parseImages(body);
    const id = await DB.transaction(async tx => {
      for (const im of imgs) await tx.run('INSERT INTO images (name, data) VALUES (?, ?)', [im.name, im.b64]);
      const r = await tx.run('INSERT INTO items (name, price, image, created_by) VALUES (?, ?, ?, ?)',
        [name, price, imgs.length ? imgs[0].name : null, me.id]);
      const itemId = r.lastInsertRowid;
      for (let i = 0; i < imgs.length; i++){
        await tx.run('INSERT INTO item_images (item_id, name, position) VALUES (?, ?, ?)', [itemId, imgs[i].name, i]);
      }
      await insertChapter(tx, itemId, me.id, me.name, ch);
      return itemId;
    });
    await logChange('OBJECT LISTED', '#' + id + ' "' + name + '" by ' + me.name + (imgs.length ? ' [' + imgs.length + ' photo' + (imgs.length > 1 ? 's' : '') + ']' : ''), me.id);
    return json(201, { item: (await loadItems(id, me))[0] });
  }

  let m = pathname.match(/^\/api\/items\/(\d+)\/chapters$/);
  if (m && method === 'POST'){
    const me = await requireUser(req);
    if (me.role === 'admin') throw new HttpError(403, 'Admin accounts can only view objects.');
    const itemId = Number(m[1]);
    if (!(await DB.get('SELECT 1 AS x FROM items WHERE id = ?', [itemId]))) throw new HttpError(404, 'That object no longer exists.');
    const t = await DB.get('SELECT to_email FROM transfers WHERE item_id = ?', [itemId]);
    if (!t || t.to_email !== me.email){
      throw new HttpError(403, 'Only the person this object was passed to can add a chapter. Ask its owner to pass it to your email.');
    }
    const ch = chapterFields(await readJson(req));
    const done = await DB.transaction(async tx => {
      const r = await tx.run('DELETE FROM transfers WHERE item_id = ? AND to_email = ?', [itemId, me.email]);
      if (!r.changes) return false;
      await insertChapter(tx, itemId, me.id, me.name, ch);
      return true;
    });
    if (!done) throw new HttpError(409, 'This object is no longer waiting for you.');
    await logChange('CHAPTER ADDED', 'object #' + itemId + ' by ' + me.name + ' (new owner)', me.id);
    return json(201, { item: (await loadItems(itemId, me))[0] });
  }

  m = pathname.match(/^\/api\/items\/(\d+)\/transfer$/);
  if (m && method === 'POST'){
    const me = await requireUser(req);
    const itemId = Number(m[1]);
    const item = (await loadItems(itemId, me))[0];
    if (!item) throw new HttpError(404, 'That object no longer exists.');
    if (item.ownerId !== me.id) throw new HttpError(403, 'Only the current owner can pass this object on.');
    if (!(await allow('transfer:' + me.id, 20, 3600000))) throw new HttpError(429, 'Too many transfers. Please try again later.');
    const body = await readJson(req);
    const email = String(body.email || '').trim().toLowerCase();
    const again = String(body.confirmEmail || '').trim().toLowerCase();
    if (!EMAIL_RE.test(email) || email.length > 254) throw new HttpError(400, 'Enter a valid email address for the new owner.');
    if (email !== again)    throw new HttpError(400, 'The two email addresses do not match.');
    if (email === me.email) throw new HttpError(400, 'You cannot pass an object to yourself.');
    await DB.run(`INSERT INTO transfers (item_id, from_user_id, to_email) VALUES (?, ?, ?)
      ON CONFLICT(item_id) DO UPDATE SET from_user_id = excluded.from_user_id, to_email = excluded.to_email, created_at = CURRENT_TIMESTAMP`,
      [itemId, me.id, email]);
    const toUser = await DB.get('SELECT name FROM users WHERE email = ?', [email]);
    await deliverTransferNotice({
      fromName: me.name, toEmail: email, toName: toUser && toUser.name, itemName: item.name,
      link: base + (toUser ? '/login.html?next=' + encodeURIComponent('index.html#explore') : '/register.html')
    });
    await logChange('OBJECT PASSED ON', '#' + itemId + ' "' + item.name + '" to ' + email, me.id);
    return json(200, { item: (await loadItems(itemId, me))[0] });
  }

  if (m && method === 'DELETE'){
    const me = await requireUser(req);
    const itemId = Number(m[1]);
    const item = (await loadItems(itemId, me))[0];
    if (!item) throw new HttpError(404, 'That object no longer exists.');
    if (item.ownerId !== me.id) throw new HttpError(403, 'Only the current owner can cancel a transfer.');
    await DB.run('DELETE FROM transfers WHERE item_id = ?', [itemId]);
    await logChange('TRANSFER CANCELLED', '#' + itemId + ' "' + item.name + '"', me.id);
    return json(200, { item: (await loadItems(itemId, me))[0] });
  }

  m = pathname.match(/^\/api\/items\/(\d+)$/);
  if (m && method === 'DELETE'){
    const me = await requireUser(req);
    const itemId = Number(m[1]);
    const row = await DB.get('SELECT name, image, created_by FROM items WHERE id = ?', [itemId]);
    if (!row) throw new HttpError(404, 'That object no longer exists.');
    const owner = (await loadItems(itemId))[0].ownerId;
    const photoNames = (await DB.all('SELECT name FROM item_images WHERE item_id = ?', [itemId])).map(p => p.name);
    if (owner !== me.id && me.role !== 'admin') throw new HttpError(403, 'Only the current owner can remove an object.');
    await DB.transaction(async tx => {
      await tx.run('DELETE FROM transfers WHERE item_id = ?', [itemId]);
      await tx.run('DELETE FROM item_images WHERE item_id = ?', [itemId]);
      await tx.run('DELETE FROM chapters WHERE item_id = ?', [itemId]);
      await tx.run('DELETE FROM items WHERE id = ?', [itemId]);
    });
    for (const n of new Set([row.image, ...photoNames])) await deleteImage(n);
    await logChange('OBJECT REMOVED', '#' + itemId + ' "' + row.name + '" by ' + me.name + (me.role === 'admin' ? ' (admin)' : ''), me.id);
    if (row.created_by !== me.id) await logChange('OBJECT REMOVED', '#' + itemId + ' "' + row.name + '" was removed by ' + me.name + (me.role === 'admin' ? ' (admin)' : ''), row.created_by);
    return json(200, { ok: true });
  }

  /* admin */
  if (pathname === '/api/admin/users' && method === 'GET'){
    await requireAdmin(req);
    const users = await DB.all(`
      SELECT u.id, u.name, u.email, u.role, u.created_at,
        (SELECT COUNT(*) FROM items i WHERE i.created_by = u.id) AS items,
        (SELECT COUNT(*) FROM chapters c WHERE c.user_id = u.id) AS chapters
      FROM users u WHERE u.role != 'admin' ORDER BY u.created_at DESC`);
    return json(200, { users });
  }

  m = pathname.match(/^\/api\/admin\/users\/(\w+)\/history$/);
  if (m && method === 'GET'){
    await requireAdmin(req);
    const id = m[1];
    const user = await DB.get('SELECT id, name, email, role, created_at FROM users WHERE id = ?', [id]);
    if (!user) throw new HttpError(404, 'That account no longer exists.');
    const activity = await DB.all('SELECT action, detail, created_at FROM activity WHERE user_id = ? ORDER BY id DESC LIMIT 200', [id]);
    const items = await DB.all('SELECT id, name, price, created_at FROM items WHERE created_by = ? ORDER BY id DESC', [id]);
    const chapters = await DB.all(`
      SELECT c.id, i.name AS item_name, c.story, c.place, c.year, c.created_at
      FROM chapters c JOIN items i ON i.id = c.item_id
      WHERE c.user_id = ? ORDER BY c.id DESC`, [id]);
    return json(200, { user, activity, items, chapters });
  }

  m = pathname.match(/^\/api\/admin\/users\/(\w+)$/);
  if (m && method === 'DELETE'){
    const me = await requireAdmin(req);
    const id = m[1];
    if (id === me.id) throw new HttpError(400, 'You cannot delete your own account.');
    const target = await DB.get('SELECT id, name, email, role FROM users WHERE id = ?', [id]);
    if (!target) throw new HttpError(404, 'That account no longer exists.');
    if (target.role === 'admin') throw new HttpError(403, 'Admin accounts cannot be deleted here.');
    await DB.transaction(async tx => {
      await tx.run('DELETE FROM transfers WHERE from_user_id = ? OR item_id IN (SELECT id FROM items WHERE created_by = ?)', [id, id]);
      await tx.run('DELETE FROM images WHERE name IN (SELECT name FROM item_images WHERE item_id IN (SELECT id FROM items WHERE created_by = ?))', [id]);
      await tx.run('DELETE FROM item_images WHERE item_id IN (SELECT id FROM items WHERE created_by = ?)', [id]);
      await tx.run('DELETE FROM images WHERE name IN (SELECT image FROM items WHERE created_by = ? AND image IS NOT NULL)', [id]);
      await tx.run('DELETE FROM chapters WHERE item_id IN (SELECT id FROM items WHERE created_by = ?)', [id]);
      await tx.run('DELETE FROM items WHERE created_by = ?', [id]);
      await tx.run('DELETE FROM chapters WHERE user_id = ?', [id]);
      await tx.run('DELETE FROM activity WHERE user_id = ?', [id]);
      await tx.run('DELETE FROM sessions WHERE user_id = ?', [id]);
      await tx.run('DELETE FROM password_resets WHERE user_id = ?', [id]);
      await tx.run('DELETE FROM images WHERE name IN (SELECT avatar FROM users WHERE id = ? AND avatar IS NOT NULL)', [id]);
      await tx.run('DELETE FROM users WHERE id = ?', [id]);
    });
    await logChange('ACCOUNT DELETED', target.name + ' <' + target.email + '> by ' + me.name + ' (admin)');
    return json(200, { ok: true });
  }

  throw new HttpError(404, 'Not found.');
}

/* ---------- photos served from the database ---------- */
async function serveUpload(req, pathname){
  const notFound = () => new Response('Not found', { status: 404, headers: { 'Content-Type': 'text/plain; charset=utf-8' } });
  if (req.method !== 'GET' && req.method !== 'HEAD') return new Response(null, { status: 405, headers: { Allow: 'GET, HEAD' } });
  const name = pathname.slice('/uploads/'.length);
  if (!/^[a-f0-9]{24}\.jpg$/.test(name)) return notFound();
  const row = await DB.get('SELECT data FROM images WHERE name = ?', [name]);
  if (!row) return notFound();
  const bytes = Buffer.from(row.data, 'base64');
  const headers = {
    'Content-Type': 'image/jpeg',
    'Cache-Control': 'public, max-age=31536000, immutable',
    'X-Content-Type-Options': 'nosniff'
  };
  return new Response(req.method === 'HEAD' ? null : bytes, { status: 200, headers });
}

/* ---------- one-time setup per Worker instance ---------- */
let ready = null;
function init(){
  if (!ready) ready = (async () => {
    await DB.run('CREATE TABLE IF NOT EXISTS rate_limits (key TEXT PRIMARY KEY, count INTEGER NOT NULL, reset_at INTEGER NOT NULL)');
    const now = Date.now();
    await DB.run('DELETE FROM rate_limits WHERE reset_at < ?', [now]);
    await DB.run('DELETE FROM sessions WHERE expires_at < ?', [now]);
    await DB.run('DELETE FROM password_resets WHERE expires_at < ?', [now]);
    await seedAdmin();
  })().catch(e => { ready = null; throw e; });
  return ready;
}

async function seedAdmin(){
  const email = String(env.ADMIN_EMAIL || 'admin@atlas.local').toLowerCase();
  const existing = await DB.get('SELECT id, role FROM users WHERE email = ?', [email]);
  if (existing){
    if (existing.role !== 'admin') await DB.run("UPDATE users SET role = 'admin' WHERE id = ?", [existing.id]);
    return;
  }
  if (await DB.get("SELECT 1 AS x FROM users WHERE role = 'admin'")) return;
  if (!env.ADMIN_PASSWORD){ console.log('No admin account exists. Set ADMIN_EMAIL and ADMIN_PASSWORD to create one.'); return; }
  await DB.run("INSERT INTO users (id, name, email, password_hash, role) VALUES (?, ?, ?, ?, 'admin')",
    ['u_' + randHex(8), 'Admin', email, await hashPassword(String(env.ADMIN_PASSWORD))]);
  console.log('Admin account created for ' + email);
}

/* ---------- entry point ---------- */
export default {
  async fetch(request){
    try{
      if (!env.TURSO_DATABASE_URL || !env.TURSO_AUTH_TOKEN) throw new HttpError(500, 'Database not configured.');
      await init();
      const pathname = new URL(request.url).pathname;
      if (pathname.startsWith('/api/')) return await api(request, pathname);
      if (pathname.startsWith('/uploads/')) return await serveUpload(request, pathname);
      return await env.ASSETS.fetch(request);
    }catch(err){
      if (err instanceof HttpError) return json(err.status, { error: err.message });
      console.error(err);
      return json(500, { error: 'Something went wrong on the server.' });
    }
  }
};