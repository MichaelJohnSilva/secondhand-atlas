'use strict';
const http = require('node:http');
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const db = require('./db');

/* ---------- terminal log + activity history ---------- */
const SHOW_TABLES = process.env.SHOW_TABLES !== '0';   // set SHOW_TABLES=0 to print only the one-line messages
function logChange(action, detail, userId){
  console.log('[' + new Date().toLocaleTimeString() + '] ' + action + (detail ? ': ' + detail : ''));
  if (userId){
    try { db.prepare('INSERT INTO activity (user_id, action, detail) VALUES (?, ?, ?)').run(userId, action, detail || null); }
    catch (e) {}
  }
}
function showTables(){
  if (!SHOW_TABLES) return;
  console.log('USERS');
  console.table(db.prepare('SELECT id, name, email, role, created_at FROM users').all());
  console.log('ITEMS');
  console.table(db.prepare('SELECT id, name, price, image, created_by FROM items').all());
  console.log('CHAPTERS');
  console.table(db.prepare('SELECT id, item_id, owner_name, place, year, substr(story, 1, 40) AS story FROM chapters').all());
}

const PORT = Number(process.env.PORT) || 3000;
const HOST = process.env.HOST || '127.0.0.1';      // set HOST=0.0.0.0 on a real server
const SECURE = process.env.COOKIE_SECURE === '1';   // set to 1 once the site runs on https
const PUBLIC = path.join(__dirname, 'public');
const DATA_DIR = process.env.DATA_DIR || path.join(__dirname, 'data');
const UPLOADS = path.join(DATA_DIR, 'uploads');     // object photos are saved here
fs.mkdirSync(UPLOADS, { recursive: true });
const SESSION_DAYS = 30;
const MAX_BODY = 100 * 1024;
const MAX_BODY_WITH_PHOTO = 3.5 * 1024 * 1024;
const IMAGE_MAX_BYTES = 2 * 1024 * 1024;

class HttpError extends Error {
  constructor(status, message){ super(message); this.status = status; }
}

/* ---------- small helpers ---------- */
const sha256 = t => crypto.createHash('sha256').update(t).digest('hex');

function send(res, status, body, headers = {}){
  const json = body === undefined ? '' : JSON.stringify(body);
  res.writeHead(status, {
    'Content-Type': 'application/json; charset=utf-8',
    'Cache-Control': 'no-store',
    ...headers
  });
  res.end(json);
}

function readJson(req, limit = MAX_BODY){
  return new Promise((resolve, reject) => {
    const type = String(req.headers['content-type'] || '');
    if (!type.toLowerCase().startsWith('application/json')) return reject(new HttpError(415, 'Send JSON.'));
    let size = 0; const chunks = [];
    req.on('data', c => {
      size += c.length;
      if (size > limit){ reject(new HttpError(413, 'That request is too large.')); req.destroy(); return; }
      chunks.push(c);
    });
    req.on('end', () => {
      try { resolve(JSON.parse(Buffer.concat(chunks).toString('utf8') || '{}')); }
      catch (e) { reject(new HttpError(400, 'Bad JSON.')); }
    });
    req.on('error', reject);
  });
}

function parseCookies(req){
  const out = {};
  String(req.headers.cookie || '').split(';').forEach(part => {
    const i = part.indexOf('=');
    if (i > 0) out[part.slice(0, i).trim()] = part.slice(i + 1).trim();
  });
  return out;
}

const sessionCookie = (value, maxAgeSeconds) =>
  `sid=${value}; HttpOnly; SameSite=Lax; Path=/; Max-Age=${maxAgeSeconds}${SECURE ? '; Secure' : ''}`;

/* ---------- photos ---------- */
/* takes "data:image/jpeg;base64,...", checks it really is a JPEG, saves it, returns the file name */
function saveImage(dataUrl){
  if (dataUrl == null || dataUrl === '') return null;
  const m = /^data:image\/jpeg;base64,([A-Za-z0-9+/]+={0,2})$/.exec(String(dataUrl));
  if (!m) throw new HttpError(400, 'The photo must be a JPEG image.');
  const bytes = Buffer.from(m[1], 'base64');
  if (bytes.length > IMAGE_MAX_BYTES) throw new HttpError(400, 'That photo is too large (at most 2 MB).');
  if (bytes.length < 4 || bytes[0] !== 0xFF || bytes[1] !== 0xD8 || bytes[2] !== 0xFF){
    throw new HttpError(400, 'The photo must be a JPEG image.');
  }
  const name = crypto.randomBytes(12).toString('hex') + '.jpg';
  fs.writeFileSync(path.join(UPLOADS, name), bytes);
  return name;
}

function deleteImage(name){
  if (!name || !/^[a-f0-9]{24}\.jpg$/.test(name)) return;
  fs.unlink(path.join(UPLOADS, name), () => {});
}

/* ---------- passwords (scrypt, built into Node) ---------- */
const scrypt = (password, salt) => new Promise((resolve, reject) => {
  crypto.scrypt(password, salt, 64, { N: 16384, r: 8, p: 1, maxmem: 64 * 1024 * 1024 },
    (err, key) => err ? reject(err) : resolve(key));
});

async function hashPassword(password){
  const salt = crypto.randomBytes(16);
  const key = await scrypt(password, salt);
  return 'scrypt$' + salt.toString('hex') + '$' + key.toString('hex');
}

async function verifyPassword(password, stored){
  const [alg, saltHex, keyHex] = String(stored).split('$');
  if (alg !== 'scrypt' || !saltHex || !keyHex) return false;
  const expected = Buffer.from(keyHex, 'hex');
  const key = await scrypt(password, Buffer.from(saltHex, 'hex'));
  return key.length === expected.length && crypto.timingSafeEqual(key, expected);
}

let dummyHash = null;   // so "no such email" takes as long as "wrong password"

/* ---------- sessions ---------- */
function startSession(res, userId){
  const token = crypto.randomBytes(32).toString('base64url');
  const expires = Date.now() + SESSION_DAYS * 86400000;
  db.prepare('INSERT INTO sessions (token_hash, user_id, expires_at) VALUES (?, ?, ?)')
    .run(sha256(token), userId, expires);
  res.setHeader('Set-Cookie', sessionCookie(token, SESSION_DAYS * 86400));
}

function currentUser(req){
  const token = parseCookies(req).sid;
  if (!token) return null;
  const row = db.prepare(`
    SELECT u.id, u.name, u.email, u.role, s.expires_at
    FROM sessions s JOIN users u ON u.id = s.user_id
    WHERE s.token_hash = ?`).get(sha256(token));
  if (!row) return null;
  if (row.expires_at < Date.now()){
    db.prepare('DELETE FROM sessions WHERE token_hash = ?').run(sha256(token));
    return null;
  }
  return { id: row.id, name: row.name, email: row.email, role: row.role };
}

function requireUser(req){
  const u = currentUser(req);
  if (!u) throw new HttpError(401, 'Please log in first.');
  return u;
}

function requireAdmin(req){
  const u = requireUser(req);
  if (u.role !== 'admin') throw new HttpError(403, 'Admins only.');
  return u;
}

setInterval(() => {
  db.prepare('DELETE FROM sessions WHERE expires_at < ?').run(Date.now());
}, 3600000).unref();

/* ---------- slow down password guessing ---------- */
const attempts = new Map();   // key -> { count, resetAt }
function tooManyFailures(key){
  const a = attempts.get(key);
  return !!a && a.resetAt > Date.now() && a.count >= 10;
}
function noteFailure(key){
  const now = Date.now();
  const a = attempts.get(key);
  if (!a || a.resetAt <= now) attempts.set(key, { count: 1, resetAt: now + 15 * 60000 });
  else a.count++;
}
setInterval(() => {
  const now = Date.now();
  for (const [k, v] of attempts) if (v.resetAt <= now) attempts.delete(k);
}, 600000).unref();

/* ---------- password reset ---------- */
const RESET_MINUTES = 60;

db.exec(`CREATE TABLE IF NOT EXISTS password_resets (
  token_hash TEXT PRIMARY KEY,
  user_id    TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  expires_at INTEGER NOT NULL
)`);

/* ---------- passing an object on ---------- */
// One row per object that its owner passed on and that is waiting for the new owner's chapter.
db.exec(`CREATE TABLE IF NOT EXISTS transfers (
  item_id      INTEGER PRIMARY KEY REFERENCES items(id) ON DELETE CASCADE,
  from_user_id TEXT NOT NULL,
  to_email     TEXT NOT NULL,
  created_at   TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
)`);

setInterval(() => {
  db.prepare('DELETE FROM password_resets WHERE expires_at < ?').run(Date.now());
}, 3600000).unref();

/* simple "at most N times per window" limiter */
const hits = new Map();
function allow(key, max, windowMs){
  const now = Date.now();
  const h = hits.get(key);
  if (!h || h.resetAt <= now){ hits.set(key, { count: 1, resetAt: now + windowMs }); return true; }
  h.count++;
  return h.count <= max;
}
setInterval(() => {
  const now = Date.now();
  for (const [k, v] of hits) if (v.resetAt <= now) hits.delete(k);
}, 600000).unref();

/* ---------- sending email (Brevo) ---------- */
const BREVO_API_KEY = process.env.BREVO_API_KEY || '';
const MAIL_FROM_EMAIL = process.env.MAIL_FROM_EMAIL || '';
const MAIL_FROM_NAME = process.env.MAIL_FROM_NAME || 'Secondhand Atlas';

const escHtml = s => String(s).replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));

async function sendEmail({ to, toName, subject, html, textBody }){
  const res = await fetch('https://api.brevo.com/v3/smtp/email', {
    method: 'POST',
    headers: {
      'accept': 'application/json',
      'content-type': 'application/json',
      'api-key': BREVO_API_KEY
    },
    body: JSON.stringify({
      sender: { name: MAIL_FROM_NAME, email: MAIL_FROM_EMAIL },
      to: [{ email: to, name: toName }],
      subject,
      htmlContent: html,
      textContent: textBody
    }),
    signal: AbortSignal.timeout(15000)
  });
  if (!res.ok){
    let msg = '';
    try { msg = (await res.json()).message || ''; } catch (e) {}
    throw new Error('Brevo answered ' + res.status + (msg ? ': ' + msg : ''));
  }
}

/* Sends the reset email. It never throws, so the forgot-password reply stays the same
   whether or not an account exists. With no Brevo settings it prints the link instead (test mode). */
async function deliverResetLink(user, link){
  if (!BREVO_API_KEY || !MAIL_FROM_EMAIL){
    console.log('\n=== PASSWORD RESET LINK (test mode: email is not set up) ===');
    console.log('For:  ' + user.email);
    console.log('Link: ' + link);
    console.log('Valid for ' + RESET_MINUTES + ' minutes, one use.\n');
    return;
  }
  try{
    const name = escHtml(user.name);
    await sendEmail({
      to: user.email,
      toName: user.name,
      subject: 'Reset your Secondhand Atlas password',
      textBody:
        'Hi ' + user.name + ',\n\n' +
        'Someone asked to reset the password for your Secondhand Atlas account. ' +
        'Open this link to choose a new one (it works once and expires in ' + RESET_MINUTES + ' minutes):\n\n' +
        link + '\n\n' +
        'If you did not ask for this, you can ignore this email. Your password will not change.',
      html:
        '<div style="font-family:Arial,Helvetica,sans-serif;max-width:480px;margin:0 auto;color:#1D2B33;line-height:1.5">' +
        '<h2 style="margin:0 0 12px">Reset your password</h2>' +
        '<p>Hi ' + name + ',</p>' +
        '<p>Someone asked to reset the password for your Secondhand Atlas account. ' +
        'Use the button below to choose a new one. It works once and expires in ' + RESET_MINUTES + ' minutes.</p>' +
        '<p style="margin:24px 0"><a href="' + escHtml(link) + '" style="background:#1D2B33;color:#ffffff;' +
        'padding:12px 20px;border-radius:6px;text-decoration:none;font-weight:bold;display:inline-block">Choose a new password</a></p>' +
        '<p style="font-size:14px;color:#586870">Button not working? Copy this link into your browser:<br>' + escHtml(link) + '</p>' +
        '<p style="font-size:14px;color:#586870">If you did not ask for this, you can ignore this email. Your password will not change.</p>' +
        '</div>'
    });
    console.log('Reset email handed to Brevo for ' + user.email + ' (check Brevo > Transactional > Logs for delivery)');
  }catch(e){
    console.error('Could not send the reset email to ' + user.email + ': ' + e.message);
  }
}

/* Tells the new owner an object was passed to them. Never throws. */
async function deliverTransferNotice({ fromName, toEmail, toName, itemName, link }){
  if (!BREVO_API_KEY || !MAIL_FROM_EMAIL){
    console.log('\n=== OBJECT PASSED ON (test mode: email is not set up) ===');
    console.log('To:   ' + toEmail);
    console.log('Link: ' + link + '\n');
    return;
  }
  try{
    await sendEmail({
      to: toEmail,
      toName: toName || toEmail,
      subject: fromName + ' passed "' + itemName + '" to you on Secondhand Atlas',
      textBody:
        fromName + ' passed "' + itemName + '" to you.\n\n' +
        'Log in (or register with this same email address) and add your chapter to become its new owner:\n\n' +
        link + '\n\nIf you were not expecting this, you can ignore this email.',
      html:
        '<div style="font-family:Arial,Helvetica,sans-serif;max-width:480px;margin:0 auto;color:#242424;line-height:1.5">' +
        '<h2 style="margin:0 0 12px">An object was passed to you</h2>' +
        '<p>' + escHtml(fromName) + ' passed <b>' + escHtml(itemName) + '</b> to you.</p>' +
        '<p>Log in, or register with this same email address, and add your chapter to become its new owner.</p>' +
        '<p style="margin:24px 0"><a href="' + escHtml(link) + '" style="background:#0F6CBD;color:#ffffff;' +
        'padding:12px 20px;border-radius:4px;text-decoration:none;font-weight:bold;display:inline-block">Open Secondhand Atlas</a></p>' +
        '<p style="font-size:14px;color:#616161">If you were not expecting this, you can ignore this email.</p></div>'
    });
    console.log('Transfer email handed to Brevo for ' + toEmail + ' (check Brevo > Transactional > Logs)');
  }catch(e){
    console.error('Could not send the transfer email to ' + toEmail + ': ' + e.message);
  }
}

/* ---------- validation ---------- */
const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/;

function text(value, label, max){
  const s = String(value == null ? '' : value).trim();
  if (!s) throw new HttpError(400, label + ' is required.');
  if (s.length > max) throw new HttpError(400, label + ' is too long (at most ' + max + ' characters).');
  return s;
}

function coords(lat, lng){
  if (typeof lat !== 'number' || typeof lng !== 'number' ||
      !Number.isFinite(lat) || !Number.isFinite(lng) || Math.abs(lat) > 90 || Math.abs(lng) > 180){
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
/* viewer (optional) decides what the person may see about a transfer */
function loadItems(onlyId, viewer){
  const items = onlyId == null
    ? db.prepare('SELECT id, name, price, image, created_by FROM items ORDER BY id').all()
    : db.prepare('SELECT id, name, price, image, created_by FROM items WHERE id = ?').all(onlyId);
  const chapters = onlyId == null
    ? db.prepare('SELECT * FROM chapters ORDER BY id').all()
    : db.prepare('SELECT * FROM chapters WHERE item_id = ? ORDER BY id').all(onlyId);
  const transfers = onlyId == null
    ? db.prepare('SELECT item_id, to_email FROM transfers').all()
    : db.prepare('SELECT item_id, to_email FROM transfers WHERE item_id = ?').all(onlyId);
  const tById = new Map(transfers.map(t => [t.item_id, t]));
  const byId = new Map(items.map(i => [i.id, {
    id: i.id, name: i.name, price: i.price,
    image: i.image ? '/uploads/' + i.image : null,
    createdBy: i.created_by,
    chapters: []
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
    it.ownerId = (last && last.userId) || it.createdBy;   // the current owner wrote the newest chapter
    const t = tById.get(it.id);
    it.passedOn = !!t;                                      // everyone may see that it was passed on
    if (t && viewer){
      if (viewer.id === it.ownerId) it.passedTo = t.to_email;      // only the owner sees the email
      if (viewer.email === t.to_email) it.passedToYou = true;      // and the person it was passed to
    }
    delete it.createdBy;
  }
  return [...byId.values()];
}

const insertChapter = db.prepare(`
  INSERT INTO chapters (item_id, user_id, owner_name, story, lat, lng, place, year)
  VALUES (?, ?, ?, ?, ?, ?, ?, ?)`);

/* ---------- API routes ---------- */
async function api(req, res, pathname){
  const method = req.method;

  // block other websites from making changes on a logged-in person's behalf
  if (method !== 'GET' && method !== 'HEAD'){
    const origin = req.headers.origin;
    if (origin){
      let host = '';
      try { host = new URL(origin).host; } catch (e) {}
      if (host !== req.headers.host) throw new HttpError(403, 'Cross-site requests are not allowed.');
    }
  }

  if (pathname === '/api/me' && method === 'GET'){
    return send(res, 200, { user: currentUser(req) });
  }

  if (pathname === '/api/register' && method === 'POST'){
    const body = await readJson(req);
    const name = String(body.name || '').trim();
    const email = String(body.email || '').trim().toLowerCase();
    const password = String(body.password || '');
    if (name.length < 2)             throw new HttpError(400, 'Enter your name.');
    if (name.length > 60)            throw new HttpError(400, 'That name is too long.');
    if (!EMAIL_RE.test(email) || email.length > 254) throw new HttpError(400, 'Enter a valid email address.');
    if (password.length < 8)         throw new HttpError(400, 'Use a password with at least 8 characters.');
    if (password.length > 200)       throw new HttpError(400, 'That password is too long.');

    const ipKey = 'reg:' + req.socket.remoteAddress;
    if (tooManyFailures(ipKey)) throw new HttpError(429, 'Too many sign-ups from here. Try again later.');
    if (db.prepare('SELECT 1 FROM users WHERE email = ?').get(email)){
      throw new HttpError(409, 'An account with this email already exists. Try logging in.');
    }
    noteFailure(ipKey);   // limit: 10 sign-ups per 15 minutes from one address

    const id = 'u_' + crypto.randomBytes(8).toString('hex');
    db.prepare('INSERT INTO users (id, name, email, password_hash) VALUES (?, ?, ?, ?)')
      .run(id, name, email, await hashPassword(password));
    startSession(res, id);
    logChange('NEW ACCOUNT', name + ' <' + email + '>', id);
    showTables();
    return send(res, 201, { user: { id, name, email, role: 'user' } });
  }

  if (pathname === '/api/login' && method === 'POST'){
    const body = await readJson(req);
    const email = String(body.email || '').trim().toLowerCase();
    const password = String(body.password || '').slice(0, 200);
    const key = 'login:' + req.socket.remoteAddress + ':' + email;
    if (tooManyFailures(key)) throw new HttpError(429, 'Too many tries. Wait a few minutes and try again.');

    const user = db.prepare('SELECT * FROM users WHERE email = ?').get(email);
    if (!dummyHash) dummyHash = await hashPassword('not-a-real-password');
    const ok = await verifyPassword(password, user ? user.password_hash : dummyHash);
    if (!user || !ok){
      noteFailure(key);
      throw new HttpError(401, 'Email or password is incorrect.');
    }
    attempts.delete(key);
    startSession(res, user.id);
    logChange('LOGIN', user.name + ' <' + user.email + '>', user.id);
    return send(res, 200, { user: { id: user.id, name: user.name, email: user.email, role: user.role } });
  }

  if (pathname === '/api/logout' && method === 'POST'){
    const who = currentUser(req);
    const token = parseCookies(req).sid;
    if (token) db.prepare('DELETE FROM sessions WHERE token_hash = ?').run(sha256(token));
    if (who) logChange('LOGOUT', who.name + ' <' + who.email + '>', who.id);
    return send(res, 200, { ok: true }, { 'Set-Cookie': sessionCookie('', 0) });
  }

  /* ---------- forgot / reset password ---------- */
  if (pathname === '/api/forgot-password' && method === 'POST'){
    const body = await readJson(req);
    const email = String(body.email || '').trim().toLowerCase();
    const ip = req.socket.remoteAddress;
    if (!allow('forgot-ip:' + ip, 10, 3600000)) throw new HttpError(429, 'Too many requests. Please try again later.');

    // the answer is always the same, so this form cannot be used to find out who has an account
    const reply = () => send(res, 200, { ok: true });
    if (!EMAIL_RE.test(email) || email.length > 254) return reply();
    if (!allow('forgot-mail:' + email, 3, 3600000)) return reply();

    const user = db.prepare('SELECT id, name, email FROM users WHERE email = ?').get(email);
    if (user){
      const token = crypto.randomBytes(32).toString('base64url');
      db.prepare('DELETE FROM password_resets WHERE user_id = ?').run(user.id);   // only the newest link works
      db.prepare('INSERT INTO password_resets (token_hash, user_id, expires_at) VALUES (?, ?, ?)')
        .run(sha256(token), user.id, Date.now() + RESET_MINUTES * 60000);
      // on a live site set SITE_URL (for example https://yourdomain.com) so the link cannot be tampered with
      const base = process.env.SITE_URL || ('http://' + (req.headers.host || 'localhost:' + PORT));
      deliverResetLink(user, base + '/reset.html?token=' + encodeURIComponent(token));
      logChange('PASSWORD RESET REQUESTED', user.name + ' <' + user.email + '>', user.id);
    }
    return reply();
  }

  if (pathname === '/api/reset-password' && method === 'POST'){
    const body = await readJson(req);
    const token = String(body.token || '');
    const password = String(body.password || '');
    if (!allow('reset-ip:' + req.socket.remoteAddress, 20, 900000)) throw new HttpError(429, 'Too many tries. Please wait a few minutes.');
    if (password.length < 8)   throw new HttpError(400, 'Use a password with at least 8 characters.');
    if (password.length > 200) throw new HttpError(400, 'That password is too long.');

    const invalid = () => new HttpError(400, 'This link is invalid or has expired. Ask for a new one.');
    if (!token || token.length > 200) throw invalid();
    const tokenHash = sha256(token);
    const row = db.prepare('SELECT user_id, expires_at FROM password_resets WHERE token_hash = ?').get(tokenHash);
    if (!row || row.expires_at < Date.now()) throw invalid();

    const newHash = await hashPassword(password);
    // deleting the token is what makes the link single-use, even if two requests arrive at once
    if (!db.prepare('DELETE FROM password_resets WHERE token_hash = ?').run(tokenHash).changes) throw invalid();

    db.prepare('UPDATE users SET password_hash = ? WHERE id = ?').run(newHash, row.user_id);
    db.prepare('DELETE FROM password_resets WHERE user_id = ?').run(row.user_id);
    db.prepare('DELETE FROM sessions WHERE user_id = ?').run(row.user_id);   // sign out everywhere
    const who = db.prepare('SELECT name, email FROM users WHERE id = ?').get(row.user_id);
    if (who) logChange('PASSWORD RESET', who.name + ' <' + who.email + '>', row.user_id);
    return send(res, 200, { ok: true });
  }

  if (pathname === '/api/items' && method === 'GET'){
    return send(res, 200, { items: loadItems(null, currentUser(req)) });
  }

  if (pathname === '/api/items' && method === 'POST'){
    const me = requireUser(req);
    if (me.role === 'admin') throw new HttpError(403, 'Admin accounts can only view objects.');
    const body = await readJson(req, MAX_BODY_WITH_PHOTO);
    const name = text(body.name, 'The object name', 80);
    let price = body.price == null || body.price === '' ? 0 : body.price;
    if (!Number.isInteger(price) || price < 0 || price > 10000000){
      throw new HttpError(400, 'Price must be a whole number of pesos (0 or more).');
    }
    const ch = chapterFields(body.chapter || {});
    const imageName = saveImage(body.image);   // checked last, so bad forms never leave a file behind
    let id;
    try{
      id = db.transaction(() => {
        const r = db.prepare('INSERT INTO items (name, price, image, created_by) VALUES (?, ?, ?, ?)')
          .run(name, price, imageName, me.id);
        const itemId = Number(r.lastInsertRowid);
        insertChapter.run(itemId, me.id, me.name, ch.story, ch.lat, ch.lng, ch.place, new Date().getFullYear());
        return itemId;
      });
    }catch(e){
      deleteImage(imageName);
      throw e;
    }
    logChange('OBJECT LISTED', '#' + id + ' "' + name + '" by ' + me.name + (imageName ? ' [photo ' + imageName + ']' : ''), me.id);
    showTables();
    return send(res, 201, { item: loadItems(id, me)[0] });
  }

  let m = pathname.match(/^\/api\/items\/(\d+)\/chapters$/);
  if (m && method === 'POST'){
    const me = requireUser(req);
    if (me.role === 'admin') throw new HttpError(403, 'Admin accounts can only view objects.');
    const itemId = Number(m[1]);
    if (!db.prepare('SELECT 1 FROM items WHERE id = ?').get(itemId)) throw new HttpError(404, 'That object no longer exists.');
    // only the person the owner passed it to may add a chapter
    const t = db.prepare('SELECT to_email FROM transfers WHERE item_id = ?').get(itemId);
    if (!t || t.to_email !== me.email){
      throw new HttpError(403, 'Only the person this object was passed to can add a chapter. Ask its owner to pass it to your email.');
    }
    const ch = chapterFields(await readJson(req));
    let done = false;
    db.transaction(() => {
      // deleting the transfer is what makes it single-use, even if two requests arrive at once
      if (!db.prepare('DELETE FROM transfers WHERE item_id = ? AND to_email = ?').run(itemId, me.email).changes) return;
      insertChapter.run(itemId, me.id, me.name, ch.story, ch.lat, ch.lng, ch.place, new Date().getFullYear());
      done = true;
    });
    if (!done) throw new HttpError(409, 'This object is no longer waiting for you.');
    logChange('CHAPTER ADDED', 'object #' + itemId + ' by ' + me.name + ' (new owner)', me.id);
    showTables();
    return send(res, 201, { item: loadItems(itemId, me)[0] });
  }

  m = pathname.match(/^\/api\/items\/(\d+)\/transfer$/);
  if (m && method === 'POST'){            // the owner says: passed on, to this email
    const me = requireUser(req);
    const itemId = Number(m[1]);
    const item = loadItems(itemId, me)[0];
    if (!item) throw new HttpError(404, 'That object no longer exists.');
    if (item.ownerId !== me.id) throw new HttpError(403, 'Only the current owner can pass this object on.');
    if (!allow('transfer:' + me.id, 20, 3600000)) throw new HttpError(429, 'Too many transfers. Please try again later.');
    const body = await readJson(req);
    const email = String(body.email || '').trim().toLowerCase();
    const again = String(body.confirmEmail || '').trim().toLowerCase();
    if (!EMAIL_RE.test(email) || email.length > 254) throw new HttpError(400, 'Enter a valid email address for the new owner.');
    if (email !== again)    throw new HttpError(400, 'The two email addresses do not match.');
    if (email === me.email) throw new HttpError(400, 'You cannot pass an object to yourself.');
    db.prepare(`INSERT INTO transfers (item_id, from_user_id, to_email) VALUES (?, ?, ?)
      ON CONFLICT(item_id) DO UPDATE SET from_user_id = excluded.from_user_id, to_email = excluded.to_email, created_at = CURRENT_TIMESTAMP`)
      .run(itemId, me.id, email);
    const toUser = db.prepare('SELECT name FROM users WHERE email = ?').get(email);
    const base = process.env.SITE_URL || ('http://' + (req.headers.host || 'localhost:' + PORT));
    deliverTransferNotice({
      fromName: me.name, toEmail: email, toName: toUser && toUser.name, itemName: item.name,
      link: base + (toUser ? '/login.html?next=' + encodeURIComponent('index.html#explore') : '/register.html')
    });
    logChange('OBJECT PASSED ON', '#' + itemId + ' "' + item.name + '" to ' + email, me.id);
    return send(res, 200, { item: loadItems(itemId, me)[0] });
  }

  if (m && method === 'DELETE'){          // the owner cancels (for example, a wrong email)
    const me = requireUser(req);
    const itemId = Number(m[1]);
    const item = loadItems(itemId, me)[0];
    if (!item) throw new HttpError(404, 'That object no longer exists.');
    if (item.ownerId !== me.id) throw new HttpError(403, 'Only the current owner can cancel a transfer.');
    db.prepare('DELETE FROM transfers WHERE item_id = ?').run(itemId);
    logChange('TRANSFER CANCELLED', '#' + itemId + ' "' + item.name + '"', me.id);
    return send(res, 200, { item: loadItems(itemId, me)[0] });
  }

  m = pathname.match(/^\/api\/items\/(\d+)$/);
  if (m && method === 'DELETE'){
    const me = requireUser(req);
    const itemId = Number(m[1]);
    const row = db.prepare('SELECT name, image, created_by FROM items WHERE id = ?').get(itemId);
    if (!row) throw new HttpError(404, 'That object no longer exists.');
    const owner = loadItems(itemId)[0].ownerId;
    if (owner !== me.id && me.role !== 'admin') throw new HttpError(403, 'Only the current owner can remove an object.');
    db.prepare('DELETE FROM transfers WHERE item_id = ?').run(itemId);
    db.prepare('DELETE FROM items WHERE id = ?').run(itemId);   // its chapters are deleted with it
    deleteImage(row.image);                                     // and its photo file
    logChange('OBJECT REMOVED', '#' + itemId + ' "' + row.name + '" by ' + me.name + (me.role === 'admin' ? ' (admin)' : ''), me.id);
    if (row.created_by !== me.id) logChange('OBJECT REMOVED', '#' + itemId + ' "' + row.name + '" was removed by ' + me.name + (me.role === 'admin' ? ' (admin)' : ''), row.created_by);
    showTables();
    return send(res, 200, { ok: true });
  }

  /* ---------- admin: list accounts, view history, delete accounts ---------- */
  if (pathname === '/api/admin/users' && method === 'GET'){
    requireAdmin(req);
    const users = db.prepare(`
      SELECT u.id, u.name, u.email, u.role, u.created_at,
        (SELECT COUNT(*) FROM items i WHERE i.created_by = u.id) AS items,
        (SELECT COUNT(*) FROM chapters c WHERE c.user_id = u.id) AS chapters
      FROM users u
      WHERE u.role != 'admin'
      ORDER BY u.created_at DESC`).all();
    return send(res, 200, { users });
  }

  m = pathname.match(/^\/api\/admin\/users\/(\w+)\/history$/);
  if (m && method === 'GET'){
    requireAdmin(req);
    const id = m[1];
    const user = db.prepare('SELECT id, name, email, role, created_at FROM users WHERE id = ?').get(id);
    if (!user) throw new HttpError(404, 'That account no longer exists.');
    const activity = db.prepare('SELECT action, detail, created_at FROM activity WHERE user_id = ? ORDER BY id DESC LIMIT 200').all(id);
    const items = db.prepare('SELECT id, name, price, created_at FROM items WHERE created_by = ? ORDER BY id DESC').all(id);
    const chapters = db.prepare(`
      SELECT c.id, i.name AS item_name, c.story, c.place, c.year, c.created_at
      FROM chapters c JOIN items i ON i.id = c.item_id
      WHERE c.user_id = ? ORDER BY c.id DESC`).all(id);
    return send(res, 200, { user, activity, items, chapters });
  }

  m = pathname.match(/^\/api\/admin\/users\/(\w+)$/);
  if (m && method === 'DELETE'){
    const me = requireAdmin(req);
    const id = m[1];
    if (id === me.id) throw new HttpError(400, 'You cannot delete your own account.');
    const target = db.prepare('SELECT id, name, email, role FROM users WHERE id = ?').get(id);
    if (!target) throw new HttpError(404, 'That account no longer exists.');
    if (target.role === 'admin') throw new HttpError(403, 'Admin accounts cannot be deleted here.');
    const photos = db.prepare('SELECT image FROM items WHERE created_by = ?').all(id);
    db.transaction(() => {
      db.prepare('DELETE FROM transfers WHERE from_user_id = ? OR item_id IN (SELECT id FROM items WHERE created_by = ?)').run(id, id);
      db.prepare('DELETE FROM items WHERE created_by = ?').run(id);    // their objects (and all chapters on them)
      db.prepare('DELETE FROM chapters WHERE user_id = ?').run(id);    // their chapters on other people's objects
      db.prepare('DELETE FROM activity WHERE user_id = ?').run(id);    // their history
      db.prepare('DELETE FROM users WHERE id = ?').run(id);            // sessions go with it
    });
    photos.forEach(p => deleteImage(p.image));
    logChange('ACCOUNT DELETED', target.name + ' <' + target.email + '> by ' + me.name + ' (admin)');
    showTables();
    return send(res, 200, { ok: true });
  }

  throw new HttpError(404, 'Not found.');
}

/* ---------- photos served from data/uploads ---------- */
function serveUpload(req, res, pathname){
  if (req.method !== 'GET' && req.method !== 'HEAD'){
    res.writeHead(405, { Allow: 'GET, HEAD' }); return res.end();
  }
  const name = pathname.slice('/uploads/'.length);
  const notFound = () => { res.writeHead(404, { 'Content-Type': 'text/plain; charset=utf-8' }); res.end('Not found'); };
  if (!/^[a-f0-9]{24}\.jpg$/.test(name)) return notFound();
  const file = path.join(UPLOADS, name);
  fs.stat(file, (err, st) => {
    if (err || !st.isFile()) return notFound();
    res.writeHead(200, {
      'Content-Type': 'image/jpeg',
      'Content-Length': st.size,
      'Cache-Control': 'public, max-age=31536000, immutable'
    });
    if (req.method === 'HEAD') return res.end();
    fs.createReadStream(file).pipe(res);
  });
}

/* ---------- static files ---------- */
const MIME = {
  '.html': 'text/html; charset=utf-8', '.css': 'text/css; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8', '.json': 'application/json; charset=utf-8',
  '.svg': 'image/svg+xml', '.png': 'image/png', '.jpg': 'image/jpeg', '.jpeg': 'image/jpeg',
  '.webp': 'image/webp', '.ico': 'image/x-icon', '.txt': 'text/plain; charset=utf-8'
};

function serveStatic(req, res, pathname){
  if (req.method !== 'GET' && req.method !== 'HEAD'){
    res.writeHead(405, { Allow: 'GET, HEAD' }); return res.end();
  }
  let rel;
  try { rel = decodeURIComponent(pathname); } catch (e) { res.writeHead(400); return res.end('Bad request'); }
  if (rel.includes('\0')){ res.writeHead(400); return res.end('Bad request'); }
  if (rel === '/') rel = '/index.html';

  const file = path.normalize(path.join(PUBLIC, rel));
  const notFound = () => { res.writeHead(404, { 'Content-Type': 'text/plain; charset=utf-8' }); res.end('Not found'); };
  if (!file.startsWith(PUBLIC + path.sep) || path.basename(file).startsWith('.')) return notFound();

  fs.stat(file, (err, st) => {
    if (err || !st.isFile()) return notFound();
    res.writeHead(200, {
      'Content-Type': MIME[path.extname(file).toLowerCase()] || 'application/octet-stream',
      'Content-Length': st.size,
      'Cache-Control': 'no-cache'
    });
    if (req.method === 'HEAD') return res.end();
    fs.createReadStream(file).pipe(res);
  });
}

/* ---------- server ---------- */
const server = http.createServer(async (req, res) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
  try{
    const pathname = new URL(req.url, 'http://localhost').pathname;
    if (pathname.startsWith('/api/')) await api(req, res, pathname);
    else if (pathname.startsWith('/uploads/')) serveUpload(req, res, pathname);
    else serveStatic(req, res, pathname);
  }catch(err){
    if (err instanceof HttpError){
      if (!res.headersSent) send(res, err.status, { error: err.message });
    } else {
      console.error(err);
      if (!res.headersSent) send(res, 500, { error: 'Something went wrong on the server.' });
    }
  }
});

/* ---------- default admin (created once, on first start) ---------- */
async function seedAdmin(){
  const email = (process.env.ADMIN_EMAIL || 'admin@atlas.local').toLowerCase();
  const existing = db.prepare('SELECT id, role FROM users WHERE email = ?').get(email);
  if (existing){
    if (existing.role !== 'admin') db.prepare("UPDATE users SET role = 'admin' WHERE id = ?").run(existing.id);
    return;
  }
  if (db.prepare("SELECT 1 FROM users WHERE role = 'admin'").get()) return;   // already have one
  const password = process.env.ADMIN_PASSWORD || crypto.randomBytes(9).toString('base64url');
  const id = 'u_' + crypto.randomBytes(8).toString('hex');
  db.prepare("INSERT INTO users (id, name, email, password_hash, role) VALUES (?, ?, ?, ?, 'admin')")
    .run(id, 'Admin', email, await hashPassword(password));
  console.log('\n=== ADMIN ACCOUNT CREATED ===');
  console.log('Email:    ' + email);
  console.log('Password: ' + password + '   (shown once, save it)');
  console.log('=============================\n');
}

if (require.main === module){
  seedAdmin().then(() => {
    server.listen(PORT, HOST, () => {
      console.log('Secondhand Atlas is running at http://' + (HOST === '0.0.0.0' ? 'localhost' : HOST) + ':' + PORT);
    });
  });
}

module.exports = server;