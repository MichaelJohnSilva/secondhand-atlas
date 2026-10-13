'use strict';
const http = require('node:http');
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const db = require('./db');

/* ---------- terminal log + activity history ---------- */
const SHOW_TABLES = process.env.SHOW_TABLES !== '0';   // set SHOW_TABLES=0 to print only the one-line messages
async function logChange(action, detail, userId){
  console.log('[' + new Date().toLocaleTimeString() + '] ' + action + (detail ? ': ' + detail : ''));
  if (userId){
    try { await db.run('INSERT INTO activity (user_id, action, detail) VALUES (?, ?, ?)', [userId, action, detail || null]); }
    catch (e) {}
  }
}
async function showTables(){
  if (!SHOW_TABLES) return;
  try{
    console.log('USERS');
    console.table(await db.all('SELECT id, name, email, role, created_at FROM users'));
    console.log('ITEMS');
    console.table(await db.all('SELECT id, name, price, image, created_by FROM items'));
    console.log('CHAPTERS');
    console.table(await db.all('SELECT id, item_id, owner_name, place, year, substr(story, 1, 40) AS story FROM chapters'));
  }catch(e){ console.error('Could not print tables: ' + e.message); }
}

const PORT = Number(process.env.PORT) || 3000;
const HOST = process.env.HOST || '0.0.0.0';         // listen on all addresses (needed on Render)
const SECURE = process.env.COOKIE_SECURE === '1';   // set to 1 once the site runs on https
const PUBLIC = path.join(__dirname, 'public');
const SESSION_DAYS = 30;
const MAX_BODY = 100 * 1024;
const MAX_BODY_WITH_PHOTO = 12 * 1024 * 1024;   // room for up to 5 photos in one request
const MAX_PHOTOS = 5;
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

/* maxAgeSeconds = null makes a "session cookie": the browser forgets it when it is closed, so the person is logged out */
const sessionCookie = (value, maxAgeSeconds) =>
  `sid=${value}; HttpOnly; SameSite=Lax; Path=/${maxAgeSeconds == null ? '' : '; Max-Age=' + maxAgeSeconds}${SECURE ? '; Secure' : ''}`;


/* ---------- photos (stored in the database, so they survive restarts) ---------- */
/* takes "data:image/jpeg;base64,...", checks it really is a JPEG, returns { name, b64 } (nothing is saved yet) */
function parseImage(dataUrl){
  if (dataUrl == null || dataUrl === '') return null;
  const m = /^data:image\/jpeg;base64,([A-Za-z0-9+/]+={0,2})$/.exec(String(dataUrl));
  if (!m) throw new HttpError(400, 'The photo must be a JPEG image.');
  const bytes = Buffer.from(m[1], 'base64');
  if (bytes.length > IMAGE_MAX_BYTES) throw new HttpError(400, 'That photo is too large (at most 2 MB).');
  if (bytes.length < 4 || bytes[0] !== 0xFF || bytes[1] !== 0xD8 || bytes[2] !== 0xFF){
    throw new HttpError(400, 'The photo must be a JPEG image.');
  }
  return { name: crypto.randomBytes(12).toString('hex') + '.jpg', b64: m[1] };
}

/* accepts body.images (a list) or the old single body.image; returns up to MAX_PHOTOS checked photos */
function parseImages(body){
  let list = body.images;
  if (list == null) list = body.image ? [body.image] : [];
  if (!Array.isArray(list)) throw new HttpError(400, 'Photos must be a list.');
  if (list.length > MAX_PHOTOS) throw new HttpError(400, 'You can add at most ' + MAX_PHOTOS + ' photos.');
  return list.map(parseImage).filter(Boolean);
}

async function deleteImage(name){
  if (!name || !/^[a-f0-9]{24}\.jpg$/.test(name)) return;
  try { await db.run('DELETE FROM images WHERE name = ?', [name]); } catch (e) {}
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
async function startSession(res, userId){
  const token = crypto.randomBytes(32).toString('base64url');
  const expires = Date.now() + SESSION_DAYS * 86400000;
  await db.run('INSERT INTO sessions (token_hash, user_id, expires_at) VALUES (?, ?, ?)',
    [sha256(token), userId, expires]);
  res.setHeader('Set-Cookie', sessionCookie(token, null));   // no Max-Age: logs out when the browser is closed
}

async function currentUser(req){
  const token = parseCookies(req).sid;
  if (!token) return null;
  const row = await db.get(`
    SELECT u.id, u.name, u.email, u.role, u.avatar, s.expires_at
    FROM sessions s JOIN users u ON u.id = s.user_id
    WHERE s.token_hash = ?`, [sha256(token)]);
  if (!row) return null;
  if (row.expires_at < Date.now()){
    await db.run('DELETE FROM sessions WHERE token_hash = ?', [sha256(token)]);
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

setInterval(() => {
  db.run('DELETE FROM sessions WHERE expires_at < ?', [Date.now()]).catch(() => {});
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

/* (the password_resets, transfers and images tables are created in db.js) */

setInterval(() => {
  db.run('DELETE FROM password_resets WHERE expires_at < ?', [Date.now()]).catch(() => {});
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
async function loadItems(onlyId, viewer){
  const items = onlyId == null
    ? await db.all('SELECT id, name, price, image, created_by FROM items ORDER BY id')
    : await db.all('SELECT id, name, price, image, created_by FROM items WHERE id = ?', [onlyId]);
  const chapters = onlyId == null
    ? await db.all('SELECT * FROM chapters ORDER BY id')
    : await db.all('SELECT * FROM chapters WHERE item_id = ? ORDER BY id', [onlyId]);
  const transfers = onlyId == null
    ? await db.all('SELECT item_id, to_email FROM transfers')
    : await db.all('SELECT item_id, to_email FROM transfers WHERE item_id = ?', [onlyId]);
  const photoRows = onlyId == null
    ? await db.all('SELECT item_id, name FROM item_images ORDER BY item_id, position')
    : await db.all('SELECT item_id, name FROM item_images WHERE item_id = ? ORDER BY position', [onlyId]);
  const photosBy = new Map();
  for (const p of photoRows){
    if (!photosBy.has(p.item_id)) photosBy.set(p.item_id, []);
    photosBy.get(p.item_id).push(p.name);
  }
  /* objects listed before this change have only items.image, so fall back to it */
  const namesOf = i => photosBy.get(i.id) || (i.image ? [i.image] : []);
  const tById = new Map(transfers.map(t => [t.item_id, t]));
  const byId = new Map(items.map(i => [i.id, {
    id: i.id, name: i.name, price: i.price,
    images: namesOf(i).map(n => '/uploads/' + n),
    image: namesOf(i)[0] ? '/uploads/' + namesOf(i)[0] : null,
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

/* runner is either db or the tx given inside db.transaction */
const insertChapter = (runner, itemId, userId, ownerName, ch) => runner.run(`
  INSERT INTO chapters (item_id, user_id, owner_name, story, lat, lng, place, year)
  VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
  [itemId, userId, ownerName, ch.story, ch.lat, ch.lng, ch.place, new Date().getFullYear()]);

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
    return send(res, 200, { user: await currentUser(req) });
  }

  /* ---------- another person's public page ---------- */
  const pu = pathname.match(/^\/api\/users\/(\w+)$/);
  if (pu && method === 'GET'){
    await requireUser(req);
    const uid = pu[1];
    const u = await db.get("SELECT id, name, avatar, created_at FROM users WHERE id = ? AND role != 'admin'", [uid]);
    if (!u) throw new HttpError(404, 'That person no longer exists.');
    const items = await db.all('SELECT id, name, price, image, created_at FROM items WHERE created_by = ? ORDER BY id DESC', [uid]);
    const chapters = await db.all(`
      SELECT i.name AS item_name, c.story, c.year, c.created_at
      FROM chapters c JOIN items i ON i.id = c.item_id
      WHERE c.user_id = ? ORDER BY c.id DESC`, [uid]);
    return send(res, 200, {
      user: { id: u.id, name: u.name, avatar: u.avatar ? '/uploads/' + u.avatar : null, createdAt: u.created_at },
      items: items.map(i => ({ id: i.id, name: i.name, price: i.price, image: i.image ? '/uploads/' + i.image : null, createdAt: i.created_at })),
      chapters
    });
  }

  /* ---------- profile ---------- */
  if (pathname === '/api/profile' && method === 'GET'){
    const me = await requireUser(req);
    const row = await db.get('SELECT created_at FROM users WHERE id = ?', [me.id]);
    const stats = await db.get(`SELECT
      (SELECT COUNT(*) FROM items WHERE created_by = ?) AS items,
      (SELECT COUNT(*) FROM chapters WHERE user_id = ?) AS chapters`, [me.id, me.id]);
    return send(res, 200, { user: { ...me, createdAt: row ? row.created_at : null }, stats });
  }

  if (pathname === '/api/profile' && method === 'POST'){
    const me = await requireUser(req);
    if (!allow('profile:' + me.id, 30, 3600000)) throw new HttpError(429, 'Too many changes. Please try again later.');
    const body = await readJson(req);
    const name = String(body.name || '').trim();
    const email = String(body.email || '').trim().toLowerCase();
    if (name.length < 2)   throw new HttpError(400, 'Enter your name.');
    if (name.length > 60)  throw new HttpError(400, 'That name is too long.');
    if (!EMAIL_RE.test(email) || email.length > 254) throw new HttpError(400, 'Enter a valid email address.');

    const emailChanged = email !== me.email;
    if (emailChanged){
      const key = 'pwcheck:' + me.id;
      if (tooManyFailures(key)) throw new HttpError(429, 'Too many wrong passwords. Wait a few minutes and try again.');
      const full = await db.get('SELECT password_hash FROM users WHERE id = ?', [me.id]);
      const ok = await verifyPassword(String(body.currentPassword || '').slice(0, 200), full.password_hash);
      if (!ok){ noteFailure(key); throw new HttpError(403, 'Your current password is incorrect.'); }
      attempts.delete(key);
      if (await db.get('SELECT 1 AS x FROM users WHERE email = ? AND id != ?', [email, me.id])){
        throw new HttpError(409, 'Another account already uses this email address.');
      }
    }
    await db.transaction(async tx => {
      await tx.run('UPDATE users SET name = ?, email = ? WHERE id = ?', [name, email, me.id]);
      await tx.run('UPDATE chapters SET owner_name = ? WHERE user_id = ?', [name, me.id]);
      if (emailChanged) await tx.run('UPDATE transfers SET to_email = ? WHERE to_email = ?', [email, me.email]);
    });
    await logChange('PROFILE UPDATED', name + ' <' + email + '>' + (emailChanged ? ' (email changed from ' + me.email + ')' : ''), me.id);
    return send(res, 200, { user: { id: me.id, name, email, role: me.role, avatar: me.avatar } });
  }

  if (pathname === '/api/profile/photo' && method === 'POST'){
    const me = await requireUser(req);
    if (!allow('avatar:' + me.id, 20, 3600000)) throw new HttpError(429, 'Too many changes. Please try again later.');
    const body = await readJson(req, 4 * 1024 * 1024);
    const img = parseImage(body.image);
    if (!img) throw new HttpError(400, 'Choose a photo.');
    const old = await db.get('SELECT avatar FROM users WHERE id = ?', [me.id]);
    await db.transaction(async tx => {
      await tx.run('INSERT INTO images (name, data) VALUES (?, ?)', [img.name, img.b64]);
      await tx.run('UPDATE users SET avatar = ? WHERE id = ?', [img.name, me.id]);
    });
    if (old && old.avatar) await deleteImage(old.avatar);   // the previous photo
    await logChange('PROFILE PHOTO CHANGED', me.name + ' <' + me.email + '>', me.id);
    return send(res, 200, { avatar: '/uploads/' + img.name });
  }

  if (pathname === '/api/profile/photo' && method === 'DELETE'){
    const me = await requireUser(req);
    const old = await db.get('SELECT avatar FROM users WHERE id = ?', [me.id]);
    await db.run('UPDATE users SET avatar = NULL WHERE id = ?', [me.id]);
    if (old && old.avatar) await deleteImage(old.avatar);
    await logChange('PROFILE PHOTO REMOVED', me.name + ' <' + me.email + '>', me.id);
    return send(res, 200, { avatar: null });
  }

  if (pathname === '/api/change-password' && method === 'POST'){
    const me = await requireUser(req);
    const body = await readJson(req);
    const current = String(body.currentPassword || '').slice(0, 200);
    const next = String(body.newPassword || '');
    if (next.length < 8)   throw new HttpError(400, 'Use a password with at least 8 characters.');
    if (next.length > 200) throw new HttpError(400, 'That password is too long.');

    const key = 'pwcheck:' + me.id;
    if (tooManyFailures(key)) throw new HttpError(429, 'Too many wrong passwords. Wait a few minutes and try again.');
    const full = await db.get('SELECT password_hash FROM users WHERE id = ?', [me.id]);
    if (!(await verifyPassword(current, full.password_hash))){
      noteFailure(key);
      throw new HttpError(403, 'Your current password is incorrect.');
    }
    attempts.delete(key);
    if (next === current) throw new HttpError(400, 'Choose a password different from your current one.');

    await db.run('UPDATE users SET password_hash = ? WHERE id = ?', [await hashPassword(next), me.id]);
    const token = parseCookies(req).sid;
    await db.run('DELETE FROM sessions WHERE user_id = ? AND token_hash != ?', [me.id, sha256(token || '')]);   // sign out other devices
    await logChange('PASSWORD CHANGED', me.name + ' <' + me.email + '>', me.id);
    return send(res, 200, { ok: true });
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
    if (await db.get('SELECT 1 AS x FROM users WHERE email = ?', [email])){
      throw new HttpError(409, 'An account with this email already exists. Try logging in.');
    }
    noteFailure(ipKey);   // limit: 10 sign-ups per 15 minutes from one address

    const id = 'u_' + crypto.randomBytes(8).toString('hex');
    await db.run('INSERT INTO users (id, name, email, password_hash) VALUES (?, ?, ?, ?)',
      [id, name, email, await hashPassword(password)]);
    await startSession(res, id);
    await logChange('NEW ACCOUNT', name + ' <' + email + '>', id);
    await showTables();
    return send(res, 201, { user: { id, name, email, role: 'user' } });
  }

  if (pathname === '/api/login' && method === 'POST'){
    const body = await readJson(req);
    const email = String(body.email || '').trim().toLowerCase();
    const password = String(body.password || '').slice(0, 200);
    const key = 'login:' + req.socket.remoteAddress + ':' + email;
    if (tooManyFailures(key)) throw new HttpError(429, 'Too many tries. Wait a few minutes and try again.');

    const user = await db.get('SELECT * FROM users WHERE email = ?', [email]);
    if (!dummyHash) dummyHash = await hashPassword('not-a-real-password');
    const ok = await verifyPassword(password, user ? user.password_hash : dummyHash);
    if (!user || !ok){
      noteFailure(key);
      throw new HttpError(401, 'Email or password is incorrect.');
    }
    attempts.delete(key);
    await startSession(res, user.id);
    await logChange('LOGIN', user.name + ' <' + user.email + '>', user.id);
    return send(res, 200, { user: { id: user.id, name: user.name, email: user.email, role: user.role } });
  }

  if (pathname === '/api/logout' && method === 'POST'){
    const who = await currentUser(req);
    const token = parseCookies(req).sid;
    if (token) await db.run('DELETE FROM sessions WHERE token_hash = ?', [sha256(token)]);
    if (who) await logChange('LOGOUT', who.name + ' <' + who.email + '>', who.id);
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
        if (!EMAIL_RE.test(email) || email.length > 254) throw new HttpError(400, 'Enter a valid email address.');
    if (!allow('forgot-mail:' + email, 3, 3600000)) throw new HttpError(429, 'Too many requests for this email. Try again later.');
        const user = await db.get('SELECT id, name, email FROM users WHERE email = ?', [email]);
    if (!user) throw new HttpError(404, 'No account is registered with this email address.');

    const token = crypto.randomBytes(32).toString('base64url');
    await db.run('DELETE FROM password_resets WHERE user_id = ?', [user.id]);   // only the newest link works
    await db.run('INSERT INTO password_resets (token_hash, user_id, expires_at) VALUES (?, ?, ?)',
      [sha256(token), user.id, Date.now() + RESET_MINUTES * 60000]);
    // on a live site set SITE_URL (for example https://yourdomain.com) so the link cannot be tampered with
    const base = process.env.SITE_URL || ('http://' + (req.headers.host || 'localhost:' + PORT));
    deliverResetLink(user, base + '/reset.html?token=' + encodeURIComponent(token));
    await logChange('PASSWORD RESET REQUESTED', user.name + ' <' + user.email + '>', user.id);
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
    const row = await db.get('SELECT user_id, expires_at FROM password_resets WHERE token_hash = ?', [tokenHash]);
    if (!row || row.expires_at < Date.now()) throw invalid();

    const newHash = await hashPassword(password);
    // deleting the token is what makes the link single-use, even if two requests arrive at once
    if (!(await db.run('DELETE FROM password_resets WHERE token_hash = ?', [tokenHash])).changes) throw invalid();

    await db.run('UPDATE users SET password_hash = ? WHERE id = ?', [newHash, row.user_id]);
    await db.run('DELETE FROM password_resets WHERE user_id = ?', [row.user_id]);
    await db.run('DELETE FROM sessions WHERE user_id = ?', [row.user_id]);   // sign out everywhere
    const who = await db.get('SELECT name, email FROM users WHERE id = ?', [row.user_id]);
    if (who) await logChange('PASSWORD RESET', who.name + ' <' + who.email + '>', row.user_id);
    return send(res, 200, { ok: true });
  }

  if (pathname === '/api/items' && method === 'GET'){
    return send(res, 200, { items: await loadItems(null, await currentUser(req)) });
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
    const imgs = parseImages(body);   // checked last, so bad forms never leave anything behind
    const id = await db.transaction(async tx => {
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
    await showTables();
    return send(res, 201, { item: (await loadItems(id, me))[0] });
  }

  let m = pathname.match(/^\/api\/items\/(\d+)\/chapters$/);
  if (m && method === 'POST'){
    const me = await requireUser(req);
    if (me.role === 'admin') throw new HttpError(403, 'Admin accounts can only view objects.');
    const itemId = Number(m[1]);
    if (!(await db.get('SELECT 1 AS x FROM items WHERE id = ?', [itemId]))) throw new HttpError(404, 'That object no longer exists.');
    // only the person the owner passed it to may add a chapter
    const t = await db.get('SELECT to_email FROM transfers WHERE item_id = ?', [itemId]);
    if (!t || t.to_email !== me.email){
      throw new HttpError(403, 'Only the person this object was passed to can add a chapter. Ask its owner to pass it to your email.');
    }
    const ch = chapterFields(await readJson(req));
    const done = await db.transaction(async tx => {
      // deleting the transfer is what makes it single-use, even if two requests arrive at once
      const r = await tx.run('DELETE FROM transfers WHERE item_id = ? AND to_email = ?', [itemId, me.email]);
      if (!r.changes) return false;
      await insertChapter(tx, itemId, me.id, me.name, ch);
      return true;
    });
    if (!done) throw new HttpError(409, 'This object is no longer waiting for you.');
    await logChange('CHAPTER ADDED', 'object #' + itemId + ' by ' + me.name + ' (new owner)', me.id);
    await showTables();
    return send(res, 201, { item: (await loadItems(itemId, me))[0] });
  }

  m = pathname.match(/^\/api\/items\/(\d+)\/transfer$/);
  if (m && method === 'POST'){            // the owner says: passed on, to this email
    const me = await requireUser(req);
    const itemId = Number(m[1]);
    const item = (await loadItems(itemId, me))[0];
    if (!item) throw new HttpError(404, 'That object no longer exists.');
    if (item.ownerId !== me.id) throw new HttpError(403, 'Only the current owner can pass this object on.');
    if (!allow('transfer:' + me.id, 20, 3600000)) throw new HttpError(429, 'Too many transfers. Please try again later.');
    const body = await readJson(req);
    const email = String(body.email || '').trim().toLowerCase();
    const again = String(body.confirmEmail || '').trim().toLowerCase();
    if (!EMAIL_RE.test(email) || email.length > 254) throw new HttpError(400, 'Enter a valid email address for the new owner.');
    if (email !== again)    throw new HttpError(400, 'The two email addresses do not match.');
    if (email === me.email) throw new HttpError(400, 'You cannot pass an object to yourself.');
    await db.run(`INSERT INTO transfers (item_id, from_user_id, to_email) VALUES (?, ?, ?)
      ON CONFLICT(item_id) DO UPDATE SET from_user_id = excluded.from_user_id, to_email = excluded.to_email, created_at = CURRENT_TIMESTAMP`,
      [itemId, me.id, email]);
    const toUser = await db.get('SELECT name FROM users WHERE email = ?', [email]);
    const base = process.env.SITE_URL || ('http://' + (req.headers.host || 'localhost:' + PORT));
    deliverTransferNotice({
      fromName: me.name, toEmail: email, toName: toUser && toUser.name, itemName: item.name,
      link: base + (toUser ? '/login.html?next=' + encodeURIComponent('index.html#explore') : '/register.html')
    });
    await logChange('OBJECT PASSED ON', '#' + itemId + ' "' + item.name + '" to ' + email, me.id);
    return send(res, 200, { item: (await loadItems(itemId, me))[0] });
  }

  if (m && method === 'DELETE'){          // the owner cancels (for example, a wrong email)
    const me = await requireUser(req);
    const itemId = Number(m[1]);
    const item = (await loadItems(itemId, me))[0];
    if (!item) throw new HttpError(404, 'That object no longer exists.');
    if (item.ownerId !== me.id) throw new HttpError(403, 'Only the current owner can cancel a transfer.');
    await db.run('DELETE FROM transfers WHERE item_id = ?', [itemId]);
    await logChange('TRANSFER CANCELLED', '#' + itemId + ' "' + item.name + '"', me.id);
    return send(res, 200, { item: (await loadItems(itemId, me))[0] });
  }

  m = pathname.match(/^\/api\/items\/(\d+)$/);
  if (m && method === 'DELETE'){
    const me = await requireUser(req);
    const itemId = Number(m[1]);
    const row = await db.get('SELECT name, image, created_by FROM items WHERE id = ?', [itemId]);
    if (!row) throw new HttpError(404, 'That object no longer exists.');
    const owner = (await loadItems(itemId))[0].ownerId;
    const photoNames = (await db.all('SELECT name FROM item_images WHERE item_id = ?', [itemId])).map(p => p.name);
    if (owner !== me.id && me.role !== 'admin') throw new HttpError(403, 'Only the current owner can remove an object.');
    await db.transaction(async tx => {
      await tx.run('DELETE FROM transfers WHERE item_id = ?', [itemId]);
      await tx.run('DELETE FROM item_images WHERE item_id = ?', [itemId]);
      await tx.run('DELETE FROM chapters WHERE item_id = ?', [itemId]);
      await tx.run('DELETE FROM items WHERE id = ?', [itemId]);
    });
    for (const n of new Set([row.image, ...photoNames])) await deleteImage(n);   // and all its photos
    await logChange('OBJECT REMOVED', '#' + itemId + ' "' + row.name + '" by ' + me.name + (me.role === 'admin' ? ' (admin)' : ''), me.id);
    if (row.created_by !== me.id) await logChange('OBJECT REMOVED', '#' + itemId + ' "' + row.name + '" was removed by ' + me.name + (me.role === 'admin' ? ' (admin)' : ''), row.created_by);
    await showTables();
    return send(res, 200, { ok: true });
  }

  /* ---------- admin: list accounts, view history, delete accounts ---------- */
  if (pathname === '/api/admin/users' && method === 'GET'){
    await requireAdmin(req);
    const users = await db.all(`
      SELECT u.id, u.name, u.email, u.role, u.created_at,
        (SELECT COUNT(*) FROM items i WHERE i.created_by = u.id) AS items,
        (SELECT COUNT(*) FROM chapters c WHERE c.user_id = u.id) AS chapters
      FROM users u
      WHERE u.role != 'admin'
      ORDER BY u.created_at DESC`);
    return send(res, 200, { users });
  }

  m = pathname.match(/^\/api\/admin\/users\/(\w+)\/history$/);
  if (m && method === 'GET'){
    await requireAdmin(req);
    const id = m[1];
    const user = await db.get('SELECT id, name, email, role, created_at FROM users WHERE id = ?', [id]);
    if (!user) throw new HttpError(404, 'That account no longer exists.');
    const activity = await db.all('SELECT action, detail, created_at FROM activity WHERE user_id = ? ORDER BY id DESC LIMIT 200', [id]);
    const items = await db.all('SELECT id, name, price, created_at FROM items WHERE created_by = ? ORDER BY id DESC', [id]);
    const chapters = await db.all(`
      SELECT c.id, i.name AS item_name, c.story, c.place, c.year, c.created_at
      FROM chapters c JOIN items i ON i.id = c.item_id
      WHERE c.user_id = ? ORDER BY c.id DESC`, [id]);
    return send(res, 200, { user, activity, items, chapters });
  }

  m = pathname.match(/^\/api\/admin\/users\/(\w+)$/);
  if (m && method === 'DELETE'){
    const me = await requireAdmin(req);
    const id = m[1];
    if (id === me.id) throw new HttpError(400, 'You cannot delete your own account.');
    const target = await db.get('SELECT id, name, email, role FROM users WHERE id = ?', [id]);
    if (!target) throw new HttpError(404, 'That account no longer exists.');
    if (target.role === 'admin') throw new HttpError(403, 'Admin accounts cannot be deleted here.');
    await db.transaction(async tx => {
      await tx.run('DELETE FROM transfers WHERE from_user_id = ? OR item_id IN (SELECT id FROM items WHERE created_by = ?)', [id, id]);
      await tx.run('DELETE FROM images WHERE name IN (SELECT name FROM item_images WHERE item_id IN (SELECT id FROM items WHERE created_by = ?))', [id]);
      await tx.run('DELETE FROM item_images WHERE item_id IN (SELECT id FROM items WHERE created_by = ?)', [id]);
      await tx.run('DELETE FROM images WHERE name IN (SELECT image FROM items WHERE created_by = ? AND image IS NOT NULL)', [id]);
      await tx.run('DELETE FROM chapters WHERE item_id IN (SELECT id FROM items WHERE created_by = ?)', [id]);
      await tx.run('DELETE FROM items WHERE created_by = ?', [id]);    // their objects
      await tx.run('DELETE FROM chapters WHERE user_id = ?', [id]);    // their chapters on other people's objects
      await tx.run('DELETE FROM activity WHERE user_id = ?', [id]);    // their history
      await tx.run('DELETE FROM sessions WHERE user_id = ?', [id]);
      await tx.run('DELETE FROM password_resets WHERE user_id = ?', [id]);
      await tx.run('DELETE FROM images WHERE name IN (SELECT avatar FROM users WHERE id = ? AND avatar IS NOT NULL)', [id]);
      await tx.run('DELETE FROM users WHERE id = ?', [id]);
    });
    await logChange('ACCOUNT DELETED', target.name + ' <' + target.email + '> by ' + me.name + ' (admin)');
    await showTables();
    return send(res, 200, { ok: true });
  }

  throw new HttpError(404, 'Not found.');
}

/* ---------- photos served from the database ---------- */
async function serveUpload(req, res, pathname){
  if (req.method !== 'GET' && req.method !== 'HEAD'){
    res.writeHead(405, { Allow: 'GET, HEAD' }); return res.end();
  }
  const name = pathname.slice('/uploads/'.length);
  const notFound = () => { res.writeHead(404, { 'Content-Type': 'text/plain; charset=utf-8' }); res.end('Not found'); };
  if (!/^[a-f0-9]{24}\.jpg$/.test(name)) return notFound();
  const row = await db.get('SELECT data FROM images WHERE name = ?', [name]);
  if (!row) return notFound();
  const bytes = Buffer.from(row.data, 'base64');
  res.writeHead(200, {
    'Content-Type': 'image/jpeg',
    'Content-Length': bytes.length,
    'Cache-Control': 'public, max-age=31536000, immutable'
  });
  if (req.method === 'HEAD') return res.end();
  res.end(bytes);
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
    else if (pathname.startsWith('/uploads/')) await serveUpload(req, res, pathname);
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
  const existing = await db.get('SELECT id, role FROM users WHERE email = ?', [email]);
  if (existing){
    if (existing.role !== 'admin') await db.run("UPDATE users SET role = 'admin' WHERE id = ?", [existing.id]);
    return;
  }
  if (await db.get("SELECT 1 AS x FROM users WHERE role = 'admin'")) return;   // already have one
  const password = process.env.ADMIN_PASSWORD || crypto.randomBytes(9).toString('base64url');
  const id = 'u_' + crypto.randomBytes(8).toString('hex');
  await db.run("INSERT INTO users (id, name, email, password_hash, role) VALUES (?, ?, ?, ?, 'admin')",
    [id, 'Admin', email, await hashPassword(password)]);
  console.log('\n=== ADMIN ACCOUNT CREATED ===');
  console.log('Email:    ' + email);
  console.log('Password: ' + password + '   (shown once, save it)');
  console.log('=============================\n');
}

if (require.main === module){
  (async () => {
    await db.ready;      // tables exist
    await seedAdmin();
    server.listen(PORT, HOST, () => {
      console.log('Secondhand Atlas is running at http://' + (HOST === '0.0.0.0' ? 'localhost' : HOST) + ':' + PORT);
    });
  })().catch(err => {
    console.error('Could not start: ' + err.message);
    process.exit(1);
  });
}

module.exports = server;