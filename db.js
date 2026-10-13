'use strict';
const { createClient } = require('@libsql/client');
const fs = require('node:fs');
const path = require('node:path');

/* On Render: set TURSO_DATABASE_URL and TURSO_AUTH_TOKEN.
   On your own computer (no env vars): falls back to a local file. */
let url = process.env.TURSO_DATABASE_URL;
if (!url) {
  const dataDir = process.env.DATA_DIR || path.join(__dirname, 'data');
  fs.mkdirSync(dataDir, { recursive: true });
  url = 'file:' + path.join(dataDir, 'atlas.db');
}

const client = createClient({ url, authToken: process.env.TURSO_AUTH_TOKEN });

const plain = rs => rs.rows.map(r => {
  const o = {};
  rs.columns.forEach((c, i) => { o[c] = r[i]; });
  return o;
});

const toResult = rs => ({
  changes: rs.rowsAffected,
  lastInsertRowid: rs.lastInsertRowid == null ? null : Number(rs.lastInsertRowid)
});

/* helpers shared by the db object and by transactions */
const api = exec => ({
  async all(sql, args = []) { return plain(await exec({ sql, args })); },
  async get(sql, args = []) { return plain(await exec({ sql, args }))[0]; },
  async run(sql, args = []) { return toResult(await exec({ sql, args })); }
});

const db = {
  ...api(stmt => client.execute(stmt)),

  /* run several statements as one all-or-nothing change.
     usage: await db.transaction(async tx => { await tx.run(...); await tx.get(...); }) */
  async transaction(fn) {
    const tx = await client.transaction('write');
    try {
      const out = await fn(api(stmt => tx.execute(stmt)));
      await tx.commit();
      return out;
    } catch (e) {
      try { await tx.rollback(); } catch (_) {}
      throw e;
    } finally {
      tx.close();
    }
  }
};

/* create the tables on startup. server.js must wait for this: await db.ready */
db.ready = (async () => {
  await client.executeMultiple(`
    CREATE TABLE IF NOT EXISTS users (
      id            TEXT PRIMARY KEY,
      name          TEXT NOT NULL,
      email         TEXT NOT NULL UNIQUE,
      password_hash TEXT NOT NULL,
      role          TEXT NOT NULL DEFAULT 'user',
      created_at    TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
    );

    CREATE TABLE IF NOT EXISTS sessions (
      token_hash TEXT PRIMARY KEY,
      user_id    TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      expires_at INTEGER NOT NULL
    );
    CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions(user_id);

    CREATE TABLE IF NOT EXISTS items (
      id         INTEGER PRIMARY KEY AUTOINCREMENT,
      name       TEXT NOT NULL,
      price      INTEGER NOT NULL DEFAULT 0 CHECK (price >= 0),
      image      TEXT,
      created_by TEXT NOT NULL REFERENCES users(id),
      created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
    );

    CREATE TABLE IF NOT EXISTS chapters (
      id         INTEGER PRIMARY KEY AUTOINCREMENT,
      item_id    INTEGER NOT NULL REFERENCES items(id) ON DELETE CASCADE,
      user_id    TEXT NOT NULL REFERENCES users(id),
      owner_name TEXT NOT NULL,
      story      TEXT NOT NULL,
      lat        REAL NOT NULL,
      lng        REAL NOT NULL,
      place      TEXT,
      year       INTEGER NOT NULL,
      created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
    );
    CREATE INDEX IF NOT EXISTS idx_chapters_item ON chapters(item_id, id);

    CREATE TABLE IF NOT EXISTS activity (
      id         INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id    TEXT NOT NULL,
      action     TEXT NOT NULL,
      detail     TEXT,
      created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
    );
    CREATE INDEX IF NOT EXISTS idx_activity_user ON activity(user_id, id);

    CREATE TABLE IF NOT EXISTS password_resets (
      token_hash TEXT PRIMARY KEY,
      user_id    TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      expires_at INTEGER NOT NULL
    );

    CREATE TABLE IF NOT EXISTS transfers (
      item_id      INTEGER PRIMARY KEY REFERENCES items(id) ON DELETE CASCADE,
      from_user_id TEXT NOT NULL,
      to_email     TEXT NOT NULL,
      created_at   TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
    );

    CREATE TABLE IF NOT EXISTS images (
      name TEXT PRIMARY KEY,
      data TEXT NOT NULL
    );
  `);
})();

module.exports = db;