const crypto = require("crypto");
const fs = require("fs");
const path = require("path");
const sqlite3 = require("sqlite3").verbose();

const privateDir = __dirname;
const dbPath = path.join(privateDir, "peerass.sqlite3");
const DEFAULT_PASSWORD = "Java5cript";
const DEFAULT_SALT = "peerass-default-salt";

function hashWithSalt(password, salt) {
  const iterations = 120000;
  const keylen = 64;
  const digest = "sha512";
  const hash = crypto.pbkdf2Sync(password, salt, iterations, keylen, digest).toString("hex");
  return `pbkdf2$${digest}$${iterations}$${salt}$${hash}`;
}

function hashPassword(password) {
  return hashWithSalt(password, crypto.randomBytes(16).toString("hex"));
}

function verifyPassword(password, storedHash) {
  if (!storedHash || typeof storedHash !== "string") return false;
  const parts = storedHash.split("$");
  if (parts.length !== 5 || parts[0] !== "pbkdf2") return false;
  const digest = parts[1];
  const iterations = Number(parts[2]);
  const salt = parts[3];
  const expectedHash = parts[4];
  const keylen = expectedHash.length / 2;
  const actualHash = crypto
    .pbkdf2Sync(password, salt, iterations, keylen, digest)
    .toString("hex");
  return crypto.timingSafeEqual(Buffer.from(actualHash, "hex"), Buffer.from(expectedHash, "hex"));
}

function run(db, sql, params = []) {
  return new Promise((resolve, reject) => {
    db.run(sql, params, function onRun(err) {
      if (err) return reject(err);
      resolve(this);
    });
  });
}

function get(db, sql, params = []) {
  return new Promise((resolve, reject) => {
    db.get(sql, params, (err, row) => {
      if (err) return reject(err);
      resolve(row);
    });
  });
}

function all(db, sql, params = []) {
  return new Promise((resolve, reject) => {
    db.all(sql, params, (err, rows) => {
      if (err) return reject(err);
      resolve(rows);
    });
  });
}

async function tableExists(db, name) {
  const row = await get(db, `SELECT name FROM sqlite_master WHERE type='table' AND name = ?`, [name]);
  return Boolean(row);
}

async function initDatabase() {
  if (!fs.existsSync(privateDir)) fs.mkdirSync(privateDir, { recursive: true });

  const db = new sqlite3.Database(dbPath);

  const defaultPasswordHash = hashWithSalt(DEFAULT_PASSWORD, DEFAULT_SALT);

  // SQLite runs DDL outside of explicit transactions; keep FK enforcement off during init/migrations
  // and turn it on at the end once schema is stable.
  await run(db, "PRAGMA foreign_keys = OFF");

  // Create user table if it doesn't exist (new schema: no idSub).
  await run(
    db,
    `CREATE TABLE IF NOT EXISTS user (
      idUser INTEGER PRIMARY KEY AUTOINCREMENT,
      isAdmin INTEGER NOT NULL DEFAULT 0,
      Name TEXT NOT NULL UNIQUE,
      Password TEXT NOT NULL DEFAULT '${defaultPasswordHash}',
      last_used INTEGER
    )`
  );

  try {
    await run(db, `ALTER TABLE user ADD COLUMN last_used INTEGER`);
  } catch (err) {
    if (!String(err.message || "").includes("duplicate column name")) throw err;
  }

  // Recover from a partially-applied legacy migration (user renamed to user_old, but app crashed before swap).
  if ((await tableExists(db, "user_old")) && !(await tableExists(db, "user"))) {
    await run(db, `ALTER TABLE user_old RENAME TO user`);
  }

  // Create (or keep) subject table (depends on user).
  await run(
    db,
    `CREATE TABLE IF NOT EXISTS subject (
      idSub INTEGER PRIMARY KEY AUTOINCREMENT,
      idUser INTEGER NOT NULL,
      subName TEXT NOT NULL,
      UNIQUE(idUser, subName),
      FOREIGN KEY(idUser) REFERENCES user(idUser)
    )`
  );

  // Join table connecting users <-> subjects.
  await run(
    db,
    `CREATE TABLE IF NOT EXISTS userSubject (
      idUserSub INTEGER PRIMARY KEY AUTOINCREMENT,
      idUser INTEGER NOT NULL,
      idSub INTEGER NOT NULL,
      UNIQUE(idUser, idSub),
      FOREIGN KEY(idUser) REFERENCES user(idUser) ON DELETE CASCADE,
      FOREIGN KEY(idSub) REFERENCES subject(idSub) ON DELETE CASCADE
    )`
  );

  // Placeholder for per-user activity rows; extend as the app grows.
  await run(
    db,
    `CREATE TABLE IF NOT EXISTS user_activity (
      idActivity INTEGER PRIMARY KEY AUTOINCREMENT,
      idUser INTEGER NOT NULL,
      kind TEXT NOT NULL,
      created_at INTEGER NOT NULL DEFAULT (strftime('%s','now')),
      FOREIGN KEY(idUser) REFERENCES user(idUser) ON DELETE CASCADE
    )`
  );

  // If an older DB had user.idSub, migrate it into userSubject and rebuild user table without idSub.
  const userCols = await all(db, `PRAGMA table_info(user)`);
  const hasLegacyIdSub = userCols.some((c) => c && c.name === "idSub");
  if (hasLegacyIdSub) {
    try {
      // Migrate legacy user.idSub to userSubject (ignore 0 / unset).
      await run(
        db,
        `INSERT OR IGNORE INTO userSubject (idUser, idSub)
         SELECT u.idUser, u.idSub
         FROM user u
         JOIN subject s ON s.idSub = u.idSub
         WHERE u.idSub IS NOT NULL AND u.idSub != 0`
      );

      // Rebuild user table without idSub.
      await run(db, `ALTER TABLE user RENAME TO user_old`);
      await run(
        db,
        `CREATE TABLE user (
          idUser INTEGER PRIMARY KEY AUTOINCREMENT,
          isAdmin INTEGER NOT NULL DEFAULT 0,
          Name TEXT NOT NULL UNIQUE,
          Password TEXT NOT NULL DEFAULT '${defaultPasswordHash}',
          last_used INTEGER
        )`
      );
      const oldUserCols = await all(db, `PRAGMA table_info(user_old)`);
      const oldHasLastUsed = oldUserCols.some((c) => c && c.name === "last_used");
      await run(
        db,
        oldHasLastUsed
          ? `INSERT INTO user (idUser, isAdmin, Name, Password, last_used)
             SELECT idUser, isAdmin, Name, Password, last_used FROM user_old`
          : `INSERT INTO user (idUser, isAdmin, Name, Password, last_used)
             SELECT idUser, isAdmin, Name, Password, NULL FROM user_old`
      );
      await run(db, `DROP TABLE user_old`);
    } catch (err) {
      throw err;
    }
  }

  // Keep password default encrypted, even for existing rows with legacy plain value.
  await run(
    db,
    `UPDATE user
     SET Password = ?
     WHERE Password = 'Java5cript'`,
    [defaultPasswordHash]
  );

  await run(
    db,
    `UPDATE user
     SET last_used = strftime('%s','now')
     WHERE last_used IS NULL`
  );

  const hawk = await get(db, `SELECT idUser FROM user WHERE Name = ?`, ["Hawk"]);
  if (!hawk) {
    await run(
      db,
      `INSERT INTO user (isAdmin, Name, Password, last_used) VALUES (?, ?, ?, strftime('%s','now'))`,
      [1, "Hawk", hashPassword(DEFAULT_PASSWORD)]
    );
  } else {
    await run(db, `UPDATE user SET isAdmin = 1 WHERE Name = ?`, ["Hawk"]);
  }

  await run(db, "PRAGMA foreign_keys = ON");

  return db;
}

module.exports = {
  dbPath,
  hashPassword,
  verifyPassword,
  run,
  get,
  all,
  initDatabase,
};

