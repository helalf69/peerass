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

async function initDatabase() {
  if (!fs.existsSync(privateDir)) fs.mkdirSync(privateDir, { recursive: true });

  const db = new sqlite3.Database(dbPath);

  const defaultPasswordHash = hashWithSalt(DEFAULT_PASSWORD, DEFAULT_SALT);

  await run(
    db,
    `CREATE TABLE IF NOT EXISTS user (
      idUser INTEGER PRIMARY KEY AUTOINCREMENT,
      isAdmin INTEGER NOT NULL DEFAULT 0,
      Name TEXT NOT NULL UNIQUE,
      Password TEXT NOT NULL DEFAULT '${defaultPasswordHash}'
    )`
  );

  // Keep password default encrypted, even for existing rows with legacy plain value.
  await run(
    db,
    `UPDATE user
     SET Password = ?
     WHERE Password = 'Java5cript'`,
    [defaultPasswordHash]
  );

  const hawk = await get(db, `SELECT idUser FROM user WHERE Name = ?`, ["Hawk"]);
  if (!hawk) {
    await run(
      db,
      `INSERT INTO user (isAdmin, Name, Password) VALUES (?, ?, ?)`,
      [1, "Hawk", hashPassword(DEFAULT_PASSWORD)]
    );
  } else {
    await run(db, `UPDATE user SET isAdmin = 1 WHERE Name = ?`, ["Hawk"]);
  }

  return db;
}

module.exports = {
  dbPath,
  hashPassword,
  verifyPassword,
  run,
  get,
  initDatabase,
};

