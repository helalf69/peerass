const crypto = require("crypto");
const fs = require("fs");
const path = require("path");
const sqlite3 = require("sqlite3").verbose();

const privateDir = __dirname;
const dbPath = path.join(privateDir, "peerass.db");
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

async function ensureColumn(db, tableName, columnName, alterSql) {
  const columns = await all(db, `PRAGMA table_info(${tableName})`);
  const exists = columns.some((c) => String(c.name || "").toLowerCase() === String(columnName || "").toLowerCase());
  if (!exists) await run(db, alterSql);
}

async function initDatabase() {
  if (!fs.existsSync(privateDir)) fs.mkdirSync(privateDir, { recursive: true });

  const db = new sqlite3.Database(dbPath);
  // eslint-disable-next-line no-console
  console.log(`SQLite database path: ${dbPath}`);

  const defaultPasswordHash = hashWithSalt(DEFAULT_PASSWORD, DEFAULT_SALT);

  await run(db, "PRAGMA foreign_keys = OFF");

  // Clean schema (new database file: peerass.db)
  await run(
    db,
    `CREATE TABLE IF NOT EXISTS user (
      idUser INTEGER PRIMARY KEY AUTOINCREMENT,
      isAdmin INTEGER NOT NULL DEFAULT 0,
      Name TEXT NOT NULL UNIQUE,
      Password TEXT NOT NULL,
      last_used INTEGER
    )`
  );

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

  await run(
    db,
    `CREATE TABLE IF NOT EXISTS assessment (
      idAssessment INTEGER PRIMARY KEY AUTOINCREMENT,
      idSubject INTEGER NOT NULL,
      idTeacher INTEGER NOT NULL,
      title TEXT NOT NULL,
      instructions TEXT NOT NULL,
      isPlanned INTEGER NOT NULL DEFAULT 1,
      isOpen INTEGER NOT NULL DEFAULT 0,
      starts_at INTEGER,
      ends_at INTEGER,
      created_at INTEGER NOT NULL DEFAULT (strftime('%s','now')),
      updated_at INTEGER NOT NULL DEFAULT (strftime('%s','now')),
      FOREIGN KEY(idSubject) REFERENCES subject(idSub) ON DELETE CASCADE,
      FOREIGN KEY(idTeacher) REFERENCES user(idUser)
    )`
  );

  await run(
    db,
    `CREATE TABLE IF NOT EXISTS assessment_scale_level (
      idScaleLevel INTEGER PRIMARY KEY AUTOINCREMENT,
      idAssessment INTEGER NOT NULL,
      scale_value INTEGER NOT NULL,
      label TEXT NOT NULL,
      description TEXT,
      UNIQUE(idAssessment, scale_value),
      FOREIGN KEY(idAssessment) REFERENCES assessment(idAssessment) ON DELETE CASCADE
    )`
  );

  await run(
    db,
    `CREATE TABLE IF NOT EXISTS assessment_criterion (
      idCriterion INTEGER PRIMARY KEY AUTOINCREMENT,
      idAssessment INTEGER NOT NULL,
      name TEXT NOT NULL,
      description TEXT NOT NULL,
      sort_order INTEGER NOT NULL DEFAULT 0,
      FOREIGN KEY(idAssessment) REFERENCES assessment(idAssessment) ON DELETE CASCADE
    )`
  );

  await run(
    db,
    `CREATE TABLE IF NOT EXISTS assessment_criterion_scale_guideline (
      idGuideline INTEGER PRIMARY KEY AUTOINCREMENT,
      idCriterion INTEGER NOT NULL,
      scale_value INTEGER NOT NULL,
      guideline_text TEXT NOT NULL,
      UNIQUE(idCriterion, scale_value),
      FOREIGN KEY(idCriterion) REFERENCES assessment_criterion(idCriterion) ON DELETE CASCADE
    )`
  );

  await run(
    db,
    `CREATE TABLE IF NOT EXISTS assessment_target (
      idTarget INTEGER PRIMARY KEY AUTOINCREMENT,
      idAssessment INTEGER NOT NULL,
      idStudent INTEGER NOT NULL,
      attendance_status TEXT NOT NULL DEFAULT 'present',
      marked_by INTEGER,
      marked_at INTEGER,
      note TEXT,
      UNIQUE(idAssessment, idStudent),
      FOREIGN KEY(idAssessment) REFERENCES assessment(idAssessment) ON DELETE CASCADE,
      FOREIGN KEY(idStudent) REFERENCES user(idUser) ON DELETE CASCADE
    )`
  );

  await run(
    db,
    `CREATE TABLE IF NOT EXISTS assessment_submission (
      idSubmission INTEGER PRIMARY KEY AUTOINCREMENT,
      idAssessment INTEGER NOT NULL,
      idAssessor INTEGER NOT NULL,
      idTargetStudent INTEGER NOT NULL,
      submitted_at INTEGER NOT NULL DEFAULT (strftime('%s','now')),
      is_final INTEGER NOT NULL DEFAULT 1,
      UNIQUE(idAssessment, idAssessor, idTargetStudent),
      FOREIGN KEY(idAssessment) REFERENCES assessment(idAssessment) ON DELETE CASCADE,
      FOREIGN KEY(idAssessor) REFERENCES user(idUser) ON DELETE CASCADE,
      FOREIGN KEY(idTargetStudent) REFERENCES user(idUser) ON DELETE CASCADE
    )`
  );

  await run(
    db,
    `CREATE TABLE IF NOT EXISTS assessment_submission_score (
      idSubmissionScore INTEGER PRIMARY KEY AUTOINCREMENT,
      idSubmission INTEGER NOT NULL,
      idCriterion INTEGER NOT NULL,
      scale_value INTEGER NOT NULL,
      UNIQUE(idSubmission, idCriterion),
      FOREIGN KEY(idSubmission) REFERENCES assessment_submission(idSubmission) ON DELETE CASCADE,
      FOREIGN KEY(idCriterion) REFERENCES assessment_criterion(idCriterion) ON DELETE CASCADE
    )`
  );

  // Used by the app today for login / password-change auditing (safe to keep even if you "start over" on core tables).
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

  await run(db, "PRAGMA foreign_keys = ON");
  await ensureColumn(
    db,
    "assessment_target",
    "attendance_status",
    `ALTER TABLE assessment_target ADD COLUMN attendance_status TEXT NOT NULL DEFAULT 'present'`
  );
  await ensureColumn(
    db,
    "assessment_target",
    "marked_by",
    `ALTER TABLE assessment_target ADD COLUMN marked_by INTEGER`
  );
  await ensureColumn(
    db,
    "assessment_target",
    "marked_at",
    `ALTER TABLE assessment_target ADD COLUMN marked_at INTEGER`
  );
  await ensureColumn(
    db,
    "assessment_target",
    "note",
    `ALTER TABLE assessment_target ADD COLUMN note TEXT`
  );
  await run(
    db,
    `UPDATE assessment_target
     SET attendance_status = 'present'
     WHERE attendance_status IS NULL OR attendance_status NOT IN ('present', 'absent')`
  );

  // Normalize legacy/plain default password storage (if any rows ever contain the literal default).
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
    await run(db, `INSERT INTO user (isAdmin, Name, Password, last_used) VALUES (1, ?, ?, strftime('%s','now'))`, [
      "Hawk",
      hashPassword(DEFAULT_PASSWORD),
    ]);
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
  all,
  initDatabase,
};
