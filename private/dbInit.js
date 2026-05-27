const crypto = require("crypto");
const fs = require("fs");
const path = require("path");
const sqlite3 = require("sqlite3").verbose();

const privateDir = __dirname;
const dbPath = path.join(privateDir, "peerass.db");
const DEFAULT_PASSWORD = "Java5cript";
const DEFAULT_SALT = "peerass-default-salt";
const DB_CLIENT = String(process.env.DB_CLIENT || "sqlite").trim().toLowerCase();

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
  if (db && db.__adapter === "mysql") {
    return runMySql(db, sql, params);
  }
  return new Promise((resolve, reject) => {
    db.run(sql, params, function onRun(err) {
      if (err) return reject(err);
      resolve(this);
    });
  });
}

function get(db, sql, params = []) {
  if (db && db.__adapter === "mysql") {
    return getMySql(db, sql, params);
  }
  return new Promise((resolve, reject) => {
    db.get(sql, params, (err, row) => {
      if (err) return reject(err);
      resolve(row);
    });
  });
}

function all(db, sql, params = []) {
  if (db && db.__adapter === "mysql") {
    return allMySql(db, sql, params);
  }
  return new Promise((resolve, reject) => {
    db.all(sql, params, (err, rows) => {
      if (err) return reject(err);
      resolve(rows);
    });
  });
}

async function ensureColumn(db, tableName, columnName, alterSql) {
  if (db && db.__adapter === "mysql") {
    const col = await getMySql(
      db,
      `SELECT COLUMN_NAME
       FROM INFORMATION_SCHEMA.COLUMNS
       WHERE TABLE_SCHEMA = DATABASE()
         AND TABLE_NAME = ?
         AND COLUMN_NAME = ?`,
      [tableName, columnName]
    );
    if (!col) await runMySql(db, alterSql);
    return;
  }
  const columns = await all(db, `PRAGMA table_info(${tableName})`);
  const exists = columns.some((c) => String(c.name || "").toLowerCase() === String(columnName || "").toLowerCase());
  if (!exists) await run(db, alterSql);
}

function normalizeSqlForMySql(sql) {
  return String(sql || "")
    .replace(/\bBEGIN\s+IMMEDIATE\b/gi, "START TRANSACTION")
    .replace(/strftime\('%s','now'\)/gi, "UNIX_TIMESTAMP()")
    .replace(/\bINSERT\s+OR\s+IGNORE\b/gi, "INSERT IGNORE")
    .replace(/\s+COLLATE\s+NOCASE\b/gi, "");
}

async function runMySql(db, sql, params = []) {
  const normalized = normalizeSqlForMySql(sql);
  const [result] = await db.query(normalized, params);
  return {
    lastID: result && result.insertId ? Number(result.insertId) : 0,
    changes: result && typeof result.affectedRows === "number" ? result.affectedRows : 0,
  };
}

async function getMySql(db, sql, params = []) {
  const normalized = normalizeSqlForMySql(sql);
  const [rows] = await db.query(normalized, params);
  if (!Array.isArray(rows) || rows.length === 0) return undefined;
  return rows[0];
}

async function allMySql(db, sql, params = []) {
  const normalized = normalizeSqlForMySql(sql);
  const [rows] = await db.query(normalized, params);
  return Array.isArray(rows) ? rows : [];
}

async function initMySqlDatabase() {
  let mysql;
  try {
    mysql = require("mysql2/promise");
  } catch (_err) {
    throw new Error("mysql2 is required for DB_CLIENT=mysql. Run: npm install mysql2");
  }

  const host = String(process.env.DB_HOST || "").trim();
  const port = Number(process.env.DB_PORT || 3306);
  const user = String(process.env.DB_USER || "").trim();
  const password = String(process.env.DB_PASSWORD || "");
  const database = String(process.env.DB_NAME || "").trim();
  const sslEnabled = String(process.env.DB_SSL || "false").toLowerCase() === "true";
  const sslRejectUnauthorized = String(process.env.DB_SSL_REJECT_UNAUTHORIZED || "true").toLowerCase() !== "false";

  if (!host || !user || !database) {
    throw new Error("Missing MySQL configuration. Required: DB_HOST, DB_USER, DB_NAME");
  }

  const baseConnection = await mysql.createConnection({
    host,
    port,
    user,
    password,
    ssl: sslEnabled ? { rejectUnauthorized: sslRejectUnauthorized } : undefined,
  });
  await baseConnection.query(`CREATE DATABASE IF NOT EXISTS \`${database}\` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci`);
  await baseConnection.end();

  const db = await mysql.createConnection({
    host,
    port,
    user,
    password,
    database,
    ssl: sslEnabled ? { rejectUnauthorized: sslRejectUnauthorized } : undefined,
  });
  db.__adapter = "mysql";

  const defaultPasswordHash = hashWithSalt(DEFAULT_PASSWORD, DEFAULT_SALT);

  await runMySql(
    db,
    `CREATE TABLE IF NOT EXISTS user (
      idUser INT AUTO_INCREMENT PRIMARY KEY,
      isAdmin TINYINT(1) NOT NULL DEFAULT 0,
      Name VARCHAR(255) NOT NULL UNIQUE,
      Password TEXT NOT NULL,
      last_used BIGINT
    ) ENGINE=InnoDB`
  );

  await runMySql(
    db,
    `CREATE TABLE IF NOT EXISTS subject (
      idSub INT AUTO_INCREMENT PRIMARY KEY,
      idUser INT NOT NULL,
      subName VARCHAR(255) NOT NULL,
      UNIQUE KEY uniq_subject_owner_name (idUser, subName),
      CONSTRAINT fk_subject_user FOREIGN KEY (idUser) REFERENCES user(idUser) ON DELETE CASCADE
    ) ENGINE=InnoDB`
  );

  await runMySql(
    db,
    `CREATE TABLE IF NOT EXISTS userSubject (
      idUserSub INT AUTO_INCREMENT PRIMARY KEY,
      idUser INT NOT NULL,
      idSub INT NOT NULL,
      UNIQUE KEY uniq_user_subject (idUser, idSub),
      CONSTRAINT fk_usersub_user FOREIGN KEY (idUser) REFERENCES user(idUser) ON DELETE CASCADE,
      CONSTRAINT fk_usersub_subject FOREIGN KEY (idSub) REFERENCES subject(idSub) ON DELETE CASCADE
    ) ENGINE=InnoDB`
  );

  await runMySql(
    db,
    `CREATE TABLE IF NOT EXISTS assessment (
      idAssessment INT AUTO_INCREMENT PRIMARY KEY,
      idSubject INT NOT NULL,
      idTeacher INT NOT NULL,
      title VARCHAR(255) NOT NULL,
      instructions TEXT NOT NULL,
      isPlanned TINYINT(1) NOT NULL DEFAULT 1,
      isOpen TINYINT(1) NOT NULL DEFAULT 0,
      isHidden TINYINT(1) NOT NULL DEFAULT 0,
      starts_at BIGINT,
      ends_at BIGINT,
      created_at BIGINT NOT NULL DEFAULT (UNIX_TIMESTAMP()),
      updated_at BIGINT NOT NULL DEFAULT (UNIX_TIMESTAMP()),
      CONSTRAINT fk_assessment_subject FOREIGN KEY (idSubject) REFERENCES subject(idSub) ON DELETE CASCADE,
      CONSTRAINT fk_assessment_teacher FOREIGN KEY (idTeacher) REFERENCES user(idUser) ON DELETE CASCADE
    ) ENGINE=InnoDB`
  );

  await runMySql(
    db,
    `CREATE TABLE IF NOT EXISTS assessment_scale_level (
      idScaleLevel INT AUTO_INCREMENT PRIMARY KEY,
      idAssessment INT NOT NULL,
      scale_value INT NOT NULL,
      label VARCHAR(255) NOT NULL,
      description TEXT,
      UNIQUE KEY uniq_scale_level (idAssessment, scale_value),
      CONSTRAINT fk_scale_level_assessment FOREIGN KEY (idAssessment) REFERENCES assessment(idAssessment) ON DELETE CASCADE
    ) ENGINE=InnoDB`
  );

  await runMySql(
    db,
    `CREATE TABLE IF NOT EXISTS assessment_criterion (
      idCriterion INT AUTO_INCREMENT PRIMARY KEY,
      idAssessment INT NOT NULL,
      name VARCHAR(255) NOT NULL,
      description TEXT NOT NULL,
      sort_order INT NOT NULL DEFAULT 0,
      CONSTRAINT fk_criterion_assessment FOREIGN KEY (idAssessment) REFERENCES assessment(idAssessment) ON DELETE CASCADE
    ) ENGINE=InnoDB`
  );

  await runMySql(
    db,
    `CREATE TABLE IF NOT EXISTS assessment_criterion_scale_guideline (
      idGuideline INT AUTO_INCREMENT PRIMARY KEY,
      idCriterion INT NOT NULL,
      scale_value INT NOT NULL,
      guideline_text TEXT NOT NULL,
      UNIQUE KEY uniq_criterion_scale (idCriterion, scale_value),
      CONSTRAINT fk_guideline_criterion FOREIGN KEY (idCriterion) REFERENCES assessment_criterion(idCriterion) ON DELETE CASCADE
    ) ENGINE=InnoDB`
  );

  await runMySql(
    db,
    `CREATE TABLE IF NOT EXISTS assessment_target (
      idTarget INT AUTO_INCREMENT PRIMARY KEY,
      idAssessment INT NOT NULL,
      idStudent INT NOT NULL,
      attendance_status VARCHAR(16) NOT NULL DEFAULT 'present',
      marked_by INT,
      marked_at BIGINT,
      note TEXT,
      UNIQUE KEY uniq_assessment_target (idAssessment, idStudent),
      CONSTRAINT fk_target_assessment FOREIGN KEY (idAssessment) REFERENCES assessment(idAssessment) ON DELETE CASCADE,
      CONSTRAINT fk_target_student FOREIGN KEY (idStudent) REFERENCES user(idUser) ON DELETE CASCADE
    ) ENGINE=InnoDB`
  );

  await runMySql(
    db,
    `CREATE TABLE IF NOT EXISTS assessment_submission (
      idSubmission INT AUTO_INCREMENT PRIMARY KEY,
      idAssessment INT NOT NULL,
      idAssessor INT NOT NULL,
      idTargetStudent INT NOT NULL,
      submitted_at BIGINT NOT NULL DEFAULT (UNIX_TIMESTAMP()),
      is_final TINYINT(1) NOT NULL DEFAULT 1,
      UNIQUE KEY uniq_submission (idAssessment, idAssessor, idTargetStudent),
      CONSTRAINT fk_submission_assessment FOREIGN KEY (idAssessment) REFERENCES assessment(idAssessment) ON DELETE CASCADE,
      CONSTRAINT fk_submission_assessor FOREIGN KEY (idAssessor) REFERENCES user(idUser) ON DELETE CASCADE,
      CONSTRAINT fk_submission_target FOREIGN KEY (idTargetStudent) REFERENCES user(idUser) ON DELETE CASCADE
    ) ENGINE=InnoDB`
  );

  await runMySql(
    db,
    `CREATE TABLE IF NOT EXISTS assessment_submission_score (
      idSubmissionScore INT AUTO_INCREMENT PRIMARY KEY,
      idSubmission INT NOT NULL,
      idCriterion INT NOT NULL,
      scale_value INT NOT NULL,
      UNIQUE KEY uniq_submission_criterion (idSubmission, idCriterion),
      CONSTRAINT fk_subscore_submission FOREIGN KEY (idSubmission) REFERENCES assessment_submission(idSubmission) ON DELETE CASCADE,
      CONSTRAINT fk_subscore_criterion FOREIGN KEY (idCriterion) REFERENCES assessment_criterion(idCriterion) ON DELETE CASCADE
    ) ENGINE=InnoDB`
  );

  await runMySql(
    db,
    `CREATE TABLE IF NOT EXISTS user_activity (
      idActivity INT AUTO_INCREMENT PRIMARY KEY,
      idUser INT NOT NULL,
      kind VARCHAR(64) NOT NULL,
      created_at BIGINT NOT NULL DEFAULT (UNIX_TIMESTAMP()),
      CONSTRAINT fk_activity_user FOREIGN KEY (idUser) REFERENCES user(idUser) ON DELETE CASCADE
    ) ENGINE=InnoDB`
  );

  await ensureColumn(
    db,
    "assessment",
    "isHidden",
    `ALTER TABLE assessment ADD COLUMN isHidden TINYINT(1) NOT NULL DEFAULT 0`
  );

  await ensureColumn(
    db,
    "assessment_target",
    "attendance_status",
    `ALTER TABLE assessment_target ADD COLUMN attendance_status VARCHAR(16) NOT NULL DEFAULT 'present'`
  );
  await ensureColumn(db, "assessment_target", "marked_by", `ALTER TABLE assessment_target ADD COLUMN marked_by INT`);
  await ensureColumn(db, "assessment_target", "marked_at", `ALTER TABLE assessment_target ADD COLUMN marked_at BIGINT`);
  await ensureColumn(db, "assessment_target", "note", `ALTER TABLE assessment_target ADD COLUMN note TEXT`);

  await runMySql(
    db,
    `UPDATE assessment_target
     SET attendance_status = 'present'
     WHERE attendance_status IS NULL OR attendance_status NOT IN ('present', 'absent')`
  );

  await runMySql(
    db,
    `UPDATE user
     SET Password = ?
     WHERE Password = 'Java5cript'`,
    [defaultPasswordHash]
  );

  await runMySql(
    db,
    `UPDATE user
     SET last_used = UNIX_TIMESTAMP()
     WHERE last_used IS NULL`
  );

  const hawk = await getMySql(db, `SELECT idUser FROM user WHERE Name = ?`, ["Hawk"]);
  if (!hawk) {
    await runMySql(db, `INSERT INTO user (isAdmin, Name, Password, last_used) VALUES (1, ?, ?, UNIX_TIMESTAMP())`, [
      "Hawk",
      hashPassword(DEFAULT_PASSWORD),
    ]);
  } else {
    await runMySql(db, `UPDATE user SET isAdmin = 1 WHERE Name = ?`, ["Hawk"]);
  }

  // eslint-disable-next-line no-console
  console.log(`MySQL initialized on ${host}:${port}/${database}`);
  return db;
}

async function initDatabase() {
  if (DB_CLIENT === "mysql") {
    return initMySqlDatabase();
  }
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
      isHidden INTEGER NOT NULL DEFAULT 0,
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
    "assessment",
    "isHidden",
    `ALTER TABLE assessment ADD COLUMN isHidden INTEGER NOT NULL DEFAULT 0`
  );
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
