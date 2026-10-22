/**
 * Reset the Hawk admin password to the app default (Java5cript)
 * and ensure isAdmin = 1. Creates Hawk if missing.
 *
 * Usage (from repo root, on the production machine):
 *   node tools/reset-hawk-password.js
 */
const path = require("path");
require("dotenv").config({ path: path.join(__dirname, "..", ".env") });
const { hashPassword, verifyPassword } = require("../private/dbInit");

const DEFAULT = "Java5cript";
const NAME = "Hawk";

async function openDb() {
  const client = String(process.env.DB_CLIENT || "sqlite").trim().toLowerCase();
  if (client === "mysql") {
    const mysql = require("mysql2/promise");
    const host = process.env.DB_HOST;
    const port = Number(process.env.DB_PORT || 3306);
    const database = process.env.DB_NAME;
    const c = await mysql.createConnection({
      host,
      port,
      user: process.env.DB_USER,
      password: process.env.DB_PASSWORD,
      database,
    });
    console.error(`Using MySQL ${host}:${port}/${database}`);
    return {
      async get(sql, params = []) {
        const [rows] = await c.query(sql, params);
        return rows[0];
      },
      async run(sql, params = []) {
        const [result] = await c.query(sql, params);
        return { affectedRows: result.affectedRows, insertId: result.insertId };
      },
      async end() {
        await c.end();
      },
    };
  }

  let sqlite3;
  try {
    sqlite3 = require("sqlite3").verbose();
  } catch (err) {
    throw new Error(
      `sqlite3 could not be loaded (${err.message}). Use DB_CLIENT=mysql or install sqlite3.`
    );
  }
  const dbPath = path.join(__dirname, "..", "private", "peerass.db");
  console.error(`Using SQLite ${dbPath}`);
  const db = new sqlite3.Database(dbPath);
  return {
    get(sql, params = []) {
      return new Promise((resolve, reject) => {
        db.get(sql, params, (err, row) => (err ? reject(err) : resolve(row)));
      });
    },
    run(sql, params = []) {
      return new Promise((resolve, reject) => {
        db.run(sql, params, function onRun(err) {
          if (err) return reject(err);
          resolve({ affectedRows: this.changes, insertId: this.lastID });
        });
      });
    },
    end() {
      return new Promise((resolve) => db.close(() => resolve()));
    },
  };
}

(async () => {
  const client = String(process.env.DB_CLIENT || "sqlite").trim().toLowerCase();
  const nowSql = client === "mysql" ? "UNIX_TIMESTAMP()" : "strftime('%s','now')";
  const db = await openDb();
  try {
    let row = await db.get("SELECT idUser, Name, isAdmin, Password FROM user WHERE Name = ?", [NAME]);
    const newHash = hashPassword(DEFAULT);
    let created = false;

    if (!row) {
      await db.run(
        `INSERT INTO user (isAdmin, Name, Password, last_used) VALUES (1, ?, ?, ${nowSql})`,
        [NAME, newHash]
      );
      row = await db.get("SELECT idUser, Name, isAdmin, Password FROM user WHERE Name = ?", [NAME]);
      created = true;
      if (!row) throw new Error("Failed to create Hawk user.");
    } else {
      await db.run("UPDATE user SET Password = ?, isAdmin = 1 WHERE Name = ?", [newHash, NAME]);
      row = await db.get("SELECT idUser, Name, isAdmin, Password FROM user WHERE Name = ?", [NAME]);
    }

    const ok = verifyPassword(DEFAULT, row.Password);
    console.log(
      JSON.stringify(
        {
          ok,
          created,
          name: NAME,
          idUser: row.idUser,
          isAdmin: Boolean(row.isAdmin),
          passwordResetTo: DEFAULT,
          verifiedAgainstHash: ok,
        },
        null,
        2
      )
    );
    if (!ok) {
      console.error("Password was written but verification failed. Check DB write permissions / column type.");
      process.exit(1);
    }
  } finally {
    await db.end();
  }
})().catch((e) => {
  console.error("FAIL:", e.message);
  process.exit(1);
});
