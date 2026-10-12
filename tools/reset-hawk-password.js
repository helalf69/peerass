/**
 * Reset the Hawk admin password to the app default (Java5cript)
 * and ensure isAdmin = 1.
 *
 * Usage (from repo root):
 *   node tools/reset-hawk-password.js
 */
const path = require("path");
require("dotenv").config({ path: path.join(__dirname, "..", ".env") });
const { hashPassword } = require("../private/dbInit");

const DEFAULT = "Java5cript";
const NAME = "Hawk";

async function openDb() {
  const client = String(process.env.DB_CLIENT || "sqlite").trim().toLowerCase();
  if (client === "mysql") {
    const mysql = require("mysql2/promise");
    const c = await mysql.createConnection({
      host: process.env.DB_HOST,
      port: Number(process.env.DB_PORT || 3306),
      user: process.env.DB_USER,
      password: process.env.DB_PASSWORD,
      database: process.env.DB_NAME,
    });
    return {
      async get(sql, params = []) {
        const [rows] = await c.query(sql, params);
        return rows[0];
      },
      async run(sql, params = []) {
        const [result] = await c.query(sql, params);
        return { affectedRows: result.affectedRows };
      },
      async end() {
        await c.end();
      },
    };
  }

  const sqlite3 = require("sqlite3").verbose();
  const dbPath = path.join(__dirname, "..", "private", "peerass.db");
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
          resolve({ affectedRows: this.changes });
        });
      });
    },
    end() {
      return new Promise((resolve) => db.close(() => resolve()));
    },
  };
}

(async () => {
  const db = await openDb();
  try {
    const row = await db.get("SELECT idUser, Name, isAdmin FROM user WHERE Name = ?", [NAME]);
    if (!row) {
      console.error(`No user named ${NAME} found.`);
      process.exit(1);
    }

    const newHash = hashPassword(DEFAULT);
    const result = await db.run("UPDATE user SET Password = ?, isAdmin = 1 WHERE Name = ?", [newHash, NAME]);
    console.log(
      JSON.stringify(
        {
          ok: true,
          name: NAME,
          idUser: row.idUser,
          passwordResetTo: DEFAULT,
          affectedRows: result.affectedRows,
        },
        null,
        2
      )
    );
  } finally {
    await db.end();
  }
})().catch((e) => {
  console.error("FAIL:", e.message);
  process.exit(1);
});
