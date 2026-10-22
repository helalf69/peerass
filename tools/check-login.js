/**
 * Verify that a username/password works against the configured DB
 * (same credentials the app uses). Does not create a session.
 *
 * Usage:
 *   node tools/check-login.js Hawk Java5cript
 */
const path = require("path");
require("dotenv").config({ path: path.join(__dirname, "..", ".env") });
const { verifyPassword } = require("../private/dbInit");

const name = String(process.argv[2] || "").trim();
const password = String(process.argv[3] || "");

if (!name || !password) {
  console.error("Usage: node tools/check-login.js <name> <password>");
  process.exit(1);
}

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
      async end() {
        await c.end();
      },
    };
  }

  const sqlite3 = require("sqlite3").verbose();
  const dbPath = path.join(__dirname, "..", "private", "peerass.db");
  console.error(`Using SQLite ${dbPath}`);
  const db = new sqlite3.Database(dbPath);
  return {
    get(sql, params = []) {
      return new Promise((resolve, reject) => {
        db.get(sql, params, (err, row) => (err ? reject(err) : resolve(row)));
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
    const user = await db.get("SELECT idUser, Name, isAdmin, Password FROM user WHERE Name = ?", [name]);
    if (!user) {
      console.log(JSON.stringify({ ok: false, reason: "user_not_found", name }, null, 2));
      process.exit(1);
    }
    const passwordOk = verifyPassword(password, user.Password);
    console.log(
      JSON.stringify(
        {
          ok: passwordOk,
          name: user.Name,
          idUser: user.idUser,
          isAdmin: Boolean(user.isAdmin),
          passwordOk,
          reason: passwordOk ? "credentials_ok" : "bad_password",
        },
        null,
        2
      )
    );
    process.exit(passwordOk ? 0 : 1);
  } finally {
    await db.end();
  }
})().catch((e) => {
  console.error("FAIL:", e.message);
  process.exit(1);
});
