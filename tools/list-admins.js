/**
 * List admin users and whether each still uses the default password.
 *
 * Usage (from repo root):
 *   node tools/list-admins.js
 */
const path = require("path");
require("dotenv").config({ path: path.join(__dirname, "..", ".env") });
const { verifyPassword } = require("../private/dbInit");

const DEFAULT = "Java5cript";

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
      async all(sql, params = []) {
        const [rows] = await c.query(sql, params);
        return rows;
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
    all(sql, params = []) {
      return new Promise((resolve, reject) => {
        db.all(sql, params, (err, rows) => (err ? reject(err) : resolve(rows)));
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
    const rows = await db.all("SELECT idUser, Name, isAdmin, Password FROM user WHERE isAdmin = 1 ORDER BY Name");
    console.log(
      JSON.stringify(
        rows.map((r) => ({
          idUser: r.idUser,
          name: r.Name,
          stillDefaultPassword: verifyPassword(DEFAULT, r.Password),
        })),
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
