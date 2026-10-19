/**
 * List non-admin users and when they last logged in (last_used).
 *
 * Usage (from repo root):
 *   node tools/list-students.js
 *   node tools/list-students.js --json
 *   ./tools/list-students.sh
 */
const path = require("path");
require("dotenv").config({ path: path.join(__dirname, "..", ".env") });

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

  let sqlite3;
  try {
    sqlite3 = require("sqlite3").verbose();
  } catch (err) {
    throw new Error(
      `sqlite3 could not be loaded (${err.message}). Use DB_CLIENT=mysql or install sqlite3.`
    );
  }
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

function formatLastLogin(sec) {
  if (sec == null || sec === "") return "never";
  const n = Number(sec);
  if (!Number.isFinite(n) || n <= 0) return "never";
  const d = new Date(n * 1000);
  if (Number.isNaN(d.getTime())) return "never";
  const pad = (x) => String(x).padStart(2, "0");
  return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())} ${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}`;
}

function printTable(rows) {
  const lines = rows.map((r) => ({
    id: String(r.idUser),
    name: String(r.Name || ""),
    lastLogin: formatLastLogin(r.last_used),
    lastUsedUnix: r.last_used == null ? "" : String(r.last_used),
  }));

  const idW = Math.max(2, ...lines.map((l) => l.id.length));
  const nameW = Math.max(4, ...lines.map((l) => l.name.length));
  const loginW = Math.max(10, ...lines.map((l) => l.lastLogin.length));

  const header = `${"ID".padEnd(idW)}  ${"Name".padEnd(nameW)}  ${"Last login".padEnd(loginW)}`;
  const sep = `${"-".repeat(idW)}  ${"-".repeat(nameW)}  ${"-".repeat(loginW)}`;
  console.log(header);
  console.log(sep);
  for (const l of lines) {
    console.log(`${l.id.padEnd(idW)}  ${l.name.padEnd(nameW)}  ${l.lastLogin.padEnd(loginW)}`);
  }
  console.log(`\n${lines.length} non-admin user(s).`);
}

(async () => {
  const asJson = process.argv.includes("--json");
  const db = await openDb();
  try {
    const rows = await db.all(
      `SELECT idUser, Name, last_used
       FROM user
       WHERE isAdmin = 0
       ORDER BY (last_used IS NULL), last_used DESC, Name`
    );

    if (asJson) {
      console.log(
        JSON.stringify(
          rows.map((r) => ({
            idUser: r.idUser,
            name: r.Name,
            lastUsed: r.last_used == null ? null : Number(r.last_used),
            lastLogin: formatLastLogin(r.last_used),
          })),
          null,
          2
        )
      );
      return;
    }

    if (rows.length === 0) {
      console.log("No non-admin users found.");
      return;
    }
    printTable(rows);
  } finally {
    await db.end();
  }
})().catch((e) => {
  console.error("FAIL:", e.message);
  process.exit(1);
});
