const path = require("path");
const express = require("express");
const session = require("express-session");
const helmet = require("helmet");
require("dotenv").config();

const { get, all, initDatabase, verifyPassword, run, hashPassword } = require("./private/dbInit");
const { scheduleWeeklyInactiveUserCleanup } = require("./private/cleanup");
const { registerRoutes } = require("./private/routes");

const app = express();
const port = Number(process.env.PORT || 3001);
const DEFAULT_PASSWORD = "Java5cript";
const dbClient = String(process.env.DB_CLIENT || "sqlite").trim().toLowerCase();
const sessionSecret = String(process.env.SESSION_SECRET || "");
if (sessionSecret.length < 32) {
  // eslint-disable-next-line no-console
  console.warn("SESSION_SECRET is missing or too short. Set a 32+ char secret before internet deployment.");
}

let db;
const getDb = () => db;
const publicDir = path.join(__dirname, "public");
const privateDir = path.join(__dirname, "private");

app.use(express.json());
app.use(express.urlencoded({ extended: false }));
app.set("trust proxy", 1);
app.use(
  helmet({
    contentSecurityPolicy: false,
  })
);
app.use(
  session({
    store:
      dbClient === "sqlite"
        ? (() => {
            const SQLiteStore = require("connect-sqlite3")(session);
            return new SQLiteStore({
              db: "sessions.db",
              dir: privateDir,
            });
          })()
        : undefined,
    name: "peerass.sid",
    secret: sessionSecret || "dev-only-insecure-session-secret-change-me",
    resave: false,
    saveUninitialized: false,
    cookie: {
      httpOnly: true,
      // "auto" ensures cookies work on http:// in production-like local setups,
      // while still marking cookies Secure when the app is actually served over HTTPS.
      secure: "auto",
      sameSite: "lax",
      maxAge: 1000 * 60 * 60 * 12,
    },
  })
);

registerRoutes(app, {
  getDb,
  get,
  all,
  run,
  verifyPassword,
  hashPassword,
  DEFAULT_PASSWORD,
  publicDir,
  privateDir,
});

app.use("/api", (_req, res) => {
  res.status(404).json({ ok: false, message: "API route not found." });
});

app.use(express.static(publicDir));

app.get(/.*/, (_req, res) => {
  res.sendFile(path.join(publicDir, "index.html"), (err) => {
    if (err && !res.headersSent) res.status(404).send("Not found");
  });
});

initDatabase()
  .then((database) => {
    db = database;
    scheduleWeeklyInactiveUserCleanup(db);
    app.listen(port, "0.0.0.0", () => {
      // eslint-disable-next-line no-console
      console.log(`peerass listening on http://localhost:${port}`);
    });
  })
  .catch((err) => {
    // eslint-disable-next-line no-console
    console.error("Database initialization failed:", err);
    process.exit(1);
  });

