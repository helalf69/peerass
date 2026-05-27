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

// Browser cookies: must be a real boolean. Non-boolean truthy values break HTTP deployments.
// Use SESSION_COOKIE_SECURE=true only when users reach the site over HTTPS (so the cookie can use Secure).
const sessionCookieSecure = String(process.env.SESSION_COOKIE_SECURE || "").toLowerCase() === "true";

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
      secure: sessionCookieSecure,
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

// JSON errors for API when something throws before a handler responds (avoids HTML error pages breaking fetch().json()).
app.use((err, req, res, next) => {
  // eslint-disable-next-line no-console
  console.error(err);
  if (res.headersSent) return next(err);
  const p = String(req.path || "");
  if (p.startsWith("/api")) {
    return res.status(500).json({ ok: false, message: err.message || "Server error." });
  }
  res.status(500).send("Server error.");
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

