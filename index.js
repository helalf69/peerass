const path = require("path");
const express = require("express");
require("dotenv").config();
const { get, initDatabase, verifyPassword } = require("./private/dbInit");

const app = express();

let db;
const port = Number(process.env.PORT || 3001);

app.use(express.json());
app.use(express.urlencoded({ extended: false }));

// Health check for process managers / uptime monitors.
app.get("/health", (_req, res) => {
  res.json({ status: "ok", service: "peerass" });
});

app.post("/api/login", async (req, res) => {
  try {
    const name = String(req.body.name || "").trim();
    const password = String(req.body.password || "");

    if (!name || !password) {
      return res.status(400).json({ ok: false, message: "Name and password are required." });
    }

    const user = await get(db, `SELECT idUser, isAdmin, Name, Password FROM user WHERE Name = ?`, [name]);
    if (!user) {
      return res.status(401).json({ ok: false, message: "Invalid credentials." });
    }

    if (!verifyPassword(password, user.Password)) {
      return res.status(401).json({ ok: false, message: "Invalid credentials." });
    }

    return res.json({
      ok: true,
      user: {
        idUser: user.idUser,
        name: user.Name,
        isAdmin: Boolean(user.isAdmin),
      },
    });
  } catch (_err) {
    return res.status(500).json({ ok: false, message: "Login failed." });
  }
});

// Serve static assets (if any).
app.use(express.static(path.join(__dirname, "public")));

// Basic fallback for a single-page/static site.
// Use a RegExp route to avoid Express v5 "*" matcher issues.
app.get(/.*/, (_req, res) => {
  res.sendFile(path.join(__dirname, "public", "index.html"), (err) => {
    if (err) {
      if (!res.headersSent) res.status(404).send("Not found");
    }
  });
});

initDatabase()
  .then((database) => {
    db = database;
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

