const path = require("path");
const express = require("express");
require("dotenv").config();
const { get, initDatabase, verifyPassword, run, hashPassword } = require("./private/dbInit");

const app = express();

let db;
const port = Number(process.env.PORT || 3001);
const DEFAULT_PASSWORD = "Java5cript";

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
        mustChangePassword: verifyPassword(DEFAULT_PASSWORD, user.Password),
      },
    });
  } catch (_err) {
    return res.status(500).json({ ok: false, message: "Login failed." });
  }
});

app.post("/api/change-password", async (req, res) => {
  try {
    const idUser = Number(req.body.idUser);
    const oldPassword = String(req.body.oldPassword || "");
    const newPassword = String(req.body.newPassword || "");

    if (!Number.isFinite(idUser) || idUser <= 0) {
      return res.status(400).json({ ok: false, message: "Invalid user." });
    }
    if (!oldPassword || !newPassword) {
      return res.status(400).json({ ok: false, message: "Missing password fields." });
    }
    if (newPassword.length < 8) {
      return res.status(400).json({ ok: false, message: "Password must be at least 8 characters." });
    }
    if (newPassword === DEFAULT_PASSWORD) {
      return res.status(400).json({ ok: false, message: "Choose a non-default password." });
    }

    const user = await get(db, `SELECT idUser, Password FROM user WHERE idUser = ?`, [idUser]);
    if (!user) return res.status(404).json({ ok: false, message: "User not found." });

    if (!verifyPassword(oldPassword, user.Password)) {
      return res.status(401).json({ ok: false, message: "Old password is incorrect." });
    }

    const newHash = hashPassword(newPassword);
    await run(db, `UPDATE user SET Password = ? WHERE idUser = ?`, [newHash, idUser]);

    return res.json({ ok: true });
  } catch (_err) {
    return res.status(500).json({ ok: false, message: "Password change failed." });
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

