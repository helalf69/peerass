const path = require("path");
const express = require("express");
require("dotenv").config();
const { get, all, initDatabase, verifyPassword, run, hashPassword } = require("./private/dbInit");
const { scheduleWeeklyInactiveUserCleanup } = require("./private/cleanup");

const app = express();

let db;
const port = Number(process.env.PORT || 3001);
const DEFAULT_PASSWORD = "Java5cript";

app.use(express.json());
app.use(express.urlencoded({ extended: false }));

async function requireAdminActor(actorId) {
  const id = Number(actorId);
  if (!Number.isFinite(id) || id <= 0) return { ok: false, status: 400, message: "Invalid actor." };
  const actor = await get(db, `SELECT idUser, isAdmin FROM user WHERE idUser = ?`, [id]);
  if (!actor || !actor.isAdmin) return { ok: false, status: 403, message: "Admin access required." };
  return { ok: true, actor };
}

async function safeRollback(db) {
  try {
    await run(db, "ROLLBACK");
  } catch (_e) {
    // ignore
  }
}

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

    await run(db, `UPDATE user SET last_used = strftime('%s','now') WHERE idUser = ?`, [user.idUser]);
    await run(db, `INSERT INTO user_activity (idUser, kind) VALUES (?, 'login')`, [user.idUser]);

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
    await run(db, `UPDATE user SET last_used = strftime('%s','now') WHERE idUser = ?`, [idUser]);
    await run(db, `INSERT INTO user_activity (idUser, kind) VALUES (?, 'password_change')`, [idUser]);

    return res.json({ ok: true });
  } catch (_err) {
    return res.status(500).json({ ok: false, message: "Password change failed." });
  }
});

app.post("/api/admin/add-user", async (req, res) => {
  try {
    const auth = await requireAdminActor(req.body.actorId);
    if (!auth.ok) return res.status(auth.status).json({ ok: false, message: auth.message });

    const name = String(req.body.name || "").trim();
    const idSub = Number(req.body.idSub || 0);
    if (!name) {
      return res.status(400).json({ ok: false, message: "Name is required." });
    }
    if (name.length < 2) {
      return res.status(400).json({ ok: false, message: "Name must be at least 2 characters." });
    }

    const existing = await get(db, `SELECT idUser FROM user WHERE Name = ?`, [name]);
    if (existing) {
      return res.status(409).json({ ok: false, message: "User already exists." });
    }
    if (!Number.isFinite(idSub) || idSub <= 0) {
      return res.status(400).json({ ok: false, message: "Select a subject." });
    }
    const subject = await get(db, `SELECT idSub FROM subject WHERE idSub = ? AND idUser = ?`, [
      idSub,
      auth.actor.idUser,
    ]);
    if (!subject) {
      return res.status(403).json({ ok: false, message: "Subject not available for this admin." });
    }

    const passwordHash = hashPassword(DEFAULT_PASSWORD);
    const ins = await run(
      db,
      `INSERT INTO user (Name, Password, last_used) VALUES (?, ?, strftime('%s','now'))`,
      [name, passwordHash]
    );
    await run(db, `INSERT INTO userSubject (idUser, idSub) VALUES (?, ?)`, [ins.lastID, idSub]);
    return res.json({ ok: true, message: `User ${name} registered.` });
  } catch (_err) {
    return res.status(500).json({ ok: false, message: "Could not add user." });
  }
});

app.get("/api/admin/subjects", async (req, res) => {
  try {
    const auth = await requireAdminActor(req.query.actorId);
    if (!auth.ok) return res.status(auth.status).json({ ok: false, message: auth.message });

    const subjects = await all(
      db,
      `SELECT idSub, subName FROM subject WHERE idUser = ? ORDER BY subName COLLATE NOCASE ASC`,
      [auth.actor.idUser]
    );
    return res.json({ ok: true, subjects });
  } catch (_err) {
    return res.status(500).json({ ok: false, message: "Could not load subjects." });
  }
});

app.post("/api/admin/add-subject", async (req, res) => {
  try {
    const auth = await requireAdminActor(req.body.actorId);
    if (!auth.ok) return res.status(auth.status).json({ ok: false, message: auth.message });

    const subName = String(req.body.subName || "").trim();
    if (!subName) return res.status(400).json({ ok: false, message: "Subject name is required." });

    await run(db, `INSERT INTO subject (idUser, subName) VALUES (?, ?)`, [auth.actor.idUser, subName]);
    return res.json({ ok: true, message: `Subject ${subName} added.` });
  } catch (err) {
    if (String(err.message || "").includes("UNIQUE")) {
      return res.status(409).json({ ok: false, message: "Subject already exists." });
    }
    return res.status(500).json({ ok: false, message: "Could not add subject." });
  }
});

app.post("/api/admin/copy-subject-users", async (req, res) => {
  try {
    const auth = await requireAdminActor(req.body.actorId);
    if (!auth.ok) return res.status(auth.status).json({ ok: false, message: auth.message });

    const sourceIdSub = Number(req.body.sourceIdSub);
    const newSubName = String(req.body.newSubName || "").trim();
    if (!Number.isFinite(sourceIdSub) || sourceIdSub <= 0) {
      return res.status(400).json({ ok: false, message: "Choose source subject." });
    }
    if (!newSubName) return res.status(400).json({ ok: false, message: "New subject name is required." });

    const source = await get(db, `SELECT idSub FROM subject WHERE idSub = ? AND idUser = ?`, [
      sourceIdSub,
      auth.actor.idUser,
    ]);
    if (!source) return res.status(403).json({ ok: false, message: "Source subject not available." });

    const insertSub = await run(db, `INSERT INTO subject (idUser, subName) VALUES (?, ?)`, [
      auth.actor.idUser,
      newSubName,
    ]);
    const newIdSub = insertSub.lastID;

    const sourceUsers = await all(
      db,
      `SELECT DISTINCT us.idUser as idUser
       FROM userSubject us
       WHERE us.idSub = ?`,
      [sourceIdSub]
    );
    for (const row of sourceUsers) {
      // Copy only membership links; do not create new users.
      // eslint-disable-next-line no-await-in-loop
      await run(db, `INSERT OR IGNORE INTO userSubject (idUser, idSub) VALUES (?, ?)`, [
        row.idUser,
        newIdSub,
      ]);
    }

    return res.json({
      ok: true,
      message: `Created ${newSubName} and copied ${sourceUsers.length} user membership link(s).`,
      idSub: newIdSub,
    });
  } catch (err) {
    if (String(err.message || "").includes("UNIQUE")) {
      return res.status(409).json({ ok: false, message: "New subject name already exists." });
    }
    return res.status(500).json({ ok: false, message: "Could not copy names." });
  }
});

app.post("/api/admin/delete-subject", async (req, res) => {
  try {
    const auth = await requireAdminActor(req.body.actorId);
    if (!auth.ok) return res.status(auth.status).json({ ok: false, message: auth.message });

    const idSub = Number(req.body.idSub);
    if (!Number.isFinite(idSub) || idSub <= 0) {
      return res.status(400).json({ ok: false, message: "Invalid subject." });
    }

    const subjectRow = await get(db, `SELECT idSub, subName FROM subject WHERE idSub = ? AND idUser = ?`, [
      idSub,
      auth.actor.idUser,
    ]);
    if (!subjectRow) {
      return res.status(404).json({ ok: false, message: "Subject not found." });
    }

    const orphanUsers = await all(
      db,
      `SELECT DISTINCT u.idUser as idUser, u.Name as name
       FROM user u
       JOIN userSubject us ON us.idUser = u.idUser
       WHERE us.idSub = ?
         AND u.isAdmin = 0
         AND NOT EXISTS (
           SELECT 1 FROM userSubject us2
           WHERE us2.idUser = u.idUser AND us2.idSub != ?
         )`,
      [idSub, idSub]
    );

    const deleteOrphans = req.body.deleteOrphans;
    if (orphanUsers.length > 0 && deleteOrphans === undefined) {
      return res.json({
        ok: true,
        needsOrphanDecision: true,
        idSub,
        subName: subjectRow.subName,
        orphanUsers,
      });
    }

    await run(db, "BEGIN IMMEDIATE");
    try {
      await run(db, `DELETE FROM subject WHERE idSub = ? AND idUser = ?`, [idSub, auth.actor.idUser]);

      if (orphanUsers.length > 0 && deleteOrphans === true) {
        const ids = orphanUsers.map((u) => u.idUser);
        const placeholders = ids.map(() => "?").join(",");
        await run(db, `DELETE FROM user WHERE isAdmin = 0 AND idUser IN (${placeholders})`, ids);
      }

      await run(db, "COMMIT");
    } catch (err) {
      await safeRollback(db);
      throw err;
    }

    return res.json({
      ok: true,
      message:
        orphanUsers.length > 0 && deleteOrphans === true
          ? `Deleted subject ${subjectRow.subName} and ${orphanUsers.length} user(s) with no remaining subjects.`
          : `Deleted subject ${subjectRow.subName}.`,
      deletedOrphans: Boolean(deleteOrphans === true && orphanUsers.length > 0),
    });
  } catch (err) {
    // eslint-disable-next-line no-console
    console.error("delete-subject failed:", err);
    const msg = String(err && err.message ? err.message : err);
    return res.status(500).json({
      ok: false,
      message: msg ? `Could not delete subject: ${msg}` : "Could not delete subject.",
    });
  }
});

app.get("/api/admin/users", async (req, res) => {
  try {
    const auth = await requireAdminActor(req.query.actorId);
    if (!auth.ok) return res.status(auth.status).json({ ok: false, message: auth.message });

    const rows = await all(
      db,
      `SELECT DISTINCT u.idUser, u.Name as name, u.Password as passwordHash
       FROM user u
       JOIN userSubject us ON us.idUser = u.idUser
       JOIN subject s ON s.idSub = us.idSub
       WHERE s.idUser = ? AND u.isAdmin = 0
       ORDER BY u.Name COLLATE NOCASE ASC`,
      [auth.actor.idUser]
    );

    const users = rows.map((r) => ({
      idUser: r.idUser,
      name: r.name,
      passwordChanged: !verifyPassword(DEFAULT_PASSWORD, r.passwordHash),
    }));

    return res.json({ ok: true, users });
  } catch (_err) {
    return res.status(500).json({ ok: false, message: "Could not load users." });
  }
});

// Assessments visible to a user: any assessment in a subject they teach or are enrolled in.
app.get("/api/assessments", async (req, res) => {
  try {
    const idUser = Number(req.query.userId);
    if (!Number.isFinite(idUser) || idUser <= 0) {
      return res.json({ ok: true, assessments: [] });
    }

    const rows = await all(
      db,
      `SELECT DISTINCT a.idAssessment,
         a.idSubject,
         a.title,
         a.instructions,
         a.isPlanned,
         a.isOpen,
         a.starts_at,
         a.ends_at,
         s.subName
       FROM assessment a
       JOIN subject s ON s.idSub = a.idSubject
       WHERE a.idSubject IN (
         SELECT idSub FROM userSubject WHERE idUser = ?
         UNION
         SELECT idSub FROM subject WHERE idUser = ?
       )
       ORDER BY (a.starts_at IS NULL), a.starts_at DESC, a.idAssessment DESC`,
      [idUser, idUser]
    );

    const assessments = rows.map((r) => ({
      idAssessment: r.idAssessment,
      idSubject: r.idSubject,
      subName: r.subName,
      title: r.title,
      instructions: r.instructions,
      isPlanned: Boolean(r.isPlanned),
      isOpen: Boolean(r.isOpen),
      startsAt: r.starts_at,
      endsAt: r.ends_at,
    }));

    return res.json({ ok: true, assessments });
  } catch (_err) {
    return res.status(500).json({ ok: false, message: "Could not load assessments." });
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

