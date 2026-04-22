const path = require("path");
const fs = require("fs/promises");

function selectedDateToRangeSeconds(assessmentDate) {
  const m = /^(\d{4})-(\d{2})-(\d{2})$/.exec(String(assessmentDate || "").trim());
  if (!m) return null;
  const y = Number(m[1]);
  const mo = Number(m[2]) - 1;
  const d = Number(m[3]);
  const startsAt = Math.floor(new Date(y, mo, d, 8, 0, 0, 0).getTime() / 1000);
  const endsAt = Math.floor(new Date(y, mo, d, 15, 30, 0, 0).getTime() / 1000);
  if (!Number.isFinite(startsAt) || !Number.isFinite(endsAt)) return null;
  return { startsAt, endsAt };
}

async function safeRollback(db, run) {
  try {
    await run(db, "ROLLBACK");
  } catch (_e) {
    // ignore
  }
}

function createRequireAdminActor({ getDb, get }) {
  return async function requireAdminActor(actorId) {
    const id = Number(actorId);
    if (!Number.isFinite(id) || id <= 0) return { ok: false, status: 400, message: "Invalid actor." };
    const actor = await get(getDb(), `SELECT idUser, isAdmin FROM user WHERE idUser = ?`, [id]);
    if (!actor || !actor.isAdmin) return { ok: false, status: 403, message: "Admin access required." };
    return { ok: true, actor };
  };
}

function createRequireUser({ getDb, get }) {
  return async function requireUser(actorId) {
    const id = Number(actorId);
    if (!Number.isFinite(id) || id <= 0) return { ok: false, status: 400, message: "Invalid user." };
    const actor = await get(getDb(), `SELECT idUser, isAdmin, Name FROM user WHERE idUser = ?`, [id]);
    if (!actor) return { ok: false, status: 404, message: "User not found." };
    return { ok: true, actor };
  };
}

async function syncAssessmentTargets({ getDb, run }, idAssessment, idSubject) {
  await run(
    getDb(),
    `INSERT OR IGNORE INTO assessment_target (idAssessment, idStudent, attendance_status)
     SELECT ?, u.idUser, 'present'
     FROM userSubject us
     JOIN user u ON u.idUser = us.idUser
     WHERE us.idSub = ? AND u.isAdmin = 0`,
    [idAssessment, idSubject]
  );
  await run(
    getDb(),
    `DELETE FROM assessment_target
     WHERE idAssessment = ?
       AND idStudent NOT IN (
         SELECT u.idUser
         FROM userSubject us
         JOIN user u ON u.idUser = us.idUser
         WHERE us.idSub = ? AND u.isAdmin = 0
       )`,
    [idAssessment, idSubject]
  );
}

async function getAssessmentCompletionStats({ getDb, get }, idAssessment) {
  const presentCountRow = await get(
    getDb(),
    `SELECT COUNT(*) AS cnt
     FROM assessment_target
     WHERE idAssessment = ? AND attendance_status = 'present'`,
    [idAssessment]
  );
  const absentCountRow = await get(
    getDb(),
    `SELECT COUNT(*) AS cnt
     FROM assessment_target
     WHERE idAssessment = ? AND attendance_status = 'absent'`,
    [idAssessment]
  );
  const submittedCountRow = await get(
    getDb(),
    `SELECT COUNT(*) AS cnt
     FROM assessment_submission s
     JOIN assessment_target assessor
       ON assessor.idAssessment = s.idAssessment
      AND assessor.idStudent = s.idAssessor
      AND assessor.attendance_status = 'present'
     JOIN assessment_target target
       ON target.idAssessment = s.idAssessment
      AND target.idStudent = s.idTargetStudent
      AND target.attendance_status = 'present'
     WHERE s.idAssessment = ?`,
    [idAssessment]
  );
  const presentCount = Number(presentCountRow && presentCountRow.cnt ? presentCountRow.cnt : 0);
  const expectedSubmissions = presentCount > 1 ? presentCount * (presentCount - 1) : 0;
  const receivedSubmissions = Number(submittedCountRow && submittedCountRow.cnt ? submittedCountRow.cnt : 0);
  const absentCount = Number(absentCountRow && absentCountRow.cnt ? absentCountRow.cnt : 0);
  return {
    presentCount,
    absentCount,
    expectedSubmissions,
    receivedSubmissions,
    complete: receivedSubmissions >= expectedSubmissions,
  };
}

function registerRoutes(app, deps) {
  const {
    getDb,
    get,
    all,
    run,
    verifyPassword,
    hashPassword,
    DEFAULT_PASSWORD,
    publicDir,
    privateDir,
  } = deps;
  const requireAdminActor = createRequireAdminActor({ getDb, get });
  const requireUser = createRequireUser({ getDb, get });

  app.get("/health", (_req, res) => {
    res.json({ status: "ok", service: "peerass" });
  });

  app.post("/api/login", async (req, res) => {
    try {
      const name = String(req.body.name || "").trim();
      const password = String(req.body.password || "");
      if (!name || !password) return res.status(400).json({ ok: false, message: "Name and password are required." });

      const user = await get(getDb(), `SELECT idUser, isAdmin, Name, Password FROM user WHERE Name = ?`, [name]);
      if (!user || !verifyPassword(password, user.Password)) {
        return res.status(401).json({ ok: false, message: "Invalid credentials." });
      }

      await run(getDb(), `UPDATE user SET last_used = strftime('%s','now') WHERE idUser = ?`, [user.idUser]);
      await run(getDb(), `INSERT INTO user_activity (idUser, kind) VALUES (?, 'login')`, [user.idUser]);

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
      if (!Number.isFinite(idUser) || idUser <= 0) return res.status(400).json({ ok: false, message: "Invalid user." });
      if (!oldPassword || !newPassword) return res.status(400).json({ ok: false, message: "Missing password fields." });
      if (newPassword.length < 8) return res.status(400).json({ ok: false, message: "Password must be at least 8 characters." });
      if (newPassword === DEFAULT_PASSWORD) return res.status(400).json({ ok: false, message: "Choose a non-default password." });

      const user = await get(getDb(), `SELECT idUser, Password FROM user WHERE idUser = ?`, [idUser]);
      if (!user) return res.status(404).json({ ok: false, message: "User not found." });
      if (!verifyPassword(oldPassword, user.Password)) {
        return res.status(401).json({ ok: false, message: "Old password is incorrect." });
      }

      const newHash = hashPassword(newPassword);
      await run(getDb(), `UPDATE user SET Password = ? WHERE idUser = ?`, [newHash, idUser]);
      await run(getDb(), `UPDATE user SET last_used = strftime('%s','now') WHERE idUser = ?`, [idUser]);
      await run(getDb(), `INSERT INTO user_activity (idUser, kind) VALUES (?, 'password_change')`, [idUser]);
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
      if (!name) return res.status(400).json({ ok: false, message: "Name is required." });
      if (name.length < 2) return res.status(400).json({ ok: false, message: "Name must be at least 2 characters." });
      const existing = await get(getDb(), `SELECT idUser FROM user WHERE Name = ?`, [name]);
      if (existing) return res.status(409).json({ ok: false, message: "User already exists." });
      if (!Number.isFinite(idSub) || idSub <= 0) return res.status(400).json({ ok: false, message: "Select a subject." });
      const subject = await get(getDb(), `SELECT idSub FROM subject WHERE idSub = ? AND idUser = ?`, [idSub, auth.actor.idUser]);
      if (!subject) return res.status(403).json({ ok: false, message: "Subject not available for this admin." });

      const passwordHash = hashPassword(DEFAULT_PASSWORD);
      const ins = await run(getDb(), `INSERT INTO user (Name, Password, last_used) VALUES (?, ?, strftime('%s','now'))`, [
        name,
        passwordHash,
      ]);
      await run(getDb(), `INSERT INTO userSubject (idUser, idSub) VALUES (?, ?)`, [ins.lastID, idSub]);
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
        getDb(),
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
      await run(getDb(), `INSERT INTO subject (idUser, subName) VALUES (?, ?)`, [auth.actor.idUser, subName]);
      return res.json({ ok: true, message: `Subject ${subName} added.` });
    } catch (err) {
      if (String(err.message || "").includes("UNIQUE")) return res.status(409).json({ ok: false, message: "Subject already exists." });
      return res.status(500).json({ ok: false, message: "Could not add subject." });
    }
  });

  app.post("/api/admin/copy-subject-users", async (req, res) => {
    try {
      const auth = await requireAdminActor(req.body.actorId);
      if (!auth.ok) return res.status(auth.status).json({ ok: false, message: auth.message });
      const sourceIdSub = Number(req.body.sourceIdSub);
      const newSubName = String(req.body.newSubName || "").trim();
      if (!Number.isFinite(sourceIdSub) || sourceIdSub <= 0) return res.status(400).json({ ok: false, message: "Choose source subject." });
      if (!newSubName) return res.status(400).json({ ok: false, message: "New subject name is required." });
      const source = await get(getDb(), `SELECT idSub FROM subject WHERE idSub = ? AND idUser = ?`, [sourceIdSub, auth.actor.idUser]);
      if (!source) return res.status(403).json({ ok: false, message: "Source subject not available." });
      const insertSub = await run(getDb(), `INSERT INTO subject (idUser, subName) VALUES (?, ?)`, [auth.actor.idUser, newSubName]);
      const newIdSub = insertSub.lastID;
      const sourceUsers = await all(getDb(), `SELECT DISTINCT us.idUser as idUser FROM userSubject us WHERE us.idSub = ?`, [sourceIdSub]);
      for (const row of sourceUsers) {
        // eslint-disable-next-line no-await-in-loop
        await run(getDb(), `INSERT OR IGNORE INTO userSubject (idUser, idSub) VALUES (?, ?)`, [row.idUser, newIdSub]);
      }
      return res.json({ ok: true, message: `Created ${newSubName} and copied ${sourceUsers.length} user membership link(s).`, idSub: newIdSub });
    } catch (err) {
      if (String(err.message || "").includes("UNIQUE")) return res.status(409).json({ ok: false, message: "New subject name already exists." });
      return res.status(500).json({ ok: false, message: "Could not copy names." });
    }
  });

  app.post("/api/admin/delete-subject", async (req, res) => {
    try {
      const auth = await requireAdminActor(req.body.actorId);
      if (!auth.ok) return res.status(auth.status).json({ ok: false, message: auth.message });
      const idSub = Number(req.body.idSub);
      if (!Number.isFinite(idSub) || idSub <= 0) return res.status(400).json({ ok: false, message: "Invalid subject." });
      const subjectRow = await get(getDb(), `SELECT idSub, subName FROM subject WHERE idSub = ? AND idUser = ?`, [idSub, auth.actor.idUser]);
      if (!subjectRow) return res.status(404).json({ ok: false, message: "Subject not found." });

      const orphanUsers = await all(
        getDb(),
        `SELECT DISTINCT u.idUser as idUser, u.Name as name
         FROM user u
         JOIN userSubject us ON us.idUser = u.idUser
         WHERE us.idSub = ?
           AND u.isAdmin = 0
           AND NOT EXISTS (SELECT 1 FROM userSubject us2 WHERE us2.idUser = u.idUser AND us2.idSub != ?)`,
        [idSub, idSub]
      );
      const deleteOrphans = req.body.deleteOrphans;
      if (orphanUsers.length > 0 && deleteOrphans === undefined) {
        return res.json({ ok: true, needsOrphanDecision: true, idSub, subName: subjectRow.subName, orphanUsers });
      }

      await run(getDb(), "BEGIN IMMEDIATE");
      try {
        await run(getDb(), `DELETE FROM subject WHERE idSub = ? AND idUser = ?`, [idSub, auth.actor.idUser]);
        if (orphanUsers.length > 0 && deleteOrphans === true) {
          const ids = orphanUsers.map((u) => u.idUser);
          const placeholders = ids.map(() => "?").join(",");
          await run(getDb(), `DELETE FROM user WHERE isAdmin = 0 AND idUser IN (${placeholders})`, ids);
        }
        await run(getDb(), "COMMIT");
      } catch (err) {
        await safeRollback(getDb(), run);
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
      return res.status(500).json({ ok: false, message: msg ? `Could not delete subject: ${msg}` : "Could not delete subject." });
    }
  });

  app.get("/api/admin/users", async (req, res) => {
    try {
      const auth = await requireAdminActor(req.query.actorId);
      if (!auth.ok) return res.status(auth.status).json({ ok: false, message: auth.message });
      const rows = await all(
        getDb(),
        `SELECT DISTINCT u.idUser, u.Name as name, u.Password as passwordHash
         FROM user u
         JOIN userSubject us ON us.idUser = u.idUser
         JOIN subject s ON s.idSub = us.idSub
         WHERE s.idUser = ? AND u.isAdmin = 0
         ORDER BY u.Name COLLATE NOCASE ASC`,
        [auth.actor.idUser]
      );
      const users = rows.map((r) => ({ idUser: r.idUser, name: r.name, passwordChanged: !verifyPassword(DEFAULT_PASSWORD, r.passwordHash) }));
      return res.json({ ok: true, users });
    } catch (_err) {
      return res.status(500).json({ ok: false, message: "Could not load users." });
    }
  });

  app.get("/api/assessments", async (req, res) => {
    try {
      const idUser = Number(req.query.userId);
      if (!Number.isFinite(idUser) || idUser <= 0) return res.json({ ok: true, assessments: [] });
      const rows = await all(
        getDb(),
        `SELECT DISTINCT a.idAssessment, a.idSubject, a.title, a.instructions, a.isPlanned, a.isOpen, a.starts_at, a.ends_at, s.subName,
                at.attendance_status as my_attendance_status
         FROM assessment a
         JOIN subject s ON s.idSub = a.idSubject
         LEFT JOIN assessment_target at
                ON at.idAssessment = a.idAssessment
               AND at.idStudent = ?
         WHERE a.idSubject IN (
           SELECT idSub FROM userSubject WHERE idUser = ?
           UNION
           SELECT idSub FROM subject WHERE idUser = ?
         )
         ORDER BY (a.starts_at IS NULL), a.starts_at DESC, a.idAssessment DESC`,
        [idUser, idUser, idUser]
      );
      const submissionRows = await all(
        getDb(),
        `SELECT DISTINCT idAssessment
         FROM assessment_submission
         WHERE idAssessor = ?`,
        [idUser]
      );
      const submittedSet = new Set(submissionRows.map((r) => Number(r.idAssessment)));

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
        hasSubmission: submittedSet.has(Number(r.idAssessment)),
        attendanceStatus: r.my_attendance_status === "absent" ? "absent" : "present",
      }));
      return res.json({ ok: true, assessments });
    } catch (_err) {
      return res.status(500).json({ ok: false, message: "Could not load assessments." });
    }
  });

  app.post("/api/assessment-draft/echo", async (req, res) => {
    try {
      const actorId = Number(req.body.actorId);
      const idSub = Number(req.body.idSub);
      const assessmentDate = String(req.body.assessmentDate || "").trim();
      const title = String(req.body.title || "").trim();
      const description = String(req.body.description || "").trim();
      const items = Array.isArray(req.body.items) ? req.body.items : [];
      const auth = await requireAdminActor(actorId);
      if (!auth.ok) return res.status(auth.status).json({ ok: false, message: auth.message });
      if (!Number.isFinite(idSub) || idSub <= 0) return res.status(400).json({ ok: false, message: "Subject is required." });
      const subject = await get(getDb(), `SELECT idSub FROM subject WHERE idSub = ? AND idUser = ?`, [idSub, auth.actor.idUser]);
      if (!subject) return res.status(403).json({ ok: false, message: "Subject not available for this admin." });
      if (!title) return res.status(400).json({ ok: false, message: "Title is required." });
      const range = selectedDateToRangeSeconds(assessmentDate);
      if (!range) return res.status(400).json({ ok: false, message: "Assessment date must be YYYY-MM-DD." });
      if (items.length === 0) return res.status(400).json({ ok: false, message: "At least one assessment item is required." });

      await run(getDb(), "BEGIN IMMEDIATE");
      let idAssessment;
      try {
        const assessmentInsert = await run(
          getDb(),
          `INSERT INTO assessment (idSubject, idTeacher, title, instructions, isPlanned, isOpen, starts_at, ends_at)
           VALUES (?, ?, ?, ?, 1, 0, ?, ?)`,
          [idSub, auth.actor.idUser, title, description, range.startsAt, range.endsAt]
        );
        idAssessment = assessmentInsert.lastID;
        await syncAssessmentTargets({ getDb, run }, idAssessment, idSub);
        for (let i = 0; i < items.length; i += 1) {
          const item = items[i] || {};
          const name = String(item.name || "").trim();
          const itemDescription = String(item.description || "").trim();
          const points = Array.isArray(item.points) ? item.points : [];
          if (!name) throw new Error(`Assessment item ${i + 1} is missing a name.`);
          // eslint-disable-next-line no-await-in-loop
          const criterionInsert = await run(
            getDb(),
            `INSERT INTO assessment_criterion (idAssessment, name, description, sort_order)
             VALUES (?, ?, ?, ?)`,
            [idAssessment, name, itemDescription, i]
          );
          for (const point of points) {
            const scaleValue = Number(point.value);
            const guidelineText = String(point.description || "").trim();
            if (!Number.isInteger(scaleValue)) continue;
            // eslint-disable-next-line no-await-in-loop
            await run(
              getDb(),
              `INSERT INTO assessment_criterion_scale_guideline (idCriterion, scale_value, guideline_text)
               VALUES (?, ?, ?)`,
              [criterionInsert.lastID, scaleValue, guidelineText]
            );
          }
        }
        await run(getDb(), "COMMIT");
      } catch (err) {
        await safeRollback(getDb(), run);
        throw err;
      }

      const outPath = path.join(privateDir, "test.json");
      await fs.writeFile(outPath, `${JSON.stringify({ savedAt: Math.floor(Date.now() / 1000), idAssessment, payload: req.body || {} }, null, 2)}\n`, "utf8");
      return res.json({ ok: true, message: "Assessment saved.", idAssessment, data: req.body || {} });
    } catch (err) {
      return res.status(500).json({ ok: false, message: `Could not save assessment: ${String(err.message || err)}` });
    }
  });

  app.get("/api/assessment-draft/:idAssessment", async (req, res) => {
    try {
      const idAssessment = Number(req.params.idAssessment);
      const actorId = Number(req.query.actorId);
      if (!Number.isFinite(idAssessment) || idAssessment <= 0) return res.status(400).json({ ok: false, message: "Invalid assessment." });
      const auth = await requireAdminActor(actorId);
      if (!auth.ok) return res.status(auth.status).json({ ok: false, message: auth.message });
      const row = await get(
        getDb(),
        `SELECT a.idAssessment, a.idSubject, a.title, a.instructions, a.starts_at, a.ends_at
         FROM assessment a
         JOIN subject s ON s.idSub = a.idSubject
         WHERE a.idAssessment = ? AND s.idUser = ?`,
        [idAssessment, auth.actor.idUser]
      );
      if (!row) return res.status(404).json({ ok: false, message: "Assessment not found." });
      const criteriaRows = await all(
        getDb(),
        `SELECT c.idCriterion, c.name, c.description, c.sort_order, g.scale_value, g.guideline_text
         FROM assessment_criterion c
         LEFT JOIN assessment_criterion_scale_guideline g ON g.idCriterion = c.idCriterion
         WHERE c.idAssessment = ?
         ORDER BY c.sort_order ASC, g.scale_value ASC`,
        [idAssessment]
      );
      const map = new Map();
      for (const r of criteriaRows) {
        if (!map.has(r.idCriterion)) map.set(r.idCriterion, { idCriterion: r.idCriterion, name: r.name, description: r.description, sortOrder: r.sort_order, points: [] });
        if (r.scale_value != null) map.get(r.idCriterion).points.push({ value: r.scale_value, description: r.guideline_text || "" });
      }
      const toDateInput = (sec) => {
        if (!Number.isFinite(Number(sec))) return "";
        const d = new Date(Number(sec) * 1000);
        return `${d.getFullYear()}-${String(d.getMonth() + 1).padStart(2, "0")}-${String(d.getDate()).padStart(2, "0")}`;
      };
      return res.json({
        ok: true,
        assessment: {
          idAssessment: row.idAssessment,
          idSubject: row.idSubject,
          title: row.title,
          description: row.instructions || "",
          assessmentDate: toDateInput(row.starts_at),
          items: Array.from(map.values()),
        },
      });
    } catch (_err) {
      return res.status(500).json({ ok: false, message: "Could not load assessment." });
    }
  });

  app.post("/api/assessment-draft/:idAssessment", async (req, res) => {
    try {
      const idAssessment = Number(req.params.idAssessment);
      const actorId = Number(req.body.actorId);
      const idSub = Number(req.body.idSub);
      const assessmentDate = String(req.body.assessmentDate || "").trim();
      const title = String(req.body.title || "").trim();
      const description = String(req.body.description || "").trim();
      const items = Array.isArray(req.body.items) ? req.body.items : [];
      if (!Number.isFinite(idAssessment) || idAssessment <= 0) return res.status(400).json({ ok: false, message: "Invalid assessment." });
      const auth = await requireAdminActor(actorId);
      if (!auth.ok) return res.status(auth.status).json({ ok: false, message: auth.message });
      if (!Number.isFinite(idSub) || idSub <= 0) return res.status(400).json({ ok: false, message: "Subject is required." });
      if (!title) return res.status(400).json({ ok: false, message: "Title is required." });
      if (items.length === 0) return res.status(400).json({ ok: false, message: "At least one assessment item is required." });
      const range = selectedDateToRangeSeconds(assessmentDate);
      if (!range) return res.status(400).json({ ok: false, message: "Assessment date must be YYYY-MM-DD." });
      const existing = await get(
        getDb(),
        `SELECT a.idAssessment FROM assessment a JOIN subject s ON s.idSub = a.idSubject WHERE a.idAssessment = ? AND s.idUser = ?`,
        [idAssessment, auth.actor.idUser]
      );
      if (!existing) return res.status(404).json({ ok: false, message: "Assessment not found." });
      const subject = await get(getDb(), `SELECT idSub FROM subject WHERE idSub = ? AND idUser = ?`, [idSub, auth.actor.idUser]);
      if (!subject) return res.status(403).json({ ok: false, message: "Subject not available for this admin." });

      await run(getDb(), "BEGIN IMMEDIATE");
      try {
        await run(
          getDb(),
          `UPDATE assessment
           SET idSubject = ?, idTeacher = ?, title = ?, instructions = ?, starts_at = ?, ends_at = ?, updated_at = strftime('%s','now')
           WHERE idAssessment = ?`,
          [idSub, auth.actor.idUser, title, description, range.startsAt, range.endsAt, idAssessment]
        );
        await syncAssessmentTargets({ getDb, run }, idAssessment, idSub);
        await run(getDb(), `DELETE FROM assessment_criterion WHERE idAssessment = ?`, [idAssessment]);
        for (let i = 0; i < items.length; i += 1) {
          const item = items[i] || {};
          const name = String(item.name || "").trim();
          const itemDescription = String(item.description || "").trim();
          const points = Array.isArray(item.points) ? item.points : [];
          if (!name) throw new Error(`Assessment item ${i + 1} is missing a name.`);
          // eslint-disable-next-line no-await-in-loop
          const criterionInsert = await run(
            getDb(),
            `INSERT INTO assessment_criterion (idAssessment, name, description, sort_order)
             VALUES (?, ?, ?, ?)`,
            [idAssessment, name, itemDescription, i]
          );
          for (const point of points) {
            const scaleValue = Number(point.value);
            const guidelineText = String(point.description || "").trim();
            if (!Number.isInteger(scaleValue)) continue;
            // eslint-disable-next-line no-await-in-loop
            await run(
              getDb(),
              `INSERT INTO assessment_criterion_scale_guideline (idCriterion, scale_value, guideline_text)
               VALUES (?, ?, ?)`,
              [criterionInsert.lastID, scaleValue, guidelineText]
            );
          }
        }
        await run(getDb(), "COMMIT");
      } catch (err) {
        await safeRollback(getDb(), run);
        throw err;
      }

      const outPath = path.join(privateDir, "test.json");
      await fs.writeFile(outPath, `${JSON.stringify({ savedAt: Math.floor(Date.now() / 1000), idAssessment, payload: req.body || {} }, null, 2)}\n`, "utf8");
      return res.json({ ok: true, message: "Assessment updated.", idAssessment });
    } catch (err) {
      return res.status(500).json({ ok: false, message: `Could not update assessment: ${String(err.message || err)}` });
    }
  });

  app.get("/api/assessment-view/:idAssessment", async (req, res) => {
    try {
      const idAssessment = Number(req.params.idAssessment);
      const actorId = Number(req.query.actorId);
      if (!Number.isFinite(idAssessment) || idAssessment <= 0) return res.status(400).json({ ok: false, message: "Invalid assessment." });
      const auth = await requireUser(actorId);
      if (!auth.ok) return res.status(auth.status).json({ ok: false, message: auth.message });

      const row = await get(
        getDb(),
        `SELECT a.idAssessment, a.idSubject, a.title, a.instructions, a.starts_at, a.ends_at, s.subName
         FROM assessment a
         JOIN subject s ON s.idSub = a.idSubject
         WHERE a.idAssessment = ?
           AND a.idSubject IN (
             SELECT idSub FROM userSubject WHERE idUser = ?
             UNION
             SELECT idSub FROM subject WHERE idUser = ?
           )`,
        [idAssessment, auth.actor.idUser, auth.actor.idUser]
      );
      if (!row) return res.status(404).json({ ok: false, message: "Assessment not found." });
      await syncAssessmentTargets({ getDb, run }, idAssessment, row.idSubject);
      const actorAttendance = await get(
        getDb(),
        `SELECT attendance_status
         FROM assessment_target
         WHERE idAssessment = ? AND idStudent = ?`,
        [idAssessment, auth.actor.idUser]
      );
      const isActorAbsent = Boolean(actorAttendance && actorAttendance.attendance_status === "absent");

      const criteriaRows = await all(
        getDb(),
        `SELECT c.idCriterion, c.name, c.description, c.sort_order, g.scale_value, g.guideline_text
         FROM assessment_criterion c
         LEFT JOIN assessment_criterion_scale_guideline g ON g.idCriterion = c.idCriterion
         WHERE c.idAssessment = ?
         ORDER BY c.sort_order ASC, g.scale_value ASC`,
        [idAssessment]
      );

      const peers = isActorAbsent
        ? []
        : await all(
            getDb(),
            `SELECT u.idUser, u.Name as name
             FROM assessment_target t
             JOIN user u ON u.idUser = t.idStudent
             WHERE t.idAssessment = ?
               AND t.attendance_status = 'present'
               AND u.idUser != ?
               AND NOT EXISTS (
                 SELECT 1
                 FROM assessment_submission s
                 WHERE s.idAssessment = ?
                   AND s.idAssessor = ?
                   AND s.idTargetStudent = u.idUser
               )
             ORDER BY u.Name COLLATE NOCASE ASC`,
            [idAssessment, auth.actor.idUser, idAssessment, auth.actor.idUser]
          );

      const criteriaMap = new Map();
      for (const r of criteriaRows) {
        if (!criteriaMap.has(r.idCriterion)) {
          criteriaMap.set(r.idCriterion, {
            idCriterion: r.idCriterion,
            name: r.name,
            description: r.description,
            sortOrder: r.sort_order,
            points: [],
          });
        }
        if (r.scale_value != null) {
          criteriaMap.get(r.idCriterion).points.push({
            value: Number(r.scale_value),
            description: r.guideline_text || "",
          });
        }
      }

      return res.json({
        ok: true,
        assessment: {
          idAssessment: row.idAssessment,
          idSubject: row.idSubject,
          subName: row.subName,
          title: row.title,
          description: row.instructions || "",
          startsAt: row.starts_at,
          endsAt: row.ends_at,
          attendanceStatus: isActorAbsent ? "absent" : "present",
          peers: peers.map((p) => ({ idUser: p.idUser, name: p.name })),
          criteria: Array.from(criteriaMap.values()),
        },
      });
    } catch (_err) {
      return res.status(500).json({ ok: false, message: "Could not load assessment." });
    }
  });

  app.get("/assessment-new.html", async (req, res) => {
    try {
      const auth = await requireAdminActor(req.query.actorId);
      if (!auth.ok) return res.status(auth.status).send("Admin access required.");
      return res.sendFile(path.join(publicDir, "assessment-new.html"));
    } catch (_err) {
      return res.status(500).send("Could not open page.");
    }
  });

  app.get("/assessment-edit.html", async (req, res) => {
    try {
      const auth = await requireAdminActor(req.query.actorId);
      if (!auth.ok) return res.status(auth.status).send("Admin access required.");
      return res.sendFile(path.join(publicDir, "assessment-edit.html"));
    } catch (_err) {
      return res.status(500).send("Could not open page.");
    }
  });

  app.get("/assessment-start.html", async (req, res) => {
    try {
      const auth = await requireUser(req.query.actorId);
      if (!auth.ok) return res.status(auth.status).send("User access required.");
      return res.sendFile(path.join(publicDir, "assessment-start.html"));
    } catch (_err) {
      return res.status(500).send("Could not open page.");
    }
  });

  app.get("/assessment-view.html", async (req, res) => {
    try {
      const auth = await requireUser(req.query.actorId);
      if (!auth.ok) return res.status(auth.status).send("User access required.");
      return res.sendFile(path.join(publicDir, "assessment-view.html"));
    } catch (_err) {
      return res.status(500).send("Could not open page.");
    }
  });

  app.post("/api/assessment-submit", async (req, res) => {
    try {
      const actorId = Number(req.body.actorId);
      const idAssessment = Number(req.body.idAssessment);
      const idTargetStudent = Number(req.body.idTargetStudent);
      const scores = Array.isArray(req.body.scores) ? req.body.scores : [];

      const auth = await requireUser(actorId);
      if (!auth.ok) return res.status(auth.status).json({ ok: false, message: auth.message });
      if (!Number.isFinite(idAssessment) || idAssessment <= 0) {
        return res.status(400).json({ ok: false, message: "Invalid assessment." });
      }
      if (!Number.isFinite(idTargetStudent) || idTargetStudent <= 0) {
        return res.status(400).json({ ok: false, message: "Choose a student to assess." });
      }
      if (idTargetStudent === auth.actor.idUser) {
        return res.status(400).json({ ok: false, message: "You cannot assess yourself." });
      }
      if (scores.length === 0) {
        return res.status(400).json({ ok: false, message: "No scores submitted." });
      }

      const assessmentRow = await get(
        getDb(),
        `SELECT a.idAssessment, a.idSubject
         FROM assessment a
         WHERE a.idAssessment = ?
           AND a.idSubject IN (
             SELECT idSub FROM userSubject WHERE idUser = ?
             UNION
             SELECT idSub FROM subject WHERE idUser = ?
           )`,
        [idAssessment, auth.actor.idUser, auth.actor.idUser]
      );
      if (!assessmentRow) return res.status(404).json({ ok: false, message: "Assessment not found." });
      await syncAssessmentTargets({ getDb, run }, idAssessment, assessmentRow.idSubject);

      const assessorAttendance = await get(
        getDb(),
        `SELECT attendance_status
         FROM assessment_target
         WHERE idAssessment = ? AND idStudent = ?`,
        [idAssessment, auth.actor.idUser]
      );
      if (assessorAttendance && assessorAttendance.attendance_status === "absent") {
        return res.status(403).json({ ok: false, message: "You are marked absent for this assessment." });
      }

      const targetRow = await get(
        getDb(),
        `SELECT t.idStudent as idUser
         FROM assessment_target t
         JOIN user u ON u.idUser = t.idStudent
         WHERE t.idAssessment = ?
           AND t.idStudent = ?
           AND t.attendance_status = 'present'
           AND u.isAdmin = 0`,
        [idAssessment, idTargetStudent]
      );
      if (!targetRow) return res.status(400).json({ ok: false, message: "Target student is not in this subject." });

      const existing = await get(
        getDb(),
        `SELECT idSubmission FROM assessment_submission
         WHERE idAssessment = ? AND idAssessor = ? AND idTargetStudent = ?`,
        [idAssessment, auth.actor.idUser, idTargetStudent]
      );
      if (existing) return res.status(409).json({ ok: false, message: "You have already assessed this student." });

      const criteriaRows = await all(getDb(), `SELECT idCriterion FROM assessment_criterion WHERE idAssessment = ?`, [idAssessment]);
      const validCriteria = new Set(criteriaRows.map((r) => Number(r.idCriterion)));
      for (const s of scores) {
        if (!validCriteria.has(Number(s.idCriterion))) {
          return res.status(400).json({ ok: false, message: "Invalid criterion in submitted scores." });
        }
      }

      await run(getDb(), "BEGIN IMMEDIATE");
      try {
        const submissionInsert = await run(
          getDb(),
          `INSERT INTO assessment_submission (idAssessment, idAssessor, idTargetStudent, is_final)
           VALUES (?, ?, ?, 1)`,
          [idAssessment, auth.actor.idUser, idTargetStudent]
        );

        for (const s of scores) {
          const idCriterion = Number(s.idCriterion);
          const scaleValue = Number(s.scaleValue);
          if (!Number.isFinite(idCriterion) || !Number.isFinite(scaleValue)) continue;
          // eslint-disable-next-line no-await-in-loop
          await run(
            getDb(),
            `INSERT INTO assessment_submission_score (idSubmission, idCriterion, scale_value)
             VALUES (?, ?, ?)`,
            [submissionInsert.lastID, idCriterion, scaleValue]
          );
        }
        await run(getDb(), "COMMIT");
      } catch (err) {
        await safeRollback(getDb(), run);
        throw err;
      }

      const remaining = await get(
        getDb(),
        `SELECT COUNT(*) as cnt
         FROM assessment_target t
         JOIN user u ON u.idUser = t.idStudent
         WHERE t.idAssessment = ?
           AND t.attendance_status = 'present'
           AND u.idUser != ?
           AND NOT EXISTS (
             SELECT 1
             FROM assessment_submission s
             WHERE s.idAssessment = ?
               AND s.idAssessor = ?
               AND s.idTargetStudent = u.idUser
           )`,
        [idAssessment, auth.actor.idUser, idAssessment, auth.actor.idUser]
      );

      const remainingPeers = Number(remaining && remaining.cnt ? remaining.cnt : 0);
      return res.json({ ok: true, message: "Assessment saved.", remainingPeers, completed: remainingPeers === 0 });
    } catch (err) {
      return res.status(500).json({ ok: false, message: `Could not save submission: ${String(err.message || err)}` });
    }
  });

  app.get("/api/assessment-submissions/:idAssessment", async (req, res) => {
    try {
      const idAssessment = Number(req.params.idAssessment);
      const actorId = Number(req.query.actorId);
      if (!Number.isFinite(idAssessment) || idAssessment <= 0) {
        return res.status(400).json({ ok: false, message: "Invalid assessment." });
      }
      const auth = await requireUser(actorId);
      if (!auth.ok) return res.status(auth.status).json({ ok: false, message: auth.message });

      const assessment = await get(
        getDb(),
        `SELECT a.idAssessment, a.idSubject, a.title, a.starts_at, a.ends_at, s.subName
         FROM assessment a
         JOIN subject s ON s.idSub = a.idSubject
         WHERE a.idAssessment = ?
           AND a.idSubject IN (
             SELECT idSub FROM userSubject WHERE idUser = ?
             UNION
             SELECT idSub FROM subject WHERE idUser = ?
           )`,
        [idAssessment, auth.actor.idUser, auth.actor.idUser]
      );
      if (!assessment) return res.status(404).json({ ok: false, message: "Assessment not found." });
      await syncAssessmentTargets({ getDb, run }, idAssessment, assessment.idSubject);

      const rows = await all(
        getDb(),
        `SELECT sub.idSubmission, sub.idTargetStudent, tu.Name as targetName, c.idCriterion, c.name as criterionName, s.scale_value
         FROM assessment_submission sub
         JOIN user tu ON tu.idUser = sub.idTargetStudent
         JOIN assessment_submission_score s ON s.idSubmission = sub.idSubmission
         JOIN assessment_criterion c ON c.idCriterion = s.idCriterion
         WHERE sub.idAssessment = ? AND sub.idAssessor = ?
         ORDER BY tu.Name COLLATE NOCASE ASC, c.sort_order ASC`,
        [idAssessment, auth.actor.idUser]
      );

      const byTarget = new Map();
      for (const r of rows) {
        if (!byTarget.has(r.idTargetStudent)) {
          byTarget.set(r.idTargetStudent, {
            idTargetStudent: r.idTargetStudent,
            targetName: r.targetName,
            scores: [],
          });
        }
        byTarget.get(r.idTargetStudent).scores.push({
          idCriterion: r.idCriterion,
          criterionName: r.criterionName,
          scaleValue: r.scale_value,
        });
      }
      const classmates = await all(
        getDb(),
        `SELECT cm.idTargetStudent, u.Name as targetName
         FROM (
           SELECT t.idStudent as idTargetStudent
           FROM assessment_target t
           WHERE t.idAssessment = ?
             AND t.attendance_status = 'present'
             AND t.idStudent != ?
           UNION
           SELECT sub.idTargetStudent
           FROM assessment_submission sub
           WHERE sub.idAssessment = ?
             AND sub.idAssessor = ?
             AND sub.idTargetStudent != ?
         ) cm
         JOIN user u ON u.idUser = cm.idTargetStudent
         ORDER BY u.Name COLLATE NOCASE ASC`,
        [idAssessment, auth.actor.idUser, idAssessment, auth.actor.idUser, auth.actor.idUser]
      );

      return res.json({
        ok: true,
        actor: {
          idUser: auth.actor.idUser,
          isAdmin: Boolean(auth.actor.isAdmin),
          name: auth.actor.Name,
        },
        assessment: {
          idAssessment: assessment.idAssessment,
          title: assessment.title,
          subName: assessment.subName,
          startsAt: assessment.starts_at,
          endsAt: assessment.ends_at,
        },
        classmates: classmates.map((cm) => {
          const existing = byTarget.get(cm.idTargetStudent);
          return {
            idTargetStudent: cm.idTargetStudent,
            targetName: cm.targetName,
            assessed: Boolean(existing),
            scores: existing ? existing.scores : [],
          };
        }),
        submissions: Array.from(byTarget.values()),
      });
    } catch (_err) {
      return res.status(500).json({ ok: false, message: "Could not load assessment submissions." });
    }
  });

  app.get("/api/assessment-rollcall/:idAssessment", async (req, res) => {
    try {
      const idAssessment = Number(req.params.idAssessment);
      const actorId = Number(req.query.actorId);
      if (!Number.isFinite(idAssessment) || idAssessment <= 0) return res.status(400).json({ ok: false, message: "Invalid assessment." });
      const auth = await requireAdminActor(actorId);
      if (!auth.ok) return res.status(auth.status).json({ ok: false, message: auth.message });

      const assessment = await get(
        getDb(),
        `SELECT a.idAssessment, a.idSubject, a.idTeacher, a.title, a.starts_at, a.ends_at, s.subName
         FROM assessment a
         JOIN subject s ON s.idSub = a.idSubject
         WHERE a.idAssessment = ? AND s.idUser = ?`,
        [idAssessment, auth.actor.idUser]
      );
      if (!assessment) return res.status(404).json({ ok: false, message: "Assessment not found." });
      await syncAssessmentTargets({ getDb, run }, idAssessment, assessment.idSubject);

      const roster = await all(
        getDb(),
        `SELECT t.idStudent, u.Name as name, t.attendance_status as attendanceStatus, t.marked_at as markedAt, t.note
         FROM assessment_target t
         JOIN user u ON u.idUser = t.idStudent
         WHERE t.idAssessment = ?
         ORDER BY u.Name COLLATE NOCASE ASC`,
        [idAssessment]
      );
      const completion = await getAssessmentCompletionStats({ getDb, get }, idAssessment);
      return res.json({
        ok: true,
        assessment: {
          idAssessment: assessment.idAssessment,
          title: assessment.title,
          subName: assessment.subName,
          startsAt: assessment.starts_at,
          endsAt: assessment.ends_at,
        },
        roster: roster.map((r) => ({
          idStudent: r.idStudent,
          name: r.name,
          attendanceStatus: r.attendanceStatus === "absent" ? "absent" : "present",
          markedAt: r.markedAt,
          note: r.note || "",
        })),
        completion,
      });
    } catch (_err) {
      return res.status(500).json({ ok: false, message: "Could not load rollcall." });
    }
  });

  app.post("/api/assessment-rollcall/:idAssessment", async (req, res) => {
    try {
      const idAssessment = Number(req.params.idAssessment);
      const actorId = Number(req.body.actorId);
      const updates = Array.isArray(req.body.updates) ? req.body.updates : [];
      if (!Number.isFinite(idAssessment) || idAssessment <= 0) return res.status(400).json({ ok: false, message: "Invalid assessment." });
      const auth = await requireAdminActor(actorId);
      if (!auth.ok) return res.status(auth.status).json({ ok: false, message: auth.message });

      const assessment = await get(
        getDb(),
        `SELECT a.idAssessment, a.idSubject, a.starts_at, a.ends_at
         FROM assessment a
         JOIN subject s ON s.idSub = a.idSubject
         WHERE a.idAssessment = ? AND s.idUser = ?`,
        [idAssessment, auth.actor.idUser]
      );
      if (!assessment) return res.status(404).json({ ok: false, message: "Assessment not found." });
      await syncAssessmentTargets({ getDb, run }, idAssessment, assessment.idSubject);
      const nowSec = Math.floor(Date.now() / 1000);
      if (assessment.starts_at != null && nowSec < Number(assessment.starts_at)) {
        return res.status(400).json({ ok: false, message: "Rollcall is only available during the assessment window." });
      }
      if (assessment.ends_at != null && nowSec > Number(assessment.ends_at)) {
        return res.status(400).json({ ok: false, message: "Rollcall is only available during the assessment window." });
      }

      await run(getDb(), "BEGIN IMMEDIATE");
      try {
        for (const update of updates) {
          const idStudent = Number(update && update.idStudent);
          const attendanceStatus = String(update && update.attendanceStatus ? update.attendanceStatus : "").trim().toLowerCase();
          const note = String(update && update.note ? update.note : "").trim();
          if (!Number.isFinite(idStudent) || idStudent <= 0) continue;
          if (attendanceStatus !== "present" && attendanceStatus !== "absent") continue;
          // eslint-disable-next-line no-await-in-loop
          await run(
            getDb(),
            `UPDATE assessment_target
             SET attendance_status = ?, marked_by = ?, marked_at = strftime('%s','now'), note = ?
             WHERE idAssessment = ? AND idStudent = ?`,
            [attendanceStatus, auth.actor.idUser, note, idAssessment, idStudent]
          );
        }
        await run(getDb(), "COMMIT");
      } catch (err) {
        await safeRollback(getDb(), run);
        throw err;
      }

      const completion = await getAssessmentCompletionStats({ getDb, get }, idAssessment);
      return res.json({ ok: true, message: "Rollcall updated.", completion });
    } catch (_err) {
      return res.status(500).json({ ok: false, message: "Could not update rollcall." });
    }
  });
}

module.exports = { registerRoutes };
