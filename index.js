const path = require("path");
const express = require("express");
require("dotenv").config();

const { get, all, initDatabase, verifyPassword, run, hashPassword } = require("./private/dbInit");
const { scheduleWeeklyInactiveUserCleanup } = require("./private/cleanup");
const { registerRoutes } = require("./private/routes");

const app = express();
const port = Number(process.env.PORT || 3001);
const DEFAULT_PASSWORD = "Java5cript";

let db;
const getDb = () => db;
const publicDir = path.join(__dirname, "public");
const privateDir = path.join(__dirname, "private");

app.use(express.json());
app.use(express.urlencoded({ extended: false }));

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

