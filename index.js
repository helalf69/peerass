const path = require("path");
const express = require("express");
require("dotenv").config();

const app = express();

const port = Number(process.env.PORT || 3000);

// Health check for process managers / uptime monitors.
app.get("/health", (_req, res) => {
  res.json({ status: "ok", service: "peerass" });
});

// Serve static assets (if any).
app.use(express.static(path.join(__dirname, "public")));

// Basic fallback for a single-page/static site.
app.get("*", (_req, res) => {
  res.sendFile(path.join(__dirname, "public", "index.html"), (err) => {
    if (err) res.status(404).send("Not found");
  });
});

app.listen(port, () => {
  // eslint-disable-next-line no-console
  console.log(`peerass listening on http://localhost:${port}`);
});

