module.exports = {
  apps: [
    {
      name: "peerass",
      script: "./index.js",
      cwd: __dirname,
      instances: 1,
      exec_mode: "fork",
      autorestart: true,
      watch: false,
      max_memory_restart: "250M",
      env: {
        NODE_ENV: "production",
      },
    },
  ],
  // Helpful when running `pm2 logs peerass`.
  // PM2 will create logs/ automatically if it does not exist.
  // eslint-disable-next-line no-unused-vars
  log_date_format: "YYYY-MM-DD HH:mm:ss.SSS",
};

