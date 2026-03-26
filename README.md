# peerass

## Run with PM2

1. Install dependencies: `npm install`
2. Start the site:
   - `npm run pm2:start`
3. View logs: `npm run pm2:logs`
4. (Optional) Stop: `npm run pm2:stop`

### Environment

The server reads `PORT` from `.env` (see `env.example`).
Create `.env` by copying `env.example` and adjusting values if needed.

Health check: `GET /health`

