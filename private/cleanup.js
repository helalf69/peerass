const { run } = require("./dbInit");

function monthsToMs(months) {
  // Average month length keeps scheduling simple and stable for a weekly job.
  return Math.round(Number(months) * 30.4375 * 24 * 60 * 60 * 1000);
}

async function deleteInactiveNonAdminUsers(db, monthsInactive) {
  const cutoffMs = Date.now() - monthsToMs(monthsInactive);
  const cutoffSec = Math.floor(cutoffMs / 1000);

  const result = await run(
    db,
    `DELETE FROM user
     WHERE isAdmin = 0
       AND last_used IS NOT NULL
       AND last_used < ?`,
    [cutoffSec]
  );

  return result.changes || 0;
}

function scheduleWeeklyInactiveUserCleanup(db, options = {}) {
  const monthsInactive = Number(process.env.INACTIVITY_DELETE_MONTHS || options.monthsInactive || 15);
  const weekMs = Number(process.env.CLEANUP_INTERVAL_DAYS || options.intervalDays || 7) * 24 * 60 * 60 * 1000;

  let timer = null;

  async function tick() {
    try {
      const deleted = await deleteInactiveNonAdminUsers(db, monthsInactive);
      if (deleted > 0) {
        // eslint-disable-next-line no-console
        console.log(`Inactive user cleanup: deleted ${deleted} user(s) (>${monthsInactive} months).`);
      }
    } catch (err) {
      // eslint-disable-next-line no-console
      console.error("Inactive user cleanup failed:", err);
    }
  }

  void tick();
  timer = setInterval(() => {
    void tick();
  }, weekMs);
  if (timer && typeof timer.unref === "function") timer.unref();

  return { stop: () => clearInterval(timer) };
}

module.exports = {
  deleteInactiveNonAdminUsers,
  scheduleWeeklyInactiveUserCleanup,
};
