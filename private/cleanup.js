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

async function deleteOldHiddenAssessments(db, monthsHidden) {
  const cutoffMs = Date.now() - monthsToMs(monthsHidden);
  const cutoffSec = Math.floor(cutoffMs / 1000);

  // Hidden assessments only (used or unused). Child rows cascade via FKs.
  const result = await run(
    db,
    `DELETE FROM assessment
     WHERE isHidden = 1
       AND created_at IS NOT NULL
       AND created_at < ?`,
    [cutoffSec]
  );

  return result.changes || 0;
}

function scheduleWeeklyInactiveUserCleanup(db, options = {}) {
  const monthsInactive = Number(process.env.INACTIVITY_DELETE_MONTHS || options.monthsInactive || 15);
  const monthsHidden = Number(
    process.env.HIDDEN_ASSESSMENT_DELETE_MONTHS || options.monthsHiddenAssessment || 9
  );
  const weekMs = Number(process.env.CLEANUP_INTERVAL_DAYS || options.intervalDays || 7) * 24 * 60 * 60 * 1000;

  let timer = null;

  async function tick() {
    try {
      const deletedUsers = await deleteInactiveNonAdminUsers(db, monthsInactive);
      if (deletedUsers > 0) {
        // eslint-disable-next-line no-console
        console.log(`Inactive user cleanup: deleted ${deletedUsers} user(s) (>${monthsInactive} months).`);
      }
    } catch (err) {
      // eslint-disable-next-line no-console
      console.error("Inactive user cleanup failed:", err);
    }

    try {
      const deletedAssessments = await deleteOldHiddenAssessments(db, monthsHidden);
      if (deletedAssessments > 0) {
        // eslint-disable-next-line no-console
        console.log(
          `Hidden assessment cleanup: deleted ${deletedAssessments} assessment(s) (hidden >${monthsHidden} months from creation).`
        );
      }
    } catch (err) {
      // eslint-disable-next-line no-console
      console.error("Hidden assessment cleanup failed:", err);
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
  deleteOldHiddenAssessments,
  scheduleWeeklyInactiveUserCleanup,
};
