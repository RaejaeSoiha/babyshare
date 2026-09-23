// Admin-only user management APIs.
const bcrypt = require("bcryptjs");
const fs = require("fs");
const path = require("path");
const { hasOwn, isValidPassword, isValidUsername, normalizeUsername, resolveWithin } = require("../utils/security");

module.exports = function registerAdminRoutes(app, deps) {
  const {
    DIST_DIR,
    HAS_DIST,
    SHARES,
    UPLOADS_USERS,
    USERS,
    requireAdmin,
    requireLogin,
    saveShares,
    saveUsers,
  } = deps;

  app.get("/manage-users", requireLogin, requireAdmin, (_req, res) => {
    if (HAS_DIST) return res.sendFile(path.join(DIST_DIR, "index.html"));
    return res.status(500).send("Frontend build missing. Run: npm run build");
  });

  app.get("/api/admin/overview", requireLogin, requireAdmin, (_req, res) => {
    res.json({ guestsCount: Object.keys(SHARES.guests || {}).length, usersCount: Object.keys(USERS).length });
  });

  app.get("/api/admin/users", requireLogin, requireAdmin, (_req, res) => {
    const users = Object.keys(USERS).map((username) => ({
      fileCount: Array.isArray(SHARES.users[username]) ? SHARES.users[username].length : 0,
      username,
    }));
    res.json({ users });
  });

  app.post("/api/admin/users", requireLogin, requireAdmin, async (req, res, next) => {
    try {
      const username = normalizeUsername(req.body.username);
      const password = typeof req.body.password === "string" ? req.body.password : "";
      if (!isValidUsername(username) || !isValidPassword(password)) {
        return res.status(400).json({ error: "invalid_account" });
      }
      if (hasOwn(USERS, username)) return res.status(409).json({ error: "user_exists" });

      const directory = resolveWithin(UPLOADS_USERS, username);
      if (!directory) return res.status(400).json({ error: "invalid_account" });
      USERS[username] = await bcrypt.hash(password, 12);
      SHARES.users[username] = [];
      fs.mkdirSync(directory, { recursive: true });
      saveUsers(USERS);
      saveShares(SHARES);
      return res.status(201).json({ ok: true });
    } catch (error) {
      return next(error);
    }
  });

  app.post("/api/admin/users/:u/reset", requireLogin, requireAdmin, async (req, res, next) => {
    try {
      const username = req.params.u;
      const password = typeof req.body.newPassword === "string" ? req.body.newPassword : "";
      if (username === "admin") return res.status(403).json({ error: "protected" });
      if (!hasOwn(USERS, username)) return res.status(404).json({ error: "not_found" });
      if (!isValidPassword(password)) return res.status(400).json({ error: "invalid_password" });
      USERS[username] = await bcrypt.hash(password, 12);
      saveUsers(USERS);
      return res.status(204).end();
    } catch (error) {
      return next(error);
    }
  });

  app.delete("/api/admin/users/:u", requireLogin, requireAdmin, async (req, res, next) => {
    try {
      const username = req.params.u;
      if (username === "admin") return res.status(403).json({ error: "protected" });
      if (!hasOwn(USERS, username)) return res.status(404).json({ error: "not_found" });
      const directory = resolveWithin(UPLOADS_USERS, username);
      if (!directory) return res.status(400).json({ error: "invalid_account" });

      await fs.promises.rm(directory, { recursive: true, force: true });
      delete USERS[username];
      delete SHARES.users[username];
      saveUsers(USERS);
      saveShares(SHARES);
      return res.status(204).end();
    } catch (error) {
      return next(error);
    }
  });
};
