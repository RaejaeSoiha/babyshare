// Admin-only user management APIs.
const bcrypt = require("bcryptjs");
const path = require("path");
const { hasOwn, isValidPassword, isValidUsername, normalizeUsername } = require("../utils/security");

module.exports = function registerAdminRoutes(app, deps) {
  const {
    DIST_DIR,
    HAS_DIST,
    USERS,
    requireAdmin,
    requireLogin,
    saveUsers,
  } = deps;

  app.get("/manage-users", requireLogin, requireAdmin, (_req, res) => {
    if (HAS_DIST) return res.sendFile(path.join(DIST_DIR, "index.html"));
    return res.status(500).send("Frontend build missing. Run: npm run build");
  });

  app.get("/api/admin/overview", requireLogin, requireAdmin, (_req, res) => {
    res.json({ guestsCount: 0, usersCount: Object.keys(USERS).length });
  });

  app.get("/api/admin/users", requireLogin, requireAdmin, (_req, res) => {
    const users = Object.keys(USERS).map((username) => ({
      fileCount: 0,
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

      USERS[username] = await bcrypt.hash(password, 12);
      saveUsers(USERS);
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
      delete USERS[username];
      saveUsers(USERS);
      return res.status(204).end();
    } catch (error) {
      return next(error);
    }
  });
};
