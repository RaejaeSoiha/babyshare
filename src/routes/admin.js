// Admin-only management APIs.
const bcrypt = require("bcryptjs");
const path = require("path");
const fs = require("fs");

module.exports = function registerAdminRoutes(app, deps) {
  const { USERS, SHARES, saveUsers, saveShares, ensureDir, UPLOADS_USERS, requireLogin, requireAdmin, HAS_DIST, DIST_DIR } = deps;

  // Serve SPA admin page.
  app.get("/manage-users", requireLogin, requireAdmin, (req, res) => {
    if (HAS_DIST) return res.sendFile(path.join(DIST_DIR, "index.html"));
    return res.status(500).send("Frontend build missing. Run: npm run build");
  });

  // Summary stats for admin dashboard.
  app.get("/api/admin/overview", requireLogin, requireAdmin, (req, res) => {
    const usersCount = Object.keys(USERS).length;
    const guestsCount = Object.keys(SHARES.guests || {}).length;
    res.json({ usersCount, guestsCount });
  });

  // List all users with file counts.
  app.get("/api/admin/users", requireLogin, requireAdmin, (req, res) => {
    const users = Object.keys(USERS).map((u) => ({
      username: u,
      fileCount: (SHARES.users[u] || []).length,
    }));
    res.json({ users });
  });

  // Create a new user.
  app.post("/api/admin/users", requireLogin, requireAdmin, async (req, res) => {
    const { username, password } = req.body;
    if (!username || !password) return res.status(400).json({ error: "missing_fields" });
    if (USERS[username]) return res.status(409).json({ error: "user_exists" });
    const hash = await bcrypt.hash(password, 10);
    USERS[username] = hash;
    saveUsers(USERS);
    ensureDir(path.join(UPLOADS_USERS, username));
    if (!SHARES.users[username]) SHARES.users[username] = [];
    saveShares(SHARES);
    res.json({ ok: true });
  });

  // Reset a user's password (admin-only).
  app.post("/api/admin/users/:u/reset", requireLogin, requireAdmin, async (req, res) => {
    const user = req.params.u;
    const newPassword = req.body.newPassword || "Temp1234";
    if (user === "admin") return res.status(403).json({ error: "protected" });
    const hash = await bcrypt.hash(newPassword, 10);
    USERS[user] = hash;
    saveUsers(USERS);
    res.json({ ok: true, newPassword });
  });

  // Delete a user and all stored files.
  app.delete("/api/admin/users/:u", requireLogin, requireAdmin, (req, res) => {
    const user = req.params.u;
    if (user === "admin") return res.status(403).json({ error: "protected" });
    delete USERS[user];
    delete SHARES.users[user];
    saveUsers(USERS);
    saveShares(SHARES);
    const userDir = path.join(UPLOADS_USERS, user);
    if (fs.existsSync(userDir)) {
      fs.rmSync(userDir, { recursive: true, force: true });
    }
    res.json({ ok: true });
  });
};
