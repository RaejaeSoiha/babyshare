// Lightweight JSON APIs for the React UI.
module.exports = function registerApiRoutes(app, deps) {
  const { USERS, requireLogin, mapUserFiles } = deps;

  // Current user session info.
  app.get("/api/me", (req, res) => {
    if (!req.session.user) return res.status(401).json({ error: "unauthorized" });
    res.json({ user: req.session.user, isAdmin: req.session.user === "admin" });
  });

  // Files list for current user (admin sees all users).
  app.get("/api/files", requireLogin, (req, res) => {
    const user = req.session.user;
    if (user === "admin") {
      const users = Object.keys(USERS).map((u) => ({
        username: u,
        files: mapUserFiles(u),
      }));
      return res.json({ isAdmin: true, users });
    }
    return res.json({ isAdmin: false, user, files: mapUserFiles(user) });
  });
};
