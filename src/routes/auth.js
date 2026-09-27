// Authentication and account registration routes.
const path = require("path");
const bcrypt = require("bcryptjs");
const { isValidPassword, isValidUsername, normalizeUsername, PASSWORD_MIN_LENGTH } = require("../utils/security");

module.exports = function registerAuthRoutes(app, deps) {
  const {
    appRedirect,
    DIST_DIR,
    FRONTEND_BASE_URL,
    HAS_DIST,
    loginLimiter,
    renderError,
    saveShares,
    saveUsers,
    SHARES,
    UPLOADS_USERS,
    USERS,
  } = deps;

  function serveSpa(pathname) {
    return (_req, res) => {
      if (HAS_DIST) return res.sendFile(path.join(DIST_DIR, "index.html"));
      if (FRONTEND_BASE_URL) return res.redirect(`${FRONTEND_BASE_URL}${pathname}`);
      return res.status(500).send("Frontend build missing. Run: npm run build");
    };
  }

  app.get("/login", serveSpa("/login"));
  app.get("/register", serveSpa("/register"));

  app.post("/login", loginLimiter, async (req, res, next) => {
    try {
      const username = normalizeUsername(req.body.username);
      const password = typeof req.body.password === "string" ? req.body.password : "";
      const stored = USERS[username];
      const valid = typeof stored === "string" && (await bcrypt.compare(password, stored));
      if (!valid) {
        return res.status(401).send(renderError("Unable to sign in", "Check your username and password, then try again."));
      }

      if (bcrypt.getRounds(stored) < 12) {
        USERS[username] = await bcrypt.hash(password, 12);
        saveUsers(USERS);
      }

      return req.session.regenerate((error) => {
        if (error) return next(error);
        req.session.user = username;
        const userDir = path.join(UPLOADS_USERS, username);
        require("fs").mkdirSync(userDir, { recursive: true });
        if (!Array.isArray(SHARES.users[username])) SHARES.users[username] = [];
        saveShares(SHARES);
        return req.session.save((saveError) => {
          if (saveError) return next(saveError);
          return appRedirect(res, "/dashboard");
        });
      });
    } catch (error) {
      return next(error);
    }
  });

  app.post("/register", loginLimiter, async (req, res, next) => {
    try {
      const username = normalizeUsername(req.body.username);
      const password = typeof req.body.password === "string" ? req.body.password : "";
      if (!isValidUsername(username) || !isValidPassword(password)) {
        return res.status(400).send(
          renderError("Invalid account details", `Use a 3-32 character username and a password of at least ${PASSWORD_MIN_LENGTH} characters.`)
        );
      }
      if (Object.prototype.hasOwnProperty.call(USERS, username)) {
        return res.status(409).send(renderError("Username unavailable", "Choose a different username."));
      }

      USERS[username] = await bcrypt.hash(password, 12);
      saveUsers(USERS);
      require("fs").mkdirSync(path.join(UPLOADS_USERS, username), { recursive: true });
      SHARES.users[username] = [];
      saveShares(SHARES);
      return appRedirect(res, "/login?created=1");
    } catch (error) {
      return next(error);
    }
  });

  app.post("/logout", (req, res) => {
    req.session.destroy(() => {
      res.clearCookie("babyshare.sid");
      appRedirect(res, "/");
    });
  });
};
