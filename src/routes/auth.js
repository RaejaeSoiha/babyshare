// Auth routes: login, register, logout.
const path = require("path");
const bcrypt = require("bcryptjs");
const { renderError, renderSuccess } = require("../utils/html");

module.exports = function registerAuthRoutes(app, deps) {
  const { HAS_DIST, DIST_DIR, ROOT_DIR, USERS, SHARES, saveUsers, saveShares, ensureDir, UPLOADS_USERS } = deps;

  // Serve SPA for login route.
  app.get("/login", (req, res) => {
    if (HAS_DIST) return res.sendFile(path.join(DIST_DIR, "index.html"));
    return res.status(500).send("Frontend build missing. Run: npm run build");
  });

  // Handle login form submission.
  app.post("/login", async (req, res) => {
    const { username, password } = req.body;
    if (!USERS[username]) {
      return res.send(
        renderError(
          "User Not Found",
          `The username <b>${username}</b> does not exist.`,
          `<a href="/register">Create Account</a> | <a href="/login">Try Again</a>`
        )
      );
    }

    const stored = USERS[username];
    const valid = await bcrypt.compare(password, stored);
    if (!valid) {
      return res.send(
        renderError(
          "Incorrect Password",
          "The password you entered is not correct.",
          `<a href="/login">Back to Login</a>`
        )
      );
    }

    req.session.user = username;
    ensureDir(path.join(UPLOADS_USERS, username));
    if (!SHARES.users[username]) SHARES.users[username] = [];
    saveShares(SHARES);

    return res.redirect("/dashboard");
  });

  // Serve SPA for register route.
  app.get("/register", (req, res) => {
    if (HAS_DIST) return res.sendFile(path.join(DIST_DIR, "index.html"));
    return res.status(500).send("Frontend build missing. Run: npm run build");
  });

  // Handle registration form submission.
  app.post("/register", async (req, res) => {
    const { username, password } = req.body;
    if (!username || !password) {
      return res.send(
        renderError(
          "Missing Fields",
          "You must provide both a username and a password.",
          `<a href="/register" class="btn-primary">Try Again</a>`
        )
      );
    }

    if (USERS[username]) {
      return res.send(
        renderError(
          "Username Taken",
          `The username <b>${username}</b> is already in use.`,
          `<a href="/register" class="btn-primary">Try Again</a>`
        )
      );
    }

    const hash = await bcrypt.hash(password, 10);
    USERS[username] = hash;
    saveUsers(USERS);

    ensureDir(path.join(UPLOADS_USERS, username));
    if (!SHARES.users[username]) SHARES.users[username] = [];
    saveShares(SHARES);

    return res.redirect("/login?created=1");
  });

  // Clear session and return to home.
  app.get("/logout", (req, res) => req.session.destroy(() => res.redirect("/")));
};
