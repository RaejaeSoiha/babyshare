// User file upload and secure download routes.
const path = require("path");
const multer = require("multer");
const bcrypt = require("bcryptjs");
const QRCode = require("qrcode");

module.exports = function registerFileRoutes(app, deps) {
  const {
    SECRET_KEY,
    UPLOADS_USERS,
    USERS,
    SHARES,
    saveShares,
    ensureDir,
    encryptFile,
    decryptFile,
    renderAccessOptions,
    requireLogin,
    requireAdmin,
    mapUserFiles,
    getShareBaseUrl,
  } = deps;

  // Store user uploads under their personal directory.
  const userStorage = multer.diskStorage({
    destination: (req, f, cb) => {
      const d = path.join(UPLOADS_USERS, req.session.user);
      ensureDir(d);
      cb(null, d);
    },
    filename: (req, f, cb) => cb(null, Date.now() + "-" + f.originalname),
  });

  // Limit file size to 1GB per file.
  const uploadUser = multer({
    storage: userStorage,
    limits: { fileSize: 1024 * 1024 * 1024 },
  });

  // Handle authenticated uploads and return share links as JSON.
  app.post("/upload", requireLogin, uploadUser.array("files"), async (req, res) => {
    const label = req.body.label || "";
    const password = req.body.password || null;
    let hash = null;
    if (password && password.trim() !== "") {
      hash = await bcrypt.hash(password, 10);
    }

    const links = [];
    for (const f of req.files) {
      const encPath = f.path + ".enc";
      await encryptFile(f.path, encPath, SECRET_KEY);

      if (!SHARES.users[req.session.user]) SHARES.users[req.session.user] = [];
      SHARES.users[req.session.user].push({
        file: path.basename(encPath),
        original: f.originalname,
        label,
        uploaded: Date.now(),
        expires: Date.now() + 30 * 24 * 60 * 60 * 1000,
        hash,
      });
      saveShares(SHARES);

      const shareBase = getShareBaseUrl(req);
      const fileUrl = `${shareBase}/secure-download/${req.session.user}/${path.basename(encPath)}`;
      const qrCode = await QRCode.toDataURL(fileUrl);
      links.push({
        name: label || f.originalname,
        url: fileUrl,
        qr: qrCode,
        hash,
      });
    }

    return res.json({ ok: true, links });
  });

  // Legacy route: redirect to the files page.
  app.get("/list", requireLogin, (req, res) => res.redirect("/files"));

  // Public share endpoint (password-gated if a password was set).
  app.get("/secure-download/:u/:f", (req, res) => {
    const { u, f } = req.params;
    const fileMeta = (SHARES.users[u] || []).find((item) => item.file === f);
    if (!fileMeta) return res.status(404).send("File not found");

    const action = req.query.action;
    const fp = path.join(UPLOADS_USERS, u, f);
    if (!require("fs").existsSync(fp)) {
      SHARES.users[u] = (SHARES.users[u] || []).filter((item) => item.file !== f);
      saveShares(SHARES);
      return res.status(404).send("File not found");
    }

    if (!fileMeta.hash) {
      const filename = f.replace(/\.enc$/, "");
      if (action === "preview") {
        return decryptFile(fp, res, filename, SECRET_KEY, { disposition: "inline" });
      }
      return decryptFile(fp, res, filename, SECRET_KEY, { disposition: "attachment" });
    }

    return res.send(
      renderAccessOptions(
        "Choose an action",
        `File: <b>${fileMeta.label || fileMeta.original || f}</b>`,
        `/secure-download/${u}/${f}?action=preview`,
        `/secure-download/${u}/${f}?action=download`
      )
    );
  });

  // Password-protected download handler.
  app.post("/secure-download/:u/:f", require("express").urlencoded({ extended: true }), async (req, res) => {
    const { u, f } = req.params;
    const { password, action } = req.body;
    const fileMeta = (SHARES.users[u] || []).find((item) => item.file === f);
    if (!fileMeta) return res.status(404).send("File not found");

    if (!fileMeta.hash || (await bcrypt.compare(password, fileMeta.hash))) {
      const fp = path.join(UPLOADS_USERS, u, f);
      const filename = f.replace(/\.enc$/, "");
      if (action === "preview") {
        return decryptFile(fp, res, filename, SECRET_KEY, { disposition: "inline" });
      }
      return decryptFile(fp, res, filename, SECRET_KEY, { disposition: "attachment" });
    }

    return res.status(403).send("Invalid password");
  });

  // Auth-only download route.
  app.get("/download/:u/:f", requireLogin, (req, res) => {
    const fp = path.join(UPLOADS_USERS, req.params.u, req.params.f);
    if (!require("fs").existsSync(fp)) return res.send("Not found");
    decryptFile(fp, res, req.params.f.replace(/\.enc$/, ""), SECRET_KEY);
  });

  // Auth-only delete route (admin can delete any file).
  app.get("/delete/:u/:f", requireLogin, (req, res) => {
    if (req.session.user !== "admin" && req.session.user !== req.params.u)
      return res.send("No access");
    const fp = path.join(UPLOADS_USERS, req.params.u, req.params.f);
    if (require("fs").existsSync(fp)) require("fs").unlinkSync(fp);
    res.redirect("/files");
  });
};
