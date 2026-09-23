// Authenticated uploads, secure share links, downloads, and deletion.
const crypto = require("crypto");
const fs = require("fs");
const path = require("path");
const multer = require("multer");
const bcrypt = require("bcryptjs");
const QRCode = require("qrcode");
const { isValidAction, isValidLabel, isValidPassword, isValidUploadName, resolveWithin } = require("../utils/security");

const FILE_SIZE_LIMIT = 1024 * 1024 * 1024;
const USER_SHARE_DURATION_MS = 30 * 24 * 60 * 60 * 1000;

module.exports = function registerFileRoutes(app, deps) {
  const {
    SECRET_KEY,
    SHARES,
    UPLOADS_USERS,
    decryptFile,
    encryptFile,
    getShareBaseUrl,
    getUserFileMeta,
    getUserFilePath,
    isExpired,
    passwordLimiter,
    removeUserShare,
    renderPasswordPrompt,
    requireLogin,
    saveShares,
    uploadLimiter,
  } = deps;

  const userStorage = multer.diskStorage({
    destination: (req, _file, callback) => {
      const directory = resolveWithin(UPLOADS_USERS, req.session.user);
      if (!directory) return callback(new Error("Invalid upload destination"));
      fs.mkdirSync(directory, { recursive: true });
      return callback(null, directory);
    },
    filename: (_req, _file, callback) => callback(null, crypto.randomUUID()),
  });
  const uploadUser = multer({
    fileFilter: (_req, file, callback) => callback(null, isValidUploadName(file.originalname)),
    limits: { fieldNameSize: 100, fieldSize: 2048, fields: 4, fileSize: FILE_SIZE_LIMIT, files: 20, parts: 24 },
    storage: userStorage,
  });

  function sharePath(username, filename) {
    return `/secure-download/${encodeURIComponent(username)}/${encodeURIComponent(filename)}`;
  }

  function sendExpired(res) {
    return res.status(410).send("This share link has expired");
  }

  async function serveFile(res, filePath, fileMeta, action) {
    const disposition = action === "preview" ? "inline" : "attachment";
    return decryptFile(filePath, res, fileMeta.original || fileMeta.file.replace(/\.enc$/, ""), SECRET_KEY, { disposition });
  }

  app.post("/upload", requireLogin, uploadLimiter, uploadUser.array("files", 20), async (req, res, next) => {
    const uploadedFiles = Array.isArray(req.files) ? req.files : [];
    const label = typeof req.body.label === "string" ? req.body.label.trim() : "";
    const password = typeof req.body.password === "string" ? req.body.password : "";
    if (uploadedFiles.length === 0) return res.status(400).json({ error: "missing_file" });
    if (!isValidLabel(label)) return res.status(400).json({ error: "invalid_label" });
    if (password && !isValidPassword(password)) return res.status(400).json({ error: "invalid_password" });

    const created = [];
    try {
      const hash = password ? await bcrypt.hash(password, 12) : null;
      for (const file of uploadedFiles) {
        const encryptedPath = `${file.path}.enc`;
        await encryptFile(file.path, encryptedPath, SECRET_KEY);
        created.push({
          expires: Date.now() + USER_SHARE_DURATION_MS,
          file: path.basename(encryptedPath),
          hash,
          label,
          original: file.originalname,
          uploaded: Date.now(),
        });
      }

      if (!Array.isArray(SHARES.users[req.session.user])) SHARES.users[req.session.user] = [];
      SHARES.users[req.session.user].push(...created);
      saveShares(SHARES);

      const shareBase = getShareBaseUrl();
      const links = await Promise.all(created.map(async (fileMeta) => {
        const url = `${shareBase}${sharePath(req.session.user, fileMeta.file)}`;
        return {
          expires: fileMeta.expires,
          name: fileMeta.label || fileMeta.original,
          passwordRequired: Boolean(fileMeta.hash),
          qr: await QRCode.toDataURL(url),
          url,
        };
      }));
      return res.status(201).json({ links, ok: true });
    } catch (error) {
      for (const fileMeta of created) {
        const encryptedPath = resolveWithin(UPLOADS_USERS, req.session.user, fileMeta.file);
        if (encryptedPath) await fs.promises.unlink(encryptedPath).catch(() => {});
      }
      for (const file of uploadedFiles) {
        await fs.promises.unlink(file.path).catch(() => {});
      }
      return next(error);
    }
  });

  app.get("/list", requireLogin, (_req, res) => res.redirect("/files"));

  app.get("/secure-download/:u/:f", async (req, res) => {
    const fileMeta = getUserFileMeta(req.params.u, req.params.f);
    const filePath = getUserFilePath(req.params.u, req.params.f);
    if (!fileMeta || !filePath) return res.status(404).send("File not found");
    if (isExpired(fileMeta)) return sendExpired(res);
    if (!fs.existsSync(filePath)) {
      removeUserShare(req.params.u, req.params.f);
      return res.status(404).send("File not found");
    }

    const action = isValidAction(req.query.action) ? req.query.action : "download";
    if (!fileMeta.hash) return serveFile(res, filePath, fileMeta, action);
    return res.send(renderPasswordPrompt({
      actionUrl: sharePath(req.params.u, req.params.f),
      filename: fileMeta.label || fileMeta.original || "Shared file",
      title: "Password required",
    }));
  });

  app.post("/secure-download/:u/:f", passwordLimiter, async (req, res, next) => {
    try {
      const fileMeta = getUserFileMeta(req.params.u, req.params.f);
      const filePath = getUserFilePath(req.params.u, req.params.f);
      if (!fileMeta || !filePath || !fs.existsSync(filePath)) return res.status(404).send("File not found");
      if (isExpired(fileMeta)) return sendExpired(res);

      const action = isValidAction(req.body.action) ? req.body.action : "download";
      const password = typeof req.body.password === "string" ? req.body.password : "";
      if (!fileMeta.hash || !(await bcrypt.compare(password, fileMeta.hash))) {
        return res.status(401).send(renderPasswordPrompt({
          actionUrl: sharePath(req.params.u, req.params.f),
          error: "Incorrect password. Try again.",
          filename: fileMeta.label || fileMeta.original || "Shared file",
          title: "Password required",
        }));
      }
      return serveFile(res, filePath, fileMeta, action);
    } catch (error) {
      return next(error);
    }
  });

  app.get("/download/:u/:f", requireLogin, async (req, res) => {
    if (req.session.user !== "admin" && req.session.user !== req.params.u) {
      return res.status(403).send("No access");
    }
    const fileMeta = getUserFileMeta(req.params.u, req.params.f);
    const filePath = getUserFilePath(req.params.u, req.params.f);
    if (!fileMeta || !filePath || !fs.existsSync(filePath)) return res.status(404).send("File not found");
    if (isExpired(fileMeta)) return sendExpired(res);
    return serveFile(res, filePath, fileMeta, "download");
  });

  app.delete("/api/files/:u/:f", requireLogin, async (req, res, next) => {
    try {
      if (req.session.user !== "admin" && req.session.user !== req.params.u) {
        return res.status(403).json({ error: "forbidden" });
      }
      const fileMeta = getUserFileMeta(req.params.u, req.params.f);
      const filePath = getUserFilePath(req.params.u, req.params.f);
      if (!fileMeta || !filePath) return res.status(404).json({ error: "not_found" });
      if (fs.existsSync(filePath)) await fs.promises.unlink(filePath);
      removeUserShare(req.params.u, req.params.f);
      return res.status(204).end();
    } catch (error) {
      return next(error);
    }
  });

  app.get("/delete/:u/:f", requireLogin, (_req, res) => {
    res.status(405).send("Use the file management page to delete a file");
  });
};
