// Guest upload and access flows.
const crypto = require("crypto");
const fs = require("fs");
const path = require("path");
const multer = require("multer");
const bcrypt = require("bcryptjs");
const QRCode = require("qrcode");
const { isValidAction, isValidLabel, isValidPassword, isValidUploadName } = require("../utils/security");

const FILE_SIZE_LIMIT = 1024 * 1024 * 1024;
const GUEST_SHARE_DURATION_MS = 24 * 60 * 60 * 1000;

module.exports = function registerGuestRoutes(app, deps) {
  const {
    SECRET_KEY,
    SHARES,
    UPLOADS_GUESTS,
    UPLOADS_TMP,
    decryptFile,
    encryptFile,
    getShareBaseUrl,
    isExpired,
    passwordLimiter,
    renderGuestAccess,
    renderPasswordPrompt,
    resolveWithin,
    saveShares,
    uploadLimiter,
  } = deps;

  fs.mkdirSync(UPLOADS_TMP, { recursive: true });
  const uploadGuest = multer({
    dest: UPLOADS_TMP,
    fileFilter: (_req, file, callback) => callback(null, isValidUploadName(file.originalname)),
    limits: { fieldNameSize: 100, fieldSize: 2048, fields: 3, fileSize: FILE_SIZE_LIMIT, files: 1, parts: 4 },
  });

  function getGuestShare(token) {
    if (typeof token !== "string" || !/^[a-f0-9]{16,64}$/i.test(token)) return null;
    return Object.prototype.hasOwnProperty.call(SHARES.guests, token) ? SHARES.guests[token] : null;
  }

  function getGuestFilePath(share) {
    return share && typeof share.filename === "string" ? resolveWithin(UPLOADS_GUESTS, share.filename) : null;
  }

  function guestPath(token) {
    return `/guest-view?token=${encodeURIComponent(token)}`;
  }

  function downloadPath(token, action) {
    return `/guest-download?token=${encodeURIComponent(token)}&action=${action}`;
  }

  function sendInvalidShare(res) {
    return res.status(404).send("Invalid or expired link");
  }

  async function serveGuestFile(res, share, action) {
    const filePath = getGuestFilePath(share);
    if (!filePath || !fs.existsSync(filePath)) return res.status(404).send("File not found");
    return decryptFile(filePath, res, share.original || path.basename(filePath).replace(/\.enc$/, ""), SECRET_KEY, {
      disposition: action === "preview" ? "inline" : "attachment",
    });
  }

  app.post("/guest-upload", uploadLimiter, uploadGuest.single("file"), async (req, res, next) => {
    const label = typeof req.body.label === "string" ? req.body.label.trim() : "";
    const password = typeof req.body.password === "string" ? req.body.password : "";
    if (!req.file) return res.status(400).json({ error: "missing_file" });
    if (!isValidLabel(label)) return res.status(400).json({ error: "invalid_label" });
    if (password && !isValidPassword(password)) return res.status(400).json({ error: "invalid_password" });

    const directoryName = crypto.randomBytes(16).toString("hex");
    const directory = resolveWithin(UPLOADS_GUESTS, directoryName);
    const storedFilename = `${crypto.randomUUID()}.enc`;
    const encryptedPath = resolveWithin(directory, storedFilename);
    if (!directory || !encryptedPath) return res.status(400).json({ error: "invalid_request" });

    try {
      fs.mkdirSync(directory, { recursive: true });
      await encryptFile(req.file.path, encryptedPath, SECRET_KEY);
      const token = crypto.randomBytes(16).toString("hex");
      const hash = password ? await bcrypt.hash(password, 12) : null;
      const expires = Date.now() + GUEST_SHARE_DURATION_MS;
      SHARES.guests[token] = {
        expires,
        filename: path.join(directoryName, storedFilename),
        hash,
        label,
        original: req.file.originalname,
      };
      saveShares(SHARES);

      const link = `${getShareBaseUrl()}${guestPath(token)}`;
      return res.status(201).json({
        expires,
        label,
        link,
        passwordRequired: Boolean(hash),
        qrCode: await QRCode.toDataURL(link),
      });
    } catch (error) {
      await fs.promises.unlink(req.file.path).catch(() => {});
      if (directory) await fs.promises.rm(directory, { recursive: true, force: true }).catch(() => {});
      return next(error);
    }
  });

  app.get("/guest-view", (req, res) => {
    const token = typeof req.query.token === "string" ? req.query.token : "";
    const share = getGuestShare(token);
    if (!share || isExpired(share) || !getGuestFilePath(share)) return sendInvalidShare(res);
    if (share.hash) {
      return res.send(renderPasswordPrompt({
        actionUrl: "/guest-login",
        filename: share.label || share.original || "Shared file",
        hiddenFields: { token },
        title: "Password required",
      }));
    }
    return res.send(renderGuestAccess({
      downloadUrl: downloadPath(token, "download"),
      filename: share.label || share.original || "Shared file",
      previewUrl: downloadPath(token, "preview"),
    }));
  });

  // Kept as a compatibility route for existing guest links and UI navigation.
  app.get("/guest-login", (req, res) => {
    const token = typeof req.query.token === "string" ? req.query.token : "";
    return res.redirect(guestPath(token));
  });

  app.post("/guest-login", passwordLimiter, async (req, res, next) => {
    try {
      const token = typeof req.body.token === "string" ? req.body.token : "";
      const share = getGuestShare(token);
      if (!share || isExpired(share)) return sendInvalidShare(res);
      const password = typeof req.body.password === "string" ? req.body.password : "";
      if (!share.hash || !(await bcrypt.compare(password, share.hash))) {
        return res.status(401).send(renderPasswordPrompt({
          actionUrl: "/guest-login",
          error: "Incorrect password. Try again.",
          filename: share.label || share.original || "Shared file",
          hiddenFields: { token },
          title: "Password required",
        }));
      }
      const action = isValidAction(req.body.action) ? req.body.action : "download";
      return serveGuestFile(res, share, action);
    } catch (error) {
      return next(error);
    }
  });

  app.get("/guest-download", async (req, res) => {
    const token = typeof req.query.token === "string" ? req.query.token : "";
    const share = getGuestShare(token);
    if (!share || isExpired(share)) return sendInvalidShare(res);
    if (share.hash) return res.redirect(guestPath(token));
    const action = isValidAction(req.query.action) ? req.query.action : "download";
    return serveGuestFile(res, share, action);
  });

  app.get("/api/guest-info/:token", (req, res) => {
    const share = getGuestShare(req.params.token);
    if (!share || isExpired(share) || !getGuestFilePath(share)) return res.status(404).json({ error: "expired" });
    return res.json({
      expiresAt: new Date(share.expires).toISOString(),
      label: share.label || "",
      original: share.original || "",
      passwordRequired: Boolean(share.hash),
    });
  });
};
