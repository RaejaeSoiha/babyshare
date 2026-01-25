// Guest upload and access flows.
const path = require("path");
const multer = require("multer");
const bcrypt = require("bcryptjs");
const crypto = require("crypto");
const QRCode = require("qrcode");
const fs = require("fs");

module.exports = function registerGuestRoutes(app, deps) {
  const {
    SECRET_KEY,
    SHARES,
    saveShares,
    ensureDir,
    encryptFile,
    decryptFile,
    UPLOADS_GUESTS,
    getShareBaseUrl,
  } = deps;

  // Temp upload directory for guest uploads.
  ensureDir(path.join(__dirname, "..", "..", "uploads", "tmp"));
  const uploadGuest = multer({ dest: "uploads/tmp" });

  // Render a minimal guest access page (for non-SPA flows).
  function renderGuestPage(token, share, baseUrl) {
    const filename = path.basename(share.filename).replace(/\.enc$/, "");
    if (!share.hash) {
      return `
      <!DOCTYPE html>
      <html lang="en">
      <head>
        <meta charset="UTF-8" />
        <meta name="viewport" content="width=device-width, initial-scale=1" />
        <title>Guest Access</title>
        <style>
          body { font-family: Arial, sans-serif; background:#0b0f16; color:#eef2f7; display:flex; justify-content:center; align-items:center; min-height:100vh; margin:0; }
          .card { background:#111827; padding:24px; border-radius:12px; max-width:420px; width:90%; text-align:center; box-shadow:0 10px 30px rgba(0,0,0,0.4); }
          .btn { display:inline-block; margin:8px; padding:10px 16px; border-radius:8px; text-decoration:none; color:white; background:#2563eb; font-weight:600; }
          .btn.alt { background:#16a34a; }
        </style>
      </head>
      <body>
        <div class="card">
          <h2>Guest Access</h2>
          <p>${share.label || share.original || filename}</p>
          <a class="btn" href="${baseUrl}/guest-download?token=${token}&action=preview">Review</a>
          <a class="btn alt" href="${baseUrl}/guest-download?token=${token}&action=download">Download</a>
        </div>
      </body>
      </html>
    `;
    }

    return `
    <!DOCTYPE html>
    <html lang="en">
    <head>
      <meta charset="UTF-8" />
      <meta name="viewport" content="width=device-width, initial-scale=1" />
      <title>Password Required</title>
      <style>
        body { font-family: Arial, sans-serif; background:#0b0f16; color:#eef2f7; display:flex; justify-content:center; align-items:center; min-height:100vh; margin:0; }
        .card { background:#111827; padding:24px; border-radius:12px; max-width:420px; width:90%; text-align:center; box-shadow:0 10px 30px rgba(0,0,0,0.4); }
        input { width:100%; padding:10px; border-radius:8px; border:1px solid #334155; margin:10px 0; background:#0b1220; color:#eef2f7; }
        .btn { display:inline-block; margin:8px; padding:10px 16px; border-radius:8px; text-decoration:none; color:white; background:#2563eb; font-weight:600; border:none; }
      </style>
    </head>
    <body>
      <div class="card">
        <h2>Password Required</h2>
        <form method="POST" action="${baseUrl}/guest-login">
          <input type="hidden" name="token" value="${token}" />
          <input type="password" name="password" placeholder="Enter password" required />
          <div>
            <button class="btn" type="submit" name="action" value="preview">Review</button>
            <button class="btn" type="submit" name="action" value="download">Download</button>
          </div>
        </form>
      </div>
    </body>
    </html>
  `;
  }

  // Guest upload: encrypt and return QR/link metadata as JSON.
  app.post("/guest-upload", uploadGuest.single("file"), async (req, res) => {
    const { password, label } = req.body;
    if (!req.file) return res.send("Missing file");

    const gid = crypto.randomBytes(6).toString("hex");
    const dir = path.join(UPLOADS_GUESTS, gid);
    ensureDir(dir);

    const encPath = path.join(dir, req.file.originalname + ".enc");
    await encryptFile(req.file.path, encPath, SECRET_KEY);

    const token = crypto.randomBytes(8).toString("hex");
    let hash = null;
    if (password && password.trim() !== "") {
      hash = await bcrypt.hash(password, 10);
    }

    SHARES.guests[token] = {
      username: "guest",
      filename: encPath,
      hash,
      label: label || "",
      original: req.file.originalname,
      expires: Date.now() + 24 * 60 * 60 * 1000,
    };
    saveShares(SHARES);

    const link = `${getShareBaseUrl(req)}/guest-view?token=${token}`;
    const qrCode = await QRCode.toDataURL(link);

    return res.json({
      token,
      link,
      qrCode,
      label: label || "",
      expires: SHARES.guests[token].expires,
      passwordRequired: Boolean(hash),
    });
  });

  // Entry point for guest share links.
  app.get("/guest-view", (req, res) => {
    const token = req.query.token;
    const share = SHARES.guests[token];
    if (!share || Date.now() > share.expires) {
      return res.send(" Invalid or expired link.");
    }
    return res.send(renderGuestPage(token, share, getShareBaseUrl(req)));
  });

  // Same as guest-view, kept for compatibility.
  app.get("/guest-login", (req, res) => {
    const token = req.query.token;
    const share = SHARES.guests[token];
    if (!share || Date.now() > share.expires) {
      return res.send(" Invalid or expired link.");
    }
    return res.send(renderGuestPage(token, share, getShareBaseUrl(req)));
  });

  // Password submission for guest access.
  app.post("/guest-login", require("express").urlencoded({ extended: true }), async (req, res) => {
    const { token, password, action } = req.body;
    const share = SHARES.guests[token];
    if (share && Date.now() < share.expires) {
      if (!share.hash) {
        const filename = path.basename(share.filename).replace(/\.enc$/, "");
        if (action === "preview") {
          return decryptFile(share.filename, res, filename, SECRET_KEY, { disposition: "inline" });
        }
        return decryptFile(share.filename, res, filename, SECRET_KEY, { disposition: "attachment" });
      }
      if (await bcrypt.compare(password, share.hash)) {
        const filename = path.basename(share.filename).replace(/\.enc$/, "");
        if (action === "preview") {
          return decryptFile(share.filename, res, filename, SECRET_KEY, { disposition: "inline" });
        }
        return decryptFile(share.filename, res, filename, SECRET_KEY, { disposition: "attachment" });
      }
    }

    res.send(" Invalid/Expired");
  });

  // Guest download or inline preview.
  app.get("/guest-download", (req, res) => {
    const token = req.query.token;
    const action = req.query.action;
    const share = SHARES.guests[token];

    if (!share || Date.now() > share.expires) {
      return res.send(" Invalid or expired link.");
    }
    if (!fs.existsSync(share.filename)) {
      delete SHARES.guests[token];
      saveShares(SHARES);
      return res.status(404).send("File not found");
    }
    if (share.hash) {
      return res.redirect(`/guest-login?token=${encodeURIComponent(token)}`);
    }

    const filename = path.basename(share.filename).replace(/\.enc$/, "");
    if (action === "preview") {
      return decryptFile(share.filename, res, filename, SECRET_KEY, { disposition: "inline" });
    }
    return decryptFile(share.filename, res, filename, SECRET_KEY, { disposition: "attachment" });
  });

  // Client-side helper for the guest login page.
  app.get("/api/guest-info/:token", (req, res) => {
    const token = req.params.token;
    const share = SHARES.guests[token];
    if (!share || Date.now() > share.expires) {
      return res.status(404).json({ error: "expired" });
    }
    return res.json({
      label: share.label || "",
      original: share.original || "",
      expiresAt: new Date(share.expires).toISOString(),
      passwordRequired: Boolean(share.hash),
    });
  });
};
