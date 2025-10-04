const express = require("express");
const multer = require("multer");
const path = require("path");
const fs = require("fs");
const session = require("express-session");
const crypto = require("crypto");
const bcrypt = require("bcryptjs");
const http = require("http");
const https = require("https");
const QRCode = require("qrcode");
const os = require("os");
require("dotenv").config();

const app = express();
const algorithm = "aes-256-ctr";
const RAW_KEY = process.env.FILE_KEY || "fallback-secret-key";
const SECRET_KEY = crypto.createHash("sha256").update(RAW_KEY).digest(); // always 32 bytes
const IV_LENGTH = 16;

// ---------------- SECURITY MIDDLEWARE ----------------
const helmet = require("helmet");
app.use(helmet());

// ---------------- FILE PATHS ----------------
const USERS_FILE = path.join(__dirname, "users.json");
const SHARES_FILE = path.join(__dirname, "shares.json");
const UPLOADS_USERS = path.join(__dirname, "uploads/users");
const UPLOADS_GUESTS = path.join(__dirname, "uploads/guests");

// ---------------- LOAD DATA ----------------
let USERS = fs.existsSync(USERS_FILE)
  ? JSON.parse(fs.readFileSync(USERS_FILE))
  : { admin: "admin123" };

let SHARES = fs.existsSync(SHARES_FILE)
  ? JSON.parse(fs.readFileSync(SHARES_FILE))
  : { users: {}, guests: {} };

// Ensure structure always exists
if (!SHARES.users) SHARES.users = {};
if (!SHARES.guests) SHARES.guests = {};

// Auto-migrate plain text users to bcrypt hashes
(async () => {
  let changed = false;
  for (const [user, pass] of Object.entries(USERS)) {
    if (!pass.startsWith("$2")) {
      USERS[user] = await bcrypt.hash(pass, 10);
      changed = true;
    }
  }
  if (changed) saveUsers();
})();

function saveUsers() {
  fs.writeFileSync(USERS_FILE, JSON.stringify(USERS, null, 2));
}
function saveShares() {
  fs.writeFileSync(SHARES_FILE, JSON.stringify(SHARES, null, 2));
}

// ---------------- UTILS ----------------
function ensureDir(dir) {
  if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
}
ensureDir(UPLOADS_USERS);
ensureDir(UPLOADS_GUESTS);

function getLocalIp() {
  const nets = os.networkInterfaces();
  for (const name of Object.keys(nets)) {
    for (const net of nets[name]) {
      if (net.family === "IPv4" && !net.internal) return net.address;
    }
  }
  return "localhost";
}

const localIp = getLocalIp();

// ✅ Moved environment variables to the top (before routes use them)
const PORT = process.env.PORT || 3000;
const NODE_ENV = process.env.NODE_ENV || "development";
const DOMAIN = process.env.DOMAIN || "";
const IS_CLOUD = NODE_ENV === "production" || process.env.KOYEB_APP_NAME;

// ✅ Helpful startup logs
console.log("🧭 Mode:", IS_CLOUD ? "Cloud (Koyeb)" : "Local (Offline)");
console.log("🌍 Domain:", DOMAIN || "Not set");

// ---------------- ENCRYPTION ----------------
function encryptFile(inputPath, outputPath) {
  return new Promise((resolve, reject) => {
    const iv = crypto.randomBytes(IV_LENGTH);
    const cipher = crypto.createCipheriv(algorithm, SECRET_KEY, iv);
    const input = fs.createReadStream(inputPath);
    const output = fs.createWriteStream(outputPath);
    output.write(iv);
    input.pipe(cipher).pipe(output);
    output.on("finish", () => {
      fs.unlinkSync(inputPath);
      resolve();
    });
    output.on("error", reject);
  });
}

function decryptFile(inputPath, res, filename) {
  return new Promise((resolve) => {
    const input = fs.createReadStream(inputPath);
    input.once("readable", () => {
      const iv = input.read(IV_LENGTH);
      const decipher = crypto.createDecipheriv(algorithm, SECRET_KEY, iv);
      res.setHeader(
        "Content-Disposition",
        `attachment; filename="${filename}"`
      );
      input.pipe(decipher).pipe(res);
      resolve();
    });
  });
}

// ---------------- CLEANUP ----------------
function cleanup() {
  const now = Date.now();

  // --- Guests cleanup (24h expiry) ---
  Object.keys(SHARES.guests || {}).forEach((t) => {
    const g = SHARES.guests[t];
    if (!g || g.expires < now) {
      if (g && fs.existsSync(g.filename)) {
        try {
          fs.unlinkSync(g.filename);
          console.log(`🗑 Deleted expired guest file: ${g.filename}`);
          const dir = path.dirname(g.filename);
          if (fs.existsSync(dir) && fs.readdirSync(dir).length === 0) {
            fs.rmdirSync(dir);
          }
        } catch (err) {
          console.error("⚠️ Failed to delete guest file:", err.message);
        }
      }
      delete SHARES.guests[t];
    }
  });

  // --- Users cleanup (30 days expiry) ---
  Object.keys(SHARES.users || {}).forEach((u) => {
    SHARES.users[u] = (SHARES.users[u] || []).filter((file) => {
      if (file.expires && file.expires < now) {
        const fp = path.join(UPLOADS_USERS, u, file.file);
        if (fs.existsSync(fp)) {
          try {
            fs.unlinkSync(fp);
            console.log(`🗑 Deleted expired user file: ${fp}`);
          } catch (err) {
            console.error("⚠️ Failed to delete user file:", err.message);
          }
        }
        return false;
      }
      return true;
    });
  });

  saveShares();
  console.log("🧹 Cleanup done at", new Date().toISOString());
}
cleanup();
setInterval(cleanup, 60 * 60 * 1000);

// ---------------- MIDDLEWARE ----------------
app.use(
  session({
    secret: process.env.SESSION_SECRET || "fallback-secret",
    resave: false,
    saveUninitialized: true,
  })
);
app.use(express.static("public"));
app.use(express.urlencoded({ extended: true, limit: "1gb" }));
app.use(express.json({ limit: "1gb" }));

function requireLogin(req, res, next) {
  if (req.session.user) return next();
  res.redirect("/login");
}
function requireAdmin(req, res, next) {
  if (req.session.user === "admin") return next();
  res.status(403).send("Admins only");
}



// ---------------- HTML HELPERS ----------------
function renderError(title, message, actionsHtml = "") {
  return `
    <!DOCTYPE html>
    <html lang="en">
    <head>
      <meta charset="UTF-8">
      <title> Error</title>
      <link rel="stylesheet" href="/style.css">
      <style>
        body {
          margin:0;
          padding:0;
          font-family:"Segoe UI", sans-serif;
          background:#000;   /*  Black background */
          overflow:hidden;
        }
        #bg-canvas {
          position:fixed;
          top:0; left:0;
          width:100%; height:100%;
          z-index:0;
        }
        .container.card {
          background:#fff;
          padding:2rem 3rem;
          border-radius:15px;
          box-shadow:0 8px 20px rgba(0,0,0,0.4);
          text-align:center;
          max-width:450px;
          margin:10% auto;
          position:relative;
          z-index:1;
        }
      </style>
    </head>
    <body>
      <canvas id="bg-canvas"></canvas>
      <div class="container card">
        <h2 style="color:#d93025;"> ${title}</h2>
        <p>${message}</p>
        <p>${actionsHtml}</p>
      </div>
      <script src="/js/particles.js"></script>
      <script>particlesJS.load('bg-canvas','/js/particles.json');</script>
    </body>
    </html>
  `;
}

function renderSuccess(title, message, actionsHtml = "") {
  return `
    <!DOCTYPE html>
    <html lang="en">
    <head>
      <meta charset="UTF-8">
      <title> Success</title>
      <link rel="stylesheet" href="/style.css">
      <style>
        body {
          margin:0;
          padding:0;
          font-family:"Segoe UI", sans-serif;
          background:#000;   /* Black background */
          overflow:hidden;
        }
        #bg-canvas {
          position:fixed;
          top:0; left:0;
          width:100%; height:100%;
          z-index:0;
        }
        .container.card {
          background:#fff;
          padding:2rem 3rem;
          border-radius:15px;
          box-shadow:0 8px 20px rgba(0,0,0,0.4);
          text-align:center;
          max-width:450px;
          margin:10% auto;
          position:relative;
          z-index:1;
        }
      </style>
    </head>
    <body>
      <canvas id="bg-canvas"></canvas>
      <div class="container card">
        <h2 style="color:green;">${title}</h2>
        <p>${message}</p>
        <p>${actionsHtml}</p>
      </div>
      <script src="/js/particles.js"></script>
      <script>particlesJS.load('bg-canvas','/js/particles.json');</script>
    </body>
    </html>
  `;
}

// ---------------- HOME ----------------
app.get("/", (req, res) => {
  if (req.session.user) {
    const username = req.session.user;
    const html = `
    <!DOCTYPE html>
    <html lang="en">
    <head>
      <meta charset="UTF-8">
      <title>LAN File Share - Dashboard</title>
      <link rel="stylesheet" href="/style.css">
      <style>
        body {
          margin:0;
          padding:0;
          font-family:"Segoe UI", sans-serif;
          background:#000;  /* black background */
          overflow:hidden;
        }
        #bg-canvas {
          position:fixed;
          top:0; left:0;
          width:100%; height:100%;
          z-index:0;
        }
        .container.dashboard-card {
          background:#fff;
          padding:2rem 3rem;
          border-radius:15px;
          box-shadow:0 8px 20px rgba(0,0,0,0.4);
          text-align:center;
          max-width:600px;
          margin:5% auto;
          position:relative;
          z-index:1;  /* ensures content is above particles */
        }
      </style>
    </head>

    <body class="dashboard">
  <canvas id="bg-canvas"></canvas>

  <div class="container dashboard-card">
  <h1>Welcome Baby Share</h1>
  <p>Welcome, <strong>${username}</strong>!</p>
  <p>
    <span class="badge encrypted">🔒 Encrypted</span>
    <span class="badge expiry">⏳ 30d retention</span>
  </p>

  <div style="display:flex; gap:30px; align-items:flex-start; justify-content:space-between;">
    
    <!-- Left column: Upload Form -->
    <div style="flex:1; min-width:300px;">
      <form action="/upload" method="POST" enctype="multipart/form-data" class="form">
        <div class="form-group">
          <label for="files">Choose files to upload:</label>
          <input type="file" id="files" name="files" multiple required>
        </div>
        <div class="form-group">
          <label for="label">File Label (optional):</label>
          <input type="text" id="label" name="label" placeholder="Enter a label to identify your file">
        </div>
        <div class="form-group">
          <label for="password">Password (optional):</label>
          <input type="password" id="password" name="password" placeholder="Protect file with a password">
          </div>

        <button type="submit" class="btn-primary">⬆ Upload Files</button>
      </form>

      <div class="info-box">
        <p>📦 Uploaded files are <b>encrypted</b> and stored for up to <b>30 days</b>.</p>
        <p>🔑 Manage your files in the <b>My Files</b> section.</p>
      </div>

      <p>
        <a href="/list">📂 View My Files</a> |
        <a href="/logout">🚪 Logout</a>
      </p>
    </div>

    <!-- Right column: Manage Users (only for admin) -->
    ${username === "admin" ? `
    <div style="flex:1; min-width:350px;">
      <h2>👥 Manage Users</h2>

      <!-- Add user form -->
      <form action="/add-user" method="POST" style="margin-bottom:20px;">
        <input type="text" name="username" placeholder="New username" required>
        <input type="password" name="password" placeholder="Password" required>
        <button type="submit" class="btn-primary">➕ Add User</button>
      </form>

      <!-- Registered Users -->
      <table class="user-table">
        <thead>
          <tr>
            <th>👤 Username</th>
            <th>📦 Files</th>
            <th>⚙️ Action</th>
          </tr>
        </thead>
        <tbody>
          <tbody>
  ${Object.keys(USERS).map(u => {
    let count = 0;
    const userDir = path.join(UPLOADS_USERS, u);
    if (fs.existsSync(userDir)) {
      count = fs.readdirSync(userDir).length;
    }
    return `
      <tr>
        <td>${u}</td>
        <td>${count} file${count !== 1 ? "s" : ""}</td>
        
        
        <td style="white-space:nowrap;">
  ${u === "admin"
    ? "<span style='color:gray'>N/A</span>"
    : `
      <a href="/remove-user/${u}" onclick="return confirm('Delete user ${u}?')" 
         style="color:red; margin-right:10px; text-decoration:none;">🗑 Remove</a>

      <form action="/reset-user/${u}" method="POST" style="display:flex; align-items:center; gap:5px; max-width:200px;">
       <input type="text" name="newPassword" placeholder="Password"
       style="flex:1; min-width:80px; padding:3px 6px; font-size:0.75rem;">
       <button type="submit"
       style="background:orange; color:white; border:none; 
           padding:3px 8px; border-radius:4px; cursor:pointer; 
           font-size:0.75rem; white-space:nowrap;">
         🔄 Reset
         </button>
      </form>

       `}
      </td>
      </tr>`;
   }).join("")}
  </tbody>

      </table>
    </div>
    ` : ""}
  </div>
</div>
  <script src="/js/particles.js"></script>
  <script>
    particlesJS.load('bg-canvas','/js/particles.json');
  </script>
</body>
    </html>
    
    `;
    res.send(html);
  } else {
    res.sendFile(path.join(__dirname, "public/home.html"));
  }
});



// ---------------- AUTH ----------------
app.get("/login", (req, res) =>
  res.sendFile(path.join(__dirname, "public/login.html"))
);

app.post("/login", async (req, res) => {
  const { username, password } = req.body;

  // Case 1: User not found
  if (!USERS[username]) {
    return res.send(renderError(
      "User Not Found",
      `The username <b>${username}</b> does not exist.`,
      `<a href="/register">Create Account</a> | <a href="/login">Try Again</a>`
    ));
  }

  const stored = USERS[username];
  const valid = await bcrypt.compare(password, stored);

  // Case 2: Wrong password
  if (!valid) {
    return res.send(renderError(
      "Incorrect Password",
      `The password you entered is not correct.`,
      `<a href="/login">Back to Login</a>`
    ));
  }

  // Case 3: Success
  req.session.user = username;
  ensureDir(path.join(UPLOADS_USERS, username));
  if (!SHARES.users[username]) SHARES.users[username] = [];
  saveShares();

  res.redirect("/");
});


// ----------------  Register ----------------

app.get("/register", (req, res) =>
  res.sendFile(path.join(__dirname, "public/register.html"))
);

app.post("/register", async (req, res) => {
  const { username, password } = req.body;

  if (!username || !password) {
    return res.send(
      renderError(
        "Missing Fields",
        "You must provide both a username and a password.",
        `<a href="/register" class="btn-primary">🔄 Try Again</a>`
      )
    );
  }

  if (USERS[username]) {
    return res.send(
      renderError(
        "Username Taken",
        `The username <b>${username}</b> is already in use.`,
        `<a href="/register" class="btn-primary">🔄 Try Again</a>`
      )
    );
  }

  const hash = await bcrypt.hash(password, 10);
  USERS[username] = hash;
  saveUsers();

  ensureDir(path.join(UPLOADS_USERS, username));
  if (!SHARES.users[username]) SHARES.users[username] = [];
  saveShares();

  return res.send(
    renderSuccess(
      "Account Created",
      `Your account <b>${username}</b> was created successfully.`,
      `<a href="/login" class="btn-primary">➡ Login Now</a>`
    )
  );
});


app.get("/logout", (req, res) =>
  req.session.destroy(() => res.redirect("/"))
);

// ---------------- USER UPLOAD ----------------
const userStorage = multer.diskStorage({
  destination: (req, f, cb) => {
    const d = path.join(UPLOADS_USERS, req.session.user);
    ensureDir(d);
    cb(null, d);
  },
  filename: (req, f, cb) => cb(null, Date.now() + "-" + f.originalname),
});

//const uploadUser = multer({ storage: userStorage }); // Limit size
const uploadUser = multer({
  storage: userStorage,
  limits: { fileSize: 1024 * 1024 * 1024 } // 1 GB

});



app.post("/upload", requireLogin, uploadUser.array("files"), async (req, res) => {
  let links = [];
  const label = req.body.label || "";
  const password = req.body.password || null; // ✅ capture password

  let hash = null;
  if (password && password.trim() !== "") {
    hash = await bcrypt.hash(password, 10); // ✅ hash password if given
  }

  for (let f of req.files) {
    const encPath = f.path + ".enc";
    await encryptFile(f.path, encPath);

    if (!SHARES.users[req.session.user]) SHARES.users[req.session.user] = [];

    SHARES.users[req.session.user].push({
    file: path.basename(encPath),
    original: f.originalname,
    label,
    uploaded: Date.now(),
     expires: Date.now() + 30 * 24 * 60 * 60 * 1000, // 30 days
    hash, // password hash if provided
    });
    saveShares();


    // use secure-download instead of direct download
    // Build correct BASE_URL for local vs cloud
  const BASE_URL = DOMAIN 
    ? DOMAIN                      // use public domain in production
    : `http://${localIp}:${PORT}`; // local testing

  const fileUrl = `${BASE_URL}/secure-download/${req.session.user}/${path.basename(encPath)}`;
  const qrCode = await QRCode.toDataURL(fileUrl);



    links.push(`
      <li>
        <strong>${label || f.originalname}</strong>
        <div class="actions">
          <a class="btn-download" href="/secure-download/${req.session.user}/${path.basename(encPath)}">⬇ Download</a>
          <a class="btn-delete" href="/delete/${req.session.user}/${path.basename(encPath)}">🗑 Delete</a>
        </div>
        <div class="qr-box"><img src="${qrCode}"></div>
        ${hash 
          ? `<p style="color:red;">🔒 Password Protected</p>` 
          : `<p style="color:green;">✅ Open Access</p>`}
      </li>
    `);
  }

  res.send(`
  <!DOCTYPE html>
  <html lang="en">
  <head>
    <meta charset="UTF-8">
    <title>File Uploaded</title>
    <link rel="stylesheet" href="/style.css">
  </head>
  <body class="upload-success">
    <canvas id="bg-canvas"></canvas>
    <div class="container">
      <h2 style="color:green;">Uploaded & Encrypted</h2>
      <ul>${links.join("")}</ul>
      <p><a href="/list">📂 View My Files</a></p>
    </div>
    <script src="/js/particles.js"></script>
    <script>
      particlesJS.load('bg-canvas', '/js/particles.json');
    </script>
  </body>
  </html>
  `);
});



// ---------------- FILE LIST ----------------
app.get("/list", requireLogin, async (req, res) => {
  let html = `
  <!DOCTYPE html>
  <html>
  <head>
    <meta charset="UTF-8">
    <title>My Files</title>
    <link rel="stylesheet" href="/style.css">
  </head>
  <body class="file-list">
    <canvas id="bg-canvas"></canvas>
    <div class="container">
      <h1>${req.session.user === "admin" ? "Admin - All Files" : req.session.user + "'s Files"}</h1>
  `;

  if (req.session.user === "admin") {
    // Admin sees all users' files
    const userCount = Object.keys(USERS).length;
    const guestCount = Object.keys(SHARES.guests || {}).length;

    html += `
      <div style="margin-bottom:20px; padding:15px; background:#f8f9fa; border-radius:10px; text-align:center;">
        <h2>📊 System Stats</h2>
        <p><strong>👥 Registered Users:</strong> ${userCount}</p>
        <p><strong>🕵️ Guests Active:</strong> ${guestCount}</p>
      </div>
    `;

    for (let u of Object.keys(USERS)) {
      if (!fs.existsSync(path.join(UPLOADS_USERS, u))) continue;

      html += `<div style="border:1px solid #ddd; padding:15px; margin-bottom:20px; border-radius:10px; background:#fff;">
        <h2>${u}</h2>
        ${u !== "admin" ? `<p><a href="/remove-user/${u}" style="color:red;">🗑 Delete User</a></p>` : "<p><em>(protected)</em></p>"}
        <ul>
      `;

      for (let f of fs.readdirSync(path.join(UPLOADS_USERS, u))) {
        const BASE_URL = DOMAIN ? DOMAIN : `http://${localIp}:${PORT}`;
        const fileUrl = `${BASE_URL}/secure-download/${u}/${f}`;
        const qr = await QRCode.toDataURL(fileUrl);

        let fileMeta = (SHARES.users[u] || []).find(item => item.file === f);
        let label = fileMeta?.label || "";
        let original = fileMeta?.original || f;

        html += `
          <li>
            <strong>${label || original}</strong>
            ${label ? `<small>(${original})</small>` : ""}
            <div class="actions">
              <a class="btn-download" href="/secure-download/${u}/${f}">⬇ Download</a>
              <a class="btn-delete" href="/delete/${u}/${f}">🗑 Delete</a>
            </div>
            <div class="qr-box">
              <img src="${qr}" alt="QR for ${f}">
              ${fileMeta?.hash 
                ? `<p style="color:red; font-weight:bold; margin-top:5px;">🔒 Password Protected</p>` 
                : `<p style="color:green; margin-top:5px;">✅ Open Access</p>`}
            </div>
          </li>`;
      }

      html += "</ul></div>";
    }

  } else {
    // Normal user sees their own files
    const u = req.session.user;
    const userDir = path.join(UPLOADS_USERS, u);

    if (fs.existsSync(userDir)) {
      html += "<ul>";

      for (let f of fs.readdirSync(userDir)) {
        const BASE_URL = DOMAIN ? DOMAIN : `http://${localIp}:${PORT}`;
        const fileUrl = `${BASE_URL}/secure-download/${u}/${f}`;
        const qr = await QRCode.toDataURL(fileUrl);

        let fileMeta = (SHARES.users[u] || []).find(item => item.file === f);
        let label = fileMeta?.label || "";
        let original = fileMeta?.original || f;

        html += `
          <li>
            <strong>${label || original}</strong>
            ${label ? `<small>(${original})</small>` : ""}
            <div class="actions">
              <a class="btn-download" href="/secure-download/${u}/${f}">⬇ Download</a>
              <a class="btn-delete" href="/delete/${u}/${f}">🗑 Delete</a>
            </div>
            <div class="qr-box">
              <img src="${qr}" alt="QR for ${f}">
              ${fileMeta?.hash 
                ? `<p style="color:red; font-weight:bold; margin-top:5px;">🔒 Password Protected</p>` 
                : `<p style="color:green; margin-top:5px;">✅ Open Access</p>`}
            </div>
          </li>`;
      }

      html += "</ul>";
    } else {
      html += `<p>No files uploaded yet.</p>`;
    }
  }

 html += `
  <p><a href="/">⬅ Back</a></p>
  </div>

  <script src="/js/particles.js"></script>
  <script>
    particlesJS.load('bg-canvas','/js/particles.json', function() {
      console.log('Particles loaded on file list page');
    });
  </script>
</body>
</html>`;

  res.send(html);
});


//  Secure Download (with optional password)
app.get("/secure-download/:u/:f", (req, res) => {
  const { u, f } = req.params;
  const fileMeta = (SHARES.users[u] || []).find(item => item.file === f);

  if (!fileMeta) return res.send(" File not found");

  // If no password required → download immediately
  if (!fileMeta.hash) {
    const fp = path.join(UPLOADS_USERS, u, f);
    return decryptFile(fp, res, f.replace(/\.enc$/, ""));
  }

  // Otherwise → show password form
res.send(`
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>Password Required</title>
  <link rel="stylesheet" href="/style.css">
  <style>
    body {
      margin: 0;
      font-family: "Segoe UI", sans-serif;
      background: #000; /* black background for particles */
      height: 100vh;
      display: flex;
      justify-content: center;
      align-items: center;
      overflow: hidden;
    }
    #bg-canvas {
      position: fixed;
      top: 0; left: 0;
      width: 100%; height: 100%;
      z-index: 0;
    }
    .container {
      background: rgba(255,255,255,0.9);
      padding: 2rem;
      border-radius: 12px;
      box-shadow: 0 8px 20px rgba(0,0,0,0.4);
      text-align: center;
      z-index: 1;
      max-width: 400px;
      width: 90%;
    }
    h2 {
      margin-bottom: 1rem;
      font-size: 1.4rem;
      color: #d93025;
    }
    input[type="password"] {
      width: 100%;
      padding: 10px;
      border: 1px solid #ddd;
      border-radius: 8px;
      margin-bottom: 1rem;
      font-size: 1rem;
    }
    button {
      width: 100%;
      padding: 10px;
      background: #0078ff;
      border: none;
      color: #fff;
      font-weight: 600;
      border-radius: 8px;
      cursor: pointer;
      transition: background 0.3s ease;
    }
    button:hover {
      background: #005fcc;
    }
  </style>
</head>
<body>
  <canvas id="bg-canvas"></canvas>
  <div class="container">
    <h2>🔒 This file is password protected</h2>
    <form action="/secure-download/${u}/${f}" method="POST">
      <input type="password" name="password" placeholder="Enter password" required>
      <button type="submit">⬇ Download</button>
    </form>
  </div>
  <script src="/js/particles.js"></script>
  <script>
    particlesJS.load('bg-canvas','/js/particles.json', function() {
      console.log('Particles loaded on password page');
    });
  </script>
</body>
</html>
`);

});


// file project by password

app.post("/secure-download/:u/:f", express.urlencoded({ extended: true }), async (req, res) => {
  const { u, f } = req.params;
  const { password } = req.body;
  const fileMeta = (SHARES.users[u] || []).find(item => item.file === f);

  if (!fileMeta) return res.send(" File not found");

  if (!fileMeta.hash || (await bcrypt.compare(password, fileMeta.hash))) {
    const fp = path.join(UPLOADS_USERS, u, f);
    return decryptFile(fp, res, f.replace(/\.enc$/, ""));
  }

  // 🔴 Wrong password → re-render password page with error message
  res.send(`
  <!DOCTYPE html>
  <html lang="en">
  <head>
    <meta charset="UTF-8">
    <title>Password Required</title>
    <link rel="stylesheet" href="/style.css">
    <style>
      body {
        margin: 0;
        font-family: "Segoe UI", sans-serif;
        background: #000;
        height: 100vh;
        display: flex;
        justify-content: center;
        align-items: center;
        overflow: hidden;
      }
      #bg-canvas {
        position: fixed;
        top: 0; left: 0;
        width: 100%; height: 100%;
        z-index: 0;
      }
      .container {
        background: rgba(255,255,255,0.9);
        padding: 2rem;
        border-radius: 12px;
        box-shadow: 0 8px 20px rgba(0,0,0,0.4);
        text-align: center;
        z-index: 1;
        max-width: 400px;
        width: 90%;
      }
      h2 {
        margin-bottom: 1rem;
        font-size: 1.4rem;
        color: #d93025;
      }
      .error {
        color: red;
        font-weight: bold;
        margin-bottom: 1rem;
      }
      input[type="password"] {
        width: 100%;
        padding: 10px;
        border: 1px solid #ddd;
        border-radius: 8px;
        margin-bottom: 1rem;
        font-size: 1rem;
      }
      button {
        width: 100%;
        padding: 10px;
        background: #0078ff;
        border: none;
        color: #fff;
        font-weight: 600;
        border-radius: 8px;
        cursor: pointer;
        transition: background 0.3s ease;
      }
      button:hover {
        background: #005fcc;
      }
    </style>
  </head>
  <body>
    <canvas id="bg-canvas"></canvas>
    <div class="container">
      <h2>🔒 This file is password protected</h2>
      <p class="error"> Wrong password. Please try again.</p>
      <form action="/secure-download/${u}/${f}" method="POST">
        <input type="password" name="password" placeholder="Enter password" required>
        <button type="submit">⬇ Download</button>
      </form>
    </div>
    <script src="/js/particles.js"></script>
    <script>
      particlesJS.load('bg-canvas','/js/particles.json');
    </script>
  </body>
  </html>
  `);
});

// ---------------- DOWNLOAD & DELETE ----------------

app.get("/delete/:u/:f", requireLogin, (req, res) => {
  const { u, f } = req.params;

  // Only admin or file owner can delete
  if (req.session.user !== "admin" && req.session.user !== u) {
    return res.send("❌ No access");
  }

  const fp = path.join(UPLOADS_USERS, u, f);

  // Delete actual file
  if (fs.existsSync(fp)) {
    fs.unlinkSync(fp);
    console.log(`🗑 Deleted file: ${fp}`);
  }

  // Delete metadata from SHARES
  if (SHARES.users[u]) {
    SHARES.users[u] = SHARES.users[u].filter(item => item.file !== f);
    saveShares();
  }

  res.redirect("/list");
});


// ---------------- GUEST UPLOAD ----------------
ensureDir(path.join(__dirname, "uploads/tmp"));
const uploadGuest = multer({ dest: "uploads/tmp" });

app.get("/guest-upload", (req, res) =>
  res.sendFile(path.join(__dirname, "public/guest-upload.html"))
);





app.post("/guest-upload", uploadGuest.single("file"), async (req, res) => {
  const { password, label } = req.body;

  // ✅ Require a file always
  if (!req.file) return res.send("❌ Missing file");

  const gid = crypto.randomBytes(6).toString("hex");
  const dir = path.join(UPLOADS_GUESTS, gid);
  ensureDir(dir);

  const encPath = path.join(dir, req.file.originalname + ".enc");
  await encryptFile(req.file.path, encPath);

  const token = crypto.randomBytes(8).toString("hex");

  // ✅ Only hash password if it exists
  let hash = null;
  if (password && password.trim() !== "") {
    hash = await bcrypt.hash(password, 10);
  }

  SHARES.guests[token] = {
    username: "guest",
    filename: encPath,
    hash, // null means no password required
    label: label || "",
    original: req.file.originalname,
    expires: Date.now() + 24 * 60 * 60 * 1000,
  };
  saveShares();

  const BASE_URL = DOMAIN 
  ? DOMAIN 
  : `http://${localIp}:${PORT}`;

  const link = `${BASE_URL}/guest-login?token=${token}`;

  
  const qrCode = await QRCode.toDataURL(link);

  // Show different message if password not required
res.send(`
  <!DOCTYPE html>
  <html lang="en">
  <head>
    <meta charset="UTF-8">
    <title>File Uploaded Successfully!</title>
    <link rel="stylesheet" href="/style.css">
    <style>
      body {
        margin: 0;
        font-family: "Segoe UI", sans-serif;
        background: #000;
        overflow: hidden;
      }
      #bg-canvas {
        position: fixed;
        top: 0; left: 0;
        width: 100%; height: 100%;
        z-index: 0;
      }
      .container {
        margin: 5% auto;
        background: rgba(12, 11, 11, 0.21);
        color: #efe9e9ff;
        padding: 2rem;
        border-radius: 12px;
        max-width: 500px;
        text-align: center;
        position: relative;
        z-index: 1;
        box-shadow: 0 8px 20px rgba(0,0,0,0.5);
      }
      .badge.expiry {
        background: #f5d7b2;
        padding: 5px 10px;
        border-radius: 6px;
      }
    </style>
  </head>
  <body>
    <canvas id="bg-canvas"></canvas>
    <div class="container">
      <h2 style="color:green;">✅ File uploaded successfully!</h2>
      <p><b>Download Link:</b> <a href="${link}">${link}</a></p>
      <p><span class="badge expiry">⏳ Valid for 24h</span></p>
      ${label ? `<p><b>Note:</b> ${label}</p>` : ""}
      <p>📱 Scan QR Code:</p>
      <img src="${qrCode}" alt="QR Code" />
      <br><br>
      ${hash 
        ? `<p style="color:red;"><b>⚠️ This file requires a password. Share it separately with recipient.</b></p>` 
        : `<p style="color:green;"><b>✅ No password required to download this file.</b></p>`}
      <a href="/guest-upload">⬆ Upload another file</a>
    </div>

    <!-- Atom/Particles Background -->
    <script src="/js/particles.js"></script>
    <script>
      particlesJS.load('bg-canvas', '/js/particles.json', function() {
        console.log('Particles background loaded on guest-upload success page');
      });
    </script>
  </body>
  </html>
`);

});


// Guest login (skip password page if not required)
app.get("/guest-login", (req, res) => {
  const token = req.query.token;
  const share = SHARES.guests[token];

  if (!share || Date.now() > share.expires) {
    return res.send(" Invalid or expired link.");
  }

  // If no password required, send file immediately
  if (!share.hash) {
    return decryptFile(
      share.filename,
      res,
      path.basename(share.filename).replace(/\.enc$/, "")
    );
  }

  // Otherwise → show password form
  res.sendFile(path.join(__dirname, "public/guest-login.html"));
});

app.post("/guest-login", express.urlencoded({ extended: true }), async (req, res) => {
  const { token, password } = req.body;
  const share = SHARES.guests[token];

  if (share && Date.now() < share.expires) {
  if (!share.hash) {
    // no password required
    return decryptFile(share.filename, res, path.basename(share.filename).replace(/\.enc$/, ""));
  }
  if (await bcrypt.compare(password, share.hash)) {
    return decryptFile(share.filename, res, path.basename(share.filename).replace(/\.enc$/, ""));
  }
}

  res.send(" Invalid/Expired");
});

// ---------------- USERS MGMT ----------------
app.get("/manage-users", requireLogin, requireAdmin, (req, res) =>
  res.sendFile(path.join(__dirname, "public/manage-users.html"))
);
app.get("/api/users", requireLogin, requireAdmin, (req, res) => res.json(USERS));
app.post("/add-user", requireLogin, requireAdmin, async (req, res) => {
  const hash = await bcrypt.hash(req.body.password, 10);
  USERS[req.body.username] = hash;
  saveUsers();
  ensureDir(path.join(UPLOADS_USERS, req.body.username));
  if (!SHARES.users[req.body.username]) SHARES.users[req.body.username] = []; // ✅ FIX
  saveShares();
  res.redirect("/");
});


app.get("/remove-user/:u", requireLogin, requireAdmin, (req, res) => {
  const user = req.params.u;

  if (user === "admin") return res.send(" Cannot delete admin");

  // Delete from USERS + SHARES
  delete USERS[user];
  delete SHARES.users[user];
  saveUsers();
  saveShares();

  // Delete uploads folder
  const userDir = path.join(UPLOADS_USERS, user);
  if (fs.existsSync(userDir)) {
    fs.rmSync(userDir, { recursive: true, force: true });
  }

  res.redirect("/list"); // back to /list instead of /manage-users
});


// ---------------- RESET USER PASSWORD ----------------
app.post("/reset-user/:u", requireLogin, requireAdmin, async (req, res) => {
  const user = req.params.u;
  const newPassword = req.body.newPassword || "Temp1234"; // default if not provided

  if (user === "admin") return res.send(" Cannot reset admin password");

  // Hash new password
  const hash = await bcrypt.hash(newPassword, 10);
  USERS[user] = hash;
  saveUsers();

  res.send(`
  <!DOCTYPE html>
  <html lang="en">
  <head>
    <meta charset="UTF-8">
    <title>Password Reset</title>
    <link rel="stylesheet" href="/style.css">
    <style>
      body {
        margin:0;
        font-family:"Segoe UI", sans-serif;
        background:#000;
        height:100vh;
        display:flex;
        justify-content:center;
        align-items:center;
        overflow:hidden;
      }
      #bg-canvas {
        position:fixed;
        top:0; left:0;
        width:100%; height:100%;
        z-index:0;
      }
      .reset-card {
        background:#fff;
        padding:2rem;
        border-radius:12px;
        box-shadow:0 8px 20px rgba(0,0,0,0.3);
        text-align:center;
        z-index:1;
        max-width:400px;
        width:90%;
      }
      .reset-card h2 { color:green; }
      .reset-card .password {
        font-size:1.2rem;
        font-weight:bold;
        color:#0078ff;
        margin:1rem 0;
      }
    </style>
  </head>
  <body>
    <canvas id="bg-canvas"></canvas>
    <div class="reset-card">
      <h2>Password Reset</h2>
      <p>User <b>${user}</b> now has new password:</p>
      <p class="password">${newPassword}</p>
      <p>Tell the user to log in with this new password.</p>
      <a href="/list">⬅ Back to User List</a>
    </div>

    <script src="/js/particles.js"></script>
    <script>
      particlesJS.load('bg-canvas','/js/particles.json');
    </script>
  </body>
  </html>
`);

});



// ---------------- FALLBACK ROUTE ----------------
app.use((req, res) => {
  res.status(404).send(`
    <html>
      <body style="background:#111;color:#eee;font-family:sans-serif;text-align:center;padding:50px">
        <h2>404 - Page Not Found</h2>
        <p>The page you requested does not exist.</p>
        <a href="/" style="color:#0af;">Go back Home</a>
      </body>
    </html>
  `);
});





// ---------------- START SERVER ----------------
const listenPort = process.env.PORT || 8000;

// ✅ Cloud (Koyeb): Only use HTTP — Koyeb automatically adds HTTPS
if (IS_CLOUD) {
  http.createServer(app).listen(listenPort, "0.0.0.0", () => {
    console.log(`✅ BabyShare running on port ${listenPort}`);
    console.log("🧭 Mode: Cloud (Koyeb)");
    console.log(`🌍 Domain: ${DOMAIN || "auto-assigned by Koyeb"}`);
  });
} else {
  // ✅ Local: Allow HTTPS for testing if certs exist
  try {
    const keyPath = path.join(__dirname, "certs/selfsigned.key");
    const certPath = path.join(__dirname, "certs/selfsigned.crt");
    if (fs.existsSync(keyPath) && fs.existsSync(certPath)) {
      const key = fs.readFileSync(keyPath);
      const cert = fs.readFileSync(certPath);
      https.createServer({ key, cert }, app).listen(443, "0.0.0.0", () => {
        console.log("✅ Local HTTPS running at https://localhost:443");
      });
    } else {
      console.warn("⚠️ No SSL certs found — starting local HTTP instead...");
      http.createServer(app).listen(listenPort, "0.0.0.0", () => {
        console.log(`✅ Local HTTP running at http://localhost:${listenPort}`);
      });
    }
  } catch (err) {
    console.error("⚠️ HTTPS failed, falling back to HTTP:", err.message);
    http.createServer(app).listen(listenPort, "0.0.0.0", () => {
      console.log(`✅ Local HTTP running at http://localhost:${listenPort}`);
    });
  }
}
