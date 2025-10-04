// ======================================================
// BabyShare - Full Encrypted File Share (Local + Cloud)
// ======================================================

const express = require("express");
const multer = require("multer");
const path = require("path");
const fs = require("fs");
const session = require("express-session");
const crypto = require("crypto");
const bcrypt = require("bcryptjs");
const QRCode = require("qrcode");
const os = require("os");
const helmet = require("helmet");
require("dotenv").config();

const app = express();

// ---------------- ENCRYPTION CONFIG ----------------
const algorithm = "aes-256-ctr";
const RAW_KEY = process.env.FILE_KEY || "fallback-secret-key";
const SECRET_KEY = crypto.createHash("sha256").update(RAW_KEY).digest();
const IV_LENGTH = 16;

// ---------------- SECURITY MIDDLEWARE ----------------
app.use(helmet());

// ---------------- FILE PATHS ----------------
const USERS_FILE = path.join(__dirname, "users.json");
const SHARES_FILE = path.join(__dirname, "shares.json");
const UPLOADS_USERS = path.join(__dirname, "uploads/users");
const UPLOADS_GUESTS = path.join(__dirname, "uploads/guests");

// ---------------- LOAD EXISTING DATA ----------------
let USERS = fs.existsSync(USERS_FILE)
  ? JSON.parse(fs.readFileSync(USERS_FILE))
  : { admin: "admin123" };

let SHARES = fs.existsSync(SHARES_FILE)
  ? JSON.parse(fs.readFileSync(SHARES_FILE))
  : { users: {}, guests: {} };

if (!SHARES.users) SHARES.users = {};
if (!SHARES.guests) SHARES.guests = {};

// ---------------- HASH MIGRATION ----------------
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

// ---------------- UTILITIES ----------------
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

// ---------------- ENVIRONMENT CONFIG ----------------
const PORT = process.env.PORT || 3000;
const DOMAIN = process.env.DOMAIN || "";
const NODE_ENV = process.env.NODE_ENV || "development";
const IS_CLOUD = NODE_ENV === "production" || process.env.KOYEB_APP_NAME;

console.log("🧭 Mode:", IS_CLOUD ? "Cloud (Koyeb)" : "Local (Offline)");
console.log("🌍 Domain:", DOMAIN || "Not set");

// ---------------- ENCRYPTION HELPERS ----------------
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
      res.setHeader("Content-Disposition", `attachment; filename="${filename}"`);
      input.pipe(decipher).pipe(res);
      resolve();
    });
  });
}

// ---------------- CLEANUP TASK ----------------
function cleanup() {
  const now = Date.now();
  Object.keys(SHARES.guests || {}).forEach((t) => {
    const g = SHARES.guests[t];
    if (!g || g.expires < now) {
      if (g && fs.existsSync(g.filename)) fs.unlinkSync(g.filename);
      delete SHARES.guests[t];
    }
  });

  Object.keys(SHARES.users || {}).forEach((u) => {
    SHARES.users[u] = (SHARES.users[u] || []).filter((file) => {
      if (file.expires && file.expires < now) {
        const fp = path.join(UPLOADS_USERS, u, file.file);
        if (fs.existsSync(fp)) fs.unlinkSync(fp);
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

// ------------- HTML HELPERS -------------
function renderError(title, message, link = "/") {
  return `
    <html><body style="font-family:sans-serif;background:#000;color:white;text-align:center;padding:40px">
      <h2 style="color:red">${title}</h2><p>${message}</p>
      <a href="${link}" style="color:#0af">Back</a>
    </body></html>`;
}

function renderSuccess(title, message, link = "/") {
  return `
    <html><body style="font-family:sans-serif;background:#000;color:white;text-align:center;padding:40px">
      <h2 style="color:lime">${title}</h2><p>${message}</p>
      <a href="${link}" style="color:#0af">Continue</a>
    </body></html>`;
}


// ======================================================
// AUTHENTICATION & DASHBOARD ROUTES
// ======================================================

// ---- LOGIN PAGE ----
app.get("/login", (req, res) =>
  res.sendFile(path.join(__dirname, "public/login.html"))
);

app.post("/login", async (req, res) => {
  const { username, password } = req.body;
  if (!USERS[username])
    return res.send(renderError("User Not Found", `No account for <b>${username}</b>.`, "/register"));

  const valid = await bcrypt.compare(password, USERS[username]);
  if (!valid)
    return res.send(renderError("Incorrect Password", "Please try again.", "/login"));

  req.session.user = username;
  ensureDir(path.join(UPLOADS_USERS, username));
  if (!SHARES.users[username]) SHARES.users[username] = [];
  saveShares();
  res.redirect("/");
});

// ---- REGISTER PAGE ----
app.get("/register", (req, res) =>
  res.sendFile(path.join(__dirname, "public/register.html"))
);

app.post("/register", async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password)
    return res.send(renderError("Missing Fields", "Both username and password required.", "/register"));
  if (USERS[username])
    return res.send(renderError("Username Taken", "Choose another one.", "/register"));

  USERS[username] = await bcrypt.hash(password, 10);
  saveUsers();
  ensureDir(path.join(UPLOADS_USERS, username));
  SHARES.users[username] = [];
  saveShares();
  res.send(renderSuccess("Account Created", `Welcome <b>${username}</b>!`, "/login"));
});

// ---- LOGOUT ----
app.get("/logout", (req, res) => req.session.destroy(() => res.redirect("/")));

// ======================================================
// DASHBOARD HOME
// ======================================================
app.get("/", (req, res) => {
  if (!req.session.user) return res.sendFile(path.join(__dirname, "public/home.html"));
  const user = req.session.user;
  const isAdmin = user === "admin";

  let html = `
  <html><head><meta charset="UTF-8"><title>BabyShare Dashboard</title>
  <link rel="stylesheet" href="/style.css"></head>
  <body class="dashboard"><h1>Welcome ${user}</h1>
  <p><a href="/upload-page">⬆ Upload Files</a> | <a href="/list">📂 My Files</a> | <a href="/logout">🚪 Logout</a></p>`;

  if (isAdmin) {
    html += `<hr><h2>👥 Manage Users</h2>
      <form action="/add-user" method="POST">
        <input name="username" placeholder="new user" required>
        <input type="password" name="password" placeholder="password" required>
        <button>➕ Add</button>
      </form>
      <ul>`;
    for (const u of Object.keys(USERS)) {
      html += `<li>${u}${u!=="admin"?` <a href="/remove-user/${u}" style="color:red">🗑</a>`:""}</li>`;
    }
    html += `</ul>`;
  }
  html += `</body></html>`;
  res.send(html);
});

// ======================================================
// UPLOAD HANDLING
// ======================================================
const userStorage = multer.diskStorage({
  destination: (req, f, cb) => {
    const d = path.join(UPLOADS_USERS, req.session.user);
    ensureDir(d);
    cb(null, d);
  },
  filename: (req, f, cb) => cb(null, Date.now()+"-"+f.originalname),
});
const uploadUser = multer({ storage: userStorage, limits:{fileSize:1024*1024*1024} }); // 1 GB limit

app.get("/upload-page", requireLogin, (req,res)=>{
  res.send(`<html><body style="font-family:sans-serif;background:#000;color:white;text-align:center;padding:40px">
  <h2>Upload Files</h2>
  <form action="/upload" method="POST" enctype="multipart/form-data">
    <input type="file" name="files" multiple required><br><br>
    <input type="text" name="label" placeholder="Label (optional)"><br><br>
    <input type="password" name="password" placeholder="Password (optional)"><br><br>
    <button>Upload</button>
  </form><p><a href="/">⬅ Back</a></p></body></html>`);
});

app.post("/upload", requireLogin, uploadUser.array("files"), async (req,res)=>{
  const user=req.session.user;
  const label=req.body.label||"";
  const password=req.body.password?.trim()||null;
  const hash=password?await bcrypt.hash(password,10):null;
  const BASE_URL=DOMAIN||`http://${localIp}:${PORT}`;
  const links=[];

  for(const f of req.files){
    const enc=f.path+".enc";
    await encryptFile(f.path,enc);
    if(!SHARES.users[user])SHARES.users[user]=[];
    SHARES.users[user].push({file:path.basename(enc),original:f.originalname,label,uploaded:Date.now(),expires:Date.now()+30*24*60*60*1000,hash});
    saveShares();
    const url=`${BASE_URL}/secure-download/${user}/${path.basename(enc)}`;
    const qr=await QRCode.toDataURL(url);
    links.push(`<li><b>${label||f.originalname}</b><br>
      <a href="${url}">⬇ Download</a> | <a href="/delete/${user}/${path.basename(enc)}" style="color:red">🗑 Delete</a><br>
      <img src="${qr}" width="120"><br>${hash?"🔒 Password Protected":"✅ Open Access"}</li>`);
  }

  res.send(`<html><body style="font-family:sans-serif;background:#000;color:white;text-align:center;padding:30px">
  <h2>✅ Uploaded & Encrypted</h2><ul>${links.join("")}</ul><p><a href="/list">📂 View My Files</a></p></body></html>`);
});

// ======================================================
// FILE LIST
// ======================================================
app.get("/list", requireLogin, async (req,res)=>{
  const user=req.session.user;
  const BASE_URL=DOMAIN||`http://${localIp}:${PORT}`;
  let html=`<html><body style="font-family:sans-serif;background:#000;color:white;padding:30px">
  <h1>${user==="admin"?"Admin File Manager":`${user}’s Files`}</h1>`;

  if(user==="admin"){
    for(const u of Object.keys(USERS)){
      if(!fs.existsSync(path.join(UPLOADS_USERS,u)))continue;
      html+=`<h3>${u}</h3><ul>`;
      for(const f of fs.readdirSync(path.join(UPLOADS_USERS,u))){
        const fileUrl=`${BASE_URL}/secure-download/${u}/${f}`;
        html+=`<li>${f} <a href="${fileUrl}">⬇</a> <a href="/delete/${u}/${f}" style="color:red">🗑</a></li>`;
      }
      html+="</ul>";
    }
  }else{
    const dir=path.join(UPLOADS_USERS,user);
    if(!fs.existsSync(dir))return res.send(renderError("No Files","Upload some first.","/upload-page"));
    html+="<ul>";
    for(const f of fs.readdirSync(dir)){
      const fileUrl=`${BASE_URL}/secure-download/${user}/${f}`;
      html+=`<li>${f} <a href="${fileUrl}">⬇</a> <a href="/delete/${user}/${f}" style="color:red">🗑</a></li>`;
    }
    html+="</ul>";
  }

  html+=`<p><a href="/">⬅ Back</a></p></body></html>`;
  res.send(html);
});


// ======================================================
// SECURE DOWNLOADS (with optional password)
// ======================================================
app.get("/secure-download/:user/:file", async (req,res)=>{
  const {user,file}=req.params;
  const meta=(SHARES.users[user]||[]).find(i=>i.file===file);
  if(!meta)return res.send(renderError("File Not Found","It may have expired.","/list"));

  const fp=path.join(UPLOADS_USERS,user,file);
  if(!meta.hash){
    return decryptFile(fp,res,meta.original||file.replace(/\.enc$/,""));
  }

  // if password protected
  res.send(`
  <html><body style="font-family:sans-serif;background:#000;color:white;text-align:center;padding:40px">
  <h2>🔒 Password Required</h2>
  <form action="/secure-download/${user}/${file}" method="POST">
    <input type="password" name="password" placeholder="Enter password" required><br><br>
    <button>Download</button>
  </form>
  <p><a href="/">⬅ Back</a></p></body></html>`);
});

app.post("/secure-download/:user/:file", express.urlencoded({extended:true}), async (req,res)=>{
  const {user,file}=req.params;
  const {password}=req.body;
  const meta=(SHARES.users[user]||[]).find(i=>i.file===file);
  if(!meta)return res.send("File not found");
  if(!meta.hash||(await bcrypt.compare(password,meta.hash))){
    const fp=path.join(UPLOADS_USERS,user,file);
    return decryptFile(fp,res,meta.original||file.replace(/\.enc$/,""));
  }
  res.send(renderError("Wrong Password","Try again.","/list"));
});

// ======================================================
// DELETE FILES
// ======================================================
app.get("/delete/:user/:file", requireLogin, (req,res)=>{
  const {user,file}=req.params;
  if(req.session.user!=="admin"&&req.session.user!==user)return res.send("❌ Unauthorized");
  const fp=path.join(UPLOADS_USERS,user,file);
  if(fs.existsSync(fp))fs.unlinkSync(fp);
  if(SHARES.users[user])SHARES.users[user]=SHARES.users[user].filter(f=>f.file!==file);
  saveShares();
  res.redirect("/list");
});

// ======================================================
// GUEST UPLOADS
// ======================================================
ensureDir(path.join(__dirname,"uploads/tmp"));
const uploadGuest=multer({dest:"uploads/tmp"});

app.get("/guest-upload",(req,res)=>{
  res.sendFile(path.join(__dirname,"public/guest-upload.html"));
});

app.post("/guest-upload",uploadGuest.single("file"),async(req,res)=>{
  if(!req.file)return res.send(renderError("No File","Please choose a file.","/guest-upload"));
  const {password,label}=req.body;
  const gid=crypto.randomBytes(6).toString("hex");
  const dir=path.join(UPLOADS_GUESTS,gid);
  ensureDir(dir);
  const enc=path.join(dir,req.file.originalname+".enc");
  await encryptFile(req.file.path,enc);
  const token=crypto.randomBytes(8).toString("hex");
  const hash=password?await bcrypt.hash(password,10):null;
  SHARES.guests[token]={filename:enc,hash,label,original:req.file.originalname,expires:Date.now()+24*60*60*1000};
  saveShares();

  const BASE_URL=DOMAIN||`http://${localIp}:${PORT}`;
  const link=`${BASE_URL}/guest-login?token=${token}`;
  const qr=await QRCode.toDataURL(link);

  res.send(`<html><body style="font-family:sans-serif;background:#000;color:white;text-align:center;padding:40px">
  <h2>✅ Guest File Uploaded</h2>
  <p><b>Link:</b> <a href="${link}">${link}</a></p>
  <img src="${qr}" width="160"><p>⏳ Valid for 24h</p>
  ${hash?"<p>🔒 Password Protected</p>":"<p>✅ No Password Needed</p>"}
  <p><a href="/guest-upload">⬆ Upload Another</a></p></body></html>`);
});

// ======================================================
// GUEST LOGIN + DOWNLOAD
// ======================================================
app.get("/guest-login",(req,res)=>{
  const {token}=req.query;
  const share=SHARES.guests[token];
  if(!share||Date.now()>share.expires)return res.send(renderError("Link Expired","Please reupload.","/guest-upload"));
  if(!share.hash){
    return decryptFile(share.filename,res,share.original);
  }
  res.send(`<html><body style="font-family:sans-serif;background:#000;color:white;text-align:center;padding:40px">
  <h2>🔒 Guest Password Required</h2>
  <form action="/guest-login" method="POST">
    <input type="hidden" name="token" value="${token}">
    <input type="password" name="password" placeholder="Password" required><br><br>
    <button>Download</button>
  </form></body></html>`);
});

app.post("/guest-login",express.urlencoded({extended:true}),async(req,res)=>{
  const {token,password}=req.body;
  const share=SHARES.guests[token];
  if(!share||Date.now()>share.expires)return res.send(renderError("Invalid or Expired","Upload again.","/guest-upload"));
  if(!share.hash||(await bcrypt.compare(password,share.hash))){
    return decryptFile(share.filename,res,share.original);
  }
  res.send(renderError("Wrong Password","Try again.","/guest-upload"));
});

// ======================================================
// ADMIN USER MANAGEMENT
// ======================================================
app.post("/add-user",requireLogin,requireAdmin,async(req,res)=>{
  const {username,password}=req.body;
  if(USERS[username])return res.send(renderError("User Exists","Choose a new name.","/"));
  USERS[username]=await bcrypt.hash(password,10);
  saveUsers();
  ensureDir(path.join(UPLOADS_USERS,username));
  SHARES.users[username]=[];
  saveShares();
  res.redirect("/");
});

app.get("/remove-user/:u",requireLogin,requireAdmin,(req,res)=>{
  const u=req.params.u;
  if(u==="admin")return res.send("Cannot delete admin");
  delete USERS[u]; delete SHARES.users[u];
  saveUsers(); saveShares();
  const d=path.join(UPLOADS_USERS,u);
  if(fs.existsSync(d))fs.rmSync(d,{recursive:true,force:true});
  res.redirect("/");
});

app.post("/reset-user/:u",requireLogin,requireAdmin,async(req,res)=>{
  const u=req.params.u;
  if(u==="admin")return res.send("Cannot reset admin password");
  const newPass=req.body.newPassword||"Temp1234";
  USERS[u]=await bcrypt.hash(newPass,10);
  saveUsers();
  res.send(`<html><body style="font-family:sans-serif;background:#000;color:white;text-align:center;padding:40px">
  <h2>Password Reset</h2><p>User <b>${u}</b> new password:</p><h3>${newPass}</h3>
  <a href="/">⬅ Back</a></body></html>`);
});



// ======================================================
// CLEANUP TASK (Runs every hour to delete expired files)
// ======================================================
function cleanup() {
  const now = Date.now();

  // --- Guests (24 hours) ---
  Object.keys(SHARES.guests || {}).forEach(token => {
    const g = SHARES.guests[token];
    if (!g || g.expires < now) {
      try {
        if (g && fs.existsSync(g.filename)) fs.unlinkSync(g.filename);
        delete SHARES.guests[token];
      } catch (e) { console.error("Guest cleanup error:", e.message); }
    }
  });

  // --- Users (30 days) ---
  Object.keys(SHARES.users || {}).forEach(u => {
    SHARES.users[u] = (SHARES.users[u] || []).filter(file => {
      if (file.expires && file.expires < now) {
        const fp = path.join(UPLOADS_USERS, u, file.file);
        try { if (fs.existsSync(fp)) fs.unlinkSync(fp); } catch {}
        return false;
      }
      return true;
    });
  });

  saveShares();
  console.log("🧹 Cleanup complete ", new Date().toISOString());
}
cleanup();
setInterval(cleanup, 60 * 60 * 1000); // every hour

// ======================================================
// 404 – NOT FOUND
// ======================================================
app.use((req, res) => {
  res.status(404).send(`
    <html>
      <body style="background:#000;color:#fff;font-family:sans-serif;text-align:center;padding:60px">
        <h2>404 – Page Not Found</h2>
        <p>The page you requested does not exist.</p>
        <a href="/" style="color:#0af;">Go Home</a>
      </body>
    </html>
  `);
});

// ======================================================
// START SERVER – Cloud + Offline Friendly
// ======================================================
const listenPort = process.env.PORT || 8000;

// Koyeb/Render terminate HTTPS externally – serve plain HTTP
app.listen(listenPort, "0.0.0.0", () => {
  console.log(`✅ BabyShare running on port ${listenPort}`);
  console.log("🧭 Mode:", IS_CLOUD ? "Cloud (Koyeb)" : "Local (Offline)");
  console.log(`🌍 Domain: ${DOMAIN || `http://${localIp}:${listenPort}`}`);
});

