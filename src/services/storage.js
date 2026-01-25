// File storage helpers: encrypt/decrypt streams and content type inference.
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");

// AES-256-CTR with a random IV per file.
const algorithm = "aes-256-ctr";
const IV_LENGTH = 16;

// Minimal MIME type map for inline previews.
function getContentType(filename) {
  const ext = path.extname(filename).toLowerCase();
  switch (ext) {
    case ".pdf":
      return "application/pdf";
    case ".png":
      return "image/png";
    case ".jpg":
    case ".jpeg":
      return "image/jpeg";
    case ".gif":
      return "image/gif";
    case ".webp":
      return "image/webp";
    case ".svg":
      return "image/svg+xml";
    case ".mp4":
      return "video/mp4";
    case ".mp3":
      return "audio/mpeg";
    case ".wav":
      return "audio/wav";
    case ".txt":
    case ".md":
    case ".json":
      return "text/plain; charset=utf-8";
    default:
      return "application/octet-stream";
  }
}

// Ensure a directory exists (recursive).
function ensureDir(dir) {
  if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
}

// Encrypt a file into outputPath, writing IV as the first bytes.
function encryptFile(inputPath, outputPath, secretKey) {
  return new Promise((resolve, reject) => {
    const iv = crypto.randomBytes(IV_LENGTH);
    const cipher = crypto.createCipheriv(algorithm, secretKey, iv);
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

// Stream-decrypt an encrypted file to the HTTP response.
function decryptFile(inputPath, res, filename, secretKey, options = {}) {
  const disposition = options.disposition || "attachment";
  const contentType = options.contentType || getContentType(filename);
  return new Promise((resolve) => {
    if (!fs.existsSync(inputPath)) {
      res.status(404).send("File not found");
      return resolve();
    }
    const input = fs.createReadStream(inputPath);
    input.on("error", () => {
      if (!res.headersSent) res.status(404).send("File not found");
      resolve();
    });
    input.once("readable", () => {
      const iv = input.read(IV_LENGTH);
      const decipher = crypto.createDecipheriv(algorithm, secretKey, iv);
      res.setHeader("Content-Disposition", `${disposition}; filename=\"${filename}\"`);
      res.setHeader("Content-Type", contentType);
      input.pipe(decipher).pipe(res);
      resolve();
    });
  });
}

module.exports = {
  ensureDir,
  encryptFile,
  decryptFile,
  getContentType,
};
