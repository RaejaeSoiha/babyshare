// Encrypted file storage helpers with legacy AES-CTR compatibility.
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");
const { Writable } = require("stream");
const { finished } = require("stream/promises");
const { pipeline } = require("stream/promises");

const FORMAT_MAGIC = Buffer.from("BBS2");
const GCM_IV_LENGTH = 12;
const GCM_TAG_LENGTH = 16;
const LEGACY_IV_LENGTH = 16;

const PREVIEW_CONTENT_TYPES = {
  ".pdf": "application/pdf",
  ".png": "image/png",
  ".jpg": "image/jpeg",
  ".jpeg": "image/jpeg",
  ".gif": "image/gif",
  ".webp": "image/webp",
  ".mp4": "video/mp4",
  ".mp3": "audio/mpeg",
  ".wav": "audio/wav",
  ".txt": "text/plain; charset=utf-8",
  ".md": "text/plain; charset=utf-8",
  ".json": "text/plain; charset=utf-8",
};

function getContentType(filename) {
  return PREVIEW_CONTENT_TYPES[path.extname(filename).toLowerCase()] || "application/octet-stream";
}

function canPreview(filename) {
  return Boolean(PREVIEW_CONTENT_TYPES[path.extname(filename).toLowerCase()]);
}

function ensureDir(dir) {
  fs.mkdirSync(dir, { recursive: true });
}

async function encryptFile(inputPath, outputPath, secretKey) {
  const iv = crypto.randomBytes(GCM_IV_LENGTH);
  const cipher = crypto.createCipheriv("aes-256-gcm", secretKey, iv);
  const output = fs.createWriteStream(outputPath, { flags: "wx", mode: 0o600 });

  try {
    output.write(Buffer.concat([FORMAT_MAGIC, iv]));
    await pipeline(fs.createReadStream(inputPath), cipher, output, { end: false });
    output.end(cipher.getAuthTag());
    await finished(output);
    await fs.promises.unlink(inputPath);
  } catch (error) {
    output.destroy();
    await fs.promises.unlink(outputPath).catch(() => {});
    throw error;
  }
}

function readFormat(inputPath) {
  const stat = fs.statSync(inputPath);
  if (stat.size < LEGACY_IV_LENGTH) throw new Error("Encrypted file is truncated");

  const fd = fs.openSync(inputPath, "r");
  try {
    const magic = Buffer.alloc(FORMAT_MAGIC.length);
    fs.readSync(fd, magic, 0, magic.length, 0);
    if (magic.equals(FORMAT_MAGIC)) {
      const headerLength = FORMAT_MAGIC.length + GCM_IV_LENGTH;
      if (stat.size <= headerLength + GCM_TAG_LENGTH) throw new Error("Encrypted file is truncated");
      const iv = Buffer.alloc(GCM_IV_LENGTH);
      const tag = Buffer.alloc(GCM_TAG_LENGTH);
      fs.readSync(fd, iv, 0, iv.length, FORMAT_MAGIC.length);
      fs.readSync(fd, tag, 0, tag.length, stat.size - GCM_TAG_LENGTH);
      return {
        algorithm: "aes-256-gcm",
        end: stat.size - GCM_TAG_LENGTH - 1,
        iv,
        start: headerLength,
        tag,
      };
    }

    const iv = Buffer.alloc(LEGACY_IV_LENGTH);
    fs.readSync(fd, iv, 0, iv.length, 0);
    return { algorithm: "aes-256-ctr", end: stat.size - 1, iv, start: LEGACY_IV_LENGTH };
  } finally {
    fs.closeSync(fd);
  }
}

function createDecipher(format, secretKey) {
  const decipher = crypto.createDecipheriv(format.algorithm, secretKey, format.iv);
  if (format.tag) decipher.setAuthTag(format.tag);
  return decipher;
}

function createDecryptedStream(inputPath, format, secretKey) {
  const input = fs.createReadStream(inputPath, { start: format.start, end: format.end });
  return { decipher: createDecipher(format, secretKey), input };
}

async function verifyAuthenticatedFile(inputPath, format, secretKey) {
  if (!format.tag) return;
  const discard = new Writable({ write(_chunk, _encoding, callback) { callback(); } });
  const { input, decipher } = createDecryptedStream(inputPath, format, secretKey);
  await pipeline(input, decipher, discard);
}

async function decryptFile(inputPath, res, filename, secretKey, options = {}) {
  try {
    if (!fs.existsSync(inputPath)) {
      res.status(404).send("File not found");
      return false;
    }

    const format = readFormat(inputPath);
    await verifyAuthenticatedFile(inputPath, format, secretKey);

    const preview = options.disposition === "inline" && canPreview(filename);
    res.setHeader("Content-Type", getContentType(filename));
    res.setHeader("X-Content-Type-Options", "nosniff");
    if (preview) {
      res.setHeader("Content-Disposition", "inline");
    } else {
      res.attachment(filename);
    }

    const { input, decipher } = createDecryptedStream(inputPath, format, secretKey);
    await pipeline(input, decipher, res);
    return true;
  } catch {
    if (!res.headersSent) {
      res.status(422).send("File cannot be decrypted");
    } else {
      res.destroy();
    }
    return false;
  }
}

module.exports = {
  canPreview,
  decryptFile,
  encryptFile,
  ensureDir,
  getContentType,
};
