import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import test from "node:test";

const root = path.resolve(import.meta.dirname, "..");
const worker = fs.readFileSync(path.join(root, "cloudflare", "worker.mjs"), "utf8");

test("Cloudflare Worker exposes direct-only upload routes and no file storage binding", () => {
  assert.match(worker, /url\.pathname === "\/upload"[\s\S]{0,900}?return peerOnly\(request\)/);
  assert.equal(worker.includes("env.FILES"), false);
  assert.equal(worker.includes("R2 Bucket"), false);
  assert.equal(worker.includes("handleUserUpload"), false);
  assert.equal(worker.includes("/content|download"), false);
});

test("QR pairing uses metadata lookup only for short codes", () => {
  assert.match(worker, /INSERT OR IGNORE INTO qr_pair_codes/);
  assert.match(worker, /SELECT pair_token FROM qr_pair_codes/);
  assert.match(worker, /Durable Object relays metadata and ICE\/SDP messages only/);
});
