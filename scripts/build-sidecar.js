const { execSync } = require("child_process");
const path = require("path");

const pkgPlatformMap = {
  win32: "win",
  darwin: "macos",
  linux: "linux",
};

const pkgArchMap = {
  x64: "x64",
  arm64: "arm64",
};

const tauriTripleMap = {
  win32: {
    x64: "x86_64-pc-windows-msvc",
    arm64: "aarch64-pc-windows-msvc",
  },
  darwin: {
    x64: "x86_64-apple-darwin",
    arm64: "aarch64-apple-darwin",
  },
  linux: {
    x64: "x86_64-unknown-linux-gnu",
    arm64: "aarch64-unknown-linux-gnu",
  },
};

const platform = pkgPlatformMap[process.platform];
const arch = pkgArchMap[process.arch];
const triple = tauriTripleMap[process.platform]?.[process.arch];

if (!platform || !arch || !triple) {
  console.error(`Unsupported platform/arch: ${process.platform}/${process.arch}`);
  process.exit(1);
}

const target = `node18-${platform}-${arch}`;
const root = path.resolve(__dirname, "..");
const outDir = path.join(root, "client", "src-tauri", "binaries");
const ext = process.platform === "win32" ? ".exe" : "";
const outName = path.join(outDir, `babyshare-server-${triple}${ext}`);
const serverEntry = path.join(root, "server.js");

const cmd = `npx pkg "${serverEntry}" --targets ${target} --output "${outName}"`;
console.log(`Building sidecar: ${cmd}`);
execSync(cmd, { stdio: "inherit" });
