// Network helpers for choosing a LAN address and configured public share URLs.
const os = require("os");
const { HTTP_PORT, HTTPS_ENABLED, PORT, PUBLIC_BASE_URL, SHARE_USE_HTTPS } = require("../config");

function normalizeRemoteAddress(value) {
  if (typeof value !== "string") return "";
  return value.toLowerCase().replace(/^::ffff:/, "").split("%")[0];
}

function isPrivateLanAddress(value) {
  const address = normalizeRemoteAddress(value);
  if (!address) return false;
  if (address === "::1" || address === "127.0.0.1") return true;

  const ipv4 = address.match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/);
  if (ipv4) {
    const parts = ipv4.slice(1).map(Number);
    if (parts.some((part) => part > 255)) return false;
    return parts[0] === 10
      || parts[0] === 127
      || (parts[0] === 172 && parts[1] >= 16 && parts[1] <= 31)
      || (parts[0] === 192 && parts[1] === 168);
  }

  // IPv6 loopback, unique-local, and link-local addresses are LAN-scoped.
  return address.startsWith("fc")
    || address.startsWith("fd")
    || address.startsWith("fe80:");
}

function getLanScope(value) {
  const address = normalizeRemoteAddress(value);
  if (address === "::1" || address === "127.0.0.1") return "loopback";
  const ipv4 = address.match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/);
  if (ipv4) return `ipv4:${ipv4[1]}.${ipv4[2]}.${ipv4[3]}`;

  // A /64 is the normal IPv6 LAN boundary and keeps transfers out of other segments.
  const hextets = address.split(":").filter(Boolean).slice(0, 4);
  return hextets.length ? `ipv6:${hextets.join(":")}` : "unknown";
}

function getPreferredLanIp() {
  const candidates = [];
  for (const [name, interfaces] of Object.entries(os.networkInterfaces())) {
    for (const net of interfaces || []) {
      if (net.family === "IPv4" && !net.internal) candidates.push({ address: net.address, name });
    }
  }

  const virtual = /vmware|virtual|vethernet|hyper-v|openvpn|tap|tunnel|loopback/i;
  const usable = candidates.filter(({ name }) => !virtual.test(name));
  const preferred = usable.find(({ name }) => /wi-?fi|wireless|ethernet/i.test(name)) || usable[0] || candidates[0];
  return preferred ? preferred.address : "localhost";
}

function getLocalBaseUrl() {
  const protocol = HTTPS_ENABLED && SHARE_USE_HTTPS ? "https" : "http";
  const port = protocol === "https" ? PORT : HTTP_PORT;
  return `${protocol}://${getPreferredLanIp()}:${port}`;
}

function getShareBaseUrl() {
  return PUBLIC_BASE_URL || getLocalBaseUrl();
}

module.exports = {
  getLanScope,
  getPreferredLanIp,
  getShareBaseUrl,
  isPrivateLanAddress,
  normalizeRemoteAddress,
};
