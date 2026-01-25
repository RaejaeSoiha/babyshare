// Network helpers for choosing a usable LAN address and share URLs.
const os = require("os");
const { PORT, HTTP_PORT, HTTPS_ENABLED, SHARE_USE_HTTPS } = require("../config");

// Pick a stable LAN IP, avoiding virtual adapters when possible.
function getPreferredLanIp() {
  const nets = os.networkInterfaces();
  const candidates = [];
  for (const name of Object.keys(nets)) {
    for (const net of nets[name]) {
      if (net.family !== "IPv4" || net.internal) continue;
      candidates.push({ name, address: net.address });
    }
  }
  const isBadInterface = (n) =>
    /vmware|virtual|vEthernet|hyper-v|openvpn|tap|tunnel|loopback/i.test(n);
  const byName = candidates.find(
    (c) => /wi-?fi|wireless/i.test(c.name) && !isBadInterface(c.name)
  );
  if (byName) return byName.address;
  const ethernet = candidates.find(
    (c) => /ethernet/i.test(c.name) && !isBadInterface(c.name)
  );
  if (ethernet) return ethernet.address;
  const prefer = candidates.find(
    (c) => c.address.startsWith("192.168.") && !isBadInterface(c.name)
  );
  if (prefer) return prefer.address;
  const fallback = candidates.find(
    (c) => c.address.startsWith("10.") && !isBadInterface(c.name)
  );
  return (fallback && fallback.address) || (candidates[0] && candidates[0].address) || "localhost";
}

// Base URL for normal app usage (respects DOMAIN/PUBLIC_BASE_URL when set).
function getBaseUrl(req) {
  const env = (process.env.DOMAIN || process.env.PUBLIC_BASE_URL || "").trim();
  if (env) return env.replace(/\/+$/, "");

  const host = req && req.headers && req.headers.host ? req.headers.host : "";
  const scheme = HTTPS_ENABLED ? "https" : "http";
  if (host && !host.startsWith("localhost") && !host.startsWith("127.0.0.1")) {
    return `${scheme}://${host}`;
  }
  const ip = getPreferredLanIp();
  return `${scheme}://${ip}:${PORT}`;
}

// Preferred host for share links (use request host if available).
function getShareHost(req) {
  const hostHeader = req && req.headers ? req.headers.host : "";
  if (hostHeader) {
    const host = hostHeader.split(":")[0];
    if (!/^(localhost|127\.0\.0\.1|0\.0\.0\.0)$/i.test(host)) return host;
  }
  return getPreferredLanIp();
}

// Share link base that avoids HTTPS issues on mobile when not desired.
function getShareBaseUrl(req) {
  const env = (process.env.PUBLIC_BASE_URL || "").trim();
  if (env) return env.replace(/\/+$/, "");
  const host = getShareHost(req);
  const useHttps = SHARE_USE_HTTPS && HTTPS_ENABLED;
  const protocol = useHttps ? "https" : "http";
  const port = useHttps ? PORT : HTTP_PORT || PORT;
  return `${protocol}://${host}:${port}`;
}

module.exports = {
  getPreferredLanIp,
  getBaseUrl,
  getShareBaseUrl,
};
