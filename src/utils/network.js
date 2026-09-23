// Network helpers for choosing a LAN address and configured public share URLs.
const os = require("os");
const { HTTP_PORT, HTTPS_ENABLED, PORT, PUBLIC_BASE_URL, SHARE_USE_HTTPS } = require("../config");

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

module.exports = { getPreferredLanIp, getShareBaseUrl };
