// Lightweight LAN multicast announcements for finding a BabyShare hub without cloud services.
// Browser clients use the hub's JSON presence API as their compatibility fallback because web
// pages cannot send or receive UDP/mDNS packets directly.
const crypto = require("crypto");
const dgram = require("dgram");
const { isPrivateLanAddress } = require("../utils/network");

const GROUP = "239.255.77.77";
const PORT = 42424;
const ANNOUNCE_INTERVAL_MS = 15_000;

function validPeer(payload) {
  return payload
    && payload.type === "babyshare-lan/1"
    && typeof payload.id === "string"
    && /^[a-f0-9-]{16,64}$/i.test(payload.id)
    && Number.isInteger(payload.port)
    && payload.port > 0
    && payload.port <= 65535
    && (payload.protocol === "http" || payload.protocol === "https");
}

function startLanDiscovery({ servicePort, serviceProtocol = "http" }) {
  const id = crypto.randomUUID();
  const socket = dgram.createSocket({ type: "udp4", reuseAddr: true });
  const peers = new Map();
  let timer;
  let stopped = false;

  const announce = () => {
    if (stopped) return;
    const message = Buffer.from(JSON.stringify({
      id,
      port: servicePort,
      protocol: serviceProtocol,
      sentAt: Date.now(),
      type: "babyshare-lan/1",
    }));
    socket.send(message, PORT, GROUP, () => {});
  };

  socket.on("message", (message, remote) => {
    if (!isPrivateLanAddress(remote.address) || message.length > 2048) return;
    try {
      const peer = JSON.parse(message.toString("utf8"));
      if (!validPeer(peer) || peer.id === id) return;
      peers.set(peer.id, { address: remote.address, port: peer.port, protocol: peer.protocol, seenAt: Date.now() });
    } catch {
      // Ignore unrelated multicast traffic.
    }
  });

  socket.on("error", (error) => {
    // Multicast is frequently disabled on managed Wi-Fi or mobile tethering. The browser
    // presence path remains fully usable, so discovery errors must never stop BabyShare.
    if (!stopped) console.warn(`BabyShare LAN multicast unavailable: ${error.message}`);
  });

  socket.bind(PORT, "0.0.0.0", () => {
    try {
      socket.addMembership(GROUP);
      socket.setMulticastTTL(1);
      announce();
      timer = setInterval(announce, ANNOUNCE_INTERVAL_MS);
      timer.unref();
    } catch (error) {
      console.warn(`BabyShare LAN multicast unavailable: ${error.message}`);
    }
  });

  return {
    listPeers() {
      const oldest = Date.now() - ANNOUNCE_INTERVAL_MS * 3;
      for (const [peerId, peer] of peers) {
        if (peer.seenAt < oldest) peers.delete(peerId);
      }
      return [...peers.values()];
    },
    stop() {
      stopped = true;
      if (timer) clearInterval(timer);
      socket.close();
    },
  };
}

module.exports = { startLanDiscovery };
