// Browser-compatible LAN device presence and consent-based direct transfers.
const { getLanScope, isPrivateLanAddress } = require("../utils/network");

function credentialsFrom(req, allowQuery = false) {
  const body = req.body && typeof req.body === "object" ? req.body : {};
  return {
    deviceId: req.get("x-babyshare-device-id") || body.deviceId || (allowQuery ? req.query.deviceId : ""),
    deviceToken: req.get("x-babyshare-device-token") || body.deviceToken || (allowQuery ? req.query.deviceToken : ""),
  };
}

module.exports = function registerLanRoutes(app, deps) {
  const {
    LAN_TRANSFERS,
    WEBRTC_SIGNALING_ENABLED,
    lanLimiter,
  } = deps;

  app.use("/api/lan", lanLimiter);

  function requireLanRequest(req, res) {
    // req.ip is the client address only when the explicitly configured, one-hop
    // reverse proxy is trusted. Otherwise Express derives it from the socket.
    const remoteAddress = req.ip || req.socket.remoteAddress || "";
    if (!isPrivateLanAddress(remoteAddress)) {
      res.status(403).json({ error: "lan_only" });
      return null;
    }
    return getLanScope(remoteAddress);
  }

  function requireDevice(req, res, { allowQuery = false } = {}) {
    const scope = requireLanRequest(req, res);
    if (!scope) return null;
    const device = LAN_TRANSFERS.getAuthorizedDevice(credentialsFrom(req, allowQuery), scope);
    if (!device) {
      res.status(403).json({ error: "device_unauthorized" });
      return null;
    }
    return device;
  }

  app.post("/api/lan/presence", (req, res) => {
    const scope = requireLanRequest(req, res);
    if (!scope) return;
    // Session identity comes only from the server-side session, never from the
    // browser's presence payload.
    const device = LAN_TRANSFERS.heartbeat(req.body || {}, scope, req.session?.user);
    if (!device) return res.status(400).json({ error: "invalid_device" });
    return res.status(200).json({ ok: true });
  });

  app.get("/api/lan/devices", (req, res) => {
    const device = requireDevice(req, res);
    if (!device) return;
    return res.json({ devices: LAN_TRANSFERS.listDevices(device) });
  });

  app.get("/api/lan/transfers", (req, res) => {
    const device = requireDevice(req, res);
    if (!device) return;
    return res.json({ transfers: LAN_TRANSFERS.listTransfers(device) });
  });

  app.get("/api/lan/chats", (req, res) => {
    const device = requireDevice(req, res);
    if (!device) return;
    return res.json({ chats: LAN_TRANSFERS.listChats(device) });
  });

  // WebRTC uses the same short-lived LAN device credentials as direct sharing.
  // This relay carries only SDP/ICE negotiation data; it stores neither calls nor files.
  if (WEBRTC_SIGNALING_ENABLED) {
    app.get("/api/lan/signals", (req, res) => {
      const device = requireDevice(req, res);
      if (!device) return;
      return res.json({ signals: LAN_TRANSFERS.takeSignals(device) });
    });

    app.post("/api/lan/signals", (req, res) => {
      const sender = requireDevice(req, res);
      if (!sender) return;
      const result = LAN_TRANSFERS.relaySignal(sender, req.body?.recipientId, req.body?.signal);
      if (result.error) return res.status(result.error === "device_unavailable" ? 404 : 400).json({ error: result.error });
      return res.status(202).json(result);
    });
  }

  app.post("/api/lan/chats/request", (req, res) => {
    const sender = requireDevice(req, res);
    if (!sender) return;
    const result = LAN_TRANSFERS.requestChat(sender, req.body?.recipientId);
    if (result.error) return res.status(result.error === "device_unavailable" ? 404 : 400).json({ error: result.error });
    return res.status(201).json(result);
  });

  app.post("/api/lan/chats/:id/accept", (req, res) => {
    const recipient = requireDevice(req, res);
    if (!recipient) return;
    const chat = LAN_TRANSFERS.acceptChat(req.params.id, recipient);
    if (!chat) return res.status(404).json({ error: "chat_unavailable" });
    return res.json({ chat });
  });

  app.post("/api/lan/chats/:id/messages", (req, res) => {
    const device = requireDevice(req, res);
    if (!device) return;
    const chat = LAN_TRANSFERS.sendChatMessage(req.params.id, device, req.body?.text);
    if (!chat) return res.status(400).json({ error: "invalid_chat_message" });
    return res.status(201).json({ chat });
  });

  app.post("/api/lan/chats/:id/end", (req, res) => {
    const device = requireDevice(req, res);
    if (!device) return;
    if (!LAN_TRANSFERS.endChat(req.params.id, device)) return res.status(404).json({ error: "chat_unavailable" });
    return res.status(204).end();
  });

  app.post("/api/lan/transfers/request", (req, res) => {
    const sender = requireDevice(req, res);
    if (!sender) return;
    const { recipientId, files } = req.body || {};
    const result = LAN_TRANSFERS.requestTransfers(sender, recipientId, files);
    if (result.error) return res.status(result.error === "device_unavailable" ? 404 : 400).json({ error: result.error });
    return res.status(201).json(result);
  });

  app.post("/api/lan/transfers/:id/accept", (req, res) => {
    const recipient = requireDevice(req, res);
    if (!recipient) return;
    const transfer = LAN_TRANSFERS.acceptTransfer(req.params.id, recipient);
    if (!transfer) return res.status(404).json({ error: "transfer_unavailable" });
    return res.json({ transfer });
  });

  app.post("/api/lan/transfers/:id/peer-start", (req, res) => {
    const sender = requireDevice(req, res);
    if (!sender) return;
    const transfer = LAN_TRANSFERS.beginPeerTransfer(req.params.id, sender);
    if (!transfer) return res.status(409).json({ error: "transfer_not_accepted" });
    return res.json({ transfer });
  });

  app.post("/api/lan/transfers/:id/peer-progress", (req, res) => {
    const sender = requireDevice(req, res);
    if (!sender) return;
    const transfer = LAN_TRANSFERS.updatePeerProgress(req.params.id, sender, req.body?.bytesTransferred);
    if (!transfer) return res.status(409).json({ error: "transfer_unavailable" });
    return res.json({ transfer });
  });

  app.post("/api/lan/transfers/:id/peer-complete", (req, res) => {
    const recipient = requireDevice(req, res);
    if (!recipient) return;
    const transfer = LAN_TRANSFERS.completePeerTransfer(req.params.id, recipient);
    if (!transfer) return res.status(409).json({ error: "transfer_incomplete" });
    return res.json({ transfer });
  });

  app.post("/api/lan/transfers/:id/decline", (req, res) => {
    const recipient = requireDevice(req, res);
    if (!recipient) return;
    if (!LAN_TRANSFERS.declineTransfer(req.params.id, recipient)) return res.status(404).json({ error: "transfer_unavailable" });
    return res.status(204).end();
  });

  // Both participants can cancel an in-flight direct transfer. This changes
  // metadata only; BabyShare never receives the file bytes.
  app.post("/api/lan/transfers/:id/cancel", (req, res) => {
    const device = requireDevice(req, res);
    if (!device) return;
    const transfer = LAN_TRANSFERS.cancelTransfer(req.params.id, device, { failed: req.body?.failed === true });
    if (!transfer) return res.status(404).json({ error: "transfer_unavailable" });
    return res.json({ transfer });
  });
};
