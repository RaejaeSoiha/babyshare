// Ephemeral, consent-based transfers between browser devices connected to one BabyShare LAN hub.
const crypto = require("crypto");
const { isValidUploadName } = require("../utils/security");

const DEVICE_TTL_MS = 45_000;
const PENDING_TTL_MS = 10 * 60 * 1000;
const ACCEPTED_TTL_MS = 20 * 60 * 1000;
const READY_TTL_MS = 24 * 60 * 60 * 1000;
const MAX_FILE_SIZE = 1024 * 1024 * 1024;
const MAX_ACTIVE_TRANSFERS_PER_DEVICE = 20;
const MAX_CHAT_MESSAGE_LENGTH = 1_000;
const MAX_CHAT_MESSAGES = 200;
const SIGNAL_TTL_MS = 60 * 1000;
const MAX_SIGNAL_BYTES = 32 * 1024;
const MAX_SIGNALS_PER_DEVICE = 24;

function hashToken(value) {
  return crypto.createHash("sha256").update(value).digest("hex");
}

function isDeviceId(value) {
  return typeof value === "string" && /^[a-z0-9_-]{16,96}$/i.test(value);
}

function isDeviceToken(value) {
  return typeof value === "string" && /^[a-z0-9_-]{24,192}$/i.test(value);
}

function cleanName(value, fallback) {
  if (typeof value !== "string") return fallback;
  const cleaned = value.replace(/[\u0000-\u001f<>]/g, "").trim().slice(0, 80);
  return cleaned || fallback;
}

function validFileMeta(file) {
  return file
    && typeof file === "object"
    && typeof file.name === "string"
    && isValidUploadName(file.name)
    && Number.isSafeInteger(file.size)
    && file.size > 0
    && file.size <= MAX_FILE_SIZE
    && (file.relativePath === undefined || (typeof file.relativePath === "string" && file.relativePath.length <= 500 && !file.relativePath.includes("..")));
}

function cleanChatMessage(value) {
  if (typeof value !== "string") return null;
  const cleaned = value.replace(/\u0000/g, "").trim();
  return cleaned.length > 0 && cleaned.length <= MAX_CHAT_MESSAGE_LENGTH ? cleaned : null;
}

function validSignal(signal) {
  if (!signal || typeof signal !== "object" || Array.isArray(signal)) return false;
  if (!(["offer", "answer", "candidate", "hangup"].includes(signal.type))) return false;
  if (typeof signal.sessionId !== "string" || !/^[a-z0-9_-]{8,96}$/i.test(signal.sessionId)) return false;
  try {
    return Buffer.byteLength(JSON.stringify(signal), "utf8") <= MAX_SIGNAL_BYTES;
  } catch {
    return false;
  }
}

class LanTransferService {
  constructor() {
    this.devices = new Map();
    this.chats = new Map();
    this.transfers = new Map();
    this.signals = new Map();
  }

  heartbeat({ deviceId, deviceToken, deviceName, platform }, scope, user) {
    if (!isDeviceId(deviceId) || !isDeviceToken(deviceToken)) return null;
    const now = Date.now();
    const existing = this.devices.get(deviceId);
    const tokenHash = hashToken(deviceToken);
    if (existing && existing.tokenHash !== tokenHash) return null;

    const normalizedPlatform = cleanName(platform, "Browser");
    const displayName = cleanName(user, "Guest");
    const device = {
      deviceName: cleanName(deviceName, `${normalizedPlatform} device`),
      displayName,
      id: deviceId,
      name: displayName,
      platform: normalizedPlatform,
      scope,
      tokenHash,
      updatedAt: now,
    };
    this.devices.set(deviceId, device);
    return device;
  }

  getAuthorizedDevice({ deviceId, deviceToken }, scope) {
    if (!isDeviceId(deviceId) || !isDeviceToken(deviceToken)) return null;
    const device = this.devices.get(deviceId);
    if (!device || device.scope !== scope || device.updatedAt + DEVICE_TTL_MS < Date.now()) return null;
    return crypto.timingSafeEqual(Buffer.from(device.tokenHash), Buffer.from(hashToken(deviceToken))) ? device : null;
  }

  listDevices(device) {
    this.cleanup();
    return [...this.devices.values()]
      .filter((candidate) => candidate.id !== device.id && candidate.scope === device.scope && candidate.updatedAt + DEVICE_TTL_MS >= Date.now())
      .sort((left, right) => right.updatedAt - left.updatedAt || left.name.localeCompare(right.name))
      .map(({ deviceName, displayName, id, platform }) => ({
        deviceName,
        displayName,
        id,
        online: true,
        platform,
      }));
  }

  requestChat(sender, recipientId) {
    if (!isDeviceId(recipientId) || recipientId === sender.id) return { error: "invalid_device" };
    this.cleanup();
    const recipient = this.devices.get(recipientId);
    if (!recipient || recipient.scope !== sender.scope || recipient.updatedAt + DEVICE_TTL_MS < Date.now()) {
      return { error: "device_unavailable" };
    }
    const existing = [...this.chats.values()].find((chat) => (chat.status === "pending" || chat.status === "active")
      && ((chat.senderId === sender.id && chat.recipientId === recipient.id)
        || (chat.senderId === recipient.id && chat.recipientId === sender.id)));
    if (existing) return { chat: this.toClientChat(existing, sender) };

    const now = Date.now();
    const chat = {
      createdAt: now,
      id: crypto.randomUUID(),
      messages: [],
      recipientId: recipient.id,
      recipientName: recipient.name,
      senderId: sender.id,
      senderName: sender.name,
      // Chat is available immediately. File transfers retain their separate
      // recipient-approval step, but text conversations do not need one.
      status: "active",
      updatedAt: now,
    };
    this.chats.set(chat.id, chat);
    return { chat: this.toClientChat(chat, sender) };
  }

  getChatForDevice(id, device) {
    const chat = this.chats.get(id);
    return chat && (chat.senderId === device.id || chat.recipientId === device.id) ? chat : null;
  }

  listChats(device) {
    this.cleanup();
    return [...this.chats.values()]
      .filter((chat) => chat.senderId === device.id || chat.recipientId === device.id)
      .sort((left, right) => right.updatedAt - left.updatedAt)
      .map((chat) => this.toClientChat(chat, device));
  }

  acceptChat(id, recipient) {
    const chat = this.getChatForDevice(id, recipient);
    if (!chat || chat.recipientId !== recipient.id || !["pending", "active"].includes(chat.status)) return null;
    if (chat.status === "pending") {
      chat.status = "active";
      chat.updatedAt = Date.now();
    }
    return this.toClientChat(chat, recipient);
  }

  sendChatMessage(id, device, text) {
    const chat = this.getChatForDevice(id, device);
    const messageText = cleanChatMessage(text);
    if (!chat || chat.status !== "active" || !messageText) return null;
    chat.messages.push({
      id: crypto.randomUUID(),
      senderId: device.id,
      text: messageText,
      sentAt: Date.now(),
    });
    if (chat.messages.length > MAX_CHAT_MESSAGES) chat.messages.splice(0, chat.messages.length - MAX_CHAT_MESSAGES);
    chat.updatedAt = Date.now();
    return this.toClientChat(chat, device);
  }

  endChat(id, device) {
    const chat = this.getChatForDevice(id, device);
    if (!chat) return false;
    this.chats.delete(id);
    return true;
  }

  relaySignal(sender, recipientId, signal) {
    if (!isDeviceId(recipientId) || recipientId === sender.id || !validSignal(signal)) return { error: "invalid_signal" };
    this.cleanup();
    const recipient = this.devices.get(recipientId);
    if (!recipient || recipient.scope !== sender.scope || recipient.updatedAt + DEVICE_TTL_MS < Date.now()) {
      return { error: "device_unavailable" };
    }

    const queue = this.signals.get(recipient.id) || [];
    if (queue.length >= MAX_SIGNALS_PER_DEVICE) queue.splice(0, queue.length - MAX_SIGNALS_PER_DEVICE + 1);
    const relayed = {
      createdAt: Date.now(),
      id: crypto.randomUUID(),
      senderId: sender.id,
      signal: JSON.parse(JSON.stringify(signal)),
      scope: sender.scope,
    };
    queue.push(relayed);
    this.signals.set(recipient.id, queue);
    return { signal: { id: relayed.id, queued: true } };
  }

  takeSignals(device) {
    this.cleanup();
    const queue = this.signals.get(device.id) || [];
    this.signals.delete(device.id);
    return queue.filter((entry) => entry.scope === device.scope).map((entry) => ({
      createdAt: entry.createdAt,
      id: entry.id,
      senderId: entry.senderId,
      signal: entry.signal,
    }));
  }

  requestTransfers(sender, recipientId, files) {
    if (!isDeviceId(recipientId) || !Array.isArray(files) || files.length === 0 || files.length > 20 || files.some((file) => !validFileMeta(file))) {
      return { error: "invalid_transfer" };
    }
    this.cleanup();
    const recipient = this.devices.get(recipientId);
    if (!recipient || recipient.scope !== sender.scope || recipient.updatedAt + DEVICE_TTL_MS < Date.now()) {
      return { error: "device_unavailable" };
    }

    const isActive = (transfer) => ["pending", "accepted", "receiving"].includes(transfer.status);
    const activeForSender = [...this.transfers.values()].filter((transfer) => transfer.senderId === sender.id && isActive(transfer)).length;
    const activeForRecipient = [...this.transfers.values()].filter((transfer) => transfer.recipientId === recipient.id && isActive(transfer)).length;
    if (activeForSender + files.length > MAX_ACTIVE_TRANSFERS_PER_DEVICE || activeForRecipient + files.length > MAX_ACTIVE_TRANSFERS_PER_DEVICE) {
      return { error: "transfer_limit_reached" };
    }

    const now = Date.now();
    const transfers = files.map((file) => {
      const transfer = {
        id: crypto.randomUUID(),
        senderId: sender.id,
        senderName: sender.name,
        recipientId: recipient.id,
        recipientName: recipient.name,
        name: file.name,
        relativePath: typeof file.relativePath === "string" ? file.relativePath : "",
        size: file.size,
        status: "pending",
        // BabyShare only negotiates WebRTC metadata. File bytes never enter this service.
        transport: "peer",
        createdAt: now,
        updatedAt: now,
        bytesTransferred: 0,
      };
      this.transfers.set(transfer.id, transfer);
      return this.toClientTransfer(transfer, sender);
    });
    return { transfers };
  }

  getTransferForSender(id, sender) {
    const transfer = this.transfers.get(id);
    return transfer && transfer.senderId === sender.id ? transfer : null;
  }

  getTransferForRecipient(id, recipient) {
    const transfer = this.transfers.get(id);
    return transfer && transfer.recipientId === recipient.id ? transfer : null;
  }

  acceptTransfer(id, recipient) {
    const transfer = this.getTransferForRecipient(id, recipient);
    if (!transfer || transfer.status !== "pending") return null;
    transfer.status = "accepted";
    transfer.updatedAt = Date.now();
    return this.toClientTransfer(transfer, recipient);
  }

  declineTransfer(id, recipient) {
    const transfer = this.getTransferForRecipient(id, recipient);
    if (!transfer || transfer.status !== "pending") return false;
    this.transfers.delete(id);
    return true;
  }

  updateProgress(transfer, bytesTransferred) {
    if (!transfer || transfer.status !== "receiving") return;
    transfer.bytesTransferred = Math.min(transfer.size, Math.max(0, Math.floor(bytesTransferred)));
    transfer.updatedAt = Date.now();
  }

  beginPeerTransfer(id, sender) {
    const transfer = this.getTransferForSender(id, sender);
    if (!transfer || transfer.status !== "accepted") return null;
    transfer.transport = "peer";
    transfer.status = "receiving";
    transfer.bytesTransferred = 0;
    transfer.updatedAt = Date.now();
    return this.toClientTransfer(transfer, sender);
  }

  updatePeerProgress(id, sender, bytesTransferred) {
    const transfer = this.getTransferForSender(id, sender);
    if (!transfer || transfer.transport !== "peer" || transfer.status !== "receiving" || !Number.isSafeInteger(bytesTransferred)) return null;
    this.updateProgress(transfer, bytesTransferred);
    return this.toClientTransfer(transfer, sender);
  }

  completePeerTransfer(id, recipient) {
    const transfer = this.getTransferForRecipient(id, recipient);
    if (!transfer || transfer.transport !== "peer" || transfer.status !== "receiving" || transfer.bytesTransferred < transfer.size) return null;
    transfer.bytesTransferred = transfer.size;
    transfer.status = "completed";
    transfer.updatedAt = Date.now();
    return this.toClientTransfer(transfer, recipient);
  }

  cancelTransfer(id, device, { failed = false } = {}) {
    const transfer = this.transfers.get(id);
    if (!transfer || (transfer.senderId !== device.id && transfer.recipientId !== device.id)) return null;
    if (["completed", "cancelled", "failed"].includes(transfer.status)) return null;
    transfer.status = failed ? "failed" : "cancelled";
    transfer.updatedAt = Date.now();
    return this.toClientTransfer(transfer, device);
  }

  listTransfers(device) {
    this.cleanup();
    return [...this.transfers.values()]
      .filter((transfer) => transfer.senderId === device.id || transfer.recipientId === device.id)
      .sort((left, right) => right.updatedAt - left.updatedAt)
      .map((transfer) => this.toClientTransfer(transfer, device));
  }

  toClientChat(chat, device) {
    const outgoing = chat.senderId === device.id;
    return {
      createdAt: chat.createdAt,
      direction: outgoing ? "outgoing" : "incoming",
      id: chat.id,
      messages: chat.status === "active" ? chat.messages.map((message) => ({
        id: message.id,
        mine: message.senderId === device.id,
        sentAt: message.sentAt,
        text: message.text,
      })) : [],
      peerId: outgoing ? chat.recipientId : chat.senderId,
      peerName: outgoing ? chat.recipientName : chat.senderName,
      status: chat.status,
      updatedAt: chat.updatedAt,
    };
  }

  toClientTransfer(transfer, device) {
    const outgoing = transfer.senderId === device.id;
    const peerId = outgoing ? transfer.recipientId : transfer.senderId;
    const peerName = outgoing ? transfer.recipientName : transfer.senderName;
    const progress = transfer.status === "completed"
      ? 100
      : transfer.size > 0
        ? Math.min(99, Math.round((transfer.bytesTransferred / transfer.size) * 100))
        : 0;
    return {
      createdAt: transfer.createdAt,
      direction: outgoing ? "outgoing" : "incoming",
      id: transfer.id,
      name: transfer.name,
      relativePath: transfer.relativePath || undefined,
      peerId,
      peerName: peerName || "Nearby device",
      progress,
      size: transfer.size,
      status: transfer.status,
      transport: "peer",
      updatedAt: transfer.updatedAt,
    };
  }

  cleanup() {
    const now = Date.now();
    for (const [id, device] of this.devices) {
      if (device.updatedAt + DEVICE_TTL_MS < now) this.devices.delete(id);
    }
    for (const [id, chat] of this.chats) {
      // Promote conversations created before immediate chat was introduced.
      // This keeps an older in-memory hub from showing an approval prompt.
      if (chat.status === "pending") {
        chat.status = "active";
        chat.updatedAt = now;
      }
      if (chat.status === "active") {
        const sender = this.devices.get(chat.senderId);
        const recipient = this.devices.get(chat.recipientId);
        // An accepted chat remains available for as long as both participants
        // keep their BabyShare presence alive. It is removed when either user
        // explicitly ends it or genuinely leaves the nearby network.
        if (!sender || !recipient || sender.updatedAt + DEVICE_TTL_MS < now || recipient.updatedAt + DEVICE_TTL_MS < now) {
          this.chats.delete(id);
        }
      }
    }
    for (const [id, transfer] of this.transfers) {
      const ttl = transfer.status === "pending"
        ? PENDING_TTL_MS
        : transfer.status === "accepted" || transfer.status === "receiving"
          ? ACCEPTED_TTL_MS
          : READY_TTL_MS;
      if (transfer.updatedAt + ttl >= now) continue;
      this.transfers.delete(id);
    }
    for (const [deviceId, queue] of this.signals) {
      const active = queue.filter((entry) => entry.createdAt + SIGNAL_TTL_MS >= now);
      if (active.length > 0) this.signals.set(deviceId, active);
      else this.signals.delete(deviceId);
    }
  }
}

module.exports = { LanTransferService, MAX_FILE_SIZE };
