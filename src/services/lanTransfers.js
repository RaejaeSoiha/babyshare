// Ephemeral, consent-based transfers between browser devices connected to one BabyShare LAN hub.
const crypto = require("crypto");
const fs = require("fs");
const { isValidUploadName, resolveWithin } = require("../utils/security");

const DEVICE_TTL_MS = 45_000;
const VERIFICATION_TTL_MS = 5 * 60 * 1000;
const CHAT_PENDING_TTL_MS = 10 * 60 * 1000;
const CHAT_TTL_MS = 30 * 60 * 1000;
const PENDING_TTL_MS = 10 * 60 * 1000;
const ACCEPTED_TTL_MS = 20 * 60 * 1000;
const READY_TTL_MS = 24 * 60 * 60 * 1000;
const MAX_FILE_SIZE = 1024 * 1024 * 1024;
const MAX_CHAT_MESSAGE_LENGTH = 1_000;
const MAX_CHAT_MESSAGES = 200;

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
    && file.size <= MAX_FILE_SIZE;
}

function cleanChatMessage(value) {
  if (typeof value !== "string") return null;
  const cleaned = value.replace(/\u0000/g, "").trim();
  return cleaned.length > 0 && cleaned.length <= MAX_CHAT_MESSAGE_LENGTH ? cleaned : null;
}

class LanTransferService {
  constructor({ uploadDirectory }) {
    this.uploadDirectory = uploadDirectory;
    this.devices = new Map();
    this.verifications = new Map();
    this.chats = new Map();
    this.transfers = new Map();
    fs.mkdirSync(uploadDirectory, { recursive: true });
  }

  heartbeat({ deviceId, deviceToken, platform }, scope, user) {
    if (!isDeviceId(deviceId) || !isDeviceToken(deviceToken)) return null;
    const now = Date.now();
    const existing = this.devices.get(deviceId);
    const tokenHash = hashToken(deviceToken);
    if (existing && existing.tokenHash !== tokenHash) return null;

    const normalizedPlatform = cleanName(platform, "Browser");
    const displayName = cleanName(user, "Guest");
    const device = {
      deviceName: `${normalizedPlatform} device`,
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

  requestVerification(sender, recipientId) {
    if (!isDeviceId(recipientId) || recipientId === sender.id) return { error: "invalid_device" };
    const recipient = this.devices.get(recipientId);
    if (!recipient || recipient.scope !== sender.scope || recipient.updatedAt + DEVICE_TTL_MS < Date.now()) {
      return { error: "device_unavailable" };
    }

    this.cleanup();
    const existing = [...this.verifications.values()].find((verification) => verification.status === "pending"
      && ((verification.senderId === sender.id && verification.recipientId === recipient.id)
        || (verification.senderId === recipient.id && verification.recipientId === sender.id)));
    if (existing) return { verification: this.toClientVerification(existing, sender) };

    const now = Date.now();
    const verification = {
      code: crypto.randomInt(10, 100).toString(),
      createdAt: now,
      id: crypto.randomUUID(),
      recipientConfirmed: false,
      recipientId: recipient.id,
      recipientName: recipient.name,
      senderConfirmed: false,
      senderId: sender.id,
      senderName: sender.name,
      status: "pending",
      updatedAt: now,
    };
    this.verifications.set(verification.id, verification);
    return { verification: this.toClientVerification(verification, sender) };
  }

  listVerifications(device) {
    this.cleanup();
    return [...this.verifications.values()]
      .filter((verification) => verification.senderId === device.id || verification.recipientId === device.id)
      .sort((left, right) => right.updatedAt - left.updatedAt)
      .map((verification) => this.toClientVerification(verification, device));
  }

  confirmVerification(id, device) {
    const verification = this.verifications.get(id);
    if (!verification || verification.status !== "pending") return null;
    if (verification.senderId === device.id) verification.senderConfirmed = true;
    else if (verification.recipientId === device.id) verification.recipientConfirmed = true;
    else return null;

    verification.status = verification.senderConfirmed && verification.recipientConfirmed ? "verified" : "pending";
    verification.updatedAt = Date.now();
    return this.toClientVerification(verification, device);
  }

  declineVerification(id, device) {
    const verification = this.verifications.get(id);
    if (!verification || (verification.senderId !== device.id && verification.recipientId !== device.id)) return false;
    this.verifications.delete(id);
    return true;
  }

  verifiedPair(sender, recipient) {
    return [...this.verifications.values()].some((verification) => verification.status === "verified"
      && ((verification.senderId === sender.id && verification.recipientId === recipient.id)
        || (verification.senderId === recipient.id && verification.recipientId === sender.id)));
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
      status: "pending",
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
    if (!chat || chat.recipientId !== recipient.id || chat.status !== "pending") return null;
    chat.status = "active";
    chat.updatedAt = Date.now();
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

  requestTransfers(sender, recipientId, files) {
    if (!isDeviceId(recipientId) || !Array.isArray(files) || files.length === 0 || files.length > 20 || files.some((file) => !validFileMeta(file))) {
      return { error: "invalid_transfer" };
    }
    const recipient = this.devices.get(recipientId);
    if (!recipient || recipient.scope !== sender.scope || recipient.updatedAt + DEVICE_TTL_MS < Date.now()) {
      return { error: "device_unavailable" };
    }

    const verifiedId = [...this.verifications.values()].find((verification) => verification.status === "verified"
      && ((verification.senderId === sender.id && verification.recipientId === recipient.id)
        || (verification.senderId === recipient.id && verification.recipientId === sender.id)))?.id;
    if (!verifiedId) return { error: "verification_required" };

    // The code is one-use: no durable contact or conversation state remains after a transfer begins.
    this.verifications.delete(verifiedId);
    const now = Date.now();
    const transfers = files.map((file) => {
      const transfer = {
        id: crypto.randomUUID(),
        senderId: sender.id,
        senderName: sender.name,
        recipientId: recipient.id,
        recipientName: recipient.name,
        name: file.name,
        size: file.size,
        status: "pending",
        createdAt: now,
        updatedAt: now,
        bytesTransferred: 0,
        storedFile: null,
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

  beginUpload(id, sender) {
    const transfer = this.getTransferForSender(id, sender);
    if (!transfer || transfer.status !== "accepted") return null;
    transfer.status = "receiving";
    transfer.updatedAt = Date.now();
    transfer.bytesTransferred = 0;
    return transfer;
  }

  updateProgress(transfer, bytesTransferred) {
    if (!transfer || transfer.status !== "receiving") return;
    transfer.bytesTransferred = Math.min(transfer.size, Math.max(0, Math.floor(bytesTransferred)));
    transfer.updatedAt = Date.now();
  }

  completeUpload(transfer, storedFile) {
    if (!transfer || transfer.status !== "receiving") return null;
    transfer.storedFile = storedFile;
    transfer.bytesTransferred = transfer.size;
    transfer.status = "ready";
    transfer.updatedAt = Date.now();
    return transfer;
  }

  failUpload(transfer) {
    if (!transfer || transfer.status !== "receiving") return;
    this.transfers.delete(transfer.id);
  }

  listTransfers(device) {
    this.cleanup();
    return [...this.transfers.values()]
      .filter((transfer) => transfer.senderId === device.id || transfer.recipientId === device.id)
      .sort((left, right) => right.updatedAt - left.updatedAt)
      .map((transfer) => this.toClientTransfer(transfer, device));
  }

  claimDownload(id, recipient) {
    const transfer = this.getTransferForRecipient(id, recipient);
    if (!transfer || transfer.status !== "ready" || !transfer.storedFile) return null;
    const filePath = resolveWithin(this.uploadDirectory, transfer.storedFile);
    if (!filePath || !fs.existsSync(filePath)) return null;
    transfer.status = "downloading";
    transfer.updatedAt = Date.now();
    return { filePath, name: transfer.name };
  }

  async completeDownload(id, recipient) {
    const transfer = this.getTransferForRecipient(id, recipient);
    if (!transfer || transfer.status !== "downloading" || !transfer.storedFile) return false;
    const filePath = resolveWithin(this.uploadDirectory, transfer.storedFile);
    if (!filePath) return false;
    await fs.promises.unlink(filePath);
    this.transfers.delete(id);
    return true;
  }

  releaseDownload(id, recipient) {
    const transfer = this.getTransferForRecipient(id, recipient);
    if (transfer && transfer.status === "downloading") {
      transfer.status = "ready";
      transfer.updatedAt = Date.now();
    }
  }

  toClientVerification(verification, device) {
    const outgoing = verification.senderId === device.id;
    return {
      code: verification.code,
      createdAt: verification.createdAt,
      direction: outgoing ? "outgoing" : "incoming",
      id: verification.id,
      peerId: outgoing ? verification.recipientId : verification.senderId,
      peerName: outgoing ? verification.recipientName : verification.senderName,
      status: verification.status,
      updatedAt: verification.updatedAt,
      yourConfirmed: outgoing ? verification.senderConfirmed : verification.recipientConfirmed,
    };
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
    const peerName = outgoing ? transfer.recipientName : transfer.senderName;
    const progress = transfer.status === "ready"
      ? 100
      : transfer.size > 0
        ? Math.min(99, Math.round((transfer.bytesTransferred / transfer.size) * 100))
        : 0;
    return {
      createdAt: transfer.createdAt,
      direction: outgoing ? "outgoing" : "incoming",
      id: transfer.id,
      name: transfer.name,
      peerName: peerName || "Nearby device",
      progress,
      size: transfer.size,
      status: transfer.status,
      updatedAt: transfer.updatedAt,
    };
  }

  cleanup() {
    const now = Date.now();
    for (const [id, device] of this.devices) {
      if (device.updatedAt + DEVICE_TTL_MS < now) this.devices.delete(id);
    }
    for (const [id, verification] of this.verifications) {
      if (verification.updatedAt + VERIFICATION_TTL_MS < now) this.verifications.delete(id);
    }
    for (const [id, chat] of this.chats) {
      const ttl = chat.status === "pending" ? CHAT_PENDING_TTL_MS : CHAT_TTL_MS;
      if (chat.updatedAt + ttl < now) this.chats.delete(id);
    }
    for (const [id, transfer] of this.transfers) {
      const ttl = transfer.status === "pending"
        ? PENDING_TTL_MS
        : transfer.status === "accepted" || transfer.status === "receiving"
          ? ACCEPTED_TTL_MS
          : READY_TTL_MS;
      if (transfer.updatedAt + ttl >= now) continue;
      if (transfer.storedFile) {
        const filePath = resolveWithin(this.uploadDirectory, transfer.storedFile);
        if (filePath) fs.promises.unlink(filePath).catch(() => {});
      }
      this.transfers.delete(id);
    }
  }
}

module.exports = { LanTransferService, MAX_FILE_SIZE };
