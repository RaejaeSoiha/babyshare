import { createContext, useCallback, useContext, useEffect, useRef, useState } from "react";
import type { ReactNode } from "react";
import { apiFetch } from "../lib/api";
import { createReceiveSink, receiveStorageError } from "../lib/receiveStorage";
import type { ReceiveSink } from "../lib/receiveStorage";
import { sendFileChunks } from "../lib/sendFileChunks";
import { QR_PEER_CONFIG } from "../lib/qrPairing";

export type LanDevice = {
  deviceName: string;
  displayName: string;
  id: string;
  online: true;
  platform: string;
};
export type LanChatMessage = { id: string; mine: boolean; sentAt: number; text: string };
export type LanChat = {
  createdAt: number;
  direction: "incoming" | "outgoing";
  id: string;
  messages: LanChatMessage[];
  peerId: string;
  peerName: string;
  status: "pending" | "active";
  updatedAt: number;
};
export type LanMessageNotification = {
  chatId: string;
  id: string;
  peerId: string;
  peerName: string;
  text: string;
};
export type LanTransfer = {
  createdAt: number;
  direction: "incoming" | "outgoing";
  id: string;
  name: string;
  relativePath?: string;
  peerId: string;
  peerName: string;
  progress: number;
  size: number;
  status: "pending" | "accepted" | "receiving" | "completed" | "cancelled" | "failed";
  transport: "peer";
  updatedAt: number;
};

type DeviceIdentity = { deviceId: string; deviceToken: string; platform: string };
type LanSignal = {
  candidate?: RTCIceCandidateInit;
  description?: RTCSessionDescriptionInit;
  transferId?: string;
  type: "answer" | "candidate" | "hangup" | "offer";
  sessionId: string;
};
type SignalEnvelope = { senderId: string; signal: LanSignal };
type PeerSession = {
  channel?: RTCDataChannel;
  sink?: ReceiveSink;
  queuedBytes?: number;
  expectedSize: number;
  finished: boolean;
  id: string;
  lastProgress: number;
  pc: RTCPeerConnection;
  receivedBytes: number;
  role: "recipient" | "sender";
  transfer: LanTransfer;
  peerId: string;
  timeout?: number;
  writeChain: Promise<void>;
};
type PendingPeerCandidate = { candidate: RTCIceCandidateInit; senderId: string };
type ReceiverSink = ReceiveSink;
type LanTransferContextValue = {
  chats: LanChat[];
  devices: LanDevice[];
  error: string;
  requestChat: (recipientId: string) => Promise<void>;
  acceptChat: (chatId: string) => Promise<void>;
  sendChatMessage: (chatId: string, text: string) => Promise<void>;
  endChat: (chatId: string) => Promise<void>;
  markChatRead: (chatId: string) => void;
  requestTransfers: (recipientId: string, files: File[]) => Promise<void>;
  currentDevice: { id: string; name: string; platform: string };
  renameCurrentDevice: (name: string) => void;
  signOutCurrentDevice: () => void;
  discoverable: boolean;
  setDiscoverable: (value: boolean) => void;
  transfers: LanTransfer[];
  unreadChatIds: string[];
  acceptTransfer: (transferId: string) => Promise<void>;
  declineTransfer: (transferId: string) => Promise<void>;
  cancelTransfer: (transfer: LanTransfer) => Promise<void>;
  canDownloadTransfer: (transferId: string) => boolean;
  downloadTransfer: (transfer: LanTransfer) => boolean;
  dismissedTransferIds: string[];
  dismissTransferNotification: (transferId: string) => void;
  dismissMessageNotification: (messageId: string) => void;
  messageNotifications: LanMessageNotification[];
};

const LanTransferContext = createContext<LanTransferContextValue | null>(null);
const DEVICE_ID_KEY = "babyshare.lan.device-id";
const DEVICE_TOKEN_KEY = "babyshare.lan.device-token";
const DEVICE_NAME_KEY = "babyshare.lan.device-name";
const DISCOVERABLE_KEY = "babyshare.lan.discoverable";
const DEVICE_NAME_DISALLOWED_CHARACTERS = /[\p{Cc}<>]/gu;

function randomValue() {
  if (typeof crypto.randomUUID === "function") return crypto.randomUUID().replace(/-/g, "");
  const bytes = new Uint8Array(24);
  crypto.getRandomValues(bytes);
  return Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join("");
}

function devicePlatform() {
  const value = navigator.userAgent.toLowerCase();
  if (/android|iphone|ipad|ipod|mobile/.test(value)) return "Mobile";
  if (/windows/.test(value)) return "Windows";
  if (/mac os|macintosh/.test(value)) return "macOS";
  if (/linux/.test(value)) return "Linux";
  return "Browser";
}

function getIdentity(): DeviceIdentity {
  let deviceId = localStorage.getItem(DEVICE_ID_KEY) || "";
  let deviceToken = localStorage.getItem(DEVICE_TOKEN_KEY) || "";
  if (!/^[a-z0-9_-]{16,96}$/i.test(deviceId)) {
    deviceId = randomValue();
    localStorage.setItem(DEVICE_ID_KEY, deviceId);
  }
  if (!/^[a-z0-9_-]{24,192}$/i.test(deviceToken)) {
    deviceToken = `${randomValue()}${randomValue()}`;
    localStorage.setItem(DEVICE_TOKEN_KEY, deviceToken);
  }
  return { deviceId, deviceToken, platform: devicePlatform() };
}

function initialDeviceName(platform: string) {
  const saved = localStorage.getItem(DEVICE_NAME_KEY) || "";
  const cleaned = saved.replace(DEVICE_NAME_DISALLOWED_CHARACTERS, "").trim().slice(0, 80);
  return cleaned || `${platform} device`;
}

function messageForError(error: unknown) {
  if (error instanceof Error && error.message === "device_unavailable") return "That device is no longer available. Refresh and try again.";
  return "Nearby device sharing is temporarily unavailable. Keep BabyShare open and try again.";
}

export function LanTransferProvider({ children }: { children: ReactNode }) {
  const [identity] = useState(getIdentity);
  const [deviceName, setDeviceName] = useState(() => initialDeviceName(identity.platform));
  const [discoverable, setDiscoverableState] = useState(() => localStorage.getItem(DISCOVERABLE_KEY) !== "false");
  const pendingFilesRef = useRef(new Map<string, File>());
  const peerSessionsRef = useRef(new Map<string, PeerSession>());
  const receiverSinksRef = useRef(new Map<string, ReceiverSink>());
  const pendingPeerCandidatesRef = useRef(new Map<string, PendingPeerCandidate[]>());
  const peerFilesRef = useRef(new Map<string, Blob>());
  const savedSinksRef = useRef(new Map<string, ReceiveSink>());
  useEffect(() => {
    const pending = receiverSinksRef.current;
    const saved = savedSinksRef.current;
    return () => {
      for (const sink of [...pending.values(), ...saved.values()]) void sink.dispose();
      pending.clear();
      saved.clear();
    };
  }, []);

  const peerStartsRef = useRef(new Set<string>());
  const transfersRef = useRef<LanTransfer[]>([]);
  const knownMessageIdsRef = useRef(new Set<string>());
  const hasMessageBaselineRef = useRef(false);
  const [devices, setDevices] = useState<LanDevice[]>([]);
  const [chats, setChats] = useState<LanChat[]>([]);
  const [transfers, setTransfers] = useState<LanTransfer[]>([]);
  const [unreadChatIds, setUnreadChatIds] = useState<string[]>([]);
  const [messageNotifications, setMessageNotifications] = useState<LanMessageNotification[]>([]);
  const [dismissedTransferIds, setDismissedTransferIds] = useState<string[]>([]);
  const [error, setError] = useState("");

  const deviceHeaders = useCallback(() => ({
    "x-babyshare-device-id": identity.deviceId,
    "x-babyshare-device-token": identity.deviceToken,
  }), [identity]);

  const updateTransfer = useCallback((nextTransfer: LanTransfer) => {
    setTransfers((current) => [nextTransfer, ...current.filter((transfer) => transfer.id !== nextTransfer.id)]);
  }, []);

  useEffect(() => {
    transfersRef.current = transfers;
  }, [transfers]);

  const refresh = useCallback(async () => {
    if (!discoverable) {
      setDevices([]);
      setError("");
      return;
    }
    const presence = await apiFetch("/api/lan/presence", {
      body: JSON.stringify({ ...identity, deviceName }),
      headers: { "Content-Type": "application/json" },
      method: "POST",
    });
    if (!presence.ok) throw new Error("presence_failed");

    const [devicesResponse, chatsResponse, transfersResponse] = await Promise.all([
      apiFetch("/api/lan/devices", { headers: deviceHeaders() }),
      apiFetch("/api/lan/chats", { headers: deviceHeaders() }),
      apiFetch("/api/lan/transfers", { headers: deviceHeaders() }),
    ]);
    if (!devicesResponse.ok || !chatsResponse.ok || !transfersResponse.ok) throw new Error("lan_fetch_failed");
    const devicePayload = await devicesResponse.json() as { devices: LanDevice[] };
    const chatPayload = await chatsResponse.json() as { chats: LanChat[] };
    const transferPayload = await transfersResponse.json() as { transfers: LanTransfer[] };
    setDevices(devicePayload.devices);
    const canNotifyForMessages = hasMessageBaselineRef.current;
    const newlyReceivedMessages: LanMessageNotification[] = [];
    for (const chat of chatPayload.chats) {
      for (const message of chat.messages) {
        if (!message.mine && !knownMessageIdsRef.current.has(message.id)) {
          newlyReceivedMessages.push({
            chatId: chat.id,
            id: message.id,
            peerId: chat.peerId,
            peerName: chat.peerName,
            text: message.text,
          });
        }
        knownMessageIdsRef.current.add(message.id);
      }
    }
    setChats(chatPayload.chats);
    setUnreadChatIds((current) => {
      const activeChatIds = new Set(chatPayload.chats.map((chat) => chat.id));
      const next = new Set(current.filter((chatId) => activeChatIds.has(chatId)));
      newlyReceivedMessages.forEach((message) => next.add(message.chatId));
      return [...next];
    });
    hasMessageBaselineRef.current = true;
    if (canNotifyForMessages && newlyReceivedMessages.length > 0) {
      setMessageNotifications((current) => [
        ...newlyReceivedMessages.reverse(),
        ...current.filter((notification) => !newlyReceivedMessages.some((message) => message.id === notification.id)),
      ].slice(0, 50));
    }
    setTransfers(transferPayload.transfers);
    setError("");
  }, [deviceHeaders, deviceName, discoverable, identity]);

  useEffect(() => {
    let active = true;
    const poll = async () => {
      try {
        await refresh();
      } catch (refreshError) {
        if (active) setError(messageForError(refreshError));
      }
    };
    void poll();
    // REST polling is the browser-compatible LAN fallback. A short interval
    // keeps active chats feeling immediate without retaining message history.
    const interval = window.setInterval(() => void poll(), 1_000);
    const onVisibilityChange = () => {
      if (document.visibilityState === "visible") void poll();
    };
    document.addEventListener("visibilitychange", onVisibilityChange);
    return () => {
      active = false;
      window.clearInterval(interval);
      document.removeEventListener("visibilitychange", onVisibilityChange);
    };
  }, [refresh]);

  const updateChat = useCallback((nextChat: LanChat) => {
    setChats((current) => [nextChat, ...current.filter((chat) => chat.id !== nextChat.id)]);
  }, []);

  const requestChat = useCallback(async (recipientId: string) => {
    const response = await apiFetch("/api/lan/chats/request", {
      body: JSON.stringify({ recipientId }),
      headers: { "Content-Type": "application/json", ...deviceHeaders() },
      method: "POST",
    });
    const payload = await response.json().catch(() => ({})) as { chat?: LanChat; error?: string };
    if (!response.ok || !payload.chat) throw new Error(payload.error || "chat_request_failed");
    updateChat(payload.chat);
    setError("");
  }, [deviceHeaders, updateChat]);

  const acceptChat = useCallback(async (chatId: string) => {
    try {
      const response = await apiFetch(`/api/lan/chats/${encodeURIComponent(chatId)}/accept`, {
        body: JSON.stringify({}),
        headers: { "Content-Type": "application/json", ...deviceHeaders() },
        method: "POST",
      });
      const payload = await response.json().catch(() => ({})) as { chat?: LanChat };
      if (!response.ok || !payload.chat) throw new Error("chat_accept_failed");
      updateChat(payload.chat);
      setError("");
    } catch (chatError) {
      setError(messageForError(chatError));
    }
  }, [deviceHeaders, updateChat]);

  const sendChatMessage = useCallback(async (chatId: string, text: string) => {
    const response = await apiFetch(`/api/lan/chats/${encodeURIComponent(chatId)}/messages`, {
      body: JSON.stringify({ text }),
      headers: { "Content-Type": "application/json", ...deviceHeaders() },
      method: "POST",
    });
    const payload = await response.json().catch(() => ({})) as { chat?: LanChat; error?: string };
    if (!response.ok || !payload.chat) throw new Error(payload.error || "chat_message_failed");
    updateChat(payload.chat);
    setError("");
  }, [deviceHeaders, updateChat]);

  const endChat = useCallback(async (chatId: string) => {
    const response = await apiFetch(`/api/lan/chats/${encodeURIComponent(chatId)}/end`, {
      body: JSON.stringify({}),
      headers: { "Content-Type": "application/json", ...deviceHeaders() },
      method: "POST",
    });
    if (!response.ok) throw new Error("chat_end_failed");
    setChats((current) => current.filter((chat) => chat.id !== chatId));
    setUnreadChatIds((current) => current.filter((unreadChatId) => unreadChatId !== chatId));
    setMessageNotifications((current) => current.filter((notification) => notification.chatId !== chatId));
    setError("");
  }, [deviceHeaders]);

  const markChatRead = useCallback((chatId: string) => {
    setUnreadChatIds((current) => current.filter((unreadChatId) => unreadChatId !== chatId));
    setMessageNotifications((current) => current.filter((notification) => notification.chatId !== chatId));
  }, []);

  const dismissMessageNotification = useCallback((messageId: string) => {
    setMessageNotifications((current) => current.filter((notification) => notification.id !== messageId));
  }, []);

  const requestTransfers = useCallback(async (recipientId: string, files: File[]) => {
    const response = await apiFetch("/api/lan/transfers/request", {
      body: JSON.stringify({
        files: files.map((file) => ({ name: file.name, relativePath: file.webkitRelativePath || undefined, size: file.size })),
        recipientId,
      }),
      headers: { "Content-Type": "application/json", ...deviceHeaders() },
      method: "POST",
    });
    const payload = await response.json().catch(() => ({})) as { error?: string; transfers?: LanTransfer[] };
    if (!response.ok || !payload.transfers) throw new Error(payload.error || "request_failed");
    payload.transfers.forEach((transfer, index) => pendingFilesRef.current.set(transfer.id, files[index]));
    setTransfers((current) => [...payload.transfers!, ...current.filter((transfer) => !payload.transfers!.some((added) => added.id === transfer.id))]);
    setError("");
  }, [deviceHeaders]);

  const acceptTransfer = useCallback(async (transferId: string) => {
    let sink: ReceiveSink | undefined;
    try {
      const requested = transfersRef.current.find((transfer) => transfer.id === transferId && transfer.direction === "incoming");
      if (!requested) throw new Error("transfer_unavailable");
      sink = await createReceiveSink(requested.name, requested.size);
      const response = await apiFetch(`/api/lan/transfers/${encodeURIComponent(transferId)}/accept`, {
        body: JSON.stringify({}),
        headers: { "Content-Type": "application/json", ...deviceHeaders() },
        method: "POST",
      });
      const payload = await response.json().catch(() => ({})) as { transfer?: LanTransfer };
      if (!response.ok || !payload.transfer) throw new Error("transfer_response_failed");
      // Store the stream before the offer can arrive. The session is created
      // later when WebRTC receives that offer.
      receiverSinksRef.current.set(transferId, sink);
      updateTransfer(payload.transfer);
      setError("");
    } catch (responseError) {
      await sink?.dispose();
      if (responseError instanceof DOMException && responseError.name === "AbortError") {
        setError("");
      } else {
        setError(receiveStorageError(responseError));
      }
      throw responseError;
    }
  }, [deviceHeaders, updateTransfer]);

  const declineTransfer = useCallback(async (transferId: string) => {
    try {
      const response = await apiFetch(`/api/lan/transfers/${encodeURIComponent(transferId)}/decline`, {
        body: JSON.stringify({}),
        headers: { "Content-Type": "application/json", ...deviceHeaders() },
        method: "POST",
      });
      if (!response.ok) throw new Error("transfer_response_failed");
      setTransfers((current) => current.filter((transfer) => transfer.id !== transferId));
      setError("");
    } catch (responseError) {
      setError(messageForError(responseError));
    }
  }, [deviceHeaders]);

  const sendPeerSignal = useCallback(async (recipientId: string, signal: LanSignal) => {
    const response = await apiFetch("/api/lan/signals", {
      body: JSON.stringify({ recipientId, signal }),
      headers: { "Content-Type": "application/json", ...deviceHeaders() },
      method: "POST",
    });
    if (!response.ok) throw new Error("peer_signal_failed");
  }, [deviceHeaders]);

  const closePeerSession = useCallback((transferId: string) => {
    const session = peerSessionsRef.current.get(transferId);
    if (!session) return;
    if (!session.finished) void session.sink?.dispose();
    session.finished = true;
    if (session.timeout) window.clearTimeout(session.timeout);
    try { session.channel?.close(); } catch { /* The peer may already be gone. */ }
    try { session.pc.close(); } catch { /* The peer may already be gone. */ }
    peerSessionsRef.current.delete(transferId);
  }, []);

  const abortReceiverSave = useCallback(async (transferId: string) => {
    const pendingSink = receiverSinksRef.current.get(transferId);
    const activeSession = peerSessionsRef.current.get(transferId);
    receiverSinksRef.current.delete(transferId);
    await Promise.all([
      pendingSink?.dispose(),
      activeSession?.sink?.dispose(),
    ].filter((operation): operation is Promise<void> => Boolean(operation)).map((operation) => operation.catch(() => undefined)));
  }, []);

  const failPeerTransfer = useCallback(async (transfer: LanTransfer, message = "Could not establish a direct connection. Keep both devices open and try again.") => {
    await abortReceiverSave(transfer.id);
    closePeerSession(transfer.id);
    peerStartsRef.current.delete(transfer.id);
    pendingFilesRef.current.delete(transfer.id);
    try {
      const response = await apiFetch(`/api/lan/transfers/${encodeURIComponent(transfer.id)}/cancel`, {
        body: JSON.stringify({ failed: true }),
        headers: { "Content-Type": "application/json", ...deviceHeaders() },
        method: "POST",
      });
      const payload = await response.json().catch(() => ({})) as { transfer?: LanTransfer };
      if (!response.ok || !payload.transfer) throw new Error("peer_cancel_failed");
      updateTransfer(payload.transfer);
      setError(message);
    } catch {
      setError(message);
    }
  }, [abortReceiverSave, closePeerSession, deviceHeaders, updateTransfer]);

  const cancelTransfer = useCallback(async (transfer: LanTransfer) => {
    await abortReceiverSave(transfer.id);
    closePeerSession(transfer.id);
    pendingFilesRef.current.delete(transfer.id);
    peerStartsRef.current.delete(transfer.id);
    const response = await apiFetch(`/api/lan/transfers/${encodeURIComponent(transfer.id)}/cancel`, {
      body: JSON.stringify({}),
      headers: { "Content-Type": "application/json", ...deviceHeaders() },
      method: "POST",
    });
    const payload = await response.json().catch(() => ({})) as { transfer?: LanTransfer };
    if (!response.ok || !payload.transfer) throw new Error("transfer_cancel_failed");
    updateTransfer(payload.transfer);
  }, [abortReceiverSave, closePeerSession, deviceHeaders, updateTransfer]);

  const reportPeerProgress = useCallback(async (session: PeerSession, bytesTransferred: number) => {
    const percentage = session.expectedSize > 0 ? Math.floor((bytesTransferred / session.expectedSize) * 100) : 100;
    if (bytesTransferred !== session.expectedSize && percentage < session.lastProgress + 5) return;
    session.lastProgress = percentage;
    const response = await apiFetch(`/api/lan/transfers/${encodeURIComponent(session.id)}/peer-progress`, {
      body: JSON.stringify({ bytesTransferred }),
      headers: { "Content-Type": "application/json", ...deviceHeaders() },
      method: "POST",
    });
    const payload = await response.json().catch(() => ({})) as { transfer?: LanTransfer };
    if (!response.ok || !payload.transfer) throw new Error("peer_progress_failed");
    updateTransfer(payload.transfer);
  }, [deviceHeaders, updateTransfer]);

  const sendPeerFile = useCallback(async (session: PeerSession, file: File) => {
    const channel = session.channel;
    if (!channel || channel.readyState !== "open") throw new Error("peer_channel_unavailable");
    channel.send(JSON.stringify({ name: file.name, size: file.size, transferId: session.id, type: "metadata" }));
    if (session.timeout) window.clearTimeout(session.timeout);
    const sending = await sendFileChunks(channel, file, bytes => reportPeerProgress(session, bytes));
    try {
      channel.send(JSON.stringify({ transferId: session.id, type: "complete" }));
      await sending.waitForSave();
    } finally { sending.dispose(); }
    pendingFilesRef.current.delete(session.id);
    session.finished = true;
    if (session.timeout) window.clearTimeout(session.timeout);
    window.setTimeout(() => closePeerSession(session.id), 30_000);
  }, [closePeerSession, reportPeerProgress]);

  const handlePeerSignal = useCallback(async (envelope: SignalEnvelope) => {
    const signal = envelope.signal;
    if (!signal || !signal.transferId || !signal.sessionId || !["offer", "answer", "candidate", "hangup"].includes(signal.type)) return;
    const transferId = signal.transferId;
    let session = peerSessionsRef.current.get(transferId);

    if (signal.type === "offer") {
      const transfer = transfersRef.current.find((item) => item.id === transferId && item.direction === "incoming" && item.peerId === envelope.senderId);
      if (!transfer || (transfer.status !== "accepted" && transfer.status !== "receiving") || session || typeof RTCPeerConnection === "undefined" || !signal.description) return;
      const sink = receiverSinksRef.current.get(transferId);
      if (!sink) return;
      receiverSinksRef.current.delete(transferId);
      const pc = new RTCPeerConnection(QR_PEER_CONFIG);
      session = {
        sink,
        queuedBytes: 0,
        expectedSize: transfer.size,
        finished: false,
        id: transfer.id,
        lastProgress: 0,
        pc,
        peerId: envelope.senderId,
        receivedBytes: 0,
        role: "recipient",
        transfer,
        writeChain: Promise.resolve(),
      };
      peerSessionsRef.current.set(transferId, session);
      pc.onicecandidate = (event) => {
        if (event.candidate) void sendPeerSignal(envelope.senderId, { candidate: event.candidate.toJSON(), sessionId: signal.sessionId, transferId, type: "candidate" }).catch(() => void failPeerTransfer(session!.transfer));
      };
      pc.onconnectionstatechange = () => {
        if (["failed", "closed"].includes(pc.connectionState) && !session?.finished) void failPeerTransfer(session!.transfer);
      };
      pc.ondatachannel = (event) => {
        const channel = event.channel;
        session!.channel = channel;
        channel.binaryType = "arraybuffer";
        channel.onmessage = (message) => {
          if (typeof message.data === "string") {
            let control: { type?: string; transferId?: string } = {};
            try { control = JSON.parse(message.data) as { type?: string; transferId?: string }; } catch { return; }
            if (control.transferId !== transferId || control.type !== "complete") return;
            if (session!.receivedBytes !== session!.expectedSize) {
              setError("The direct transfer was incomplete. Ask the sender to try again.");
              closePeerSession(transferId);
              return;
            }
            void session!.writeChain.then(async () => {
              const file = await session!.sink!.close();
              if (file) {
                peerFilesRef.current.set(transferId, file);
                savedSinksRef.current.set(transferId, session!.sink!);
              }

              const response = await apiFetch(`/api/lan/transfers/${encodeURIComponent(transferId)}/peer-complete`, {
                body: JSON.stringify({}),
                headers: { "Content-Type": "application/json", ...deviceHeaders() },
                method: "POST",
              });
              const payload = await response.json().catch(() => ({})) as { transfer?: LanTransfer };
              if (!response.ok || !payload.transfer) throw new Error("peer_complete_failed");
              updateTransfer(payload.transfer);
              session!.finished = true;
              channel.send(JSON.stringify({ type: "saved" }));
              if (session!.timeout) window.clearTimeout(session!.timeout);
              window.setTimeout(() => closePeerSession(transferId), 30_000);
            }).catch(() => void failPeerTransfer(session!.transfer, "The received file could not be saved. Ask the sender to try again."));
            return;
          }
          const chunk = message.data instanceof ArrayBuffer ? message.data : null;
          if (!chunk) return;
          if (session!.receivedBytes + chunk.byteLength > session!.expectedSize) {
            void failPeerTransfer(session!.transfer, "The sender sent more data than expected, so the transfer was cancelled.");
            return;
          }
          const length = chunk.byteLength;
          session!.queuedBytes = (session!.queuedBytes ?? 0) + length;
          if (session!.queuedBytes > 2 * 1024 * 1024) {
            void failPeerTransfer(session!.transfer, "The sender sent data too quickly. Update both devices and try again.");
            return;
          }
          session!.writeChain = session!.writeChain.then(async () => {
            if (session!.finished) return;
            await session!.sink!.write(chunk);
            session!.queuedBytes! -= length;
            channel.send(JSON.stringify({ type: "ack", bytes: session!.receivedBytes - session!.queuedBytes! }));
          });
          void session!.writeChain.catch(cause => {
            if (!session!.finished) void failPeerTransfer(session!.transfer, receiveStorageError(cause));
          });
          session!.receivedBytes += chunk.byteLength;
          const progress = Math.min(99, Math.round((session!.receivedBytes / session!.expectedSize) * 100));
          updateTransfer({ ...session!.transfer, progress, status: "receiving" });
        };
      };
      await pc.setRemoteDescription(signal.description);
      const queuedCandidates = (pendingPeerCandidatesRef.current.get(transferId) || [])
        .filter((candidate) => candidate.senderId === envelope.senderId)
        .map((candidate) => candidate.candidate);
      pendingPeerCandidatesRef.current.delete(transferId);
      await Promise.all(queuedCandidates.map((candidate) => pc.addIceCandidate(candidate)));
      await pc.setLocalDescription(await pc.createAnswer());
      await sendPeerSignal(envelope.senderId, { description: pc.localDescription?.toJSON(), sessionId: signal.sessionId, transferId, type: "answer" });
      return;
    }

    if (!session) {
      if (signal.type === "candidate" && signal.candidate) {
        pendingPeerCandidatesRef.current.set(transferId, [...(pendingPeerCandidatesRef.current.get(transferId) || []), { candidate: signal.candidate, senderId: envelope.senderId }]);
      }
      return;
    }
    if (session.peerId !== envelope.senderId) return;
    if (signal.type === "answer" && session.role === "sender" && signal.description) {
      await session.pc.setRemoteDescription(signal.description);
      const queuedCandidates = (pendingPeerCandidatesRef.current.get(transferId) || [])
        .filter((candidate) => candidate.senderId === envelope.senderId)
        .map((candidate) => candidate.candidate);
      pendingPeerCandidatesRef.current.delete(transferId);
      await Promise.all(queuedCandidates.map((candidate) => session!.pc.addIceCandidate(candidate)));
      return;
    }
    if (signal.type === "candidate" && signal.candidate) {
      if (session.pc.remoteDescription) await session.pc.addIceCandidate(signal.candidate);
      else pendingPeerCandidatesRef.current.set(transferId, [...(pendingPeerCandidatesRef.current.get(transferId) || []), { candidate: signal.candidate, senderId: envelope.senderId }]);
    }
    if (signal.type === "hangup") closePeerSession(transferId);
  }, [closePeerSession, deviceHeaders, failPeerTransfer, sendPeerSignal, updateTransfer]);

  const pollPeerSignals = useCallback(async () => {
    if (typeof RTCPeerConnection === "undefined") return;
    const response = await apiFetch("/api/lan/signals", { headers: deviceHeaders() });
    if (!response.ok) return;
    const payload = await response.json().catch(() => ({ signals: [] })) as { signals?: SignalEnvelope[] };
    for (const signal of payload.signals || []) {
      try { await handlePeerSignal(signal); } catch { setError("Could not establish the direct transfer connection."); }
    }
  }, [deviceHeaders, handlePeerSignal]);

  useEffect(() => {
    const peerSessions = peerSessionsRef.current;
    const poll = () => void pollPeerSignals();
    poll();
    const interval = window.setInterval(poll, 750);
    const onVisibilityChange = () => { if (document.visibilityState === "visible") poll(); };
    document.addEventListener("visibilitychange", onVisibilityChange);
    return () => {
      window.clearInterval(interval);
      document.removeEventListener("visibilitychange", onVisibilityChange);
      peerSessions.forEach((_session, transferId) => closePeerSession(transferId));
    };
  }, [closePeerSession, pollPeerSignals]);

  const startPeerTransfer = useCallback(async (transfer: LanTransfer, file: File) => {
    if (typeof RTCPeerConnection === "undefined") {
      await failPeerTransfer(transfer, "This browser does not support direct WebRTC file transfers.");
      return;
    }
    const pc = new RTCPeerConnection(QR_PEER_CONFIG);
    const session: PeerSession = {
      expectedSize: file.size,
      finished: false,
      id: transfer.id,
      lastProgress: 0,
      pc,
      peerId: transfer.peerId,
      receivedBytes: 0,
      role: "sender",
      transfer,
      writeChain: Promise.resolve(),
    };
    peerSessionsRef.current.set(transfer.id, session);
    const sessionId = `transfer_${transfer.id.replaceAll("-", "")}`;
    const channel = pc.createDataChannel("babyshare-file", { ordered: true });
    session.channel = channel;
    channel.bufferedAmountLowThreshold = 256 * 1024;
    pc.onicecandidate = (event) => {
      if (event.candidate) void sendPeerSignal(transfer.peerId, { candidate: event.candidate.toJSON(), sessionId, transferId: transfer.id, type: "candidate" }).catch(() => void failPeerTransfer(transfer));
    };
    pc.onconnectionstatechange = () => {
      if (["failed", "disconnected", "closed"].includes(pc.connectionState) && !session.finished) void failPeerTransfer(transfer);
    };
    channel.onopen = () => {
      if (session.timeout) window.clearTimeout(session.timeout);
      void sendPeerFile(session, file).catch(() => void failPeerTransfer(transfer));
    };
    try {
      const started = await apiFetch(`/api/lan/transfers/${encodeURIComponent(transfer.id)}/peer-start`, {
        body: JSON.stringify({}),
        headers: { "Content-Type": "application/json", ...deviceHeaders() },
        method: "POST",
      });
      const payload = await started.json().catch(() => ({})) as { transfer?: LanTransfer };
      if (!started.ok || !payload.transfer) throw new Error("peer_start_failed");
      session.transfer = payload.transfer;
      updateTransfer(payload.transfer);
      await pc.setLocalDescription(await pc.createOffer());
      await sendPeerSignal(transfer.peerId, { description: pc.localDescription?.toJSON(), sessionId, transferId: transfer.id, type: "offer" });
      session.timeout = window.setTimeout(() => {
        if (!session.finished) void failPeerTransfer(transfer);
      }, 12_000);
    } catch {
      await failPeerTransfer(transfer);
    }
  }, [deviceHeaders, failPeerTransfer, sendPeerFile, sendPeerSignal, updateTransfer]);

  useEffect(() => {
    const next = transfers.find((transfer) => transfer.direction === "outgoing"
      && transfer.transport === "peer"
      && transfer.status === "accepted"
      && pendingFilesRef.current.has(transfer.id)
      && !peerStartsRef.current.has(transfer.id));
    if (!next) return;
    const file = pendingFilesRef.current.get(next.id);
    if (!file) return;
    peerStartsRef.current.add(next.id);
    void startPeerTransfer(next, file);
  }, [startPeerTransfer, transfers]);

  const downloadTransfer = useCallback((transfer: LanTransfer) => {
    const file = peerFilesRef.current.get(transfer.id);
    if (!file) {
      setError("This file was saved directly to your device. BabyShare does not keep a second copy.");
      return false;
    }
    const link = document.createElement("a");
    const objectUrl = URL.createObjectURL(file);
    link.href = objectUrl;
    link.download = transfer.name;
    document.body.append(link);
    link.click();
    link.remove();
    window.setTimeout(() => {
      URL.revokeObjectURL(objectUrl);
      void savedSinksRef.current.get(transfer.id)?.dispose();
      savedSinksRef.current.delete(transfer.id);
    }, 60_000);
    peerFilesRef.current.delete(transfer.id);
    return true;
  }, []);

  const canDownloadTransfer = useCallback((transferId: string) => peerFilesRef.current.has(transferId), []);

  const dismissTransferNotification = useCallback((transferId: string) => {
    setDismissedTransferIds((current) => current.includes(transferId) ? current : [...current, transferId]);
  }, []);

  const renameCurrentDevice = useCallback((name: string) => {
    const cleaned = name.replace(DEVICE_NAME_DISALLOWED_CHARACTERS, "").trim().slice(0, 80) || `${identity.platform} device`;
    localStorage.setItem(DEVICE_NAME_KEY, cleaned);
    setDeviceName(cleaned);
  }, [identity.platform]);

  const signOutCurrentDevice = useCallback(() => {
    localStorage.removeItem(DEVICE_ID_KEY);
    localStorage.removeItem(DEVICE_TOKEN_KEY);
    localStorage.removeItem(DEVICE_NAME_KEY);
    window.location.assign("/");
  }, []);

  const setDiscoverable = useCallback((value: boolean) => {
    localStorage.setItem(DISCOVERABLE_KEY, String(value));
    setDiscoverableState(value);
  }, []);

  return (
    <LanTransferContext.Provider value={{
      acceptTransfer,
      acceptChat,
      cancelTransfer,
      chats,
      canDownloadTransfer,
      currentDevice: { id: identity.deviceId, name: deviceName, platform: identity.platform },
      discoverable,
      declineTransfer,
      dismissedTransferIds,
      devices,
      dismissMessageNotification,
      dismissTransferNotification,
      downloadTransfer,
      endChat,
      error,
      markChatRead,
      messageNotifications,
      requestChat,
      requestTransfers,
      renameCurrentDevice,
      sendChatMessage,
      setDiscoverable,
      signOutCurrentDevice,
      transfers,
      unreadChatIds,
    }}>
      {children}
    </LanTransferContext.Provider>
  );
}

// eslint-disable-next-line react-refresh/only-export-components
export function useLanTransfers() {
  const context = useContext(LanTransferContext);
  if (!context) throw new Error("useLanTransfers must be used within LanTransferProvider");
  return context;
}

function transferStatus(transfer: LanTransfer, canDownload = false) {
  if (transfer.status === "pending") return "Waiting for your response";
  if (transfer.status === "accepted") return "Save location selected — establishing a direct connection";
  if (transfer.status === "receiving") return `Receiving directly ${transfer.progress}%`;
  if (transfer.status === "completed") return canDownload ? "File received — ready to save" : "Saved directly to this device";
  if (transfer.status === "cancelled") return "Cancelled";
  return "Direct connection failed — ask the sender to try again";
}

export function LanTransferNotifications() {
  const {
    acceptChat,
    acceptTransfer,
    chats,
    canDownloadTransfer,
    cancelTransfer,
    declineTransfer,
    dismissedTransferIds,
    downloadTransfer,
    dismissMessageNotification,
    dismissTransferNotification,
    endChat,
    messageNotifications,
    transfers,
  } = useLanTransfers();
  const [savingTransferId, setSavingTransferId] = useState<string | null>(null);
  const [transferActionErrors, setTransferActionErrors] = useState<Record<string, string>>({});
  const incomingChats = chats.filter((chat) => chat.direction === "incoming" && chat.status === "pending").slice(0, 3);
  const incomingTransfers = transfers.filter((transfer) => transfer.direction === "incoming"
    && !dismissedTransferIds.includes(transfer.id)
    && ["pending", "accepted", "receiving", "completed"].includes(transfer.status)).slice(0, 3);
  const messageGroups: Array<{ chatId: string; messages: LanMessageNotification[]; peerId: string; peerName: string }> = [];
  messageNotifications.forEach((message) => {
    const group = messageGroups.find((candidate) => candidate.chatId === message.chatId);
    if (group) group.messages.push(message);
    else messageGroups.push({ chatId: message.chatId, messages: [message], peerId: message.peerId, peerName: message.peerName });
  });
  const openMessage = (message: LanMessageNotification) => {
    window.dispatchEvent(new CustomEvent("babyshare:open-chat", { detail: { peerId: message.peerId } }));
    dismissMessageNotification(message.id);
  };
  const dismissMessageGroup = (messages: LanMessageNotification[]) => messages.forEach((message) => dismissMessageNotification(message.id));
  const saveIncomingTransfer = async (transfer: LanTransfer) => {
    setSavingTransferId(transfer.id);
    setTransferActionErrors((current) => {
      const next = { ...current };
      delete next[transfer.id];
      return next;
    });
    try {
      await acceptTransfer(transfer.id);
    } catch (cause) {
      if (cause instanceof DOMException && cause.name === "AbortError") return;
      const message = cause instanceof Error && ["storage_unavailable", "storage_full"].includes(cause.message)
        ? receiveStorageError(cause)
        : receiveStorageError(cause);
      setTransferActionErrors((current) => ({ ...current, [transfer.id]: message }));
    } finally {
      setSavingTransferId((current) => current === transfer.id ? null : current);
    }
  };
  const cancelIncomingTransfer = async (transfer: LanTransfer) => {
    setTransferActionErrors((current) => {
      const next = { ...current };
      delete next[transfer.id];
      return next;
    });
    try {
      if (transfer.status === "pending") await declineTransfer(transfer.id);
      else await cancelTransfer(transfer);
    } catch {
      setTransferActionErrors((current) => ({ ...current, [transfer.id]: "Could not cancel this transfer. Please try again." }));
    }
  };

  useEffect(() => {
    if (messageNotifications.length === 0) return;
    const timer = window.setTimeout(() => messageNotifications.forEach((message) => dismissMessageNotification(message.id)), 8_000);
    return () => window.clearTimeout(timer);
  }, [dismissMessageNotification, messageNotifications]);

  if (messageNotifications.length === 0 && incomingChats.length === 0 && incomingTransfers.length === 0) return null;

  return (
    <aside className="lan-notifications" aria-live="polite" aria-label="Nearby device alerts">
      {messageGroups.slice(0, 2).map((group) => {
        const latestMessage = group.messages[0];
        const messageCount = group.messages.length;
        return (
        <section className="lan-notification lan-message-notification" key={group.chatId}>
          <div className="lan-message-heading">
            <span className="lan-message-avatar" aria-hidden="true">{group.peerName.trim().charAt(0).toUpperCase() || "G"}</span>
            <div>
              <p className="lan-notification-kicker">{messageCount === 1 ? "New message" : `${messageCount} new messages`}</p>
              <strong>{group.peerName}</strong>
            </div>
            <button type="button" className="lan-message-close" onClick={() => dismissMessageGroup(group.messages)} aria-label={`Dismiss messages from ${group.peerName}`}>×</button>
          </div>
          <p className="lan-message-preview">{latestMessage.text}</p>
          <button type="button" className="lan-accept lan-message-open" onClick={() => openMessage(latestMessage)}>Open chat</button>
        </section>
        );
      })}
      {incomingChats.map((chat) => (
        <section className="lan-notification lan-chat-request" key={chat.id}>
          <div className="lan-request-heading">
            <span className="lan-request-avatar" aria-hidden="true">{chat.peerName.trim().charAt(0).toUpperCase() || "G"}</span>
            <div><p className="lan-notification-kicker">Private chat request</p><strong>{chat.peerName}</strong></div>
            <span className="lan-request-new"><i aria-hidden="true" />New</span>
          </div>
          <p className="lan-request-copy">Wants to start a private chat</p>
          <div className="lan-notification-actions">
            <button type="button" className="lan-accept" onClick={() => void acceptChat(chat.id)}>Accept</button>
            <button type="button" className="lan-decline" onClick={() => void endChat(chat.id).catch(() => {})}>Decline</button>
          </div>
        </section>
      ))}
      {incomingTransfers.map((transfer) => (
        <section className="lan-notification" key={transfer.id}>
          <p className="lan-notification-kicker">Nearby file request</p>
          <strong>{transfer.peerName} wants to send {transfer.name}</strong>
          <p>Private one-time transfer — no conversation history is saved.</p>
          <p className="lan-transfer-state">{transferStatus(transfer, canDownloadTransfer(transfer.id))}</p>
          {transferActionErrors[transfer.id] && <p className="lan-transfer-error" role="alert">{transferActionErrors[transfer.id]}</p>}
          {transfer.status === "receiving" && <progress max="100" value={transfer.progress} />}
          {transfer.status === "pending" && (
            <div className="lan-notification-actions">
              <button type="button" className="lan-accept" disabled={savingTransferId === transfer.id} onClick={() => void saveIncomingTransfer(transfer)}>
                {savingTransferId === transfer.id ? "Preparing storage…" : "Accept file"}
              </button>
              <button type="button" className="lan-decline" disabled={savingTransferId === transfer.id} onClick={() => void cancelIncomingTransfer(transfer)}>Cancel</button>
            </div>
          )}
          {transfer.status === "completed" && (canDownloadTransfer(transfer.id) ? (
            <div className="lan-notification-actions">
              <button type="button" className="lan-accept" onClick={() => {
                if (downloadTransfer(transfer)) dismissTransferNotification(transfer.id);
              }}>Save file</button>
              <button type="button" className="lan-decline" onClick={() => dismissTransferNotification(transfer.id)}>Dismiss</button>
            </div>
          ) : (
            <div className="lan-notification-actions lan-notification-complete-actions">
              <span>Saved to the location you chose.</span>
              <button type="button" className="lan-decline" onClick={() => dismissTransferNotification(transfer.id)}>Dismiss</button>
            </div>
          ))}
          {["accepted", "receiving"].includes(transfer.status) && <button type="button" className="lan-decline" onClick={() => void cancelIncomingTransfer(transfer)}>Cancel transfer</button>}
        </section>
      ))}
    </aside>
  );
}
