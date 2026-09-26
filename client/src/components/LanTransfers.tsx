import { createContext, useCallback, useContext, useEffect, useRef, useState } from "react";
import type { ReactNode } from "react";
import { apiFetch, apiUrl, uploadFormData } from "../lib/api";

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
export type LanTransfer = {
  createdAt: number;
  direction: "incoming" | "outgoing";
  id: string;
  name: string;
  peerName: string;
  progress: number;
  size: number;
  status: "pending" | "accepted" | "receiving" | "ready" | "downloading";
  updatedAt: number;
};

type DeviceIdentity = { deviceId: string; deviceToken: string; platform: string };
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
  transfers: LanTransfer[];
  unreadChatIds: string[];
  acceptTransfer: (transferId: string) => Promise<void>;
  declineTransfer: (transferId: string) => Promise<void>;
  downloadTransfer: (transfer: LanTransfer) => void;
};

const LanTransferContext = createContext<LanTransferContextValue | null>(null);
const DEVICE_ID_KEY = "babyshare.lan.device-id";
const DEVICE_TOKEN_KEY = "babyshare.lan.device-token";

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

function messageForError(error: unknown) {
  if (error instanceof Error && error.message === "device_unavailable") return "That device is no longer available. Refresh and try again.";
  return "Nearby device sharing is temporarily unavailable. Keep BabyShare open and try again.";
}

export function LanTransferProvider({ children }: { children: ReactNode }) {
  const [identity] = useState(getIdentity);
  const pendingFilesRef = useRef(new Map<string, File>());
  const uploadsInFlightRef = useRef(new Set<string>());
  const knownMessageIdsRef = useRef(new Set<string>());
  const [devices, setDevices] = useState<LanDevice[]>([]);
  const [chats, setChats] = useState<LanChat[]>([]);
  const [transfers, setTransfers] = useState<LanTransfer[]>([]);
  const [unreadChatIds, setUnreadChatIds] = useState<string[]>([]);
  const [error, setError] = useState("");

  const deviceHeaders = useCallback(() => ({
    "x-babyshare-device-id": identity.deviceId,
    "x-babyshare-device-token": identity.deviceToken,
  }), [identity]);

  const refresh = useCallback(async () => {
    const presence = await apiFetch("/api/lan/presence", {
      body: JSON.stringify(identity),
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
    setChats(chatPayload.chats);
    setUnreadChatIds((current) => {
      const activeChatIds = new Set(chatPayload.chats.map((chat) => chat.id));
      const next = new Set(current.filter((chatId) => activeChatIds.has(chatId)));
      for (const chat of chatPayload.chats) {
        for (const message of chat.messages) {
          if (!message.mine && !knownMessageIdsRef.current.has(message.id)) next.add(chat.id);
          knownMessageIdsRef.current.add(message.id);
        }
      }
      return [...next];
    });
    setTransfers(transferPayload.transfers);
    setError("");
  }, [deviceHeaders, identity]);

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
    setError("");
  }, [deviceHeaders]);

  const markChatRead = useCallback((chatId: string) => {
    setUnreadChatIds((current) => current.filter((unreadChatId) => unreadChatId !== chatId));
  }, []);

  const requestTransfers = useCallback(async (recipientId: string, files: File[]) => {
    const response = await apiFetch("/api/lan/transfers/request", {
      body: JSON.stringify({
        files: files.map((file) => ({ name: file.name, size: file.size })),
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

  const updateTransfer = useCallback((nextTransfer: LanTransfer) => {
    setTransfers((current) => [nextTransfer, ...current.filter((transfer) => transfer.id !== nextTransfer.id)]);
  }, []);

  const acceptTransfer = useCallback(async (transferId: string) => {
    try {
      const response = await apiFetch(`/api/lan/transfers/${encodeURIComponent(transferId)}/accept`, {
        body: JSON.stringify({}),
        headers: { "Content-Type": "application/json", ...deviceHeaders() },
        method: "POST",
      });
      const payload = await response.json().catch(() => ({})) as { transfer?: LanTransfer };
      if (!response.ok || !payload.transfer) throw new Error("transfer_response_failed");
      updateTransfer(payload.transfer);
      setError("");
    } catch (responseError) {
      setError(messageForError(responseError));
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

  useEffect(() => {
    const next = transfers.find((transfer) => transfer.direction === "outgoing"
      && transfer.status === "accepted"
      && pendingFilesRef.current.has(transfer.id)
      && !uploadsInFlightRef.current.has(transfer.id));
    if (!next) return;

    const file = pendingFilesRef.current.get(next.id);
    if (!file) return;
    uploadsInFlightRef.current.add(next.id);
    const data = new FormData();
    data.append("file", file);
    updateTransfer({ ...next, progress: 0, status: "receiving" });

    void uploadFormData<{ transfer: LanTransfer }>(
      `/api/lan/transfers/${encodeURIComponent(next.id)}/content`,
      data,
      (progress) => updateTransfer({ ...next, progress, status: "receiving" }),
      { headers: deviceHeaders() },
    ).then((payload) => {
      pendingFilesRef.current.delete(next.id);
      updateTransfer(payload.transfer);
    }).catch(() => {
      setError("The selected file could not be sent. Keep this page open and try again.");
    }).finally(() => {
      uploadsInFlightRef.current.delete(next.id);
      void refresh();
    });
  }, [deviceHeaders, refresh, transfers, updateTransfer]);

  const downloadTransfer = useCallback((transfer: LanTransfer) => {
    const params = new URLSearchParams({ deviceId: identity.deviceId, deviceToken: identity.deviceToken });
    const link = document.createElement("a");
    link.href = apiUrl(`/api/lan/transfers/${encodeURIComponent(transfer.id)}/download?${params.toString()}`);
    link.download = transfer.name;
    document.body.append(link);
    link.click();
    link.remove();
    updateTransfer({ ...transfer, status: "downloading" });
  }, [identity, updateTransfer]);

  return (
    <LanTransferContext.Provider value={{
      acceptTransfer,
      acceptChat,
      chats,
      declineTransfer,
      devices,
      downloadTransfer,
      endChat,
      error,
      markChatRead,
      requestChat,
      requestTransfers,
      sendChatMessage,
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

function transferStatus(transfer: LanTransfer) {
  if (transfer.status === "pending") return "Waiting for your response";
  if (transfer.status === "accepted") return "Accepted — sender is preparing the file";
  if (transfer.status === "receiving") return `Receiving ${transfer.progress}%`;
  return "Ready to download once";
}

export function LanTransferNotifications() {
  const {
    acceptChat,
    acceptTransfer,
    chats,
    declineTransfer,
    downloadTransfer,
    endChat,
    transfers,
  } = useLanTransfers();
  const incomingChats = chats.filter((chat) => chat.direction === "incoming" && chat.status === "pending").slice(0, 3);
  const incomingTransfers = transfers.filter((transfer) => transfer.direction === "incoming"
    && ["pending", "accepted", "receiving", "ready"].includes(transfer.status)).slice(0, 3);
  if (incomingChats.length === 0 && incomingTransfers.length === 0) return null;

  return (
    <aside className="lan-notifications" aria-live="polite" aria-label="Nearby device alerts">
      {incomingChats.map((chat) => (
        <section className="lan-notification" key={chat.id}>
          <p className="lan-notification-kicker">Private chat request</p>
          <strong>{chat.peerName} wants to start a private chat</strong>
          <p>Messages are available only during this chat and are deleted for both people when either person ends it.</p>
          <div className="lan-notification-actions">
            <button type="button" className="lan-accept" onClick={() => void acceptChat(chat.id)}>Accept chat</button>
            <button type="button" className="lan-decline" onClick={() => void endChat(chat.id).catch(() => {})}>Decline</button>
          </div>
        </section>
      ))}
      {incomingTransfers.map((transfer) => (
        <section className="lan-notification" key={transfer.id}>
          <p className="lan-notification-kicker">Nearby file request</p>
          <strong>{transfer.peerName} wants to send {transfer.name}</strong>
          <p>Private one-time transfer — no conversation history is saved.</p>
          <p>{transferStatus(transfer)}</p>
          {transfer.status === "receiving" && <progress max="100" value={transfer.progress} />}
          {transfer.status === "pending" && (
            <div className="lan-notification-actions">
              <button type="button" className="lan-accept" onClick={() => void acceptTransfer(transfer.id)}>Accept file</button>
              <button type="button" className="lan-decline" onClick={() => void declineTransfer(transfer.id)}>Decline</button>
            </div>
          )}
          {transfer.status === "ready" && <button type="button" className="lan-accept" onClick={() => downloadTransfer(transfer)}>Download once</button>}
        </section>
      ))}
    </aside>
  );
}
